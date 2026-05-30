// Copyright (C) 2026 Christian Rößner
//
// SPDX-License-Identifier: AGPL-3.0-only
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package backend

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/croessner/nauthilus-director/internal/config"
)

// Backend describes one protocol-specific backend entry.
type Backend struct {
	Identifier      string
	Protocol        string
	BackendPool     string
	ShardTag        string
	Address         string
	TLS             TLSConfig
	Auth            AuthConfig
	MaintenanceMode MaintenanceMode
	Weight          int
	MaxConnections  int
	HealthEnabled   bool
	Health          HealthConfig
}

// PlacementFacts contains the bounded backend identity used by runtime overrides.
type PlacementFacts struct {
	BackendIdentifier string
	Protocol          string
	BackendPool       string
	EffectiveShard    string
}

// TLSConfig describes the transport security policy for one backend connection.
type TLSConfig struct {
	Mode               string
	CAFile             string
	Cert               string
	Key                config.SecretString
	ServerName         string
	MinTLSVersion      string
	InsecureSkipVerify bool
}

// AuthConfig describes the backend login mode used after frontend auth succeeds.
type AuthConfig struct {
	Mode             string
	MasterUser       MasterUserConfig
	CredentialReplay CredentialReplayConfig
	SASL             SASLConfig
	OAuthBearer      OAuthBearerConfig
}

// MasterUserConfig contains the configured administrative IMAP login identity.
type MasterUserConfig struct {
	Username   string
	Password   config.SecretString
	UserFormat string
	Mechanism  string
}

// CredentialReplayConfig contains the mechanism policy for replaying frontend credentials.
type CredentialReplayConfig struct {
	RequireBackendTLS bool
	PreserveMechanism bool
	AllowedMechanisms []string
}

// SASLConfig contains LMTP director-to-backend service credentials.
type SASLConfig struct {
	Mechanism  string
	Username   string
	Password   config.SecretString
	RequireTLS bool
}

// OAuthBearerConfig contains LMTP director-to-backend bearer token material.
type OAuthBearerConfig struct {
	Token      config.SecretString
	RequireTLS bool
}

// HealthConfig describes the credentialed backend health-check policy.
type HealthConfig struct {
	Enabled   bool
	DeepCheck bool
	Username  string
	Password  config.SecretString
}

// Pool describes one configured backend pool and its selector.
type Pool struct {
	Name     string
	Protocol string
	Selector string
	Backends []string
}

// PlacementFacts returns secret-free backend identity for runtime state.
func (b Backend) PlacementFacts() PlacementFacts {
	return PlacementFacts{
		BackendIdentifier: strings.TrimSpace(b.Identifier),
		Protocol:          normalizeProtocol(b.Protocol),
		BackendPool:       strings.TrimSpace(b.BackendPool),
		EffectiveShard:    strings.TrimSpace(b.ShardTag),
	}
}

// Registry exposes backend entries without owning selection policy.
type Registry interface {
	AllBackends(ctx context.Context) ([]Backend, error)
	BackendsForShard(ctx context.Context, request RegistryRequest) ([]Backend, error)
	Lookup(ctx context.Context, identifier string) (Backend, error)
	Pool(ctx context.Context, name string) (Pool, error)
}

// RegistryRequest identifies the logical shard-to-backend lookup.
type RegistryRequest struct {
	Protocol    string
	BackendPool string
	ShardTag    string
}

// ErrorKind classifies fail-closed backend registry and selector failures.
type ErrorKind string

const (
	// ErrorKindAmbiguous reports backend state that cannot be interpreted safely.
	ErrorKindAmbiguous ErrorKind = "ambiguous"
	// ErrorKindConfig reports unusable local backend configuration.
	ErrorKindConfig ErrorKind = "config"
	// ErrorKindInvalidRequest reports missing selector or registry request facts.
	ErrorKindInvalidRequest ErrorKind = "invalid_request"
	// ErrorKindNoBackend reports that no statically eligible backend exists.
	ErrorKindNoBackend ErrorKind = "no_backend"
)

// Error is a secret-safe backend registry or selector failure.
type Error struct {
	Kind      ErrorKind
	Operation string
	Message   string
	cause     error
}

// Error returns a backend diagnostic without high-cardinality account values.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}

	message := "backend failed: " + string(e.Kind)
	if e.Operation != "" {
		message += " operation=" + e.Operation
	}

	if e.Message != "" {
		message += " " + e.Message
	}

	return message
}

// Unwrap exposes the wrapped cause for classification.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.cause
}

// IsErrorKind reports whether err wraps a backend error with kind.
func IsErrorKind(err error, kind ErrorKind) bool {
	var backendErr *Error
	if !errors.As(err, &backendErr) {
		return false
	}

	return backendErr.Kind == kind
}

// StaticRegistry indexes backend config by protocol, pool and shard.
type StaticRegistry struct {
	mu       sync.RWMutex
	pools    map[string]Pool
	backends map[string]Backend
	byShard  map[registryKey][]Backend
}

type registryKey struct {
	protocol    string
	backendPool string
	shardTag    string
}

// NewStaticRegistry builds a fail-closed static backend registry from typed config.
func NewStaticRegistry(director config.DirectorConfig) (*StaticRegistry, error) {
	return buildStaticRegistry(director)
}

// Reload replaces the immutable backend snapshot used by new selections.
func (r *StaticRegistry) Reload(director config.DirectorConfig) error {
	if r == nil {
		return newBackendError(ErrorKindConfig, "registry", "registry unavailable", nil)
	}

	next, err := buildStaticRegistry(director)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.pools = next.pools
	r.backends = next.backends
	r.byShard = next.byShard

	return nil
}

// buildStaticRegistry builds a detached registry snapshot from typed config.
func buildStaticRegistry(director config.DirectorConfig) (*StaticRegistry, error) {
	director = director.Normalize()

	registry := &StaticRegistry{
		pools:    make(map[string]Pool, len(director.BackendPools)),
		backends: make(map[string]Backend, len(director.Backends)),
		byShard:  make(map[registryKey][]Backend),
	}

	poolNames := sortedPoolNames(director.BackendPools)
	for _, poolName := range poolNames {
		poolConfig := director.BackendPools[poolName]

		pool, err := newBackendPool(poolName, poolConfig)
		if err != nil {
			return nil, err
		}

		registry.pools[pool.Name] = pool

		for _, backendID := range pool.Backends {
			backendConfig, ok := director.Backends[backendID]
			if !ok {
				return nil, newBackendError(ErrorKindConfig, "registry", "pool references unknown backend", nil)
			}

			entry, err := newBackend(pool.Name, backendID, backendConfig, director.Maintenance.DefaultMode)
			if err != nil {
				return nil, err
			}

			if entry.Protocol != pool.Protocol {
				return nil, newBackendError(ErrorKindConfig, "registry", "pool and backend protocol mismatch", nil)
			}

			if existing, exists := registry.backends[entry.Identifier]; exists && existing.BackendPool != entry.BackendPool {
				return nil, newBackendError(ErrorKindAmbiguous, "registry", "backend appears in multiple pools", nil)
			}

			registry.backends[entry.Identifier] = entry

			key := registryKey{
				protocol:    entry.Protocol,
				backendPool: entry.BackendPool,
				shardTag:    entry.ShardTag,
			}
			registry.byShard[key] = append(registry.byShard[key], entry)
		}
	}

	registry.sort()

	return registry, nil
}

// AllBackends returns every configured backend in deterministic order.
func (r *StaticRegistry) AllBackends(_ context.Context) ([]Backend, error) {
	if r == nil {
		return nil, newBackendError(ErrorKindConfig, "registry", "registry unavailable", nil)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	identifiers := make([]string, 0, len(r.backends))
	for identifier := range r.backends {
		identifiers = append(identifiers, identifier)
	}

	sort.Strings(identifiers)

	backends := make([]Backend, 0, len(identifiers))
	for _, identifier := range identifiers {
		backends = append(backends, r.backends[identifier])
	}

	return backends, nil
}

// BackendsForShard returns configured backends matching protocol, pool and shard.
func (r *StaticRegistry) BackendsForShard(_ context.Context, request RegistryRequest) ([]Backend, error) {
	if r == nil {
		return nil, newBackendError(ErrorKindConfig, "registry", "registry unavailable", nil)
	}

	key, err := newRegistryKey(request)
	if err != nil {
		return nil, err
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	backends, ok := r.byShard[key]
	if !ok {
		return nil, newBackendError(ErrorKindNoBackend, "registry", "no backend for shard", nil)
	}

	return append([]Backend(nil), backends...), nil
}

// Lookup returns one configured backend by identifier.
func (r *StaticRegistry) Lookup(_ context.Context, identifier string) (Backend, error) {
	if r == nil {
		return Backend{}, newBackendError(ErrorKindConfig, "registry", "registry unavailable", nil)
	}

	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return Backend{}, newBackendError(ErrorKindInvalidRequest, "registry", "backend identifier required", nil)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	backend, ok := r.backends[identifier]
	if !ok {
		return Backend{}, newBackendError(ErrorKindNoBackend, "registry", "backend not found", nil)
	}

	return backend, nil
}

// Pool returns one configured backend pool by name.
func (r *StaticRegistry) Pool(_ context.Context, name string) (Pool, error) {
	if r == nil {
		return Pool{}, newBackendError(ErrorKindConfig, "registry", "registry unavailable", nil)
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return Pool{}, newBackendError(ErrorKindInvalidRequest, "registry", "backend pool required", nil)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	pool, ok := r.pools[name]
	if !ok {
		return Pool{}, newBackendError(ErrorKindNoBackend, "registry", "backend pool not found", nil)
	}

	pool.Backends = append([]string(nil), pool.Backends...)

	return pool, nil
}

// sort keeps registry readback deterministic for tests and diagnostics.
func (r *StaticRegistry) sort() {
	for key := range r.byShard {
		sort.Slice(r.byShard[key], func(left int, right int) bool {
			return r.byShard[key][left].Identifier < r.byShard[key][right].Identifier
		})
	}
}

// newBackendPool normalizes one configured backend pool.
func newBackendPool(name string, pool config.BackendPoolConfig) (Pool, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Pool{}, newBackendError(ErrorKindConfig, "registry", "backend pool name required", nil)
	}

	protocol := normalizeProtocol(pool.Protocol)
	if protocol == "" {
		return Pool{}, newBackendError(ErrorKindConfig, "registry", "backend pool protocol required", nil)
	}

	selector := strings.ToLower(strings.TrimSpace(pool.Selector))
	if selector == "" {
		return Pool{}, newBackendError(ErrorKindConfig, "registry", "backend pool selector required", nil)
	}

	backends := make([]string, 0, len(pool.Backends))

	seen := make(map[string]struct{}, len(pool.Backends))
	for _, backendID := range pool.Backends {
		backendID = strings.TrimSpace(backendID)
		if backendID == "" {
			return Pool{}, newBackendError(ErrorKindConfig, "registry", "backend identifier required", nil)
		}

		if _, exists := seen[backendID]; exists {
			return Pool{}, newBackendError(ErrorKindAmbiguous, "registry", "duplicate backend in pool", nil)
		}

		seen[backendID] = struct{}{}
		backends = append(backends, backendID)
	}

	if len(backends) == 0 {
		return Pool{}, newBackendError(ErrorKindConfig, "registry", "backend pool must not be empty", nil)
	}

	return Pool{Name: name, Protocol: protocol, Selector: selector, Backends: backends}, nil
}

// newBackend normalizes one configured backend entry.
func newBackend(poolName string, identifier string, backend config.BackendConfig, defaultMode string) (Backend, error) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return Backend{}, newBackendError(ErrorKindConfig, "registry", "backend identifier required", nil)
	}

	protocol := normalizeProtocol(backend.Protocol)
	if protocol == "" {
		return Backend{}, newBackendError(ErrorKindConfig, "registry", "backend protocol required", nil)
	}

	shardTag := strings.TrimSpace(backend.ShardTag)
	if shardTag == "" {
		return Backend{}, newBackendError(ErrorKindConfig, "registry", "backend shard required", nil)
	}

	mode, err := normalizeMaintenanceMode(backend.Maintenance, defaultMode)
	if err != nil {
		return Backend{}, err
	}

	if backend.Weight < 0 {
		return Backend{}, newBackendError(ErrorKindConfig, "registry", "backend weight must not be negative", nil)
	}

	if backend.MaxConnections <= 0 {
		return Backend{}, newBackendError(ErrorKindConfig, "registry", "backend max connections required", nil)
	}

	address, err := normalizeTCPAddress(backend.Address)
	if err != nil {
		return Backend{}, err
	}

	return Backend{
		Identifier:      identifier,
		Protocol:        protocol,
		BackendPool:     poolName,
		ShardTag:        shardTag,
		Address:         address,
		TLS:             newBackendTLSConfig(backend.TLS),
		Auth:            newBackendAuthConfig(backend.Auth),
		MaintenanceMode: mode,
		Weight:          backend.Weight,
		MaxConnections:  backend.MaxConnections,
		HealthEnabled:   backend.HealthCheck.Enabled,
		Health:          newBackendHealthConfig(backend.HealthCheck),
	}, nil
}

// normalizeMaintenanceMode applies the default mode and validates known static states.
func normalizeMaintenanceMode(value string, defaultMode string) (MaintenanceMode, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		value = strings.ToLower(strings.TrimSpace(defaultMode))
	}

	switch MaintenanceMode(value) {
	case MaintenanceModeDisabled, MaintenanceModeSoft, MaintenanceModeHard:
		return MaintenanceMode(value), nil
	default:
		return "", newBackendError(ErrorKindConfig, "registry", "unsupported maintenance mode", nil)
	}
}

// newRegistryKey normalizes a shard lookup request.
func newRegistryKey(request RegistryRequest) (registryKey, error) {
	key := registryKey{
		protocol:    normalizeProtocol(request.Protocol),
		backendPool: strings.TrimSpace(request.BackendPool),
		shardTag:    strings.TrimSpace(request.ShardTag),
	}

	if key.protocol == "" {
		return registryKey{}, newBackendError(ErrorKindInvalidRequest, "registry", "protocol required", nil)
	}

	if key.backendPool == "" {
		return registryKey{}, newBackendError(ErrorKindInvalidRequest, "registry", "backend pool required", nil)
	}

	if key.shardTag == "" {
		return registryKey{}, newBackendError(ErrorKindInvalidRequest, "registry", "shard tag required", nil)
	}

	return key, nil
}

// sortedPoolNames returns backend pool names in deterministic order.
func sortedPoolNames(pools map[string]config.BackendPoolConfig) []string {
	names := make([]string, 0, len(pools))
	for name := range pools {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}

// normalizeProtocol makes protocol matching case-insensitive at the boundary.
func normalizeProtocol(protocol string) string {
	return strings.ToLower(strings.TrimSpace(protocol))
}

// normalizeTCPAddress rejects Unix-socket paths before runtime backend dialing.
func normalizeTCPAddress(address string) (string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", newBackendError(ErrorKindConfig, "registry", "backend tcp address required", nil)
	}

	if looksLikeUnixSocketAddress(address) {
		return "", newBackendError(ErrorKindConfig, "registry", "backend unix socket addresses are not supported for IMAP backend connectivity", nil)
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", newBackendError(ErrorKindConfig, "registry", "backend tcp address must be host:port", err)
	}

	if strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
		return "", newBackendError(ErrorKindConfig, "registry", "backend tcp address must include host and port", nil)
	}

	if _, err := netip.ParseAddrPort(address); err == nil {
		return address, nil
	}

	return net.JoinHostPort(strings.TrimSpace(host), strings.TrimSpace(port)), nil
}

// looksLikeUnixSocketAddress detects explicit Unix networks and absolute socket paths.
func looksLikeUnixSocketAddress(address string) bool {
	lower := strings.ToLower(address)
	return strings.HasPrefix(lower, "unix:") || strings.HasPrefix(address, "/")
}

// newBackendTLSConfig copies backend TLS config into the selector result domain.
func newBackendTLSConfig(tlsConfig config.BackendTLSConfig) TLSConfig {
	return TLSConfig{
		Mode:               strings.ToLower(strings.TrimSpace(tlsConfig.Mode)),
		CAFile:             strings.TrimSpace(tlsConfig.CAFile),
		Cert:               strings.TrimSpace(tlsConfig.Cert),
		Key:                tlsConfig.Key,
		ServerName:         strings.TrimSpace(tlsConfig.ServerName),
		MinTLSVersion:      strings.TrimSpace(tlsConfig.MinTLSVersion),
		InsecureSkipVerify: tlsConfig.InsecureSkipVerify,
	}
}

// newBackendAuthConfig copies backend auth config into the selector result domain.
func newBackendAuthConfig(auth config.BackendAuthConfig) AuthConfig {
	return AuthConfig{
		Mode: strings.ToLower(strings.TrimSpace(auth.Mode)),
		MasterUser: MasterUserConfig{
			Username:   strings.TrimSpace(auth.MasterUser.Username),
			Password:   auth.MasterUser.PasswordFile,
			UserFormat: strings.TrimSpace(auth.MasterUser.UserFormat),
			Mechanism:  strings.ToLower(strings.TrimSpace(auth.MasterUser.Mechanism)),
		},
		CredentialReplay: CredentialReplayConfig{
			RequireBackendTLS: auth.CredentialReplay.RequireBackendTLS,
			PreserveMechanism: auth.CredentialReplay.PreserveMechanism,
			AllowedMechanisms: normalizeMechanisms(auth.CredentialReplay.AllowedMechanisms),
		},
		SASL: SASLConfig{
			Mechanism:  strings.ToLower(strings.TrimSpace(auth.SASL.Mechanism)),
			Username:   strings.TrimSpace(auth.SASL.Username),
			Password:   auth.SASL.PasswordFile,
			RequireTLS: auth.SASL.RequireTLS,
		},
		OAuthBearer: OAuthBearerConfig{
			Token:      auth.OAuthBearer.TokenFile,
			RequireTLS: auth.OAuthBearer.RequireTLS,
		},
	}
}

// newBackendHealthConfig copies health config without exposing credentials.
func newBackendHealthConfig(health config.BackendHealthConfig) HealthConfig {
	return HealthConfig{
		Enabled:   health.Enabled,
		DeepCheck: health.DeepCheck,
		Username:  strings.TrimSpace(health.Username),
		Password:  health.PasswordFile,
	}
}

// normalizeMechanisms canonicalizes configured mechanism names at the backend boundary.
func normalizeMechanisms(mechanisms []string) []string {
	normalized := make([]string, 0, len(mechanisms))
	for _, mechanism := range mechanisms {
		mechanism = strings.ToLower(strings.TrimSpace(mechanism))
		if mechanism != "" {
			normalized = append(normalized, mechanism)
		}
	}

	return normalized
}

// newBackendError creates a classified backend error.
func newBackendError(kind ErrorKind, operation string, message string, cause error) *Error {
	return &Error{
		Kind:      kind,
		Operation: operation,
		Message:   message,
		cause:     cause,
	}
}

// formatBackendCount builds a secret-free backend count diagnostic.
func formatBackendCount(count int) string {
	return fmt.Sprintf("%d backend candidates", count)
}
