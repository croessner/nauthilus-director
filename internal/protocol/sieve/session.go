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

// Package sieve owns ManageSieve protocol behavior after listener transport setup.
package sieve

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/placement"
	"github.com/croessner/nauthilus-director/internal/protocol/greeting"
	"github.com/croessner/nauthilus-director/internal/proxy"
	"github.com/croessner/nauthilus-director/internal/routing"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
)

const (
	// ImplementationName is the stable ManageSieve implementation product name.
	ImplementationName = "nauthilus-director"
	// ProtocolVersionRFC5804 is the RFC 5804 ManageSieve protocol version.
	ProtocolVersionRFC5804 = "1.0"
	// TLSModeImplicit marks Sieve-over-TLS listeners where TLS is active before greeting.
	TLSModeImplicit = "implicit"
	// TLSModeStartTLS marks cleartext Sieve listeners where STARTTLS may be advertised.
	TLSModeStartTLS = "starttls"

	defaultMaxLineBytes      = 8192
	defaultMaxLiteralBytes   = 8192
	defaultMaxBearerBytes    = 8192
	defaultAuthCallTimeout   = time.Second
	protocolSieve            = "sieve"
	startTLSInjectionMessage = "STARTTLS cannot be pipelined"
)

var (
	// ErrPreauthLineTooLarge reports that pre-auth input exceeded the configured line boundary.
	ErrPreauthLineTooLarge = errors.New("sieve: preauth line exceeds configured limit")
	// ErrPreauthLiteralTooLarge reports that a literal marker exceeded the configured boundary.
	ErrPreauthLiteralTooLarge = errors.New("sieve: preauth literal exceeds configured limit")
	// ErrPreauthPartialCommand reports a connection closed before a command line was complete.
	ErrPreauthPartialCommand = errors.New("sieve: partial preauth command")
	// ErrBackendReadinessUnavailable reports an unsupported backend-readiness continuation boundary.
	ErrBackendReadinessUnavailable = errors.New("sieve: backend readiness continuation unavailable")
)

// CapabilitiesConfig contains typed ManageSieve capability facts.
type CapabilitiesConfig struct {
	Implementation   string
	ProtocolVersion  string
	ScriptExtensions []string
	Language         string
}

// SessionConfig contains immutable listener settings for one ManageSieve handler.
type SessionConfig struct {
	ListenerName           string
	AuthorityName          string
	AuthorityTransport     string
	ServiceName            string
	Network                string
	BackendPool            string
	TLSMode                string
	AuthMechanisms         []string
	Capabilities           CapabilitiesConfig
	PreauthTimeout         time.Duration
	AuthTimeout            time.Duration
	BackendConnectTimeout  time.Duration
	ProxyIdleTimeout       time.Duration
	MaxPreauthLineBytes    int
	MaxPreauthLiteralBytes int
	MaxBearerTokenBytes    int
	FrontendTLSConfig      *tls.Config
	Authenticator          nauthilus.Authenticator
	BearerIntrospector     nauthilus.BearerIntrospector
	RoutingResolver        routing.RoutingResolver
	PlacementService       placement.SessionPlacer
	PlacementGate          runtimectl.PlacementGate
	BackendConnector       BackendConnector
	ProxyRunner            proxy.Runner
	LocalSessions          *runtimectl.LocalSessionRegistry
	Observability          observability.Recorder
	DirectorInstanceID     string
	DefaultTenant          string
	DefaultShard           string
	GreetingPolicy         greeting.Policy
	SessionLeaseTTL        time.Duration
	SessionIdleGrace       time.Duration
	BackendRetentionTTL    time.Duration
}

// Handler creates bounded ManageSieve sessions for one configured listener.
type Handler struct {
	config SessionConfig
}

// Session owns one accepted ManageSieve frontend stream through the pre-auth boundary.
type Session struct {
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer

	listenerName           string
	authorityName          string
	authorityTransport     string
	serviceName            string
	network                string
	backendPool            string
	tlsMode                string
	authMechanisms         []string
	capabilities           CapabilitiesConfig
	preauthTimeout         time.Duration
	authTimeout            time.Duration
	maxPreauthLineBytes    int
	maxPreauthLiteralBytes int
	maxBearerTokenBytes    int
	frontendTLSConfig      *tls.Config
	authenticator          nauthilus.Authenticator
	bearerIntrospector     nauthilus.BearerIntrospector

	tlsActive bool

	sessionID             string
	directorInstanceID    string
	defaultTenant         string
	defaultShard          string
	greetingPolicy        greeting.Policy
	sessionLeaseTTL       time.Duration
	sessionIdleGrace      time.Duration
	backendRetentionTTL   time.Duration
	backendConnectTimeout time.Duration
	proxyIdleTimeout      time.Duration
	routingResolver       routing.RoutingResolver
	placementService      placement.SessionPlacer
	placementGate         runtimectl.PlacementGate
	backendConnector      BackendConnector
	proxyRunner           proxy.Runner
	localSessions         *runtimectl.LocalSessionRegistry
	observability         observability.Recorder
	placement             Placement
	placementLease        placement.LeaseHandle
	placed                bool
}

// NewHandler creates a ManageSieve session handler with immutable listener settings.
func NewHandler(config SessionConfig) *Handler {
	config.ListenerName = strings.TrimSpace(config.ListenerName)
	config.AuthorityName = strings.TrimSpace(config.AuthorityName)
	config.AuthorityTransport = strings.TrimSpace(config.AuthorityTransport)
	config.ServiceName = strings.TrimSpace(config.ServiceName)
	config.Network = strings.TrimSpace(config.Network)
	config.BackendPool = strings.TrimSpace(config.BackendPool)
	config.TLSMode = strings.TrimSpace(config.TLSMode)
	config.AuthMechanisms = append([]string(nil), config.AuthMechanisms...)
	config.Capabilities.ScriptExtensions = append([]string(nil), config.Capabilities.ScriptExtensions...)
	config.FrontendTLSConfig = cloneTLSConfig(config.FrontendTLSConfig)

	if config.BackendConnector == nil {
		config.BackendConnector = NewTCPBackendConnector(nil)
	}

	if config.ProxyRunner == nil {
		config.ProxyRunner = proxy.NewPipe()
	}

	return &Handler{config: config}
}

// ImplementationCapability builds the compatible default IMPLEMENTATION value.
func ImplementationCapability(processVersion string) string {
	displayName, err := greeting.NewDisplayNameOrDefault(ImplementationName)
	if err != nil {
		return ImplementationName
	}

	policy, err := greeting.NewPolicy(displayName, processVersion, greeting.DisclosureDefault)
	if err != nil {
		return ImplementationName
	}

	return policy.DisplayIdentity(greeting.ProtocolSieve)
}

// Capabilities returns a detached copy of the handler's internal capability facts.
func (h *Handler) Capabilities() CapabilitiesConfig {
	if h == nil {
		return CapabilitiesConfig{}
	}

	capabilities := h.config.Capabilities

	capabilities.Implementation = h.config.GreetingPolicy.DisplayIdentity(greeting.ProtocolSieve)
	if strings.TrimSpace(capabilities.Implementation) == "" {
		capabilities.Implementation = ImplementationName
	}

	capabilities.ProtocolVersion = ProtocolVersionRFC5804
	capabilities.ScriptExtensions = append([]string(nil), capabilities.ScriptExtensions...)

	return capabilities
}

// Serve accepts one frontend connection and runs the bounded ManageSieve pre-auth state machine.
func (h *Handler) Serve(ctx context.Context, conn net.Conn) error {
	session, err := NewSession(h.config, conn)
	if err != nil {
		return err
	}

	return session.Serve(ctx)
}

// NewSession creates a bounded ManageSieve session context for an accepted connection.
//
//nolint:funlen // Constructor keeps immutable listener defaults in one auditable place.
func NewSession(config SessionConfig, conn net.Conn) (*Session, error) {
	if conn == nil {
		return nil, errors.New("sieve: session connection is nil")
	}

	sessionID, err := newSessionID()
	if err != nil {
		return nil, err
	}

	maxLineBytes := effectivePositive(config.MaxPreauthLineBytes, defaultMaxLineBytes)
	maxLiteralBytes := effectivePositive(config.MaxPreauthLiteralBytes, defaultMaxLiteralBytes)
	maxBearerBytes := effectivePositive(config.MaxBearerTokenBytes, defaultMaxBearerBytes)
	leaseTTL := defaultSessionLease(config.SessionLeaseTTL)
	backendConnector := config.BackendConnector

	if backendConnector == nil {
		backendConnector = NewTCPBackendConnector(nil)
	}

	proxyRunner := config.ProxyRunner
	if proxyRunner == nil {
		proxyRunner = proxy.NewPipe()
	}

	return &Session{
		conn:                   conn,
		reader:                 bufio.NewReaderSize(conn, maxLineBytes+1),
		writer:                 bufio.NewWriter(conn),
		listenerName:           config.ListenerName,
		authorityName:          config.AuthorityName,
		authorityTransport:     config.AuthorityTransport,
		serviceName:            config.ServiceName,
		network:                config.Network,
		backendPool:            config.BackendPool,
		tlsMode:                config.TLSMode,
		authMechanisms:         append([]string(nil), config.AuthMechanisms...),
		capabilities:           cloneCapabilities(config.Capabilities),
		preauthTimeout:         config.PreauthTimeout,
		authTimeout:            effectiveDuration(config.AuthTimeout, defaultAuthCallTimeout),
		maxPreauthLineBytes:    maxLineBytes,
		maxPreauthLiteralBytes: maxLiteralBytes,
		maxBearerTokenBytes:    maxBearerBytes,
		frontendTLSConfig:      cloneTLSConfig(config.FrontendTLSConfig),
		authenticator:          config.Authenticator,
		bearerIntrospector:     config.BearerIntrospector,
		tlsActive:              config.TLSMode == TLSModeImplicit,
		sessionID:              sessionID,
		directorInstanceID:     config.DirectorInstanceID,
		defaultTenant:          defaultTenant(config.DefaultTenant),
		defaultShard:           defaultShard(config.DefaultShard),
		greetingPolicy:         config.GreetingPolicy,
		sessionLeaseTTL:        leaseTTL,
		sessionIdleGrace:       defaultSessionGrace(config.SessionIdleGrace, config.SessionLeaseTTL),
		backendRetentionTTL:    config.BackendRetentionTTL,
		backendConnectTimeout:  config.BackendConnectTimeout,
		proxyIdleTimeout:       defaultProxyIdleTimeout(config.ProxyIdleTimeout, leaseTTL),
		routingResolver:        config.RoutingResolver,
		placementService:       config.PlacementService,
		placementGate:          config.PlacementGate,
		backendConnector:       backendConnector,
		proxyRunner:            proxyRunner,
		localSessions:          config.LocalSessions,
		observability:          observability.NormalizeRecorder(config.Observability),
	}, nil
}

// Placement returns the director-owned placement facts after shared placement succeeds.
func (s *Session) Placement() (Placement, bool) {
	if !s.placed {
		return Placement{}, false
	}

	return s.placement.Clone(), true
}

// Serve writes the greeting and processes pre-auth commands in wire order.
func (s *Session) Serve(ctx context.Context) (err error) {
	ctx, sessionSpan := s.startObservationSpan(ctx, observability.TraceBoundarySession, sieveObservationOperationSession, sieveObservationResultStart, "", nil)
	ctx, preAuthSpan := s.startObservationSpan(ctx, observability.TraceBoundarySievePreAuth, sieveObservationOperationPreAuth, sieveObservationResultStart, "", nil)

	s.recordSessionStart(ctx)
	defer func() {
		s.recordSessionEnd(ctx, err)
		preAuthSpan.End(sieveResultLabel(err), sieveReasonClass(err))
		sessionSpan.End(sieveResultLabel(err), sieveReasonClass(err))
	}()

	if err := s.applyPreauthDeadline(); err != nil {
		return err
	}

	if err := s.writeCapabilityGreeting(); err != nil {
		s.recordCapability(ctx, sieveObservationResultFailure, sieveReasonClass(err))

		return err
	}

	if err := s.writer.Flush(); err != nil {
		s.recordCapability(ctx, sieveObservationResultFailure, sieveReasonClass(err))

		return err
	}

	s.recordCapability(ctx, sieveObservationResultOK, sieveReasonOK)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		closeSession, err := s.serveNextCommand(ctx)
		if err != nil {
			return err
		}

		if closeSession {
			return nil
		}
	}
}

// TLSActive reports whether the session has crossed an implicit or STARTTLS boundary.
func (s *Session) TLSActive() bool {
	return s.tlsActive
}

// serveNextCommand reads and dispatches one pre-auth command.
func (s *Session) serveNextCommand(ctx context.Context) (bool, error) {
	command, closeSession, dispatch, err := s.readCommand(ctx)
	if closeSession || err != nil || !dispatch {
		return closeSession, err
	}

	return s.dispatchCommand(ctx, command)
}

// readCommand reads, parses and resolves one command from the frontend stream.
func (s *Session) readCommand(ctx context.Context) (preauthCommand, bool, bool, error) {
	line, err := s.readPreauthLine()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return preauthCommand{}, true, false, nil
		}

		if errors.Is(err, ErrPreauthPartialCommand) {
			_ = s.writeNo(codeClientBug, "Invalid command")
			_ = s.writer.Flush()
			s.recordPreAuth(ctx, "parse", sieveObservationResultRejected, sieveReasonClass(err))

			return preauthCommand{}, true, false, err
		}

		if errors.Is(err, ErrPreauthLineTooLarge) {
			_ = s.writeNo(codeClientBug, "Command line too large")
			_ = s.writer.Flush()
			s.recordPreAuth(ctx, "parse", sieveObservationResultRejected, sieveReasonClass(err))

			return preauthCommand{}, true, false, nil
		}

		return preauthCommand{}, false, false, err
	}

	command, err := parsePreauthCommand(line, s.maxPreauthLineBytes)
	if err != nil {
		if writeErr := s.writeNo(codeClientBug, "Invalid command"); writeErr != nil {
			return preauthCommand{}, false, false, writeErr
		}

		if flushErr := s.writer.Flush(); flushErr != nil {
			return preauthCommand{}, false, false, flushErr
		}

		s.recordPreAuth(ctx, "parse", sieveObservationResultRejected, sieveReasonClass(err))

		return preauthCommand{}, false, false, nil
	}

	command, err = s.resolveCommandLiterals(command)
	if err != nil {
		if writeErr := s.writeNo(codeClientBug, "Invalid literal"); writeErr != nil {
			return preauthCommand{}, false, false, writeErr
		}

		if flushErr := s.writer.Flush(); flushErr != nil {
			return preauthCommand{}, false, false, flushErr
		}

		s.recordPreAuth(ctx, command.name, sieveObservationResultRejected, sieveReasonClass(err))

		return preauthCommand{}, true, false, nil
	}

	return command, false, true, nil
}

// dispatchCommand executes one parsed command and flushes its response.
func (s *Session) dispatchCommand(ctx context.Context, command preauthCommand) (bool, error) {
	s.recordPreAuth(ctx, command.name, sieveObservationResultStart, "")

	outcome, err := s.handlePreauthCommand(ctx, command)
	if !outcome.flushed {
		if flushErr := s.writer.Flush(); flushErr != nil {
			return false, flushErr
		}
	}

	if errors.Is(err, ErrUnsupportedCommand) {
		s.recordPreAuth(ctx, command.name, sieveObservationResultUnsupported, sieveReasonClass(err))

		return outcome.closeSession, nil
	}

	if err != nil {
		s.recordPreAuth(ctx, command.name, sieveObservationResultFailure, sieveReasonClass(err))
	} else {
		s.recordPreAuth(ctx, command.name, sieveObservationResultOK, sieveReasonOK)
	}

	return outcome.closeSession, err
}

// readPreauthLine reads one bounded command line.
func (s *Session) readPreauthLine() ([]byte, error) {
	line, err := s.reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > s.maxPreauthLineBytes {
		return nil, ErrPreauthLineTooLarge
	}

	if errors.Is(err, io.EOF) && len(line) > 0 {
		return line, ErrPreauthPartialCommand
	}

	if err != nil {
		return nil, err
	}

	return line, nil
}

// resolveCommandLiterals reads bounded command literals into ordinary argument values.
func (s *Session) resolveCommandLiterals(command preauthCommand) (preauthCommand, error) {
	for index := range command.arguments {
		token := command.arguments[index]
		if token.kind != tokenLiteral {
			continue
		}

		if index != len(command.arguments)-1 {
			return preauthCommand{}, ErrMalformedCommand
		}

		value, err := s.readLiteralValue(token.literalSize)
		if err != nil {
			return preauthCommand{}, err
		}

		command.arguments[index] = argumentToken{kind: tokenQuoted, value: value}
	}

	return command, nil
}

// readLiteralValue reads a bounded literal and consumes an already-buffered CRLF terminator.
func (s *Session) readLiteralValue(size int) (string, error) {
	if size < 0 || size > s.maxPreauthLiteralBytes {
		return "", ErrPreauthLiteralTooLarge
	}

	payload := make([]byte, size)
	if _, err := io.ReadFull(s.reader, payload); err != nil {
		return "", err
	}

	if s.reader.Buffered() >= 2 {
		next, err := s.reader.Peek(2)
		if err == nil && string(next) == "\r\n" {
			_, _ = s.reader.Discard(2)
		}
	}

	if strings.ContainsAny(string(payload), "\r\n") {
		return "", ErrMalformedCommand
	}

	return string(payload), nil
}

// applyPreauthDeadline sets the initial session read/write deadline.
func (s *Session) applyPreauthDeadline() error {
	if s.preauthTimeout <= 0 {
		return nil
	}

	return s.conn.SetDeadline(time.Now().Add(s.preauthTimeout))
}

// cloneCapabilities detaches mutable capability slices from callers.
func cloneCapabilities(capabilities CapabilitiesConfig) CapabilitiesConfig {
	capabilities.ScriptExtensions = append([]string(nil), capabilities.ScriptExtensions...)

	return capabilities
}

// cloneTLSConfig detaches mutable frontend TLS config from session callers.
func cloneTLSConfig(config *tls.Config) *tls.Config {
	if config == nil {
		return nil
	}

	return config.Clone()
}

// effectivePositive returns the configured positive value or a conservative fallback.
func effectivePositive(configured int, fallback int) int {
	if configured > 0 {
		return configured
	}

	return fallback
}

// effectiveDuration returns the configured positive duration or a conservative fallback.
func effectiveDuration(configured time.Duration, fallback time.Duration) time.Duration {
	if configured > 0 {
		return configured
	}

	return fallback
}
