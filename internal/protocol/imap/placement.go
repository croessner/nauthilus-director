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

package imap

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/routing"
	"github.com/croessner/nauthilus-director/internal/state"
)

// authenticateAndPlace maps frontend credentials through Nauthilus and director placement.
func (s *Session) authenticateAndPlace(ctx context.Context, tag string, credentials *frontendCredentials) error {
	result, err := s.authenticateWithAuthority(ctx, credentials)
	if err != nil {
		return s.writeTagged(tag, responseNo, authUnavailableText)
	}

	switch result.Decision {
	case nauthilus.DecisionAuthenticated:
		if err := s.placeAuthenticatedSession(ctx, credentials, result); err != nil {
			return s.writeTagged(tag, responseNo, authUnavailableText)
		}

		s.authenticated = true

		return s.writeTagged(tag, responseOK, authSuccessText)
	case nauthilus.DecisionRejected:
		return s.writeTagged(tag, responseNo, rejectedAuthResponseText(result.StatusMessage))
	case nauthilus.DecisionTemporaryFailure:
		return s.writeTagged(tag, responseNo, authUnavailableText)
	default:
		return s.writeTagged(tag, responseNo, authUnavailableText)
	}
}

// authenticateWithAuthority sends short-lived credentials to the configured Nauthilus authority.
func (s *Session) authenticateWithAuthority(
	ctx context.Context,
	credentials *frontendCredentials,
) (nauthilus.AuthResult, error) {
	if s.authenticator == nil {
		return nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure}, errors.New("imap: authenticator unavailable")
	}

	if credentials == nil {
		return nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure}, errors.New("imap: credentials unavailable")
	}

	authCtx, cancel := s.authContext(ctx)
	defer cancel()

	method := credentials.Mechanism().Normalized()
	request := credentials.NauthilusAuthRequest(s.NauthilusRequestContext(method))

	return s.authenticator.Authenticate(authCtx, request)
}

// authContext derives the bounded authority call context for one authentication attempt.
func (s *Session) authContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}

	if s.context.AuthTimeout <= 0 {
		return ctx, func() {}
	}

	return context.WithTimeout(ctx, s.context.AuthTimeout)
}

// placeAuthenticatedSession applies side-effect-free routing before opening session state.
func (s *Session) placeAuthenticatedSession(
	ctx context.Context,
	credentials *frontendCredentials,
	result nauthilus.AuthResult,
) error {
	if err := s.ensurePlacementDependencies(); err != nil {
		return err
	}

	routingRequest, err := s.routingRequest(credentials, result)
	if err != nil {
		return err
	}

	routingResult, err := s.routingResolver.Resolve(ctx, routingRequest)
	if err != nil {
		return err
	}

	if !routingResult.Complete() {
		return errors.New("imap: incomplete routing result")
	}

	sessionRecord := s.sessionRecord(routingResult)

	affinity, err := s.sessionStore.OpenSession(ctx, sessionRecord)
	if err != nil {
		return err
	}

	selectedShardTag := selectedAffinityShard(routingResult, affinity)

	backendResult, err := s.backendSelector.Select(ctx, s.selectionRequest(routingResult, selectedShardTag))
	if err != nil {
		return err
	}

	s.placement = Placement{
		AuthResult:       cloneAuthResult(result),
		Routing:          routingResult.Clone(),
		Affinity:         affinity,
		Backend:          backendResult,
		SelectedShardTag: selectedShardTag,
	}
	s.placed = true

	return nil
}

// routingRequest builds the side-effect-free routing input from authenticated facts.
func (s *Session) routingRequest(
	credentials *frontendCredentials,
	result nauthilus.AuthResult,
) (routing.RoutingRequest, error) {
	account := normalizedAccount(result.Account)
	if account == "" && credentials != nil {
		account = normalizedAccount(credentials.Username())
	}

	if account == "" {
		return routing.RoutingRequest{}, errors.New("imap: authenticated account unavailable")
	}

	clientIP, _ := splitSessionAddr(s.context.RemoteAddr)
	loginName := account

	if credentials != nil {
		loginName = normalizedRoutingFact(credentials.Username())
	}

	return routing.RoutingRequest{
		Tenant:            normalizedRoutingFact(s.context.DefaultTenant),
		Protocol:          protocolIMAP,
		ListenerName:      s.context.ListenerName,
		ServiceName:       s.context.ServiceName,
		BackendPool:       s.context.BackendPool,
		LoginName:         loginName,
		NormalizedAccount: account,
		AuthAttributes:    cloneStringSlices(result.Attributes),
		ClientIP:          clientIP,
	}, nil
}

// sessionRecord builds the Redis session-open request after logical routing completes.
func (s *Session) sessionRecord(result routing.RoutingResult) state.SessionRecord {
	ttl := result.TTL
	if ttl <= 0 {
		ttl = s.context.SessionLeaseTTL
	}

	return state.SessionRecord{
		ID: s.context.ID,
		Key: state.AffinityKey{
			Tenant:     normalizedRoutingFact(result.Tenant),
			AccountKey: normalizedAccount(result.AccountKey),
		},
		Protocol:  protocolIMAP,
		ShardTag:  normalizedRoutingFact(result.ShardTag),
		ExpiresAt: time.Now().UTC().Add(ttl),
	}
}

// selectionRequest builds the backend selector input from the final active shard.
func (s *Session) selectionRequest(result routing.RoutingResult, shardTag string) backend.SelectionRequest {
	return backend.SelectionRequest{
		AccountKey:  normalizedAccount(result.AccountKey),
		Tenant:      normalizedRoutingFact(result.Tenant),
		ShardTag:    normalizedRoutingFact(shardTag),
		Protocol:    protocolIMAP,
		BackendPool: s.context.BackendPool,
	}
}

// selectedAffinityShard applies active affinity precedence over initial placement.
func selectedAffinityShard(result routing.RoutingResult, affinity state.AffinityRecord) string {
	if shardTag := normalizedRoutingFact(affinity.ShardTag); shardTag != "" {
		return shardTag
	}

	return normalizedRoutingFact(result.ShardTag)
}

// normalizedAccount returns the canonical account key used for routing and affinity.
func normalizedAccount(value string) string {
	return strings.ToLower(normalizedRoutingFact(value))
}

// normalizedRoutingFact trims a routing fact without exposing it in errors.
func normalizedRoutingFact(value string) string {
	return strings.TrimSpace(value)
}

// splitSessionAddr extracts host and port from TCP-style session addresses.
func splitSessionAddr(addr net.Addr) (string, string) {
	if addr == nil {
		return "", ""
	}

	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", ""
	}

	return host, port
}

// cloneAuthResult returns detached auth result attributes for placement retention.
func cloneAuthResult(result nauthilus.AuthResult) nauthilus.AuthResult {
	result.Attributes = cloneStringSlices(result.Attributes)

	return result
}

// ensurePlacementDependencies verifies that successful auth can continue into placement.
func (s *Session) ensurePlacementDependencies() error {
	if s.routingResolver == nil {
		return errors.New("imap: routing resolver unavailable")
	}

	if s.sessionStore == nil {
		return errors.New("imap: session store unavailable")
	}

	if s.backendSelector == nil {
		return errors.New("imap: backend selector unavailable")
	}

	return nil
}
