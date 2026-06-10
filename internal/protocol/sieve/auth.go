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

//nolint:funlen,wsl_v5 // ManageSieve auth keeps parser, authority and fail-closed responses in one auditable path.
package sieve

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/protocol/saslcred"
	"github.com/croessner/nauthilus-director/internal/protocol/tlscontext"
)

const sieveBearerIntrospectionTransport = "oidc_introspection"

// handleAuthenticate extracts supported SASL credentials without retaining them on the session.
func (s *Session) handleAuthenticate(ctx context.Context, command preauthCommand) (commandOutcome, error) {
	if len(command.arguments) < 1 || len(command.arguments) > 2 {
		s.recordAuthenticate(ctx, sieveObservationResultRejected, sieveReasonParser, "")

		return commandOutcome{}, s.writeNo(codeClientBug, "Invalid AUTHENTICATE command")
	}

	mechanismText, ok := tokenStringValue(command.arguments[0])
	if !ok {
		s.recordAuthenticate(ctx, sieveObservationResultRejected, sieveReasonParser, "")

		return commandOutcome{}, s.writeNo(codeClientBug, "Invalid AUTHENTICATE mechanism")
	}

	mechanism, err := saslcred.NewMechanism(mechanismText)
	if err != nil {
		s.recordAuthenticate(ctx, sieveObservationResultUnsupported, sieveReasonUnsupported, mechanismText)

		return commandOutcome{}, s.writeNo(codeUnsupported, "Unsupported authentication mechanism")
	}

	if !s.authMechanismConfigured(mechanism.Normalized()) {
		s.recordAuthenticate(ctx, sieveObservationResultUnsupported, sieveReasonUnsupported, mechanism.Normalized())

		return commandOutcome{}, s.writeNo(codeUnsupported, "Unsupported authentication mechanism")
	}

	if !s.credentialAuthAllowed() {
		s.recordAuthenticate(ctx, sieveObservationResultRejected, sieveReasonCredentialInput, mechanism.Normalized())

		return commandOutcome{}, s.writeNo(codeEncryptNeeded, "TLS is required before authentication")
	}

	if !s.authMechanismAdvertised(mechanism.WireName()) {
		s.recordAuthenticate(ctx, sieveObservationResultUnsupported, sieveReasonUnsupported, mechanism.Normalized())

		return commandOutcome{}, s.writeNo(codeUnsupported, "Unsupported authentication mechanism")
	}

	encoded, err := s.authenticateResponsePayload(command)
	if err != nil {
		if errors.Is(err, errSASLCancelled) {
			s.recordAuthenticate(ctx, sieveObservationResultRejected, sieveReasonCanceled, mechanism.Normalized())

			return commandOutcome{}, s.writeNo(codeAuthFailed, "Authentication cancelled")
		}

		s.recordAuthenticate(ctx, sieveObservationResultRejected, sieveReasonClass(err), mechanism.Normalized())

		return commandOutcome{}, s.writeNo(codeClientBug, "Invalid authentication response")
	}

	credentials, err := parseSASLCredentials(mechanism, encoded, s.maxPreauthLineBytes, s.maxBearerTokenBytes)
	if err != nil {
		s.recordAuthenticate(ctx, sieveObservationResultRejected, sieveReasonClass(err), mechanism.Normalized())

		return commandOutcome{}, s.writeNo(codeClientBug, "Invalid authentication response")
	}
	defer credentials.Clear()

	outcome, err := s.authenticateThroughNauthilus(ctx, credentials)
	s.recordAuthenticate(ctx, sieveResultLabel(err), sieveReasonClass(err), mechanism.Normalized())

	return outcome, err
}

// credentialAuthAllowed reports whether credential-bearing SASL may reach Nauthilus.
func (s *Session) credentialAuthAllowed() bool {
	return s.tlsActive
}

// authenticateThroughNauthilus calls the configured authority and keeps frontend success delayed.
func (s *Session) authenticateThroughNauthilus(ctx context.Context, credentials *frontendCredentials) (commandOutcome, error) {
	if credentials.Kind() == saslcred.KindBearer {
		return s.authenticateThroughBearerIntrospection(ctx, credentials)
	}

	if s.authenticator == nil {
		s.recordNauthilusAuth(ctx, sieveObservationResultFailure, sieveReasonTemporaryFailure, credentials.Mechanism().Normalized(), 0)

		return commandOutcome{}, s.writeNo(codeTryLater, "Authentication service temporarily unavailable")
	}

	request := credentials.NauthilusAuthRequest(s.NauthilusRequestContext(credentials.Mechanism().Normalized()))

	authCtx, cancel := context.WithTimeout(ctx, s.authTimeout)
	defer cancel()

	authCtx, authSpan := s.startObservationSpan(authCtx, observability.TraceBoundaryNauthilusAuth, sieveObservationOperationAuthenticate, sieveObservationResultStart, "", map[string]string{
		sieveObsFieldMechanism: credentials.Mechanism().Normalized(),
		sieveObsFieldTransport: s.authObservationTransport(credentials),
	})

	authStarted := time.Now()
	result, err := s.authenticator.Authenticate(authCtx, request)
	authDuration := time.Since(authStarted)
	if err != nil {
		s.recordNauthilusAuth(authCtx, sieveObservationResultFailure, sieveReasonTemporaryFailure, credentials.Mechanism().Normalized(), authDuration)
		authSpan.End(sieveObservationResultFailure, sieveReasonTemporaryFailure)

		return commandOutcome{}, s.writeNo(codeTryLater, "Authentication service temporarily unavailable")
	}

	if !result.Authenticated() {
		switch result.Decision {
		case nauthilus.DecisionTemporaryFailure:
			s.recordNauthilusAuth(authCtx, sieveObservationResultFailure, sieveReasonTemporaryFailure, credentials.Mechanism().Normalized(), authDuration)
			authSpan.End(sieveObservationResultFailure, sieveReasonTemporaryFailure)

			return commandOutcome{}, s.writeNo(codeTryLater, "Authentication service temporarily unavailable")
		default:
			s.recordNauthilusAuth(authCtx, sieveObservationResultRejected, sieveReasonAuth, credentials.Mechanism().Normalized(), authDuration)
			authSpan.End(sieveObservationResultRejected, sieveReasonAuth)

			return commandOutcome{}, s.writeNo(codeAuthFailed, genericAuthFailedText)
		}
	}

	s.recordNauthilusAuth(authCtx, sieveObservationResultOK, sieveReasonOK, credentials.Mechanism().Normalized(), authDuration)
	authSpan.End(sieveObservationResultOK, sieveReasonOK)

	if err := s.placeAuthenticatedSession(ctx, credentials, result); err != nil {
		return commandOutcome{}, s.writeNo(codeTryLater, "Authentication service temporarily unavailable")
	}

	return s.transitionAuthenticatedSession(ctx, credentials)
}

// authenticateThroughBearerIntrospection calls the dedicated SASL bearer authority boundary.
//
//nolint:dupl // Bearer auth intentionally mirrors password result mapping across a separate boundary.
func (s *Session) authenticateThroughBearerIntrospection(ctx context.Context, credentials *frontendCredentials) (commandOutcome, error) {
	if s.bearerIntrospector == nil {
		s.recordNauthilusAuth(ctx, sieveObservationResultFailure, sieveReasonTemporaryFailure, credentials.Mechanism().Normalized(), 0)

		return commandOutcome{}, s.writeNo(codeTryLater, "Authentication service temporarily unavailable")
	}

	authCtx, cancel := context.WithTimeout(ctx, s.authTimeout)
	defer cancel()

	authCtx, authSpan := s.startObservationSpan(authCtx, observability.TraceBoundaryNauthilusAuth, sieveObservationOperationAuthenticate, sieveObservationResultStart, "", map[string]string{
		sieveObsFieldMechanism: credentials.Mechanism().Normalized(),
		sieveObsFieldTransport: s.authObservationTransport(credentials),
	})

	authStarted := time.Now()
	result, err := s.bearerIntrospector.Introspect(authCtx, credentials.BearerIntrospectionRequest(
		s.NauthilusRequestContext(credentials.Mechanism().Normalized()),
		protocolSieve,
		s.listenerName,
		s.authorityName,
	))
	authDuration := time.Since(authStarted)
	if err != nil {
		s.recordNauthilusAuth(authCtx, sieveObservationResultFailure, sieveReasonTemporaryFailure, credentials.Mechanism().Normalized(), authDuration)
		authSpan.End(sieveObservationResultFailure, sieveReasonTemporaryFailure)

		return commandOutcome{}, s.writeNo(codeTryLater, "Authentication service temporarily unavailable")
	}

	if !result.Authenticated() {
		switch result.Decision {
		case nauthilus.DecisionTemporaryFailure:
			s.recordNauthilusAuth(authCtx, sieveObservationResultFailure, sieveReasonTemporaryFailure, credentials.Mechanism().Normalized(), authDuration)
			authSpan.End(sieveObservationResultFailure, sieveReasonTemporaryFailure)

			return commandOutcome{}, s.writeNo(codeTryLater, "Authentication service temporarily unavailable")
		default:
			s.recordNauthilusAuth(authCtx, sieveObservationResultRejected, sieveReasonAuth, credentials.Mechanism().Normalized(), authDuration)
			authSpan.End(sieveObservationResultRejected, sieveReasonAuth)

			return commandOutcome{}, s.writeNo(codeAuthFailed, genericAuthFailedText)
		}
	}

	s.recordNauthilusAuth(authCtx, sieveObservationResultOK, sieveReasonOK, credentials.Mechanism().Normalized(), authDuration)
	authSpan.End(sieveObservationResultOK, sieveReasonOK)

	if err := s.placeAuthenticatedSession(ctx, credentials, result); err != nil {
		return commandOutcome{}, s.writeNo(codeTryLater, "Authentication service temporarily unavailable")
	}

	return s.transitionAuthenticatedSession(ctx, credentials)
}

// authObservationTransport returns the bounded auth transport class for this credential.
func (s *Session) authObservationTransport(credentials *frontendCredentials) string {
	if credentials != nil && credentials.Kind() == saslcred.KindBearer {
		return sieveBearerIntrospectionTransport
	}

	return strings.ToLower(strings.TrimSpace(s.authorityTransport))
}

// sessionBackendConnectRequest carries selected backend and effective frontend tuple.
func (s *Session) sessionBackendConnectRequest() backend.ConnectRequest {
	return backend.ConnectRequest{
		Target:        s.placement.Backend.Backend,
		Timeout:       s.backendConnectTimeout,
		Purpose:       backend.ConnectPurposeSession,
		Observability: s.observability,
		ProxyAddresses: &backend.ProxyAddresses{
			Source:      s.conn.RemoteAddr(),
			Destination: s.conn.LocalAddr(),
		},
	}
}

// NauthilusRequestContext builds the auth-facing context for ManageSieve sessions.
func (s *Session) NauthilusRequestContext(method string) nauthilus.RequestContext {
	clientIP, clientPort := splitSessionAddr(s.conn.RemoteAddr())
	localIP, localPort := splitSessionAddr(s.conn.LocalAddr())

	requestContext := nauthilus.RequestContext{
		ClientIP:   clientIP,
		ClientPort: clientPort,
		LocalIP:    localIP,
		LocalPort:  localPort,
		Protocol:   protocolSieve,
		Method:     strings.ToLower(strings.TrimSpace(method)),
	}
	state, ok := tlscontext.ConnectionState(s.conn)

	return tlscontext.Apply(requestContext, s.tlsActive, state, ok)
}

// splitSessionAddr extracts stable host and port values from a frontend address.
func splitSessionAddr(addr net.Addr) (string, string) {
	if addr == nil {
		return "", ""
	}

	host, port, err := net.SplitHostPort(addr.String())
	if err == nil {
		return host, port
	}

	return addr.String(), ""
}

// frontendCredentials adapts shared SASL credentials to the Sieve auth boundary.
type frontendCredentials struct {
	credentials *saslcred.Credentials
}

// Clear releases the parsed credential copy held by this value.
func (c *frontendCredentials) Clear() {
	if c == nil {
		return
	}

	c.credentials.Clear()
}

// Mechanism returns the preserved frontend mechanism identity.
func (c *frontendCredentials) Mechanism() saslcred.Mechanism {
	if c == nil || c.credentials == nil {
		return saslcred.Mechanism{}
	}

	return c.credentials.Mechanism
}

// Username returns the protocol-supplied authorization identity for routing diagnostics only.
func (c *frontendCredentials) Username() string {
	if c == nil || c.credentials == nil {
		return ""
	}

	return c.credentials.Username
}

// AuthorizationID returns the optional SASL authorization identity.
func (c *frontendCredentials) AuthorizationID() string {
	if c == nil || c.credentials == nil {
		return ""
	}

	return c.credentials.AuthorizationID
}

// Kind returns the credential material class for replay policy decisions.
func (c *frontendCredentials) Kind() string {
	if c == nil || c.credentials == nil {
		return ""
	}

	return c.credentials.Kind
}

// Secret returns the wrapped credential material for the short-lived auth call path.
func (c *frontendCredentials) Secret() *credentialSecret {
	if c == nil || c.credentials == nil {
		return nil
	}

	return c.credentials.Secret
}

// NauthilusAuthRequest builds the credential-auth request without exposing SASL formatting.
func (c *frontendCredentials) NauthilusAuthRequest(requestContext nauthilus.RequestContext) nauthilus.AuthRequest {
	if c == nil || c.credentials == nil {
		return nauthilus.AuthRequest{Context: requestContext}
	}

	requestContext.Username = c.credentials.Username
	requestContext.Method = c.credentials.Mechanism.Normalized()
	if c.credentials.Kind == saslcred.KindBearer {
		return nauthilus.AuthRequest{Context: requestContext}
	}

	return nauthilus.AuthRequest{
		Context:    requestContext,
		Credential: nauthilus.NewSecret(c.Secret().Value()),
	}
}

// BearerIntrospectionRequest builds the dedicated SASL bearer validation request.
func (c *frontendCredentials) BearerIntrospectionRequest(
	requestContext nauthilus.RequestContext,
	protocol string,
	listenerName string,
	authorityName string,
) nauthilus.BearerIntrospectionRequest {
	if c == nil || c.credentials == nil {
		return nauthilus.BearerIntrospectionRequest{Context: requestContext}
	}

	requestContext.Username = c.credentials.Username
	requestContext.Method = c.credentials.Mechanism.Normalized()

	return nauthilus.BearerIntrospectionRequest{
		Context:               requestContext,
		Mechanism:             c.credentials.Mechanism.Normalized(),
		Protocol:              protocol,
		ListenerName:          listenerName,
		AuthorityName:         authorityName,
		AuthorizationIdentity: firstNonEmpty(c.credentials.AuthorizationID, c.credentials.Username),
		BearerToken:           nauthilus.NewSecret(c.Secret().Value()),
	}
}

// String returns only credential-safe metadata for diagnostics and tests.
func (c *frontendCredentials) String() string {
	if c == nil || c.credentials == nil {
		return "frontendCredentials<nil>"
	}

	return c.credentials.String()
}

// GoString returns only credential-safe metadata for Go-syntax formatting.
func (c *frontendCredentials) GoString() string {
	return c.String()
}

// firstNonEmpty returns the first non-empty trimmed value.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}

	return ""
}
