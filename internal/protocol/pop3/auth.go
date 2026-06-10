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

//nolint:funlen,gocyclo,wsl_v5 // POP3 auth keeps parser, authority and fail-closed responses in one auditable path.
package pop3

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/protocol/saslcred"
	"github.com/croessner/nauthilus-director/internal/protocol/tlscontext"
)

const (
	credentialKindPassword       = "password"
	pop3BearerIntrospectionClass = "oidc_introspection"
)

// handleUser stores only provisional protocol input for the later PASS command.
func (s *Session) handleUser(ctx context.Context, command preauthCommand) error {
	if !s.userPassConfigured() || !s.configuredCapability(capabilityUser) {
		s.recordUser(ctx, pop3ObservationResultUnsupported, pop3ReasonUnsupported)

		return s.writeERR("USER is not available")
	}

	if !s.tlsActive {
		s.recordUser(ctx, pop3ObservationResultRejected, pop3ReasonCredentialInput)

		return s.writeERR("TLS is required before authentication")
	}

	username, err := singleArgument(command)
	if err != nil {
		s.recordUser(ctx, pop3ObservationResultRejected, pop3ReasonParser)

		return s.writeERR("Invalid USER command")
	}

	s.provisionalUser = username
	s.recordUser(ctx, pop3ObservationResultOK, pop3ReasonOK)

	return s.writeOK("User accepted")
}

// handlePass authenticates USER/PASS credentials through Nauthilus when TLS is active.
func (s *Session) handlePass(ctx context.Context, command preauthCommand) (commandOutcome, error) {
	if !s.userPassConfigured() || !s.configuredCapability(capabilityUser) {
		s.recordAuthenticate(ctx, pop3ObservationResultUnsupported, pop3ReasonUnsupported, authMethodUserPass)

		return commandOutcome{}, s.writeERR("PASS is not available")
	}

	if !s.tlsActive {
		s.recordAuthenticate(ctx, pop3ObservationResultRejected, pop3ReasonCredentialInput, authMethodUserPass)

		return commandOutcome{}, s.writeERR("TLS is required before authentication")
	}

	if strings.TrimSpace(s.provisionalUser) == "" {
		s.recordAuthenticate(ctx, pop3ObservationResultRejected, pop3ReasonCredentialInput, authMethodUserPass)

		return commandOutcome{}, s.writeERR("USER is required before PASS")
	}

	password, err := singleArgument(command)
	if err != nil {
		s.recordAuthenticate(ctx, pop3ObservationResultRejected, pop3ReasonParser, authMethodUserPass)

		return commandOutcome{}, s.writeERR("Invalid PASS command")
	}

	credentials := newPasswordCredentials(s.provisionalUser, password)
	defer credentials.Clear()

	return s.authenticateThroughNauthilus(ctx, credentials)
}

// handleAuth lists mechanisms or authenticates configured bearer SASL credentials.
func (s *Session) handleAuth(ctx context.Context, command preauthCommand) (commandOutcome, error) {
	if len(command.arguments) == 0 {
		s.recordAuthenticate(ctx, pop3ObservationResultOK, pop3ReasonOK, "")

		return commandOutcome{}, s.writeMultilineOK("Supported authentication mechanisms", s.effectiveBearerMechanisms())
	}

	if len(command.arguments) > 2 {
		s.recordAuthenticate(ctx, pop3ObservationResultRejected, pop3ReasonParser, "")

		return commandOutcome{}, s.writeERR("Invalid AUTH command")
	}

	mechanism, err := saslcred.NewMechanism(command.arguments[0])
	if err != nil {
		s.recordAuthenticate(ctx, pop3ObservationResultUnsupported, pop3ReasonUnsupported, command.arguments[0])

		return commandOutcome{}, s.writeERR("Unsupported authentication mechanism")
	}

	switch mechanism.Normalized() {
	case saslcred.MechanismXOAUTH2, saslcred.MechanismOAuthBearer:
	default:
		s.recordAuthenticate(ctx, pop3ObservationResultUnsupported, pop3ReasonUnsupported, mechanism.Normalized())

		return commandOutcome{}, s.writeERR("Unsupported authentication mechanism")
	}

	if !s.bearerMechanismConfigured(mechanism.Normalized()) || !s.configuredCapability(capabilitySASL) {
		s.recordAuthenticate(ctx, pop3ObservationResultUnsupported, pop3ReasonUnsupported, mechanism.Normalized())

		return commandOutcome{}, s.writeERR("Unsupported authentication mechanism")
	}

	if !s.tlsActive {
		s.recordAuthenticate(ctx, pop3ObservationResultRejected, pop3ReasonCredentialInput, mechanism.Normalized())

		return commandOutcome{}, s.writeERR("TLS is required before authentication")
	}

	if !s.bearerMechanismAdvertised(mechanism.WireName()) {
		s.recordAuthenticate(ctx, pop3ObservationResultUnsupported, pop3ReasonUnsupported, mechanism.Normalized())

		return commandOutcome{}, s.writeERR("Unsupported authentication mechanism")
	}

	encoded, err := s.authenticateResponsePayload(command)
	if err != nil {
		if errors.Is(err, errSASLCancelled) {
			s.recordAuthenticate(ctx, pop3ObservationResultRejected, pop3ReasonCanceled, mechanism.Normalized())

			return commandOutcome{}, s.writeERR("Authentication cancelled")
		}

		if errors.Is(err, ErrPreauthLineTooLarge) {
			s.recordAuthenticate(ctx, pop3ObservationResultRejected, pop3ReasonClass(err), mechanism.Normalized())

			return commandOutcome{closeSession: true}, s.writeERR("Authentication response too large")
		}

		s.recordAuthenticate(ctx, pop3ObservationResultRejected, pop3ReasonClass(err), mechanism.Normalized())

		return commandOutcome{}, s.writeERR("Invalid authentication response")
	}

	credentials, err := parseSASLCredentials(mechanism, encoded, s.maxPreauthLiteralBytes, s.maxBearerTokenBytes)
	if err != nil {
		s.recordAuthenticate(ctx, pop3ObservationResultRejected, pop3ReasonClass(err), mechanism.Normalized())

		return commandOutcome{}, s.writeERR("Invalid authentication response")
	}
	defer credentials.Clear()

	return s.authenticateThroughNauthilus(ctx, credentials)
}

// authenticateThroughNauthilus calls the configured authority and keeps frontend success delayed.
func (s *Session) authenticateThroughNauthilus(ctx context.Context, credentials *frontendCredentials) (commandOutcome, error) {
	if credentials.Kind() == saslcred.KindBearer {
		return s.authenticateThroughBearerIntrospection(ctx, credentials)
	}

	if s.authenticator == nil {
		s.recordNauthilusAuth(ctx, pop3ObservationResultFailure, pop3ReasonTemporaryFailure, credentials.Method(), 0)
		s.recordAuthenticate(ctx, pop3ObservationResultFailure, pop3ReasonTemporaryFailure, credentials.Method())

		return commandOutcome{}, s.writeERR("Authentication service temporarily unavailable")
	}

	s.authAttempts++
	request := credentials.NauthilusAuthRequest(s.NauthilusRequestContext(credentials.Method()))
	request.AuthLoginAttempt = s.authAttempts

	authCtx, cancel := context.WithTimeout(ctx, s.authTimeout)
	defer cancel()

	authCtx, authSpan := s.startObservationSpan(authCtx, observability.TraceBoundaryNauthilusAuth, pop3ObservationOperationAuthenticate, pop3ObservationResultStart, "", map[string]string{
		pop3ObsFieldMechanism: credentials.Method(),
		pop3ObsFieldTransport: s.authObservationTransport(credentials),
	})

	authStarted := time.Now()
	result, err := s.authenticator.Authenticate(authCtx, request)
	authDuration := time.Since(authStarted)
	if err != nil {
		s.recordNauthilusAuth(authCtx, pop3ObservationResultFailure, pop3ReasonTemporaryFailure, credentials.Method(), authDuration)
		s.recordAuthenticate(ctx, pop3ObservationResultFailure, pop3ReasonTemporaryFailure, credentials.Method())
		authSpan.End(pop3ObservationResultFailure, pop3ReasonTemporaryFailure)

		return commandOutcome{}, s.writeERR("Authentication service temporarily unavailable")
	}

	if !result.Authenticated() {
		switch result.Decision {
		case nauthilus.DecisionTemporaryFailure:
			s.recordNauthilusAuth(authCtx, pop3ObservationResultFailure, pop3ReasonTemporaryFailure, credentials.Method(), authDuration)
			s.recordAuthenticate(ctx, pop3ObservationResultFailure, pop3ReasonTemporaryFailure, credentials.Method())
			authSpan.End(pop3ObservationResultFailure, pop3ReasonTemporaryFailure)

			return commandOutcome{}, s.writeERR("Authentication service temporarily unavailable")
		default:
			s.recordNauthilusAuth(authCtx, pop3ObservationResultRejected, pop3ReasonAuth, credentials.Method(), authDuration)
			s.recordAuthenticate(ctx, pop3ObservationResultRejected, pop3ReasonAuth, credentials.Method())
			authSpan.End(pop3ObservationResultRejected, pop3ReasonAuth)

			return commandOutcome{}, s.writeERR(genericAuthFailedText)
		}
	}

	s.recordNauthilusAuth(authCtx, pop3ObservationResultOK, pop3ReasonOK, credentials.Method(), authDuration)
	authSpan.End(pop3ObservationResultOK, pop3ReasonOK)

	if err := s.placeAuthenticatedSession(ctx, credentials, result); err != nil {
		s.recordAuthenticate(ctx, pop3ObservationResultFailure, pop3ReasonClass(err), credentials.Method())
		_ = s.closePlacedSession(context.Background())

		return commandOutcome{}, s.writeBackendReadinessERR()
	}

	return s.transitionAuthenticatedSession(ctx, credentials, result)
}

// authenticateThroughBearerIntrospection calls the dedicated SASL bearer authority boundary.
//
//nolint:dupl // Bearer auth intentionally mirrors password result mapping across a separate boundary.
func (s *Session) authenticateThroughBearerIntrospection(ctx context.Context, credentials *frontendCredentials) (commandOutcome, error) {
	if s.bearerIntrospector == nil {
		s.recordNauthilusAuth(ctx, pop3ObservationResultFailure, pop3ReasonTemporaryFailure, credentials.Method(), 0)
		s.recordAuthenticate(ctx, pop3ObservationResultFailure, pop3ReasonTemporaryFailure, credentials.Method())

		return commandOutcome{}, s.writeERR("Authentication service temporarily unavailable")
	}

	s.authAttempts++
	authCtx, cancel := context.WithTimeout(ctx, s.authTimeout)
	defer cancel()

	authCtx, authSpan := s.startObservationSpan(authCtx, observability.TraceBoundaryNauthilusAuth, pop3ObservationOperationAuthenticate, pop3ObservationResultStart, "", map[string]string{
		pop3ObsFieldMechanism: credentials.Method(),
		pop3ObsFieldTransport: s.authObservationTransport(credentials),
	})

	authStarted := time.Now()
	result, err := s.bearerIntrospector.Introspect(authCtx, credentials.BearerIntrospectionRequest(
		s.NauthilusRequestContext(credentials.Method()),
		ProtocolPOP3,
		s.listenerName,
		s.authorityName,
	))
	authDuration := time.Since(authStarted)
	if err != nil {
		s.recordNauthilusAuth(authCtx, pop3ObservationResultFailure, pop3ReasonTemporaryFailure, credentials.Method(), authDuration)
		s.recordAuthenticate(ctx, pop3ObservationResultFailure, pop3ReasonTemporaryFailure, credentials.Method())
		authSpan.End(pop3ObservationResultFailure, pop3ReasonTemporaryFailure)

		return commandOutcome{}, s.writeERR("Authentication service temporarily unavailable")
	}

	if !result.Authenticated() {
		switch result.Decision {
		case nauthilus.DecisionTemporaryFailure:
			s.recordNauthilusAuth(authCtx, pop3ObservationResultFailure, pop3ReasonTemporaryFailure, credentials.Method(), authDuration)
			s.recordAuthenticate(ctx, pop3ObservationResultFailure, pop3ReasonTemporaryFailure, credentials.Method())
			authSpan.End(pop3ObservationResultFailure, pop3ReasonTemporaryFailure)

			return commandOutcome{}, s.writeERR("Authentication service temporarily unavailable")
		default:
			s.recordNauthilusAuth(authCtx, pop3ObservationResultRejected, pop3ReasonAuth, credentials.Method(), authDuration)
			s.recordAuthenticate(ctx, pop3ObservationResultRejected, pop3ReasonAuth, credentials.Method())
			authSpan.End(pop3ObservationResultRejected, pop3ReasonAuth)

			return commandOutcome{}, s.writeERR(genericAuthFailedText)
		}
	}

	s.recordNauthilusAuth(authCtx, pop3ObservationResultOK, pop3ReasonOK, credentials.Method(), authDuration)
	authSpan.End(pop3ObservationResultOK, pop3ReasonOK)

	if err := s.placeAuthenticatedSession(ctx, credentials, result); err != nil {
		s.recordAuthenticate(ctx, pop3ObservationResultFailure, pop3ReasonClass(err), credentials.Method())
		_ = s.closePlacedSession(context.Background())

		return commandOutcome{}, s.writeBackendReadinessERR()
	}

	return s.transitionAuthenticatedSession(ctx, credentials, result)
}

// authObservationTransport returns the bounded auth transport class for this credential.
func (s *Session) authObservationTransport(credentials *frontendCredentials) string {
	if credentials != nil && credentials.Kind() == saslcred.KindBearer {
		return pop3BearerIntrospectionClass
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

// writeBackendReadinessERR sends the generic temporary failure for backend/proxy readiness failures.
func (s *Session) writeBackendReadinessERR() error {
	if err := s.writeERR("Mailbox temporarily unavailable"); err != nil {
		return err
	}

	return ErrBackendReadinessUnavailable
}

// NauthilusRequestContext builds the auth-facing context for POP3 sessions.
func (s *Session) NauthilusRequestContext(method string) nauthilus.RequestContext {
	clientIP, clientPort := splitSessionAddr(s.conn.RemoteAddr())
	localIP, localPort := splitSessionAddr(s.conn.LocalAddr())

	requestContext := nauthilus.RequestContext{
		ClientIP:   clientIP,
		ClientPort: clientPort,
		LocalIP:    localIP,
		LocalPort:  localPort,
		Protocol:   ProtocolPOP3,
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

// frontendCredentials contains one short-lived parsed frontend credential.
type frontendCredentials struct {
	method          string
	kind            string
	username        string
	authorizationID string
	secret          *saslcred.Secret
}

// newPasswordCredentials builds a USER/PASS credential without making USER authoritative.
func newPasswordCredentials(username string, password string) *frontendCredentials {
	return &frontendCredentials{
		method:   authMethodUserPass,
		kind:     credentialKindPassword,
		username: strings.TrimSpace(username),
		secret:   newCredentialSecret(password),
	}
}

// credentialsFromSASL adapts shared SASL credentials to the POP3 auth boundary.
func credentialsFromSASL(credentials *saslcred.Credentials) *frontendCredentials {
	if credentials == nil {
		return &frontendCredentials{}
	}

	return &frontendCredentials{
		method:          credentials.Mechanism.Normalized(),
		kind:            credentials.Kind,
		username:        credentials.Username,
		authorizationID: credentials.AuthorizationID,
		secret:          credentials.Secret,
	}
}

// Clear releases the parsed credential copy held by this value.
func (c *frontendCredentials) Clear() {
	if c == nil {
		return
	}

	c.secret.Clear()
	c.method = ""
	c.kind = ""
	c.username = ""
	c.authorizationID = ""
}

// Method returns the normalized frontend authentication mechanism.
func (c *frontendCredentials) Method() string {
	if c == nil {
		return ""
	}

	return c.method
}

// Kind returns the bounded credential class.
func (c *frontendCredentials) Kind() string {
	if c == nil {
		return ""
	}

	return c.kind
}

// Username returns the protocol-supplied identity for routing diagnostics only.
func (c *frontendCredentials) Username() string {
	if c == nil {
		return ""
	}

	return c.username
}

// AuthorizationID returns the SASL authorization identity when one was supplied.
func (c *frontendCredentials) AuthorizationID() string {
	if c == nil {
		return ""
	}

	return c.authorizationID
}

// Secret returns the redaction-aware credential material wrapper.
func (c *frontendCredentials) Secret() *saslcred.Secret {
	if c == nil {
		return nil
	}

	return c.secret
}

// NauthilusAuthRequest builds the credential-auth request without exposing credential formatting.
func (c *frontendCredentials) NauthilusAuthRequest(requestContext nauthilus.RequestContext) nauthilus.AuthRequest {
	if c == nil {
		return nauthilus.AuthRequest{Context: requestContext}
	}

	requestContext.Username = c.username
	requestContext.Method = c.method
	if c.kind == saslcred.KindBearer {
		return nauthilus.AuthRequest{Context: requestContext}
	}

	return nauthilus.AuthRequest{
		Context:    requestContext,
		Credential: nauthilus.NewSecret(c.secret.Value()),
	}
}

// BearerIntrospectionRequest builds the dedicated SASL bearer validation request.
func (c *frontendCredentials) BearerIntrospectionRequest(
	requestContext nauthilus.RequestContext,
	protocol string,
	listenerName string,
	authorityName string,
) nauthilus.BearerIntrospectionRequest {
	if c == nil {
		return nauthilus.BearerIntrospectionRequest{Context: requestContext}
	}

	requestContext.Username = c.username
	requestContext.Method = c.method

	return nauthilus.BearerIntrospectionRequest{
		Context:               requestContext,
		Mechanism:             c.method,
		Protocol:              protocol,
		ListenerName:          listenerName,
		AuthorityName:         authorityName,
		AuthorizationIdentity: firstNonEmpty(c.authorizationID, c.username),
		BearerToken:           nauthilus.NewSecret(c.secret.Value()),
	}
}

// String returns only credential-safe metadata for diagnostics and tests.
func (c *frontendCredentials) String() string {
	if c == nil {
		return "frontendCredentials<nil>"
	}

	return fmt.Sprintf(
		"frontendCredentials{method:%q kind:%q username_present:%t credential:%s}",
		c.method,
		c.kind,
		strings.TrimSpace(c.username) != "",
		c.secret.String(),
	)
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
