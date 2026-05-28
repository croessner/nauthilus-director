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

package lmtp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/croessner/nauthilus-director/internal/nauthilus"
)

const (
	credentialKindBearer   = "bearer"
	credentialKindPassword = "password"

	mechanismLogin       = "login"
	mechanismOAuthBearer = "oauthbearer"
	mechanismPlain       = "plain"
	mechanismXOAUTH2     = "xoauth2"

	bearerPrefix = "bearer "
	saslFieldSep = "\x01"

	loginUsernameChallenge = "VXNlcm5hbWU6"
	loginPasswordChallenge = "UGFzc3dvcmQ6"
)

var (
	// ErrCredentialRejected reports credential input that must fail without exposing raw material.
	ErrCredentialRejected = errors.New("lmtp: credential input rejected")
	// ErrCredentialTooLarge reports credential input that exceeded a configured byte limit.
	ErrCredentialTooLarge = errors.New("lmtp: credential input too large")
	// ErrUnsupportedAuthMechanism reports an AUTH mechanism outside the supported LMTP set.
	ErrUnsupportedAuthMechanism = errors.New("lmtp: unsupported authentication mechanism")
)

type mechanismIdentity struct {
	original   string
	normalized string
}

type peerCredentials struct {
	mechanism mechanismIdentity
	kind      string
	username  string
	authzid   string
	secret    *credentialSecret
}

type credentialSecret struct {
	value []byte
}

// newMechanismIdentity validates and normalizes a frontend peer-auth mechanism.
func newMechanismIdentity(value string) (mechanismIdentity, error) {
	original := strings.TrimSpace(value)
	if original == "" {
		return mechanismIdentity{}, fmt.Errorf("%w: missing mechanism", ErrCredentialRejected)
	}

	normalized := strings.ToLower(original)
	switch normalized {
	case mechanismLogin, mechanismPlain, mechanismXOAUTH2, mechanismOAuthBearer:
		return mechanismIdentity{original: original, normalized: normalized}, nil
	default:
		return mechanismIdentity{}, fmt.Errorf("%w: unsupported mechanism", ErrUnsupportedAuthMechanism)
	}
}

// Normalized returns the canonical lower-case mechanism name.
func (m mechanismIdentity) Normalized() string {
	return m.normalized
}

// WireName returns the canonical LMTP AUTH mechanism token.
func (m mechanismIdentity) WireName() string {
	return strings.ToUpper(m.normalized)
}

// newCredentialSecret copies credential material into a redaction-aware wrapper.
func newCredentialSecret(value string) *credentialSecret {
	return &credentialSecret{value: []byte(value)}
}

// Value returns the wrapped credential for the short-lived authority call path.
func (s *credentialSecret) Value() string {
	if s == nil {
		return ""
	}

	return string(s.value)
}

// Clear overwrites the local copy and releases the wrapped credential bytes.
func (s *credentialSecret) Clear() {
	if s == nil {
		return
	}

	for index := range s.value {
		s.value[index] = 0
	}

	s.value = nil
}

// String returns only a redaction marker for non-empty credentials.
func (s *credentialSecret) String() string {
	if s == nil || len(s.value) == 0 {
		return ""
	}

	return "<redacted>"
}

// GoString returns only a redaction marker for Go-syntax formatting.
func (s *credentialSecret) GoString() string {
	return s.String()
}

// Clear releases the parsed credential copy held by this value.
func (c *peerCredentials) Clear() {
	if c == nil {
		return
	}

	c.secret.Clear()
	c.username = ""
	c.authzid = ""
}

// NauthilusAuthRequest builds the credential-auth request for the submitter peer only.
func (c *peerCredentials) NauthilusAuthRequest(context nauthilus.RequestContext) nauthilus.AuthRequest {
	if c == nil {
		return nauthilus.AuthRequest{Context: context}
	}

	context.Username = c.username
	context.Method = c.mechanism.Normalized()

	return nauthilus.AuthRequest{
		Context:    context,
		Credential: nauthilus.NewSecret(c.secret.Value()),
	}
}

// String returns only credential-safe metadata for diagnostics and tests.
func (c *peerCredentials) String() string {
	if c == nil {
		return "peerCredentials<nil>"
	}

	return fmt.Sprintf(
		"peerCredentials{mechanism:%q kind:%q username_present:%t credential:%s}",
		c.mechanism.Normalized(),
		c.kind,
		strings.TrimSpace(c.username) != "",
		c.secret.String(),
	)
}

// GoString returns only credential-safe metadata for Go-syntax formatting.
func (c *peerCredentials) GoString() string {
	return c.String()
}

// handleAUTH parses and verifies one SMTP-style AUTH command.
func (s *Session) handleAUTH(ctx context.Context, command frontendCommand) error {
	if s.peerAuthenticated {
		return s.writeEnhanced(responseStatusBadSequence, enhancedBadSequence, "Already authenticated")
	}

	if s.transaction.active() {
		return s.writeEnhanced(responseStatusBadSequence, enhancedBadSequence, "AUTH not allowed during transaction")
	}

	if !s.tlsActive {
		return s.writeEnhanced(responseStatusAuthRequired, enhancedAuthRequired, noTLSAuthText)
	}

	if !s.authAdvertised() {
		return s.writeEnhanced(responseStatusUnavailable, enhancedUnavailable, "AUTH is not available")
	}

	fields := strings.Fields(command.args)
	if len(fields) < 1 || len(fields) > 2 {
		return s.writeEnhanced(responseStatusParameter, enhancedParameter, malformedAuthText)
	}

	mechanism, err := newMechanismIdentity(fields[0])
	if err != nil || !s.authMechanismAdvertised(mechanism.WireName()) {
		return s.writeEnhanced(responseStatusAuthRejected, enhancedAuthRejected, "Unsupported authentication mechanism")
	}

	credentials, err := s.credentialsForMechanism(mechanism, fields)
	if err != nil {
		return s.writeEnhanced(responseStatusParameter, enhancedParameter, malformedAuthText)
	}
	defer credentials.Clear()

	return s.authenticatePeer(ctx, credentials)
}

// credentialsForMechanism reads the bounded AUTH exchange for the requested mechanism.
func (s *Session) credentialsForMechanism(mechanism mechanismIdentity, fields []string) (*peerCredentials, error) {
	switch mechanism.Normalized() {
	case mechanismPlain, mechanismXOAUTH2, mechanismOAuthBearer:
		encoded, err := s.initialOrContinuation(fields)
		if err != nil {
			return nil, err
		}

		return parseSASLCredentials(mechanism, encoded, s.maxLineBytes, s.maxBearerTokenBytes)
	case mechanismLogin:
		return s.loginCredentials(fields)
	default:
		return nil, fmt.Errorf("%w: unsupported sasl mechanism", ErrUnsupportedAuthMechanism)
	}
}

// initialOrContinuation returns the SASL initial response or reads one continuation line.
func (s *Session) initialOrContinuation(fields []string) (string, error) {
	if len(fields) == 2 {
		return fields[1], nil
	}

	if err := s.writePlain(responseStatusAuthContinue, authContinueText); err != nil {
		return "", err
	}

	if err := s.writer.Flush(); err != nil {
		return "", err
	}

	return s.readContinuationResponse()
}

// loginCredentials performs the two-step AUTH LOGIN exchange.
func (s *Session) loginCredentials(fields []string) (*peerCredentials, error) {
	mechanism, err := newMechanismIdentity(mechanismLogin)
	if err != nil {
		return nil, err
	}

	username, err := s.loginUsername(fields)
	if err != nil {
		return nil, err
	}

	password, err := s.loginPassword()
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(username) == "" || password == "" {
		return nil, fmt.Errorf("%w: missing login field", ErrCredentialRejected)
	}

	return &peerCredentials{
		mechanism: mechanism,
		kind:      credentialKindPassword,
		username:  strings.TrimSpace(username),
		secret:    newCredentialSecret(password),
	}, nil
}

// loginUsername returns the initial or challenged AUTH LOGIN username.
func (s *Session) loginUsername(fields []string) (string, error) {
	if len(fields) == 2 {
		return decodeBase64Field(fields[1], s.maxLineBytes)
	}

	if err := s.writePlain(responseStatusAuthContinue, loginUsernameChallenge); err != nil {
		return "", err
	}

	if err := s.writer.Flush(); err != nil {
		return "", err
	}

	encodedUsername, err := s.readContinuationResponse()
	if err != nil {
		return "", err
	}

	return decodeBase64Field(encodedUsername, s.maxLineBytes)
}

// loginPassword returns the challenged AUTH LOGIN password.
func (s *Session) loginPassword() (string, error) {
	if err := s.writePlain(responseStatusAuthContinue, loginPasswordChallenge); err != nil {
		return "", err
	}

	if err := s.writer.Flush(); err != nil {
		return "", err
	}

	encodedPassword, err := s.readContinuationResponse()
	if err != nil {
		return "", err
	}

	return decodeBase64Field(encodedPassword, s.maxLineBytes)
}

// readContinuationResponse reads one bounded AUTH continuation response.
func (s *Session) readContinuationResponse() (string, error) {
	line, err := s.readLine()
	if err != nil {
		return "", err
	}

	response, err := trimCommandLine(line, s.maxLineBytes)
	if err != nil {
		return "", err
	}

	if response == "*" {
		return "", fmt.Errorf("%w: sasl cancelled", ErrCredentialRejected)
	}

	if strings.ContainsAny(response, " \t") {
		return "", fmt.Errorf("%w: invalid sasl response", ErrCredentialRejected)
	}

	return response, nil
}

// parseSASLCredentials decodes and parses the configured SASL mechanism payload.
func parseSASLCredentials(
	mechanism mechanismIdentity,
	encoded string,
	maxPayloadBytes int,
	maxBearerTokenBytes int,
) (*peerCredentials, error) {
	payload, err := decodeSASLPayload(encoded, maxPayloadBytes)
	if err != nil {
		return nil, err
	}

	switch mechanism.Normalized() {
	case mechanismPlain:
		return parsePlainPayload(mechanism, payload)
	case mechanismXOAUTH2:
		return parseXOAUTH2Payload(mechanism, payload, maxBearerTokenBytes)
	case mechanismOAuthBearer:
		return parseOAuthBearerPayload(mechanism, payload, maxBearerTokenBytes)
	default:
		return nil, fmt.Errorf("%w: unsupported sasl mechanism", ErrUnsupportedAuthMechanism)
	}
}

// decodeSASLPayload converts base64 input into bounded raw SASL bytes.
func decodeSASLPayload(encoded string, maxPayloadBytes int) ([]byte, error) {
	if encoded == "" {
		return nil, fmt.Errorf("%w: empty sasl response", ErrCredentialRejected)
	}

	payload, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed sasl response", ErrCredentialRejected)
	}

	if maxPayloadBytes > 0 && len(payload) > maxPayloadBytes {
		return nil, fmt.Errorf("%w: sasl payload", ErrCredentialTooLarge)
	}

	return payload, nil
}

// decodeBase64Field decodes one AUTH LOGIN field with the same bounded input policy.
func decodeBase64Field(encoded string, maxPayloadBytes int) (string, error) {
	payload, err := decodeSASLPayload(encoded, maxPayloadBytes)
	if err != nil {
		return "", err
	}

	return string(payload), nil
}

// parsePlainPayload extracts authzid, authcid and password from SASL PLAIN.
func parsePlainPayload(mechanism mechanismIdentity, payload []byte) (*peerCredentials, error) {
	parts := strings.Split(string(payload), "\x00")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: malformed plain payload", ErrCredentialRejected)
	}

	authzid := strings.TrimSpace(parts[0])
	authcid := strings.TrimSpace(parts[1])
	password := parts[2]

	if authcid == "" || password == "" {
		return nil, fmt.Errorf("%w: missing plain field", ErrCredentialRejected)
	}

	return &peerCredentials{
		mechanism: mechanism,
		kind:      credentialKindPassword,
		username:  authcid,
		authzid:   authzid,
		secret:    newCredentialSecret(password),
	}, nil
}

// parseXOAUTH2Payload extracts the user and bearer token from an XOAUTH2 envelope.
func parseXOAUTH2Payload(
	mechanism mechanismIdentity,
	payload []byte,
	maxBearerTokenBytes int,
) (*peerCredentials, error) {
	fields, err := parseSASLKeyValueEnvelope(string(payload))
	if err != nil {
		return nil, err
	}

	username := strings.TrimSpace(fields["user"])

	token, err := bearerTokenFromAuthField(fields["auth"], maxBearerTokenBytes)
	if err != nil {
		return nil, err
	}

	if username == "" {
		return nil, fmt.Errorf("%w: missing xoauth2 identity", ErrCredentialRejected)
	}

	return &peerCredentials{
		mechanism: mechanism,
		kind:      credentialKindBearer,
		username:  username,
		secret:    newCredentialSecret(token),
	}, nil
}

// parseOAuthBearerPayload extracts the GS2 auth identity and bearer token.
func parseOAuthBearerPayload(
	mechanism mechanismIdentity,
	payload []byte,
	maxBearerTokenBytes int,
) (*peerCredentials, error) {
	segments := strings.Split(string(payload), saslFieldSep)
	if len(segments) < 3 || segments[len(segments)-1] != "" || segments[len(segments)-2] != "" {
		return nil, fmt.Errorf("%w: malformed oauthbearer envelope", ErrCredentialRejected)
	}

	authzid, err := oauthBearerAuthzID(segments[0])
	if err != nil {
		return nil, err
	}

	fields, err := collectSASLFields(segments[1 : len(segments)-2])
	if err != nil {
		return nil, err
	}

	token, err := bearerTokenFromAuthField(fields["auth"], maxBearerTokenBytes)
	if err != nil {
		return nil, err
	}

	return &peerCredentials{
		mechanism: mechanism,
		kind:      credentialKindBearer,
		username:  authzid,
		authzid:   authzid,
		secret:    newCredentialSecret(token),
	}, nil
}

// parseSASLKeyValueEnvelope parses Ctrl-A separated key-value pairs with a required terminator.
func parseSASLKeyValueEnvelope(payload string) (map[string]string, error) {
	segments := strings.Split(payload, saslFieldSep)
	if len(segments) < 3 || segments[len(segments)-1] != "" || segments[len(segments)-2] != "" {
		return nil, fmt.Errorf("%w: malformed sasl envelope", ErrCredentialRejected)
	}

	return collectSASLFields(segments[:len(segments)-2])
}

// collectSASLFields normalizes simple key-value fields from a SASL envelope.
func collectSASLFields(segments []string) (map[string]string, error) {
	fields := make(map[string]string, len(segments))
	for _, segment := range segments {
		if segment == "" {
			return nil, fmt.Errorf("%w: empty sasl field", ErrCredentialRejected)
		}

		key, value, ok := strings.Cut(segment, "=")

		key = strings.ToLower(strings.TrimSpace(key))
		if !ok || key == "" {
			return nil, fmt.Errorf("%w: malformed sasl field", ErrCredentialRejected)
		}

		if _, exists := fields[key]; exists {
			return nil, fmt.Errorf("%w: duplicate sasl field", ErrCredentialRejected)
		}

		fields[key] = value
	}

	return fields, nil
}

// bearerTokenFromAuthField extracts and bounds the bearer token from an auth field.
func bearerTokenFromAuthField(value string, maxBearerTokenBytes int) (string, error) {
	if len(value) < len(bearerPrefix) || !strings.EqualFold(value[:len(bearerPrefix)], bearerPrefix) {
		return "", fmt.Errorf("%w: missing bearer auth field", ErrCredentialRejected)
	}

	token := strings.TrimSpace(value[len(bearerPrefix):])
	if token == "" {
		return "", fmt.Errorf("%w: missing bearer token", ErrCredentialRejected)
	}

	if maxBearerTokenBytes > 0 && len([]byte(token)) > maxBearerTokenBytes {
		return "", fmt.Errorf("%w: bearer token", ErrCredentialTooLarge)
	}

	return token, nil
}

// oauthBearerAuthzID extracts the required authorization identity from the GS2 header.
func oauthBearerAuthzID(header string) (string, error) {
	if !strings.HasPrefix(header, "n,") && !strings.HasPrefix(header, "y,") {
		return "", fmt.Errorf("%w: unsupported oauthbearer gs2 header", ErrCredentialRejected)
	}

	for part := range strings.SplitSeq(header, ",") {
		if !strings.HasPrefix(part, "a=") {
			continue
		}

		authzid, err := decodeGS2AuthzID(strings.TrimPrefix(part, "a="))
		if err != nil {
			return "", err
		}

		if strings.TrimSpace(authzid) == "" {
			return "", fmt.Errorf("%w: missing oauthbearer identity", ErrCredentialRejected)
		}

		return authzid, nil
	}

	return "", fmt.Errorf("%w: missing oauthbearer identity", ErrCredentialRejected)
}

// decodeGS2AuthzID decodes the two escapes allowed by the GS2 authzid syntax.
func decodeGS2AuthzID(value string) (string, error) {
	var builder strings.Builder
	builder.Grow(len(value))

	for index := 0; index < len(value); index++ {
		if value[index] != '=' {
			builder.WriteByte(value[index])

			continue
		}

		if index+2 >= len(value) {
			return "", fmt.Errorf("%w: malformed oauthbearer identity", ErrCredentialRejected)
		}

		escape := value[index : index+3]
		switch escape {
		case "=2C":
			builder.WriteByte(',')
		case "=3D":
			builder.WriteByte('=')
		default:
			return "", fmt.Errorf("%w: malformed oauthbearer identity", ErrCredentialRejected)
		}

		index += 2
	}

	return builder.String(), nil
}

// authenticatePeer delegates technical submitter credential verification to Nauthilus.
func (s *Session) authenticatePeer(ctx context.Context, credentials *peerCredentials) error {
	if s.authenticator == nil {
		return s.writeEnhanced(responseStatusAuthUnavailable, enhancedAuthUnavailable, authUnavailableText)
	}

	authCtx, cancel := context.WithTimeout(ctx, defaultAuthTimeout(s.authTimeout))
	defer cancel()

	request := credentials.NauthilusAuthRequest(s.nauthilusRequestContext())

	result, err := s.authenticator.Authenticate(authCtx, request)
	if err != nil {
		return s.writeEnhanced(responseStatusAuthUnavailable, enhancedAuthUnavailable, authUnavailableText)
	}

	switch result.Decision {
	case nauthilus.DecisionAuthenticated:
		s.peerAuthenticated = true
		s.peerAuthMethod = credentials.mechanism.Normalized()
		s.peerIdentity = boundedSafeIdentity(credentials.username)

		return s.writeEnhanced(responseStatusAuthSuccess, enhancedAuthOK, authSuccessText)
	case nauthilus.DecisionRejected:
		return s.writeEnhanced(responseStatusAuthRejected, enhancedAuthRejected, authRejectedText)
	default:
		return s.writeEnhanced(responseStatusAuthUnavailable, enhancedAuthUnavailable, authUnavailableText)
	}
}

// supportsAuthMechanism reports whether a normalized mechanism is configured for this listener.
func (s *Session) supportsAuthMechanism(mechanism string) bool {
	for _, supported := range s.peerAuthMechanisms {
		if strings.EqualFold(supported, mechanism) {
			return true
		}
	}

	return false
}

// authAdvertised reports whether AUTH is currently part of the effective LMTP surface.
func (s *Session) authAdvertised() bool {
	for _, capability := range s.effectiveCapabilities {
		fields := strings.Fields(capability)
		if len(fields) > 0 && strings.EqualFold(fields[0], capabilityAUTH) {
			return true
		}
	}

	return false
}

// authMechanismAdvertised reports whether a mechanism is enabled and advertised.
func (s *Session) authMechanismAdvertised(wireName string) bool {
	for _, capability := range s.effectiveCapabilities {
		fields := strings.Fields(capability)
		if len(fields) < 2 || !strings.EqualFold(fields[0], capabilityAUTH) {
			continue
		}

		for _, mechanism := range fields[1:] {
			if strings.EqualFold(mechanism, wireName) {
				return true
			}
		}
	}

	return false
}

// nauthilusRequestContext builds the submitter-auth authority context.
func (s *Session) nauthilusRequestContext() nauthilus.RequestContext {
	context := nauthilus.RequestContext{
		Protocol: protocolLMTP,
		TLS:      boolString(s.tlsActive),
	}

	if s.tlsClientVerified {
		context.TLSClientVerify = "SUCCESS"
		context.TLSClientCN = s.tlsClientCommonName
	} else if s.tlsActive {
		context.TLSClientVerify = "NONE"
	}

	return context
}

// boolString returns a stable text representation for authority context booleans.
func boolString(value bool) string {
	if value {
		return "true"
	}

	return "false"
}

// authCapability returns the advertised AUTH line if configured and currently safe.
func (s *Session) authCapability(configured string) string {
	if !s.tlsActive || len(s.peerAuthMechanisms) == 0 {
		return ""
	}

	allowed := make(map[string]struct{}, len(s.peerAuthMechanisms))
	for _, mechanism := range s.peerAuthMechanisms {
		identity, err := newMechanismIdentity(mechanism)
		if err != nil {
			continue
		}

		allowed[identity.WireName()] = struct{}{}
	}

	fields := strings.Fields(configured)
	if len(fields) < 2 {
		return ""
	}

	mechanisms := make([]string, 0, len(fields)-1)

	seen := make(map[string]struct{}, len(fields)-1)
	for _, field := range fields[1:] {
		identity, err := newMechanismIdentity(field)
		if err != nil {
			continue
		}

		wireName := identity.WireName()
		if _, ok := allowed[wireName]; !ok {
			continue
		}

		if _, exists := seen[wireName]; exists {
			continue
		}

		seen[wireName] = struct{}{}
		mechanisms = append(mechanisms, wireName)
	}

	if len(mechanisms) == 0 {
		return ""
	}

	return "AUTH " + strings.Join(mechanisms, " ")
}
