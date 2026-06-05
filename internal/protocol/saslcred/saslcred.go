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

// Package saslcred parses one-shot SASL credential envelopes without protocol
// command-state coupling.
package saslcred

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	// KindBearer identifies bearer-token credential material.
	KindBearer = "bearer"
	// KindPassword identifies reusable password credential material.
	KindPassword = "password"

	// MechanismOAuthBearer is the normalized OAuthBearer mechanism name.
	MechanismOAuthBearer = "oauthbearer"
	// MechanismPlain is the normalized PLAIN mechanism name.
	MechanismPlain = "plain"
	// MechanismXOAUTH2 is the normalized XOAUTH2 mechanism name.
	MechanismXOAUTH2 = "xoauth2"

	bearerPrefix = "bearer "
	saslFieldSep = "\x01"
)

var (
	// ErrRejected reports credential input that must fail without exposing raw material.
	ErrRejected = errors.New("sasl credential input rejected")
	// ErrTooLarge reports credential input that exceeded a configured byte limit.
	ErrTooLarge = errors.New("sasl credential input too large")
	// ErrUnsupportedMechanism reports a mechanism outside the one-shot SASL set.
	ErrUnsupportedMechanism = errors.New("unsupported sasl authentication mechanism")
)

// Mechanism records normalized and accepted frontend mechanism names.
type Mechanism struct {
	original   string
	normalized string
}

// Credentials contains one short-lived parsed frontend credential.
type Credentials struct {
	Mechanism       Mechanism
	Kind            string
	Username        string
	AuthorizationID string
	Secret          *Secret
}

// Secret wraps credential-bearing material so formatting remains redacted.
type Secret struct {
	value []byte
}

// NewMechanism validates and normalizes a one-shot SASL mechanism.
func NewMechanism(value string) (Mechanism, error) {
	original := strings.TrimSpace(value)
	if original == "" {
		return Mechanism{}, fmt.Errorf("%w: missing mechanism", ErrRejected)
	}

	normalized := strings.ToLower(original)
	switch normalized {
	case MechanismPlain, MechanismXOAUTH2, MechanismOAuthBearer:
		return Mechanism{original: original, normalized: normalized}, nil
	default:
		return Mechanism{}, fmt.Errorf("%w: %s", ErrUnsupportedMechanism, normalized)
	}
}

// Original returns the accepted mechanism spelling from the frontend command.
func (m Mechanism) Original() string {
	return m.original
}

// Normalized returns the canonical lower-case mechanism name.
func (m Mechanism) Normalized() string {
	return m.normalized
}

// WireName returns the canonical upper-case SASL mechanism token.
func (m Mechanism) WireName() string {
	return strings.ToUpper(m.normalized)
}

// NewSecret copies credential material into a redaction-aware wrapper.
func NewSecret(value string) *Secret {
	return &Secret{value: []byte(value)}
}

// Value returns the wrapped credential for the short-lived authority call path.
func (s *Secret) Value() string {
	if s == nil {
		return ""
	}

	return string(s.value)
}

// Clear overwrites the local copy and releases the wrapped credential bytes.
func (s *Secret) Clear() {
	if s == nil {
		return
	}

	for index := range s.value {
		s.value[index] = 0
	}

	s.value = nil
}

// String returns only a redaction marker for non-empty credentials.
func (s *Secret) String() string {
	if s == nil || len(s.value) == 0 {
		return ""
	}

	return "<redacted>"
}

// GoString returns only a redaction marker for Go-syntax formatting.
func (s *Secret) GoString() string {
	return s.String()
}

// Clear releases the parsed credential copy held by this value.
func (c *Credentials) Clear() {
	if c == nil {
		return
	}

	c.Secret.Clear()
	c.Username = ""
	c.AuthorizationID = ""
}

// String returns only credential-safe metadata for diagnostics and tests.
func (c *Credentials) String() string {
	if c == nil {
		return "Credentials<nil>"
	}

	return fmt.Sprintf(
		"Credentials{mechanism:%q kind:%q username_present:%t credential:%s}",
		c.Mechanism.Normalized(),
		c.Kind,
		strings.TrimSpace(c.Username) != "",
		c.Secret.String(),
	)
}

// GoString returns only credential-safe metadata for Go-syntax formatting.
func (c *Credentials) GoString() string {
	return c.String()
}

// Parse decodes and parses the configured one-shot SASL mechanism payload.
func Parse(
	mechanism Mechanism,
	encoded string,
	maxPayloadBytes int,
	maxBearerTokenBytes int,
) (*Credentials, error) {
	payload, err := decodePayload(encoded, maxPayloadBytes)
	if err != nil {
		return nil, err
	}

	switch mechanism.Normalized() {
	case MechanismPlain:
		return parsePlainPayload(mechanism, payload)
	case MechanismXOAUTH2:
		return parseXOAUTH2Payload(mechanism, payload, maxBearerTokenBytes)
	case MechanismOAuthBearer:
		return parseOAuthBearerPayload(mechanism, payload, maxBearerTokenBytes)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedMechanism, mechanism.Normalized())
	}
}

// decodePayload converts base64 input into bounded raw SASL bytes.
func decodePayload(encoded string, maxPayloadBytes int) ([]byte, error) {
	if encoded == "" {
		return nil, fmt.Errorf("%w: empty sasl response", ErrRejected)
	}

	payload, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed sasl response", ErrRejected)
	}

	if maxPayloadBytes > 0 && len(payload) > maxPayloadBytes {
		return nil, fmt.Errorf("%w: sasl payload", ErrTooLarge)
	}

	return payload, nil
}

// parsePlainPayload extracts authzid, authcid and password from SASL PLAIN.
func parsePlainPayload(mechanism Mechanism, payload []byte) (*Credentials, error) {
	parts := strings.Split(string(payload), "\x00")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: malformed plain payload", ErrRejected)
	}

	authzid := strings.TrimSpace(parts[0])
	authcid := strings.TrimSpace(parts[1])

	password := parts[2]
	if authcid == "" || password == "" {
		return nil, fmt.Errorf("%w: missing plain field", ErrRejected)
	}

	return &Credentials{
		Mechanism:       mechanism,
		Kind:            KindPassword,
		Username:        authcid,
		AuthorizationID: authzid,
		Secret:          NewSecret(password),
	}, nil
}

// parseXOAUTH2Payload extracts the user and bearer token from an XOAUTH2 envelope.
func parseXOAUTH2Payload(
	mechanism Mechanism,
	payload []byte,
	maxBearerTokenBytes int,
) (*Credentials, error) {
	fields, err := parseKeyValueEnvelope(string(payload))
	if err != nil {
		return nil, err
	}

	username := strings.TrimSpace(fields["user"])

	token, err := bearerTokenFromAuthField(fields["auth"], maxBearerTokenBytes)
	if err != nil {
		return nil, err
	}

	if username == "" {
		return nil, fmt.Errorf("%w: missing xoauth2 identity", ErrRejected)
	}

	return &Credentials{
		Mechanism: mechanism,
		Kind:      KindBearer,
		Username:  username,
		Secret:    NewSecret(token),
	}, nil
}

// parseOAuthBearerPayload extracts the GS2 auth identity and bearer token.
func parseOAuthBearerPayload(
	mechanism Mechanism,
	payload []byte,
	maxBearerTokenBytes int,
) (*Credentials, error) {
	segments := strings.Split(string(payload), saslFieldSep)
	if len(segments) < 3 || segments[len(segments)-1] != "" || segments[len(segments)-2] != "" {
		return nil, fmt.Errorf("%w: malformed oauthbearer envelope", ErrRejected)
	}

	authzid, err := oauthBearerAuthzID(segments[0])
	if err != nil {
		return nil, err
	}

	fields, err := collectFields(segments[1 : len(segments)-2])
	if err != nil {
		return nil, err
	}

	token, err := bearerTokenFromAuthField(fields["auth"], maxBearerTokenBytes)
	if err != nil {
		return nil, err
	}

	return &Credentials{
		Mechanism:       mechanism,
		Kind:            KindBearer,
		Username:        authzid,
		AuthorizationID: authzid,
		Secret:          NewSecret(token),
	}, nil
}

// parseKeyValueEnvelope parses Ctrl-A separated key-value pairs with a terminator.
func parseKeyValueEnvelope(payload string) (map[string]string, error) {
	segments := strings.Split(payload, saslFieldSep)
	if len(segments) < 3 || segments[len(segments)-1] != "" || segments[len(segments)-2] != "" {
		return nil, fmt.Errorf("%w: malformed sasl envelope", ErrRejected)
	}

	return collectFields(segments[:len(segments)-2])
}

// collectFields normalizes simple key-value fields from a SASL envelope.
func collectFields(segments []string) (map[string]string, error) {
	fields := make(map[string]string, len(segments))
	for _, segment := range segments {
		if segment == "" {
			return nil, fmt.Errorf("%w: empty sasl field", ErrRejected)
		}

		key, value, ok := strings.Cut(segment, "=")

		key = strings.ToLower(strings.TrimSpace(key))
		if !ok || key == "" {
			return nil, fmt.Errorf("%w: malformed sasl field", ErrRejected)
		}

		if _, exists := fields[key]; exists {
			return nil, fmt.Errorf("%w: duplicate sasl field", ErrRejected)
		}

		fields[key] = value
	}

	return fields, nil
}

// bearerTokenFromAuthField extracts and bounds the bearer token from an auth field.
func bearerTokenFromAuthField(value string, maxBearerTokenBytes int) (string, error) {
	if len(value) < len(bearerPrefix) || !strings.EqualFold(value[:len(bearerPrefix)], bearerPrefix) {
		return "", fmt.Errorf("%w: missing bearer auth field", ErrRejected)
	}

	token := strings.TrimSpace(value[len(bearerPrefix):])
	if token == "" {
		return "", fmt.Errorf("%w: missing bearer token", ErrRejected)
	}

	if maxBearerTokenBytes > 0 && len([]byte(token)) > maxBearerTokenBytes {
		return "", fmt.Errorf("%w: bearer token", ErrTooLarge)
	}

	return token, nil
}

// oauthBearerAuthzID extracts the required authorization identity from the GS2 header.
func oauthBearerAuthzID(header string) (string, error) {
	if !strings.HasPrefix(header, "n,") && !strings.HasPrefix(header, "y,") {
		return "", fmt.Errorf("%w: unsupported oauthbearer gs2 header", ErrRejected)
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
			return "", fmt.Errorf("%w: missing oauthbearer identity", ErrRejected)
		}

		return authzid, nil
	}

	return "", fmt.Errorf("%w: missing oauthbearer identity", ErrRejected)
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
			return "", fmt.Errorf("%w: malformed oauthbearer identity", ErrRejected)
		}

		escape := value[index : index+3]
		switch escape {
		case "=2C":
			builder.WriteByte(',')
		case "=3D":
			builder.WriteByte('=')
		default:
			return "", fmt.Errorf("%w: malformed oauthbearer identity", ErrRejected)
		}

		index += 2
	}

	return builder.String(), nil
}
