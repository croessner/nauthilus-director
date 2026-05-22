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
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	bearerPrefix = "bearer "
	saslFieldSep = "\x01"
)

// parseSASLCredentials decodes and parses the configured SASL mechanism payload.
func parseSASLCredentials(
	mechanism mechanismIdentity,
	encoded string,
	maxPayloadBytes int,
	maxBearerTokenBytes int,
) (*frontendCredentials, error) {
	payload, err := decodeSASLPayload(encoded, maxPayloadBytes)
	if err != nil {
		return nil, err
	}

	switch mechanism.Normalized() {
	case mechanismPlain:
		return parsePlainPayload(mechanism, payload, maxPayloadBytes)
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

// parsePlainPayload extracts authzid, authcid and password from SASL PLAIN.
func parsePlainPayload(mechanism mechanismIdentity, payload []byte, _ int) (*frontendCredentials, error) {
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

	return &frontendCredentials{
		mechanism:       mechanism,
		kind:            credentialKindPassword,
		username:        authcid,
		authorizationID: authzid,
		secret:          newCredentialSecret(password),
	}, nil
}

// parseXOAUTH2Payload extracts the user and bearer token from an XOAUTH2 envelope.
func parseXOAUTH2Payload(
	mechanism mechanismIdentity,
	payload []byte,
	maxBearerTokenBytes int,
) (*frontendCredentials, error) {
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

	return &frontendCredentials{
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
) (*frontendCredentials, error) {
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

	return &frontendCredentials{
		mechanism:       mechanism,
		kind:            credentialKindBearer,
		username:        authzid,
		authorizationID: authzid,
		secret:          newCredentialSecret(token),
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
