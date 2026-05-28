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
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/croessner/nauthilus-director/internal/backend"
)

const (
	backendAuthModeMTLS        = "mtls"
	backendAuthModeNone        = "none"
	backendAuthModeOAuthBearer = "oauthbearer"
	backendAuthModeSASL        = "sasl"
)

var (
	// ErrBackendAuth reports backend authentication failures without credential details.
	ErrBackendAuth = errors.New("lmtp: backend auth failed")
	// ErrBackendAuthPolicy reports fail-closed backend auth policy violations.
	ErrBackendAuthPolicy = errors.New("lmtp: backend auth policy rejected")
)

// AuthenticateBackend establishes the configured director-to-backend auth state.
func AuthenticateBackend(connection *BackendConnection, target backend.Backend) error {
	if connection == nil {
		return fmt.Errorf("%w: backend connection unavailable", ErrBackendAuth)
	}

	switch strings.ToLower(strings.TrimSpace(target.Auth.Mode)) {
	case backendAuthModeNone, "":
		return nil
	case backendAuthModeMTLS:
		return authenticateMTLSBackend(connection, target)
	case backendAuthModeSASL:
		return authenticateSASLBackend(connection, target.Auth.SASL)
	case backendAuthModeOAuthBearer:
		return authenticateOAuthBearerBackend(connection, target.Auth.OAuthBearer)
	default:
		return fmt.Errorf("%w: unsupported backend auth mode", ErrBackendAuthPolicy)
	}
}

// authenticateMTLSBackend treats verified TLS client-certificate setup as auth proof.
func authenticateMTLSBackend(connection *BackendConnection, target backend.Backend) error {
	if !connection.TLSVerified() {
		return fmt.Errorf("%w: mtls requires verified backend TLS", ErrBackendAuthPolicy)
	}

	if !connection.clientCertificateConfigured || strings.TrimSpace(target.TLS.Cert) == "" || target.TLS.Key.IsZero() {
		return fmt.Errorf("%w: mtls requires backend client certificate", ErrBackendAuthPolicy)
	}

	return nil
}

// authenticateSASLBackend sends configured LMTP service credentials only.
func authenticateSASLBackend(connection *BackendConnection, config backend.SASLConfig) error {
	if config.RequireTLS && !connection.TLSVerified() {
		return fmt.Errorf("%w: sasl requires verified backend TLS", ErrBackendAuthPolicy)
	}

	if strings.TrimSpace(config.Username) == "" || config.Password.IsZero() {
		return fmt.Errorf("%w: incomplete sasl backend config", ErrBackendAuthPolicy)
	}

	mechanism := strings.ToLower(strings.TrimSpace(config.Mechanism))
	if mechanism == "" {
		mechanism = mechanismPlain
	}

	if !backendSupportsAuthMechanism(connection.capabilities, mechanism) {
		return fmt.Errorf("%w: sasl mechanism unavailable", ErrBackendAuthPolicy)
	}

	switch mechanism {
	case mechanismPlain:
		return authenticatePlainBackend(connection, config.Username, config.Password.Value())
	case mechanismLogin:
		return authenticateLoginBackend(connection, config.Username, config.Password.Value())
	default:
		return fmt.Errorf("%w: unsupported sasl mechanism", ErrBackendAuthPolicy)
	}
}

// authenticateOAuthBearerBackend sends the configured backend bearer token.
func authenticateOAuthBearerBackend(connection *BackendConnection, config backend.OAuthBearerConfig) error {
	if config.RequireTLS && !connection.TLSVerified() {
		return fmt.Errorf("%w: oauthbearer requires verified backend TLS", ErrBackendAuthPolicy)
	}

	if config.Token.IsZero() {
		return fmt.Errorf("%w: oauthbearer token unavailable", ErrBackendAuthPolicy)
	}

	if !backendSupportsAuthMechanism(connection.capabilities, mechanismOAuthBearer) {
		return fmt.Errorf("%w: oauthbearer mechanism unavailable", ErrBackendAuthPolicy)
	}

	return authenticateInitialResponseBackend(connection, mechanismOAuthBearer, oauthBearerBackendPayload(config.Token.Value()))
}

// authenticatePlainBackend sends AUTH PLAIN with an initial response.
func authenticatePlainBackend(connection *BackendConnection, username string, password string) error {
	payload := "\x00" + username + "\x00" + password

	return authenticateInitialResponseBackend(connection, mechanismPlain, payload)
}

// authenticateInitialResponseBackend sends a single-command SASL exchange.
func authenticateInitialResponseBackend(connection *BackendConnection, mechanism string, payload string) error {
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))

	response, err := connection.commandResponse("AUTH " + strings.ToUpper(mechanism) + " " + encoded)
	if err != nil {
		return err
	}

	if !response.statusOK(responseStatusAuthSuccess) {
		return fmt.Errorf("%w: backend rejected authentication", ErrBackendAuth)
	}

	return nil
}

// authenticateLoginBackend performs the two-step SMTP AUTH LOGIN exchange.
func authenticateLoginBackend(connection *BackendConnection, username string, password string) error {
	initial := base64.StdEncoding.EncodeToString([]byte(username))

	response, err := connection.commandResponse("AUTH LOGIN " + initial)
	if err != nil {
		return err
	}

	if !response.statusOK(responseStatusAuthContinue) {
		return fmt.Errorf("%w: backend rejected login username", ErrBackendAuth)
	}

	if err := connection.writeCommand(base64.StdEncoding.EncodeToString([]byte(password))); err != nil {
		return err
	}

	response, err = connection.readResponse()
	if err != nil {
		return err
	}

	if !response.statusOK(responseStatusAuthSuccess) {
		return fmt.Errorf("%w: backend rejected login password", ErrBackendAuth)
	}

	return nil
}

// oauthBearerBackendPayload builds an RFC 7628 bearer payload without user material.
func oauthBearerBackendPayload(token string) string {
	return "n,," + saslFieldSep + "auth=Bearer " + token + saslFieldSep + saslFieldSep
}

// backendSupportsAuthMechanism checks backend LHLO AUTH tokens for a mechanism.
func backendSupportsAuthMechanism(capabilities backend.CapabilitySet, mechanism string) bool {
	mechanism = strings.ToUpper(strings.TrimSpace(mechanism))
	if mechanism == "" {
		return false
	}

	return capabilities.Has(capabilityAUTH + "=" + mechanism)
}
