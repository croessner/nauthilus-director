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

//nolint:goconst,wsl_v5 // Backend auth keeps wire mechanisms explicit for security review.
package pop3

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/protocol/saslcred"
)

const (
	backendAuthModeCredentialReplay = "credential_replay"
	backendAuthModeMasterUser       = "master_user"
	defaultMasterUserFormat         = "{user}*{master_user}"
	saslFieldSep                    = "\x01"
)

var (
	// ErrBackendAuth reports backend authentication failures without credential details.
	ErrBackendAuth = errors.New("pop3: backend auth failed")
	// ErrBackendAuthPolicy reports fail-closed backend auth policy violations.
	ErrBackendAuthPolicy = errors.New("pop3: backend auth policy rejected")
)

// AuthenticateBackend establishes the configured backend authentication state.
func AuthenticateBackend(
	connection *BackendConnection,
	target backend.Backend,
	credentials *frontendCredentials,
	selectedUser string,
) error {
	if connection == nil {
		return fmt.Errorf("%w: backend connection unavailable", ErrBackendAuth)
	}

	if credentials == nil {
		return fmt.Errorf("%w: frontend credentials unavailable", ErrBackendAuth)
	}

	switch strings.ToLower(strings.TrimSpace(target.Auth.Mode)) {
	case backendAuthModeMasterUser:
		if credentials.Kind() == saslcred.KindBearer {
			return authenticateCredentialReplayBackend(connection, target.Auth.CredentialReplay, credentials)
		}

		return authenticateMasterUserBackend(connection, target.Auth.MasterUser, selectedUser)
	case backendAuthModeCredentialReplay:
		return authenticateCredentialReplayBackend(connection, target.Auth.CredentialReplay, credentials)
	default:
		return fmt.Errorf("%w: unsupported backend auth mode", ErrBackendAuthPolicy)
	}
}

// AuthenticateHealthBackend logs in with the configured health-check identity.
func AuthenticateHealthBackend(connection *BackendConnection, target backend.Backend) error {
	if connection == nil {
		return fmt.Errorf("%w: backend connection unavailable", ErrBackendAuth)
	}

	if strings.TrimSpace(target.Health.Username) == "" || target.Health.Password.IsZero() {
		return fmt.Errorf("%w: incomplete health check credentials", ErrBackendAuthPolicy)
	}

	if !backendSupportsUserPass(connection.CapabilitySet()) {
		return fmt.Errorf("%w: health userpass unavailable", ErrBackendAuthPolicy)
	}

	return authenticateUserPass(connection, target.Health.Username, target.Health.Password.Value())
}

// authenticateMasterUserBackend logs in using the configured master-user POP3 USER/PASS flow.
func authenticateMasterUserBackend(connection *BackendConnection, config backend.MasterUserConfig, selectedUser string) error {
	if !backendPasswordMechanismAllowed(config.Mechanism) {
		return fmt.Errorf("%w: unsupported master_user mechanism", ErrBackendAuthPolicy)
	}

	if !backendSupportsUserPass(connection.CapabilitySet()) {
		return fmt.Errorf("%w: master_user userpass unavailable", ErrBackendAuthPolicy)
	}

	username := formattedMasterUsername(config, selectedUser)
	if strings.TrimSpace(username) == "" || strings.TrimSpace(config.Username) == "" || config.Password.IsZero() {
		return fmt.Errorf("%w: incomplete master_user config", ErrBackendAuthPolicy)
	}

	return authenticateUserPass(connection, username, config.Password.Value())
}

// authenticateCredentialReplayBackend replays only explicitly allowed frontend credentials.
func authenticateCredentialReplayBackend(
	connection *BackendConnection,
	config backend.CredentialReplayConfig,
	credentials *frontendCredentials,
) error {
	if config.RequireBackendTLS && !connection.TLSVerified() {
		return fmt.Errorf("%w: credential replay requires verified backend TLS", ErrBackendAuthPolicy)
	}

	mechanism, err := selectReplayMechanism(config, connection.CapabilitySet(), credentials)
	if err != nil {
		return err
	}

	switch mechanism {
	case authMethodUserPass:
		return authenticateUserPass(connection, credentials.Username(), credentials.Secret().Value())
	case saslcred.MechanismXOAUTH2, saslcred.MechanismOAuthBearer:
		return authenticateBearer(connection, mechanism, credentials)
	default:
		return fmt.Errorf("%w: unsupported replay mechanism", ErrBackendAuthPolicy)
	}
}

// selectReplayMechanism enforces configured method scope and backend capability proof.
func selectReplayMechanism(
	config backend.CredentialReplayConfig,
	capabilities backend.CapabilitySet,
	credentials *frontendCredentials,
) (string, error) {
	allowed := mechanismSet(config.AllowedMechanisms)
	frontendMethod := strings.ToLower(strings.TrimSpace(credentials.Method()))

	if credentials.Kind() == saslcred.KindBearer {
		if !allowed[frontendMethod] || !backendSupportsSASLMechanism(capabilities, frontendMethod) {
			return "", fmt.Errorf("%w: bearer replay mechanism unavailable", ErrBackendAuthPolicy)
		}

		return frontendMethod, nil
	}

	if credentials.Kind() != credentialKindPassword {
		return "", fmt.Errorf("%w: replay credential kind unavailable", ErrBackendAuthPolicy)
	}

	if config.PreserveMechanism && frontendMethod != authMethodUserPass {
		return "", fmt.Errorf("%w: preserved replay mechanism unavailable", ErrBackendAuthPolicy)
	}

	if !allowed[authMethodUserPass] || !backendSupportsUserPass(capabilities) {
		return "", fmt.Errorf("%w: password replay mechanism unavailable", ErrBackendAuthPolicy)
	}

	return authMethodUserPass, nil
}

// authenticateUserPass sends POP3 USER and PASS and consumes only status classes.
func authenticateUserPass(connection *BackendConnection, username string, password string) error {
	if strings.TrimSpace(username) == "" || password == "" {
		return fmt.Errorf("%w: userpass credential unavailable", ErrBackendAuthPolicy)
	}

	if err := connection.writeCommand("USER " + sanitizeBackendArgument(username)); err != nil {
		return err
	}

	ok, err := connection.readStatusLine()
	if err != nil {
		return err
	}

	if !ok {
		return fmt.Errorf("%w: backend rejected user", ErrBackendAuth)
	}

	if err := connection.writeCommand("PASS " + sanitizeBackendArgument(password)); err != nil {
		return err
	}

	ok, err = connection.readStatusLine()
	if err != nil {
		return err
	}

	if !ok {
		return fmt.Errorf("%w: backend rejected pass", ErrBackendAuth)
	}

	return nil
}

// authenticateBearer sends one POP3 SASL AUTH command with an initial response.
func authenticateBearer(connection *BackendConnection, mechanism string, credentials *frontendCredentials) error {
	secret := credentials.Secret()
	if secret == nil || secret.Value() == "" {
		return fmt.Errorf("%w: bearer credential unavailable", ErrBackendAuthPolicy)
	}

	var payload string
	switch mechanism {
	case saslcred.MechanismXOAUTH2:
		payload = xoauth2BackendPayload(credentials.Username(), secret.Value())
	case saslcred.MechanismOAuthBearer:
		authzid := credentials.AuthorizationID()
		if authzid == "" {
			authzid = credentials.Username()
		}

		payload = oauthBearerBackendPayload(authzid, secret.Value())
	default:
		return fmt.Errorf("%w: unsupported bearer mechanism", ErrBackendAuthPolicy)
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(payload))
	if err := connection.writeCommand("AUTH " + strings.ToUpper(mechanism) + " " + encoded); err != nil {
		return err
	}

	ok, err := connection.readStatusLine()
	if err != nil {
		return err
	}

	if !ok {
		return fmt.Errorf("%w: backend rejected bearer auth", ErrBackendAuth)
	}

	return nil
}

// formattedMasterUsername applies the configured master user template.
func formattedMasterUsername(config backend.MasterUserConfig, user string) string {
	format := config.UserFormat
	if strings.TrimSpace(format) == "" {
		format = defaultMasterUserFormat
	}

	format = strings.ReplaceAll(format, "{user}", strings.TrimSpace(user))
	format = strings.ReplaceAll(format, "{master_user}", strings.TrimSpace(config.Username))

	return format
}

// backendPasswordMechanismAllowed accepts legacy password-shaped config labels for USER/PASS.
func backendPasswordMechanismAllowed(mechanism string) bool {
	switch strings.ToLower(strings.TrimSpace(mechanism)) {
	case "", "plain", "login", authMethodUserPass:
		return true
	default:
		return false
	}
}

// backendSupportsUserPass checks CAPA proof for POP3 USER/PASS.
func backendSupportsUserPass(capabilities backend.CapabilitySet) bool {
	return capabilities.Has(capabilityUser)
}

// backendSupportsSASLMechanism checks CAPA SASL proof for bearer replay.
func backendSupportsSASLMechanism(capabilities backend.CapabilitySet, mechanism string) bool {
	mechanism = strings.ToUpper(strings.TrimSpace(mechanism))
	if mechanism == "" {
		return false
	}

	return capabilities.Has(capabilitySASL + "=" + mechanism)
}

// mechanismSet canonicalizes a configured mechanism allowlist.
func mechanismSet(mechanisms []string) map[string]bool {
	set := make(map[string]bool, len(mechanisms))
	for _, mechanism := range mechanisms {
		mechanism = strings.ToLower(strings.TrimSpace(mechanism))
		if mechanism != "" {
			set[mechanism] = true
		}
	}

	return set
}

// sanitizeBackendArgument keeps USER/PASS command arguments on a single POP3 line.
func sanitizeBackendArgument(value string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(value)
}

// xoauth2BackendPayload builds an XOAUTH2 bearer envelope for backend auth.
func xoauth2BackendPayload(username string, token string) string {
	return "user=" + username + saslFieldSep + "auth=Bearer " + token + saslFieldSep + saslFieldSep
}

// oauthBearerBackendPayload builds an OAUTHBEARER envelope for backend auth.
func oauthBearerBackendPayload(authzid string, token string) string {
	return "n,a=" + encodeBackendGS2AuthzID(authzid) + "," + saslFieldSep +
		"auth=Bearer " + token + saslFieldSep + saslFieldSep
}

// encodeBackendGS2AuthzID escapes the characters reserved by RFC 7628 GS2 syntax.
func encodeBackendGS2AuthzID(value string) string {
	value = strings.ReplaceAll(value, "=", "=3D")
	value = strings.ReplaceAll(value, ",", "=2C")

	return value
}
