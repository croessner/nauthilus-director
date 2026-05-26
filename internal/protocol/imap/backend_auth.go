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
	"errors"
	"fmt"
	"strings"

	"github.com/croessner/nauthilus-director/internal/backend"
)

const (
	backendAuthModeCredentialReplay = "credential_replay"
	backendAuthModeMasterUser       = "master_user"
	defaultMasterUserFormat         = "{user}*{master_user}"
)

var (
	// ErrBackendAuth reports backend authentication failures without credential details.
	ErrBackendAuth = errors.New("imap: backend auth failed")
	// ErrBackendAuthPolicy reports fail-closed backend auth policy violations.
	ErrBackendAuthPolicy = errors.New("imap: backend auth policy rejected")
)

// AuthenticateBackend establishes the configured backend authentication state.
func AuthenticateBackend(connection *BackendConnection, target backend.Backend, credentials *frontendCredentials) error {
	if connection == nil {
		return fmt.Errorf("%w: backend connection unavailable", ErrBackendAuth)
	}

	if credentials == nil {
		return fmt.Errorf("%w: frontend credentials unavailable", ErrBackendAuth)
	}

	command, err := backendAuthCommand(target, connection, credentials)
	if err != nil {
		return err
	}

	tag := connection.nextCommandTag()
	if err := connection.writeCommand(tag, command); err != nil {
		return err
	}

	ok, err := connection.readTaggedCompletion(tag)
	if err != nil {
		return err
	}

	if !ok {
		return fmt.Errorf("%w: backend rejected authentication", ErrBackendAuth)
	}

	return nil
}

// AuthenticateHealthBackend logs in with the configured health-check identity.
func AuthenticateHealthBackend(connection *BackendConnection, target backend.Backend) error {
	if connection == nil {
		return fmt.Errorf("%w: backend connection unavailable", ErrBackendAuth)
	}

	credentials, err := healthCheckCredentials(target)
	if err != nil {
		return err
	}
	defer credentials.Clear()

	command, err := healthCheckAuthCommand(connection.capabilities, credentials)
	if err != nil {
		return err
	}

	tag := connection.nextCommandTag()
	if err := connection.writeCommand(tag, command); err != nil {
		return err
	}

	ok, err := connection.readTaggedCompletion(tag)
	if err != nil {
		return err
	}

	if !ok {
		return fmt.Errorf("%w: backend rejected health authentication", ErrBackendAuth)
	}

	return nil
}

// backendAuthCommand builds the secret-bearing backend command for immediate use only.
func backendAuthCommand(target backend.Backend, connection *BackendConnection, credentials *frontendCredentials) (string, error) {
	switch strings.ToLower(strings.TrimSpace(target.Auth.Mode)) {
	case backendAuthModeMasterUser:
		return masterUserAuthCommand(target.Auth.MasterUser, connection.capabilities, credentials)
	case backendAuthModeCredentialReplay:
		return credentialReplayCommand(target.Auth.CredentialReplay, connection, credentials)
	default:
		return "", fmt.Errorf("%w: unsupported backend auth mode", ErrBackendAuthPolicy)
	}
}

// masterUserAuthCommand builds the configured master-user IMAP login command.
func masterUserAuthCommand(
	config backend.MasterUserConfig,
	capabilities backendCapabilities,
	credentials *frontendCredentials,
) (string, error) {
	mechanism := strings.ToLower(strings.TrimSpace(config.Mechanism))
	if mechanism == "" {
		mechanism = mechanismPlain
	}

	if mechanism != mechanismPlain && mechanism != mechanismLogin {
		return "", fmt.Errorf("%w: unsupported master_user mechanism", ErrBackendAuthPolicy)
	}

	if !capabilities.SupportsMechanism(mechanism) {
		return "", fmt.Errorf("%w: master_user mechanism unavailable", ErrBackendAuthPolicy)
	}

	username := formattedMasterUsername(config, credentials.Username())
	if strings.TrimSpace(username) == "" || strings.TrimSpace(config.Username) == "" || config.Password.IsZero() {
		return "", fmt.Errorf("%w: incomplete master_user config", ErrBackendAuthPolicy)
	}

	switch mechanism {
	case mechanismLogin:
		return loginCommand(username, config.Password.Value()), nil
	default:
		return plainAuthCommand("", username, config.Password.Value()), nil
	}
}

// healthCheckCredentials creates short-lived credentials for deep health only.
func healthCheckCredentials(target backend.Backend) (*frontendCredentials, error) {
	if strings.TrimSpace(target.Health.Username) == "" || target.Health.Password.IsZero() {
		return nil, fmt.Errorf("%w: incomplete health check credentials", ErrBackendAuthPolicy)
	}

	mechanism, err := newMechanismIdentity(mechanismPlain)
	if err != nil {
		return nil, err
	}

	return &frontendCredentials{
		mechanism: mechanism,
		kind:      credentialKindPassword,
		username:  target.Health.Username,
		secret:    newCredentialSecret(target.Health.Password.Value()),
	}, nil
}

// healthCheckAuthCommand prefers AUTH PLAIN and falls back to LOGIN for health checks.
func healthCheckAuthCommand(capabilities backendCapabilities, credentials *frontendCredentials) (string, error) {
	if capabilities.SupportsMechanism(mechanismPlain) {
		return plainAuthCommand("", credentials.Username(), credentials.Secret().Value()), nil
	}

	if capabilities.SupportsMechanism(mechanismLogin) {
		return loginCommand(credentials.Username(), credentials.Secret().Value()), nil
	}

	return "", fmt.Errorf("%w: health mechanism unavailable", ErrBackendAuthPolicy)
}

// credentialReplayCommand selects and builds the configured replay mechanism.
func credentialReplayCommand(
	config backend.CredentialReplayConfig,
	connection *BackendConnection,
	credentials *frontendCredentials,
) (string, error) {
	if config.RequireBackendTLS && !connection.TLSVerified() {
		return "", fmt.Errorf("%w: credential replay requires verified backend TLS", ErrBackendAuthPolicy)
	}

	mechanism, err := selectReplayMechanism(config, connection.capabilities, credentials)
	if err != nil {
		return "", err
	}

	return replayCommandForMechanism(mechanism, credentials)
}

// selectReplayMechanism applies preserve/normalize rules and backend capability checks.
func selectReplayMechanism(
	config backend.CredentialReplayConfig,
	capabilities backendCapabilities,
	credentials *frontendCredentials,
) (string, error) {
	frontendMechanism := credentials.Mechanism().Normalized()
	allowed := mechanismSet(config.AllowedMechanisms)

	if credentials.Kind() == credentialKindBearer {
		if !allowed[frontendMechanism] || !capabilities.SupportsMechanism(frontendMechanism) {
			return "", fmt.Errorf("%w: bearer replay mechanism unavailable", ErrBackendAuthPolicy)
		}

		return frontendMechanism, nil
	}

	if config.PreserveMechanism {
		if !allowed[frontendMechanism] || !capabilities.SupportsMechanism(frontendMechanism) {
			return "", fmt.Errorf("%w: preserved replay mechanism unavailable", ErrBackendAuthPolicy)
		}

		return frontendMechanism, nil
	}

	for _, candidate := range []string{mechanismPlain, mechanismLogin} {
		if allowed[candidate] && capabilities.SupportsMechanism(candidate) {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("%w: password replay mechanism unavailable", ErrBackendAuthPolicy)
}

// replayCommandForMechanism builds the secret-bearing backend replay command.
func replayCommandForMechanism(mechanism string, credentials *frontendCredentials) (string, error) {
	secret := credentials.Secret()
	if secret.IsZero() {
		return "", fmt.Errorf("%w: replay credential unavailable", ErrBackendAuthPolicy)
	}

	switch mechanism {
	case mechanismPlain:
		return plainAuthCommand(credentials.AuthorizationID(), credentials.Username(), secret.Value()), nil
	case mechanismLogin:
		return loginCommand(credentials.Username(), secret.Value()), nil
	case mechanismXOAUTH2:
		return xoauth2AuthCommand(credentials.Username(), secret.Value()), nil
	case mechanismOAuthBearer:
		authzid := credentials.AuthorizationID()
		if authzid == "" {
			authzid = credentials.Username()
		}

		return oauthBearerAuthCommand(authzid, secret.Value()), nil
	default:
		return "", fmt.Errorf("%w: unsupported replay mechanism", ErrBackendAuthPolicy)
	}
}

// formattedMasterUsername applies the configured master user template.
func formattedMasterUsername(config backend.MasterUserConfig, user string) string {
	format := config.UserFormat
	if strings.TrimSpace(format) == "" {
		format = defaultMasterUserFormat
	}

	format = strings.ReplaceAll(format, "{user}", user)
	format = strings.ReplaceAll(format, "{master_user}", config.Username)

	return format
}

// plainAuthCommand builds an AUTHENTICATE PLAIN command with SASL initial response.
func plainAuthCommand(authzid string, authcid string, password string) string {
	payload := authzid + "\x00" + authcid + "\x00" + password

	return "AUTHENTICATE PLAIN " + base64.StdEncoding.EncodeToString([]byte(payload))
}

// loginCommand builds an IMAP LOGIN command with quoted strings.
func loginCommand(username string, password string) string {
	return "LOGIN " + quoteIMAPString(username) + " " + quoteIMAPString(password)
}

// xoauth2AuthCommand builds an AUTHENTICATE XOAUTH2 command with SASL initial response.
func xoauth2AuthCommand(username string, token string) string {
	payload := "user=" + username + saslFieldSep + "auth=Bearer " + token + saslFieldSep + saslFieldSep

	return "AUTHENTICATE XOAUTH2 " + base64.StdEncoding.EncodeToString([]byte(payload))
}

// oauthBearerAuthCommand builds an AUTHENTICATE OAUTHBEARER command with SASL initial response.
func oauthBearerAuthCommand(authzid string, token string) string {
	payload := "n,a=" + encodeBackendGS2AuthzID(authzid) + "," + saslFieldSep +
		"auth=Bearer " + token + saslFieldSep + saslFieldSep

	return "AUTHENTICATE OAUTHBEARER " + base64.StdEncoding.EncodeToString([]byte(payload))
}

// quoteIMAPString escapes a backend LOGIN string without logging it.
func quoteIMAPString(value string) string {
	var builder strings.Builder
	builder.Grow(len(value) + 2)
	builder.WriteByte('"')

	for _, current := range value {
		switch current {
		case '\\', '"':
			builder.WriteByte('\\')
			builder.WriteRune(current)
		case '\r', '\n':
			builder.WriteByte(' ')
		default:
			builder.WriteRune(current)
		}
	}

	builder.WriteByte('"')

	return builder.String()
}

// encodeBackendGS2AuthzID escapes the characters reserved by RFC 7628 GS2 syntax.
func encodeBackendGS2AuthzID(value string) string {
	value = strings.ReplaceAll(value, "=", "=3D")
	value = strings.ReplaceAll(value, ",", "=2C")

	return value
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
