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

package sieve

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
	mechanismOAuthBearer            = saslcred.MechanismOAuthBearer
	mechanismPlain                  = saslcred.MechanismPlain
	mechanismXOAUTH2                = saslcred.MechanismXOAUTH2
	saslFieldSep                    = "\x01"
	sieveBackendSASLPredicate       = "SASL="
)

var (
	// ErrBackendAuth reports backend authentication failures without credential details.
	ErrBackendAuth = errors.New("sieve: backend auth failed")
	// ErrBackendAuthPolicy reports fail-closed backend auth policy violations.
	ErrBackendAuthPolicy = errors.New("sieve: backend auth policy rejected")
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

	if err := connection.writeCommand(command); err != nil {
		return err
	}

	response, err := connection.readResponse()
	if err != nil {
		return err
	}

	if response.referral() {
		return fmt.Errorf("%w: backend referral is not supported", ErrBackendAuth)
	}

	if response.condition != backendResponseOK {
		return fmt.Errorf("%w: backend rejected authentication", ErrBackendAuth)
	}

	return nil
}

// AuthenticateHealthBackend logs in with the configured health-check identity.
func AuthenticateHealthBackend(connection *BackendConnection, target backend.Backend) error {
	if connection == nil {
		return fmt.Errorf("%w: backend connection unavailable", ErrBackendAuth)
	}

	if strings.TrimSpace(target.Health.Username) == "" || target.Health.Password.IsZero() {
		return fmt.Errorf("%w: incomplete health check credentials", ErrBackendAuthPolicy)
	}

	if !backendSupportsAuthMechanism(connection.capabilities, mechanismPlain) {
		return fmt.Errorf("%w: health mechanism unavailable", ErrBackendAuthPolicy)
	}

	password, err := target.Health.PasswordValue("director.backends.health_check.password_file")
	if err != nil {
		return fmt.Errorf("%w: invalid health check password_file", ErrBackendAuthPolicy)
	}

	command := authenticateCommand(mechanismPlain, backendPlainPayload("", target.Health.Username, password))
	if err := connection.writeCommand(command); err != nil {
		return err
	}

	response, err := connection.readResponse()
	if err != nil {
		return err
	}

	if response.condition != backendResponseOK {
		return fmt.Errorf("%w: backend rejected health authentication", ErrBackendAuth)
	}

	return nil
}

// backendAuthCommand builds the secret-bearing backend command for immediate use only.
func backendAuthCommand(target backend.Backend, connection *BackendConnection, credentials *frontendCredentials) (string, error) {
	switch strings.ToLower(strings.TrimSpace(target.Auth.Mode)) {
	case backendAuthModeMasterUser:
		if credentials.Kind() == saslcred.KindBearer {
			return credentialReplayCommand(target.Auth.CredentialReplay, connection, credentials)
		}

		return masterUserAuthCommand(target.Auth.MasterUser, connection.capabilities, credentials)
	case backendAuthModeCredentialReplay:
		return credentialReplayCommand(target.Auth.CredentialReplay, connection, credentials)
	default:
		return "", fmt.Errorf("%w: unsupported backend auth mode", ErrBackendAuthPolicy)
	}
}

// masterUserAuthCommand builds the configured master-user ManageSieve auth command.
func masterUserAuthCommand(
	config backend.MasterUserConfig,
	capabilities backend.CapabilitySet,
	credentials *frontendCredentials,
) (string, error) {
	mechanism := strings.ToLower(strings.TrimSpace(config.Mechanism))
	if mechanism == "" {
		mechanism = mechanismPlain
	}

	if mechanism != mechanismPlain {
		return "", fmt.Errorf("%w: unsupported master_user mechanism", ErrBackendAuthPolicy)
	}

	if !backendSupportsAuthMechanism(capabilities, mechanism) {
		return "", fmt.Errorf("%w: master_user mechanism unavailable", ErrBackendAuthPolicy)
	}

	username := formattedMasterUsername(config, credentials.Username())
	if strings.TrimSpace(username) == "" || strings.TrimSpace(config.Username) == "" || config.Password.IsZero() {
		return "", fmt.Errorf("%w: incomplete master_user config", ErrBackendAuthPolicy)
	}

	password, err := config.PasswordValue("director.backends.auth.master_user.password_file")
	if err != nil {
		return "", fmt.Errorf("%w: invalid master_user password_file", ErrBackendAuthPolicy)
	}

	return authenticateCommand(mechanismPlain, backendPlainPayload("", username, password)), nil
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

// selectReplayMechanism applies preserve rules and backend capability checks.
func selectReplayMechanism(
	config backend.CredentialReplayConfig,
	capabilities backend.CapabilitySet,
	credentials *frontendCredentials,
) (string, error) {
	frontendMechanism := credentials.Mechanism().Normalized()
	allowed := mechanismSet(config.AllowedMechanisms)

	if credentials.Kind() == saslcred.KindBearer {
		if !allowed[frontendMechanism] || !backendSupportsAuthMechanism(capabilities, frontendMechanism) {
			return "", fmt.Errorf("%w: bearer replay mechanism unavailable", ErrBackendAuthPolicy)
		}

		return frontendMechanism, nil
	}

	if config.PreserveMechanism {
		if !allowed[frontendMechanism] || !backendSupportsAuthMechanism(capabilities, frontendMechanism) {
			return "", fmt.Errorf("%w: preserved replay mechanism unavailable", ErrBackendAuthPolicy)
		}

		return frontendMechanism, nil
	}

	if allowed[mechanismPlain] && backendSupportsAuthMechanism(capabilities, mechanismPlain) {
		return mechanismPlain, nil
	}

	return "", fmt.Errorf("%w: password replay mechanism unavailable", ErrBackendAuthPolicy)
}

// replayCommandForMechanism builds the secret-bearing backend replay command.
func replayCommandForMechanism(mechanism string, credentials *frontendCredentials) (string, error) {
	secret := credentials.Secret()
	if secret == nil || secret.Value() == "" {
		return "", fmt.Errorf("%w: replay credential unavailable", ErrBackendAuthPolicy)
	}

	switch mechanism {
	case mechanismPlain:
		return authenticateCommand(mechanismPlain, backendPlainPayload(credentials.AuthorizationID(), credentials.Username(), secret.Value())), nil
	case mechanismXOAUTH2:
		return authenticateCommand(mechanismXOAUTH2, backendXOAUTH2Payload(credentials.Username(), secret.Value())), nil
	case mechanismOAuthBearer:
		authzid := credentials.AuthorizationID()
		if authzid == "" {
			authzid = credentials.Username()
		}

		return authenticateCommand(mechanismOAuthBearer, backendOAuthBearerPayload(authzid, secret.Value())), nil
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

// authenticateCommand builds one ManageSieve AUTHENTICATE command with initial response.
func authenticateCommand(mechanism string, payload string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))

	return commandAuthenticate + " " + backendQuoteString(strings.ToUpper(mechanism)) + " " + backendQuoteString(encoded)
}

// backendPlainPayload builds a SASL PLAIN initial response.
func backendPlainPayload(authzid string, authcid string, password string) string {
	return authzid + "\x00" + authcid + "\x00" + password
}

// backendXOAUTH2Payload builds an XOAUTH2 bearer envelope.
func backendXOAUTH2Payload(username string, token string) string {
	return "user=" + username + saslFieldSep + "auth=Bearer " + token + saslFieldSep + saslFieldSep
}

// backendOAuthBearerPayload builds an RFC 7628 OAUTHBEARER envelope.
func backendOAuthBearerPayload(authzid string, token string) string {
	return "n,a=" + encodeBackendGS2AuthzID(authzid) + "," + saslFieldSep +
		"auth=Bearer " + token + saslFieldSep + saslFieldSep
}

// encodeBackendGS2AuthzID escapes the characters reserved by RFC 7628 GS2 syntax.
func encodeBackendGS2AuthzID(value string) string {
	value = strings.ReplaceAll(value, "=", "=3D")
	value = strings.ReplaceAll(value, ",", "=2C")

	return value
}

// backendQuoteString renders a ManageSieve command string without response truncation.
func backendQuoteString(value string) string {
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

// backendSupportsAuthMechanism checks ManageSieve SASL capability proof.
func backendSupportsAuthMechanism(capabilities backend.CapabilitySet, mechanism string) bool {
	mechanism = strings.ToUpper(strings.TrimSpace(mechanism))
	if mechanism == "" {
		return false
	}

	return capabilities.Has(sieveBackendSASLPredicate + mechanism)
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
