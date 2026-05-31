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
)

var (
	// ErrCredentialRejected reports credential input that must fail without exposing raw material.
	ErrCredentialRejected = errors.New("imap: credential input rejected")
	// ErrCredentialTooLarge reports credential input that exceeded a configured byte limit.
	ErrCredentialTooLarge = errors.New("imap: credential input too large")
)

// mechanismIdentity records normalized and accepted frontend mechanism names.
type mechanismIdentity struct {
	original   string
	normalized string
}

// frontendCredentials contains one short-lived parsed frontend credential.
type frontendCredentials struct {
	mechanism       mechanismIdentity
	kind            string
	username        string
	authorizationID string
	secret          *credentialSecret
}

// newMechanismIdentity validates and normalizes a frontend authentication mechanism.
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

// Original returns the accepted mechanism spelling from the frontend command.
func (m mechanismIdentity) Original() string {
	return m.original
}

// Normalized returns the canonical lower-case mechanism name used by config and Nauthilus.
func (m mechanismIdentity) Normalized() string {
	return m.normalized
}

// IMAPName returns the canonical IMAP mechanism token for later backend replay.
func (m mechanismIdentity) IMAPName() string {
	return strings.ToUpper(m.normalized)
}

// parseLoginCredentials extracts atom or quoted-string LOGIN credentials.
func parseLoginCredentials(command preauthCommand) (*frontendCredentials, error) {
	mechanism, err := newMechanismIdentity(mechanismLogin)
	if err != nil {
		return nil, err
	}

	if len(command.arguments) != 2 || !tokenIsStringLike(command.arguments[0]) || !tokenIsStringLike(command.arguments[1]) {
		return nil, fmt.Errorf("%w: invalid login shape", ErrCredentialRejected)
	}

	username := strings.TrimSpace(command.arguments[0].value)

	password := command.arguments[1].value
	if username == "" || password == "" {
		return nil, fmt.Errorf("%w: missing login field", ErrCredentialRejected)
	}

	return &frontendCredentials{
		mechanism: mechanism,
		kind:      credentialKindPassword,
		username:  username,
		secret:    newCredentialSecret(password),
	}, nil
}

// Username returns the parsed authentication identity.
func (c *frontendCredentials) Username() string {
	if c == nil {
		return ""
	}

	return c.username
}

// AuthorizationID returns the optional authorization identity supplied by SASL.
func (c *frontendCredentials) AuthorizationID() string {
	if c == nil {
		return ""
	}

	return c.authorizationID
}

// Mechanism returns the preserved frontend mechanism identity.
func (c *frontendCredentials) Mechanism() mechanismIdentity {
	if c == nil {
		return mechanismIdentity{}
	}

	return c.mechanism
}

// Kind reports whether the credential carries password or bearer material.
func (c *frontendCredentials) Kind() string {
	if c == nil {
		return ""
	}

	return c.kind
}

// Secret returns the wrapped credential material for the short-lived auth call path.
func (c *frontendCredentials) Secret() *credentialSecret {
	if c == nil {
		return nil
	}

	return c.secret
}

// Clear releases the parsed credential copy held by this value.
func (c *frontendCredentials) Clear() {
	c.secret.Clear()
	c.username = ""
	c.authorizationID = ""
}

// NauthilusAuthRequest builds the later authority request without exposing credential formatting.
func (c *frontendCredentials) NauthilusAuthRequest(requestContext nauthilus.RequestContext) nauthilus.AuthRequest {
	if c == nil {
		return nauthilus.AuthRequest{Context: requestContext}
	}

	requestContext.Username = c.username
	requestContext.Method = c.mechanism.Normalized()

	return nauthilus.AuthRequest{
		Context:    requestContext,
		Credential: nauthilus.NewSecret(c.secret.Value()),
	}
}

// String returns only credential-safe metadata for diagnostics and tests.
func (c *frontendCredentials) String() string {
	if c == nil {
		return "frontendCredentials<nil>"
	}

	return fmt.Sprintf(
		"frontendCredentials{mechanism:%q kind:%q username_present:%t credential:%s}",
		c.mechanism.Normalized(),
		c.kind,
		strings.TrimSpace(c.username) != "",
		c.secret.String(),
	)
}

// GoString returns only credential-safe metadata for Go-syntax formatting.
func (c *frontendCredentials) GoString() string {
	return c.String()
}
