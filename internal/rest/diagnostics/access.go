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

package diagnostics

import (
	"slices"
	"strings"
)

// CredentialMethod names how a transport verified the caller.
type CredentialMethod string

const (
	// CredentialOAuthUser is a user access token issued by Nauthilus for the director's protected
	// resource and introspected by the resource server of that resource (the MCP endpoint). It names
	// a person acting through an OAuth client.
	CredentialOAuthUser CredentialMethod = "oauth_user"
)

// principalSeparator joins client and subject in the principal identity of a user credential.
const principalSeparator = "#"

// Credential carries facts a transport adapter has already verified. Only an adapter that
// validated the credential itself may construct it; nothing in it comes from request bodies or
// caller-supplied headers.
type Credential struct {
	Method   CredentialMethod
	ClientID string
	Subject  string
	Scopes   []string
}

// Verified reports whether the credential uses a known method and names a principal.
func (c Credential) Verified() bool {
	return c.Identity() != ""
}

// Identity returns the stable principal identity used for audit records and per-principal limits.
//
// A user token is identified by client and subject together, so people sharing one client never
// share an audit identity or a concurrency share. Unknown methods and user tokens without both
// values have no identity and therefore no permission.
func (c Credential) Identity() string {
	clientID, subject := strings.TrimSpace(c.ClientID), strings.TrimSpace(c.Subject)

	if c.Method != CredentialOAuthUser || clientID == "" || subject == "" {
		return ""
	}

	return clientID + principalSeparator + subject
}

// HasScope reports whether the verified scopes contain scope; an unverified credential holds no scope.
func (c Credential) HasScope(scope string) bool {
	return scope != "" && c.Verified() && slices.Contains(c.Scopes, scope)
}

// Permits reports whether the credential holds at least one scope of the operation.
func (c Credential) Permits(operation Operation) bool {
	return slices.ContainsFunc(operation.Scopes, c.HasScope)
}
