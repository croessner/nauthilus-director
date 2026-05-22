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

package nauthilus

const redactedSecret = "<redacted>"

const (
	safeFieldClientIPPresent          = "client_ip_present"
	safeFieldClientIDPresent          = "client_id_present"
	safeFieldExternalSessionIDPresent = "external_session_id_present"
	safeFieldHasCredential            = "has_credential"
	safeFieldMethod                   = "method"
	safeFieldOIDCCIDPresent           = "oidc_cid_present"
	safeFieldOperation                = "operation"
	safeFieldProtocol                 = "protocol"
)

// SafeFields contains values that may be emitted in diagnostics.
type SafeFields map[string]string

// Secret wraps credential-bearing material so formatting remains redacted.
type Secret struct {
	value string
}

// NewSecret creates a redaction-aware credential value.
func NewSecret(value string) Secret {
	return Secret{value: value}
}

// Value returns the wrapped credential for authority transports.
func (s Secret) Value() string {
	return s.value
}

// IsZero reports whether no credential material is present.
func (s Secret) IsZero() bool {
	return s.value == ""
}

// String returns only the redacted marker for non-empty secrets.
func (s Secret) String() string {
	if s.value == "" {
		return ""
	}

	return redactedSecret
}

// RequestContext contains auth-facing client and protocol context.
type RequestContext struct {
	Username          string
	ClientIP          string
	ClientPort        string
	ClientHostname    string
	ClientID          string
	ExternalSessionID string
	UserAgent         string
	LocalIP           string
	LocalPort         string
	Protocol          string
	// Method carries the normalized frontend authentication mechanism sent to Nauthilus.
	Method             string
	TLS                string
	TLSSessionID       string
	TLSClientVerify    string
	TLSClientDN        string
	TLSClientCN        string
	TLSIssuer          string
	TLSClientNotBefore string
	TLSClientNotAfter  string
	TLSSubjectDN       string
	TLSIssuerDN        string
	TLSClientSubjectDN string
	TLSClientIssuerDN  string
	TLSProtocol        string
	TLSCipher          string
	TLSSerial          string
	TLSFingerprint     string
	OIDCCID            string
}

// AuthRequest contains credential-bearing authentication input.
type AuthRequest struct {
	Context          RequestContext
	Credential       Secret
	AuthLoginAttempt uint
}

// IdentityLookupRequest contains trusted no-auth identity lookup input.
type IdentityLookupRequest struct {
	Context RequestContext
}

// ListAccountsRequest contains account-listing authority input.
type ListAccountsRequest struct {
	Context RequestContext
}

// LogFields returns secret-free fields for authentication diagnostics.
func (r AuthRequest) LogFields() SafeFields {
	fields := safeContextFields(r.Context, operationAuthenticate)
	fields[safeFieldHasCredential] = boolString(!r.Credential.IsZero())

	return fields
}

// LogFields returns secret-free fields for lookup diagnostics.
func (r IdentityLookupRequest) LogFields() SafeFields {
	return safeContextFields(r.Context, operationLookupIdentity)
}

// LogFields returns secret-free fields for list-accounts diagnostics.
func (r ListAccountsRequest) LogFields() SafeFields {
	return safeContextFields(r.Context, operationListAccounts)
}

// safeContextFields builds the common low-detail diagnostic field set.
func safeContextFields(context RequestContext, operation authOperation) SafeFields {
	fields := SafeFields{
		safeFieldOperation: string(operation),
		safeFieldProtocol:  context.Protocol,
		safeFieldMethod:    context.Method,
	}

	if context.ClientIP != "" {
		fields[safeFieldClientIPPresent] = boolString(true)
	}

	if context.ClientID != "" {
		fields[safeFieldClientIDPresent] = boolString(true)
	}

	if context.ExternalSessionID != "" {
		fields[safeFieldExternalSessionIDPresent] = boolString(true)
	}

	if context.OIDCCID != "" {
		fields[safeFieldOIDCCIDPresent] = boolString(true)
	}

	return fields
}

// boolString returns stable text for diagnostic boolean fields.
func boolString(value bool) string {
	if value {
		return "true"
	}

	return "false"
}
