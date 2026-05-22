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

const (
	// DecisionAuthenticated is the successful authority decision.
	DecisionAuthenticated = "ok"
	// DecisionRejected is the terminal credential or policy rejection decision.
	DecisionRejected = "fail"
	// DecisionTemporaryFailure is the fail-closed temporary failure decision.
	DecisionTemporaryFailure = "tempfail"
)

// AuthResult is the director-internal authentication outcome.
type AuthResult struct {
	Decision      string
	Account       string
	SessionID     string
	StatusMessage string
	Attributes    map[string][]string
}

// ListAccountsResult is the director-internal account-listing outcome.
type ListAccountsResult struct {
	Decision      string
	SessionID     string
	StatusMessage string
	Accounts      []string
}

// Authenticated reports whether the result permits routing to continue.
func (r AuthResult) Authenticated() bool {
	return r.Decision == DecisionAuthenticated
}

// Successful reports whether the account-listing operation completed.
func (r ListAccountsResult) Successful() bool {
	return r.Decision == DecisionAuthenticated
}

// cloneAttributes returns a detached copy of routing input attributes.
func cloneAttributes(attributes map[string][]string) map[string][]string {
	if attributes == nil {
		return nil
	}

	cloned := make(map[string][]string, len(attributes))
	for key, values := range attributes {
		cloned[key] = append([]string(nil), values...)
	}

	return cloned
}

// resultWithDecision builds a result with detached attribute values.
func resultWithDecision(
	decision string,
	account string,
	sessionID string,
	statusMessage string,
	attributes map[string][]string,
) AuthResult {
	return AuthResult{
		Decision:      decision,
		Account:       account,
		SessionID:     sessionID,
		StatusMessage: statusMessage,
		Attributes:    cloneAttributes(attributes),
	}
}

// listAccountsWithDecision builds a result with detached account values.
func listAccountsWithDecision(decision string, sessionID string, statusMessage string, accounts []string) ListAccountsResult {
	return ListAccountsResult{
		Decision:      decision,
		SessionID:     sessionID,
		StatusMessage: statusMessage,
		Accounts:      append([]string(nil), accounts...),
	}
}
