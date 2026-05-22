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
	"fmt"
	"strings"

	"github.com/croessner/nauthilus-director/internal/nauthilus"
)

const (
	clientIDKeyHyphen     = "client-id"
	clientIDKeyName       = "name"
	clientIDKeyUnderscore = "client_id"
	maxIDPairs            = 32
	maxIDKeyBytes         = 64
	maxIDValueBytes       = 512
)

// handleID parses RFC-2971-style client metadata and stores only normalized client ID.
func (s *Session) handleID(command preauthCommand) error {
	clientID, err := parseClientID(command.arguments)
	if err != nil {
		return s.writeTagged(command.tag, responseBad, "Invalid ID command")
	}

	s.clientID = clientID

	if _, err := s.writer.WriteString("* ID NIL\r\n"); err != nil {
		return err
	}

	return s.writeTagged(command.tag, responseOK, "ID completed")
}

// NauthilusRequestContext builds the auth-facing context without HTTP-only user-agent data.
func (s *Session) NauthilusRequestContext(method string) nauthilus.RequestContext {
	return nauthilus.RequestContext{
		ClientID: s.clientID,
		Protocol: "imap",
		Method:   method,
	}
}

// ClientID returns the normalized IMAP ID value retained for auth context.
func (s *Session) ClientID() string {
	return s.clientID
}

// parseClientID extracts only the configured client identity keys from ID arguments.
func parseClientID(tokens []argumentToken) (string, error) {
	if idCommandIsNil(tokens) {
		return "", nil
	}

	pairTokens, err := idPairTokens(tokens)
	if err != nil {
		return "", err
	}

	candidates, err := collectClientIDCandidates(pairTokens)
	if err != nil {
		return "", err
	}

	return selectedClientID(candidates), nil
}

// idCommandIsNil reports whether the client supplied ID NIL.
func idCommandIsNil(tokens []argumentToken) bool {
	return len(tokens) == 1 && tokens[0].kind == tokenAtom && strings.EqualFold(tokens[0].value, "NIL")
}

// idPairTokens validates list framing and returns only the key/value tokens.
func idPairTokens(tokens []argumentToken) ([]argumentToken, error) {
	if len(tokens) < 2 || tokens[0].kind != tokenListStart || tokens[len(tokens)-1].kind != tokenListEnd {
		return nil, fmt.Errorf("%w: invalid ID list", ErrMalformedCommand)
	}

	pairTokens := tokens[1 : len(tokens)-1]
	if len(pairTokens)%2 != 0 {
		return nil, fmt.Errorf("%w: odd ID pair count", ErrMalformedCommand)
	}

	if len(pairTokens)/2 > maxIDPairs {
		return nil, fmt.Errorf("%w: too many ID pairs", ErrMalformedCommand)
	}

	return pairTokens, nil
}

// collectClientIDCandidates validates pairs and keeps only supported client ID candidates.
func collectClientIDCandidates(pairTokens []argumentToken) (map[string]string, error) {
	seen := map[string]struct{}{}
	candidates := map[string]string{}

	for index := 0; index < len(pairTokens); index += 2 {
		key, value, err := parseIDPair(pairTokens[index], pairTokens[index+1])
		if err != nil {
			return nil, err
		}

		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("%w: duplicate ID key", ErrMalformedCommand)
		}

		seen[key] = struct{}{}
		if selectedClientIDKey(key) {
			candidates[key] = value
		}
	}

	return candidates, nil
}

// selectedClientID applies the configured priority order to parsed candidates.
func selectedClientID(candidates map[string]string) string {
	for _, key := range [...]string{clientIDKeyUnderscore, clientIDKeyHyphen, clientIDKeyName} {
		if value := candidates[key]; value != "" {
			return value
		}
	}

	return ""
}

// parseIDPair validates one ID key/value pair without retaining the whole map.
func parseIDPair(keyToken argumentToken, valueToken argumentToken) (string, string, error) {
	if !tokenIsStringLike(keyToken) {
		return "", "", fmt.Errorf("%w: invalid ID key", ErrMalformedCommand)
	}

	key := strings.ToLower(strings.TrimSpace(keyToken.value))
	if key == "" || len(key) > maxIDKeyBytes {
		return "", "", fmt.Errorf("%w: invalid ID key", ErrMalformedCommand)
	}

	if strings.ContainsAny(key, "\r\n\t ") {
		return "", "", fmt.Errorf("%w: invalid ID key", ErrMalformedCommand)
	}

	if valueToken.kind == tokenAtom && strings.EqualFold(valueToken.value, "NIL") {
		return key, "", nil
	}

	if !tokenIsStringLike(valueToken) {
		return "", "", fmt.Errorf("%w: invalid ID value", ErrMalformedCommand)
	}

	value, ok := normalizeClientIDValue(valueToken.value)
	if !ok {
		return "", "", fmt.Errorf("%w: invalid ID value", ErrMalformedCommand)
	}

	return key, value, nil
}

// normalizeClientIDValue trims and validates an ID value before auth context use.
func normalizeClientIDValue(value string) (string, bool) {
	normalized := strings.TrimSpace(value)
	if normalized == "" || len(normalized) > maxIDValueBytes {
		return "", false
	}

	for index := 0; index < len(normalized); index++ {
		char := normalized[index]
		if char < 0x20 || char == 0x7f {
			return "", false
		}
	}

	return strings.Join(strings.Fields(normalized), " "), true
}

// selectedClientIDKey reports whether an ID key can populate Nauthilus client_id.
func selectedClientIDKey(key string) bool {
	for _, selected := range [...]string{clientIDKeyUnderscore, clientIDKeyHyphen, clientIDKeyName} {
		if key == selected {
			return true
		}
	}

	return false
}
