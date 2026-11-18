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
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
)

// maxJSONNestingDepth bounds the duplicate-name scan; deeper input is treated as ambiguous.
const maxJSONNestingDepth = 64

// routeLookupForbiddenKeyFragments are canonical key fragments that imply credentials, SASL or
// bearer material, scripts or mailbox data. Route lookup is a routing diagnostic and never needs them.
var routeLookupForbiddenKeyFragments = [...]string{
	"auth",
	"bearer",
	"credential",
	"mailboxcontent",
	"mailboxdata",
	"mailboxmessage",
	"messagecontent",
	"messagedata",
	"messagenum",
	"messagenumber",
	"messagesize",
	"msgcontent",
	"msgnum",
	"msgsize",
	"password",
	"passwd",
	"sasl",
	"script",
	"secret",
	"token",
	"uidl",
}

// RouteLookupInputCarriesForbiddenKeys reports whether a route lookup body names credential,
// SASL, bearer, script or mailbox material in any object key. Values are never inspected, so
// the check cannot leak them. Undecodable input is left to the strict decoder.
func RouteLookupInputCarriesForbiddenKeys(body []byte) bool {
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return false
	}

	return containsForbiddenRouteLookupKey(value)
}

// containsForbiddenRouteLookupKey walks decoded JSON looking only at object keys.
func containsForbiddenRouteLookupKey(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			if isForbiddenRouteLookupKey(key) || containsForbiddenRouteLookupKey(nested) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(typed, containsForbiddenRouteLookupKey)
	}

	return false
}

// isForbiddenRouteLookupKey reports whether a JSON key appears to carry forbidden material.
func isForbiddenRouteLookupKey(key string) bool {
	normalized := canonicalRouteLookupKey(key)
	for _, fragment := range routeLookupForbiddenKeyFragments {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}

	return normalized == "mailbox"
}

// canonicalRouteLookupKey removes separators and case before marker matching.
func canonicalRouteLookupKey(key string) string {
	var builder strings.Builder

	for _, r := range strings.ToLower(strings.TrimSpace(key)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
		}
	}

	return builder.String()
}

// HasDuplicateNames reports whether any JSON object in data repeats a member name, nests deeper
// than the scan bound, or cannot be tokenized. Parsers disagree on which duplicate wins, so a
// transport that inspects a body before another parser must refuse duplicates outright.
func HasDuplicateNames(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	duplicate, err := scanJSONValue(decoder, 0)

	return duplicate || err != nil
}

// scanJSONValue consumes one JSON value and reports a duplicate member name inside it.
func scanJSONValue(decoder *json.Decoder, depth int) (bool, error) {
	if depth > maxJSONNestingDepth {
		return true, nil
	}

	token, err := decoder.Token()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return false, io.ErrUnexpectedEOF
		}

		return false, err
	}

	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return false, nil
	}

	switch delimiter {
	case '{':
		return scanJSONObject(decoder, depth)
	case '[':
		return scanJSONArray(decoder, depth)
	default:
		return false, errors.New("unexpected JSON delimiter")
	}
}

// scanJSONObject consumes object members after '{' and reports a repeated name.
func scanJSONObject(decoder *json.Decoder, depth int) (bool, error) {
	seen := map[string]struct{}{}

	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return false, err
		}

		name, ok := token.(string)
		if !ok {
			return false, errors.New("JSON object member name is not a string")
		}

		if _, repeated := seen[name]; repeated {
			return true, nil
		}

		seen[name] = struct{}{}

		if duplicate, scanErr := scanJSONValue(decoder, depth+1); duplicate || scanErr != nil {
			return duplicate, scanErr
		}
	}

	_, err := decoder.Token()

	return false, err
}

// scanJSONArray consumes array elements after '[' and reports a duplicate inside any element.
func scanJSONArray(decoder *json.Decoder, depth int) (bool, error) {
	for decoder.More() {
		if duplicate, err := scanJSONValue(decoder, depth+1); duplicate || err != nil {
			return duplicate, err
		}
	}

	_, err := decoder.Token()

	return false, err
}
