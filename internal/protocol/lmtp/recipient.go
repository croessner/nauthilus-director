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
	"errors"
	"fmt"
	"strings"
)

const recipientRouteSeparator = ":"

var (
	// ErrMalformedRecipient reports an LMTP recipient path that cannot be used safely.
	ErrMalformedRecipient = errors.New("lmtp: malformed recipient")
)

// RecipientPath keeps the backend wire path separate from the lookup identity.
type RecipientPath struct {
	WirePath   string
	LookupName string
}

// ParseRecipientCommand parses a frontend RCPT command into wire and lookup forms.
func ParseRecipientCommand(command frontendCommand) (RecipientPath, error) {
	return ParseRecipientPath(command.args, "TO:")
}

// ParseRecipientInput parses operator recipient input with or without the RCPT prefix.
func ParseRecipientInput(value string) (RecipientPath, error) {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToUpper(trimmed), "TO:") {
		return ParseRecipientPath(trimmed, "TO:")
	}

	if strings.HasPrefix(trimmed, "<") {
		return ParseRecipientPath("TO:"+trimmed, "TO:")
	}

	return ParseRecipientPath("TO:<"+trimmed+">", "TO:")
}

// ParseRecipientPath parses an LMTP path command argument without leaking values in errors.
func ParseRecipientPath(args string, prefix string) (RecipientPath, error) {
	path, err := parseEnvelopePath(args, prefix)
	if err != nil {
		return RecipientPath{}, err
	}

	lookup, err := lookupNameFromWirePath(path)
	if err != nil {
		return RecipientPath{}, err
	}

	return RecipientPath{
		WirePath:   path,
		LookupName: lookup,
	}, nil
}

// parseEnvelopePath extracts the bracketed LMTP path and rejects trailing parameters.
func parseEnvelopePath(args string, prefix string) (string, error) {
	args = strings.TrimSpace(args)
	if args == "" {
		return "", fmt.Errorf("%w: missing path", ErrMalformedRecipient)
	}

	expected := strings.ToUpper(prefix)
	if !strings.HasPrefix(strings.ToUpper(args), expected) {
		return "", fmt.Errorf("%w: missing path prefix", ErrMalformedRecipient)
	}

	remaining := strings.TrimSpace(args[len(prefix):])
	if remaining == "" || !strings.HasPrefix(remaining, "<") {
		return "", fmt.Errorf("%w: invalid path", ErrMalformedRecipient)
	}

	closeIndex := strings.Index(remaining, ">")
	if closeIndex <= 0 {
		return "", fmt.Errorf("%w: invalid path", ErrMalformedRecipient)
	}

	path := remaining[:closeIndex+1]
	if strings.TrimSpace(remaining[closeIndex+1:]) != "" {
		return "", fmt.Errorf("%w: unexpected path parameters", ErrMalformedRecipient)
	}

	return path, nil
}

// lookupNameFromWirePath removes LMTP path syntax and applies conservative domain folding.
func lookupNameFromWirePath(path string) (string, error) {
	if len(path) < 3 || path[0] != '<' || path[len(path)-1] != '>' {
		return "", fmt.Errorf("%w: invalid path", ErrMalformedRecipient)
	}

	address := strings.TrimSpace(path[1 : len(path)-1])
	if address == "" || strings.ContainsAny(address, " \t\r\n<>") {
		return "", fmt.Errorf("%w: invalid address", ErrMalformedRecipient)
	}

	address = stripSourceRoute(address)
	if address == "" || strings.ContainsAny(address, " \t\r\n<>") {
		return "", fmt.Errorf("%w: invalid address", ErrMalformedRecipient)
	}

	return lowercaseASCIIDomain(address), nil
}

// stripSourceRoute removes obsolete route syntax while leaving the mailbox value intact.
func stripSourceRoute(value string) string {
	if !strings.HasPrefix(value, "@") {
		return value
	}

	separator := strings.LastIndex(value, recipientRouteSeparator)
	if separator < 0 || separator == len(value)-1 {
		return value
	}

	return value[separator+1:]
}

// lowercaseASCIIDomain lowercases only ASCII letters after the final at-sign.
func lowercaseASCIIDomain(value string) string {
	at := strings.LastIndex(value, "@")
	if at < 0 || at == len(value)-1 {
		return value
	}

	local := value[:at+1]

	domain := []byte(value[at+1:])
	for index, current := range domain {
		if current >= 'A' && current <= 'Z' {
			domain[index] = current + ('a' - 'A')
		}
	}

	return local + string(domain)
}
