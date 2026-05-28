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
	"testing"
)

// TestParseRecipientPathPreservesWirePathAndBuildsLookupName verifies safe path splitting.
func TestParseRecipientPathPreservesWirePathAndBuildsLookupName(t *testing.T) {
	for _, test := range []struct {
		name       string
		input      string
		wirePath   string
		lookupName string
	}{
		{
			name:       "ascii domain folding",
			input:      "TO:<User+Tag@EXAMPLE.COM>",
			wirePath:   "<User+Tag@EXAMPLE.COM>",
			lookupName: "User+Tag@example.com",
		},
		{
			name:       "source route stripped",
			input:      "TO:<@mx.example,@mx2.example:Local@Example.COM>",
			wirePath:   "<@mx.example,@mx2.example:Local@Example.COM>",
			lookupName: testRecipientLookup,
		},
		{
			name:       "unicode left untouched except ascii domain letters",
			input:      "TO:<Müller@DÖMAIN.Example>",
			wirePath:   "<Müller@DÖMAIN.Example>",
			lookupName: "Müller@dÖmain.example",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			recipient, err := ParseRecipientPath(test.input, "TO:")
			if err != nil {
				t.Fatalf("ParseRecipientPath returned error: %v", err)
			}

			if recipient.WirePath != test.wirePath {
				t.Fatalf("wire path = %q, want %q", recipient.WirePath, test.wirePath)
			}

			if recipient.LookupName != test.lookupName {
				t.Fatalf("lookup name = %q, want %q", recipient.LookupName, test.lookupName)
			}
		})
	}
}

// TestParseRecipientInputAcceptsOperatorForms verifies route lookup input convenience forms.
func TestParseRecipientInputAcceptsOperatorForms(t *testing.T) {
	for _, input := range []string{
		"Recipient@EXAMPLE.TEST",
		"<Recipient@EXAMPLE.TEST>",
		"TO:<Recipient@EXAMPLE.TEST>",
	} {
		t.Run(input, func(t *testing.T) {
			recipient, err := ParseRecipientInput(input)
			if err != nil {
				t.Fatalf("ParseRecipientInput returned error: %v", err)
			}

			if recipient.LookupName != "Recipient@example.test" {
				t.Fatalf("lookup name = %q, want Recipient@example.test", recipient.LookupName)
			}
		})
	}
}

// TestParseRecipientPathRejectsMalformedInput verifies fail-closed recipient syntax.
func TestParseRecipientPathRejectsMalformedInput(t *testing.T) {
	for _, input := range []string{
		"",
		"FROM:<user@example.test>",
		"TO:user@example.test",
		"TO:<>",
		"TO:<user example.test>",
		"TO:<user@example.test> NOTIFY=SUCCESS",
		"TO:<user@example.test",
		"TO:<user@example.test>>",
	} {
		t.Run(input, func(t *testing.T) {
			_, err := ParseRecipientPath(input, "TO:")
			if !errors.Is(err, ErrMalformedRecipient) {
				t.Fatalf("ParseRecipientPath error = %v, want malformed recipient", err)
			}
		})
	}
}
