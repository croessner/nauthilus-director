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

package greeting

import "testing"

const (
	testDisplayName     = "Norbert"
	testDisplayIdentity = "Norbert v1.2.3"
)

// TestDefaultDisclosureIncludesOnlySieve verifies compatible default process-version behavior.
func TestDefaultDisclosureIncludesOnlySieve(t *testing.T) {
	policy := mustPolicy(t, "nauthilus-director", "v1.2.3", DisclosureDefault)

	tests := []struct {
		name     string
		protocol string
		want     bool
	}{
		{name: "imap", protocol: ProtocolIMAP, want: false},
		{name: "lmtp", protocol: ProtocolLMTP, want: false},
		{name: "sieve", protocol: ProtocolSieve, want: true},
		{name: "pop3", protocol: ProtocolPOP3, want: false},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if got := policy.IncludeSoftwareVersion(testCase.protocol); got != testCase.want {
				t.Fatalf("IncludeSoftwareVersion(%q) = %v, want %v", testCase.protocol, got, testCase.want)
			}
		})
	}
}

// TestIncludeDisclosureIncludesKnownProtocols verifies explicit disclosure for every frontend protocol.
func TestIncludeDisclosureIncludesKnownProtocols(t *testing.T) {
	policy := mustPolicy(t, "nauthilus-director", "v1.2.3", DisclosureInclude)

	for _, protocol := range []string{ProtocolIMAP, ProtocolLMTP, ProtocolSieve, ProtocolPOP3} {
		t.Run(protocol, func(t *testing.T) {
			if !policy.IncludeSoftwareVersion(protocol) {
				t.Fatalf("IncludeSoftwareVersion(%q) = false, want true", protocol)
			}
		})
	}
}

// TestSuppressDisclosureSuppressesKnownProtocols verifies explicit suppression for every frontend protocol.
func TestSuppressDisclosureSuppressesKnownProtocols(t *testing.T) {
	policy := mustPolicy(t, "nauthilus-director", "v1.2.3", DisclosureSuppress)

	for _, protocol := range []string{ProtocolIMAP, ProtocolLMTP, ProtocolSieve, ProtocolPOP3} {
		t.Run(protocol, func(t *testing.T) {
			if policy.IncludeSoftwareVersion(protocol) {
				t.Fatalf("IncludeSoftwareVersion(%q) = true, want false", protocol)
			}
		})
	}
}

// TestBlankProcessVersionSuppressesEveryMode verifies that no policy publishes an empty version.
func TestBlankProcessVersionSuppressesEveryMode(t *testing.T) {
	for _, disclosure := range []SoftwareVersionDisclosure{DisclosureDefault, DisclosureInclude, DisclosureSuppress} {
		t.Run(string(disclosure), func(t *testing.T) {
			policy := mustPolicy(t, "nauthilus-director", " \n\t ", disclosure)
			for _, protocol := range []string{ProtocolIMAP, ProtocolLMTP, ProtocolSieve, ProtocolPOP3} {
				if policy.IncludeSoftwareVersion(protocol) {
					t.Fatalf("IncludeSoftwareVersion(%q) under %q = true, want false", protocol, disclosure)
				}

				if got := policy.DisplayIdentity(protocol); got != "nauthilus-director" {
					t.Fatalf("DisplayIdentity(%q) = %q, want display name only", protocol, got)
				}
			}
		})
	}
}

// TestProcessVersionWhitespaceIsFolded verifies that version text cannot create multiline identities.
func TestProcessVersionWhitespaceIsFolded(t *testing.T) {
	policy := mustPolicy(t, "nauthilus-director", "  v1.2.3\nbuild\t7\r\n ", DisclosureInclude)

	if got := policy.SoftwareVersion(); got != "v1.2.3 build 7" {
		t.Fatalf("SoftwareVersion() = %q, want folded version", got)
	}

	if got := policy.DisplayIdentity(ProtocolIMAP); got != "nauthilus-director v1.2.3 build 7" {
		t.Fatalf("DisplayIdentity(imap) = %q, want folded version identity", got)
	}
}

// TestDisplayNameFallbackConstructor verifies blank display names only fall back through the fallback constructor.
func TestDisplayNameFallbackConstructor(t *testing.T) {
	if _, err := NewDisplayName(" \t\n "); err == nil {
		t.Fatal("NewDisplayName accepted a blank display name")
	}

	displayName, err := NewDisplayNameOrDefault(" \t\n ")
	if err != nil {
		t.Fatalf("NewDisplayNameOrDefault rejected blank display name: %v", err)
	}

	if got := displayName.String(); got != DefaultDisplayName {
		t.Fatalf("fallback display name = %q, want %q", got, DefaultDisplayName)
	}
}

// TestDisplayIdentityUsesDisplayNameAndDisclosure verifies custom display identity composition.
func TestDisplayIdentityUsesDisplayNameAndDisclosure(t *testing.T) {
	tests := []struct {
		name       string
		disclosure SoftwareVersionDisclosure
		protocol   string
		want       string
	}{
		{name: "imap default", disclosure: DisclosureDefault, protocol: ProtocolIMAP, want: testDisplayName},
		{name: "sieve default", disclosure: DisclosureDefault, protocol: ProtocolSieve, want: testDisplayIdentity},
		{name: "imap include", disclosure: DisclosureInclude, protocol: ProtocolIMAP, want: testDisplayIdentity},
		{name: "lmtp include", disclosure: DisclosureInclude, protocol: ProtocolLMTP, want: testDisplayIdentity},
		{name: "sieve include", disclosure: DisclosureInclude, protocol: ProtocolSieve, want: testDisplayIdentity},
		{name: "pop3 include", disclosure: DisclosureInclude, protocol: ProtocolPOP3, want: testDisplayIdentity},
		{name: "sieve suppress", disclosure: DisclosureSuppress, protocol: ProtocolSieve, want: testDisplayName},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			policy := mustPolicy(t, testDisplayName, "v1.2.3", testCase.disclosure)
			if got := policy.DisplayIdentity(testCase.protocol); got != testCase.want {
				t.Fatalf("DisplayIdentity(%q) = %q, want %q", testCase.protocol, got, testCase.want)
			}
		})
	}
}

// TestUnknownProtocolDoesNotDiscloseVersion verifies service-name variants and unknown names fail closed.
func TestUnknownProtocolDoesNotDiscloseVersion(t *testing.T) {
	policy := mustPolicy(t, testDisplayName, "v1.2.3", DisclosureInclude)

	for _, protocol := range []string{"", "unknown", "imap4", "imaps", "lmtps", "managesieve", "sieves", "pop3s"} {
		t.Run(protocol, func(t *testing.T) {
			if policy.IncludeSoftwareVersion(protocol) {
				t.Fatalf("IncludeSoftwareVersion(%q) = true, want false", protocol)
			}

			if got := policy.DisplayIdentity(protocol); got != testDisplayName {
				t.Fatalf("DisplayIdentity(%q) = %q, want display name only", protocol, got)
			}
		})
	}
}

// TestSoftwareVersionDisclosureNormalization verifies policy text normalization and unknown rejection.
func TestSoftwareVersionDisclosureNormalization(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  SoftwareVersionDisclosure
	}{
		{name: "blank defaults", value: "", want: DisclosureDefault},
		{name: "default", value: " DEFAULT ", want: DisclosureDefault},
		{name: "include", value: " Include ", want: DisclosureInclude},
		{name: "suppress", value: " Suppress ", want: DisclosureSuppress},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := NewSoftwareVersionDisclosure(testCase.value)
			if err != nil {
				t.Fatalf("NewSoftwareVersionDisclosure(%q) rejected value: %v", testCase.value, err)
			}

			if got != testCase.want {
				t.Fatalf("NewSoftwareVersionDisclosure(%q) = %q, want %q", testCase.value, got, testCase.want)
			}
		})
	}

	if _, err := NewSoftwareVersionDisclosure("publish"); err == nil {
		t.Fatal("NewSoftwareVersionDisclosure accepted an unknown disclosure value")
	}
}

// mustPolicy returns a policy for test cases that expect construction to succeed.
func mustPolicy(
	t *testing.T,
	displayNameValue string,
	processVersion string,
	disclosure SoftwareVersionDisclosure,
) Policy {
	t.Helper()

	displayName := mustDisplayName(t, displayNameValue)

	policy, err := NewPolicy(displayName, processVersion, disclosure)
	if err != nil {
		t.Fatalf("NewPolicy rejected test policy: %v", err)
	}

	return policy
}

// mustDisplayName returns a display name for test cases that expect construction to succeed.
func mustDisplayName(t *testing.T, value string) DisplayName {
	t.Helper()

	displayName, err := NewDisplayName(value)
	if err != nil {
		t.Fatalf("NewDisplayName(%q) rejected test display name: %v", value, err)
	}

	return displayName
}
