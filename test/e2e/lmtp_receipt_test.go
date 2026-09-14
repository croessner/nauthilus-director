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

//nolint:funlen,wsl_v5 // Keep the public socket transcript and its case matrix visible.
package e2e

import (
	"fmt"
	"strings"
	"testing"

	lmtpbackend "github.com/croessner/nauthilus-director/test/e2e/fakes/lmtp_backend"
)

const eightBitMIME = "8BITMIME"
const chunkingCapability = "CHUNKING"

// TestServerBinaryLMTPCapabilityRefresh proves health changes affect existing listeners.
func TestServerBinaryLMTPCapabilityRefresh(t *testing.T) {
	fixture := startLMTPBackendChunkingFixture(t, lmtpBackendChunkingFixtureOptions{
		BackendCapabilities: []string{chunkingCapability, eightBitMIME},
		ExtraCapabilities:   []string{eightBitMIME},
	})
	client := authenticatedLMTPClient(t, fixture.address)
	defer client.Close()
	for _, available := range []bool{false, true, false} {
		var capabilities []string
		if available {
			capabilities = []string{chunkingCapability, eightBitMIME}
		}
		publishHealthyLMTPBackends(t, fixture.redis, []string{e2eLMTPBackendAID, e2eLMTPBackendBID}, capabilities...)
		client.WriteLine("LHLO refresh.example.test")
		lines := client.ReadResponse()
		for _, capability := range []string{chunkingCapability, eightBitMIME} {
			if lmtpCapabilityPresent(lines, capability) != available {
				t.Fatalf("capability %s available=%t after health change, replies=%v", capability, available, lines)
			}
		}
	}
}

// TestServerBinaryLMTPNativeReceipt proves opt-in receipts survive real DATA and BDAT sockets.
func TestServerBinaryLMTPNativeReceipt(t *testing.T) {
	const receipt = "aakmHZ8hqGpxPgkAdY0skA:1 Saved"
	for _, enabled := range []bool{false, true} {
		for _, chunking := range []bool{false, true} {
			t.Run(fmt.Sprintf("enabled=%t/chunking=%t", enabled, chunking), func(t *testing.T) {
				capabilities := []string{eightBitMIME}
				if chunking {
					capabilities = append(capabilities, chunkingCapability)
				}
				fixture := startLMTPBackendChunkingFixture(t, lmtpBackendChunkingFixtureOptions{
					PreserveBackendDeliveryReceipt: enabled,
					BackendCapabilities:            capabilities,
					HealthCapabilities:             capabilities,
					ExtraCapabilities:              []string{eightBitMIME},
					FinalStatus: map[string]lmtpbackend.Status{
						lmtpPath(e2eLMTPRecipientA): {Code: "250", Enhanced: "2.0.0", Text: "<private@example.test> " + receipt},
					},
				})
				client := authenticatedLMTPClient(t, fixture.address)
				defer client.Close()
				client.WriteLine("MAIL FROM:<sender@example.test> BODY=8BITMIME")
				client.ExpectLine("250 2.0.0 Sender accepted\r\n")
				client.WriteLine("RCPT TO:<" + e2eLMTPRecipientA + ">")
				client.ExpectLine("250 2.0.0 Recipient accepted\r\n")
				body := "Subject: receipt proof\r\n\r\nGrüße\r\n"
				if chunking {
					client.WriteLine(fmt.Sprintf("BDAT %d LAST", len(body)))
					client.WriteRaw(body)
				} else {
					client.WriteLine("DATA")
					client.ExpectLine("354 2.0.0 End data with <CR><LF>.<CR><LF>\r\n")
					client.WriteRaw(body + ".\r\n")
				}
				want := "250 2.0.0 Message accepted\r\n"
				if enabled {
					want = "250 2.0.0 " + receipt + "\r\n"
				}
				client.ExpectLine(want)
				if strings.Contains(fixture.process.output.String(), receipt) {
					t.Fatal("native receipt leaked into process logs")
				}
			})
		}
	}
}
