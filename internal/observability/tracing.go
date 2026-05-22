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

package observability

// TraceBoundary identifies a prepared OpenTelemetry span boundary.
type TraceBoundary string

const (
	// TraceBoundaryBackendConnect wraps the outbound backend connection.
	TraceBoundaryBackendConnect TraceBoundary = "backend_connect"
	// TraceBoundaryBackendSelect wraps director-owned backend selection.
	TraceBoundaryBackendSelect TraceBoundary = "backend_select"
	// TraceBoundaryIMAPPreAuth wraps IMAP pre-auth protocol handling.
	TraceBoundaryIMAPPreAuth TraceBoundary = "imap_pre_auth"
	// TraceBoundaryLMTPTransaction wraps LMTP recipient routing transactions.
	TraceBoundaryLMTPTransaction TraceBoundary = "lmtp_transaction"
	// TraceBoundaryNauthilusAuth wraps Nauthilus authentication requests.
	TraceBoundaryNauthilusAuth TraceBoundary = "nauthilus_auth"
	// TraceBoundaryPOP3PreAuth wraps POP3 pre-auth protocol handling.
	TraceBoundaryPOP3PreAuth TraceBoundary = "pop3_pre_auth"
	// TraceBoundaryProxyPipe wraps the transparent proxy lifetime.
	TraceBoundaryProxyPipe TraceBoundary = "proxy_pipe"
	// TraceBoundaryRESTRequest wraps REST control API requests.
	TraceBoundaryRESTRequest TraceBoundary = "rest_request"
	// TraceBoundaryRoutingResolve wraps logical routing fact resolution.
	TraceBoundaryRoutingResolve TraceBoundary = "routing_resolve"
	// TraceBoundarySession wraps accepted frontend sessions.
	TraceBoundarySession TraceBoundary = "session"
	// TraceBoundarySievePreAuth wraps ManageSieve pre-auth protocol handling.
	TraceBoundarySievePreAuth TraceBoundary = "sieve_pre_auth"
)

const (
	traceSpanBackendConnect  = "nauthilus_director.backend.connect"
	traceSpanBackendSelect   = "nauthilus_director.backend.select"
	traceSpanIMAPPreAuth     = "nauthilus_director.imap.pre_auth"
	traceSpanLMTPTransaction = "nauthilus_director.lmtp.transaction"
	traceSpanNauthilusAuth   = "nauthilus_director.nauthilus.auth"
	traceSpanPOP3PreAuth     = "nauthilus_director.pop3.pre_auth"
	traceSpanProxyPipe       = "nauthilus_director.proxy.pipe"
	traceSpanRESTRequest     = "nauthilus_director.rest.request"
	traceSpanRoutingResolve  = "nauthilus_director.routing.resolve"
	traceSpanSession         = "nauthilus_director.session"
	traceSpanSievePreAuth    = "nauthilus_director.sieve.pre_auth"
)

var spanNames = map[TraceBoundary]string{
	TraceBoundaryBackendConnect:  traceSpanBackendConnect,
	TraceBoundaryBackendSelect:   traceSpanBackendSelect,
	TraceBoundaryIMAPPreAuth:     traceSpanIMAPPreAuth,
	TraceBoundaryLMTPTransaction: traceSpanLMTPTransaction,
	TraceBoundaryNauthilusAuth:   traceSpanNauthilusAuth,
	TraceBoundaryPOP3PreAuth:     traceSpanPOP3PreAuth,
	TraceBoundaryProxyPipe:       traceSpanProxyPipe,
	TraceBoundaryRESTRequest:     traceSpanRESTRequest,
	TraceBoundaryRoutingResolve:  traceSpanRoutingResolve,
	TraceBoundarySession:         traceSpanSession,
	TraceBoundarySievePreAuth:    traceSpanSievePreAuth,
}

// SpanName returns the prepared span name for a known boundary.
func SpanName(boundary TraceBoundary) (string, bool) {
	name, ok := spanNames[boundary]

	return name, ok
}

// PreparedSpanNames returns all prepared span names in deterministic order.
func PreparedSpanNames() []string {
	boundaries := []TraceBoundary{
		TraceBoundaryBackendConnect,
		TraceBoundaryBackendSelect,
		TraceBoundaryIMAPPreAuth,
		TraceBoundaryLMTPTransaction,
		TraceBoundaryNauthilusAuth,
		TraceBoundaryPOP3PreAuth,
		TraceBoundaryProxyPipe,
		TraceBoundaryRESTRequest,
		TraceBoundaryRoutingResolve,
		TraceBoundarySession,
		TraceBoundarySievePreAuth,
	}

	names := make([]string, 0, len(boundaries))
	for _, boundary := range boundaries {
		names = append(names, spanNames[boundary])
	}

	return names
}
