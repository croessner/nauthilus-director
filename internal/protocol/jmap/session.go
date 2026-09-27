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

package jmap

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// maxSessionInspectionBytes bounds how much of a session resource is copied for the URL check.
const maxSessionInspectionBytes = 256 * 1024

// sessionURLFields lists the JMAP session resource properties that carry service URLs (RFC 8620 2).
var sessionURLFields = []string{"apiUrl", "downloadUrl", "uploadUrl", "eventSourceUrl"}

// inspectSessionResource tees the streamed session resource and checks its URLs once it is read.
//
// The body is still streamed to the client unchanged; the director only observes a bounded copy
// and never rewrites the session resource.
func (h *Handler) inspectSessionResource(response *http.Response) {
	origin := publicOrigin(h.config.Settings.PublicBaseURL)
	if origin == "" || response.Body == nil {
		return
	}

	ctx := context.WithoutCancel(response.Request.Context())
	response.Body = &sessionInspectingBody{
		body: response.Body,
		onComplete: func(document []byte) {
			for _, field := range mismatchedSessionURLs(document, origin) {
				h.recordSessionURLMismatch(ctx, field)
			}
		},
	}
}

// publicOrigin returns scheme://host of the configured public base URL.
func publicOrigin(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}

	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host)
}

// mismatchedSessionURLs returns the session URL properties whose origin differs from origin.
func mismatchedSessionURLs(document []byte, origin string) []string {
	var session map[string]json.RawMessage
	if err := json.Unmarshal(document, &session); err != nil {
		return nil
	}

	var mismatched []string

	for _, field := range sessionURLFields {
		raw, ok := session[field]
		if !ok {
			continue
		}

		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			continue
		}

		if !sameOrigin(value, origin) {
			mismatched = append(mismatched, field)
		}
	}

	return mismatched
}

// sameOrigin compares the scheme and authority of a URL or URL template with origin.
func sameOrigin(value string, origin string) bool {
	before, after, ok := strings.Cut(value, "://")
	if !ok {
		return false
	}

	rest := after
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		rest = rest[:slash]
	}

	return strings.ToLower(before)+"://"+strings.ToLower(rest) == origin
}

// sessionInspectingBody copies up to maxSessionInspectionBytes while the proxy streams the body.
type sessionInspectingBody struct {
	body       io.ReadCloser
	buffer     bytes.Buffer
	overflow   bool
	once       sync.Once
	onComplete func([]byte)
}

// Read streams the backend body and keeps a bounded copy.
func (b *sessionInspectingBody) Read(payload []byte) (int, error) {
	n, err := b.body.Read(payload)
	if n > 0 && !b.overflow {
		if b.buffer.Len()+n > maxSessionInspectionBytes {
			b.overflow = true
			b.buffer.Reset()
		} else {
			_, _ = b.buffer.Write(payload[:n])
		}
	}

	if err == io.EOF {
		b.complete()
	}

	return n, err
}

// Close closes the backend body.
func (b *sessionInspectingBody) Close() error {
	return b.body.Close()
}

// complete runs the URL check once on a fully read, bounded body.
func (b *sessionInspectingBody) complete() {
	b.once.Do(func() {
		if !b.overflow && b.onComplete != nil {
			b.onComplete(b.buffer.Bytes())
		}
	})
}
