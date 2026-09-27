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
	"net/http"
	"path"
	"slices"
	"strings"

	"github.com/croessner/nauthilus-director/internal/config"
)

// endpoint is the bounded classification of one request path; it doubles as a metric label value.
type endpoint string

const (
	endpointSession     endpoint = "session"
	endpointAPI         endpoint = "api"
	endpointUpload      endpoint = "upload"
	endpointDownload    endpoint = "download"
	endpointEventSource endpoint = "eventsource"
	endpointHealth      endpoint = "health"
	endpointUnknown     endpoint = "unknown"

	pathSession            = "/.well-known/jmap"
	pathAPI                = "/jmap/api"
	pathUploadPrefix       = "/jmap/upload/"
	pathDownloadPrefix     = "/jmap/download/"
	pathEventSource        = "/jmap/eventsource"
	pathTrailingSlash      = "/"
	allowHeader            = "Allow"
	allowedMethodSeparator = ", "
)

// classifyEndpoint maps a request path onto the proxied JMAP surface or the local health path.
//
// Paths that are not in canonical form (dot segments, duplicate slashes) are never proxied, so a
// backend that cleans paths cannot be tricked into serving a path outside the allowlist.
func classifyEndpoint(requestPath string, healthPath string) endpoint {
	if !canonicalPath(requestPath) {
		return endpointUnknown
	}

	switch {
	case healthPath != "" && requestPath == healthPath:
		return endpointHealth
	case requestPath == pathSession:
		return endpointSession
	case requestPath == pathAPI || requestPath == pathAPI+pathTrailingSlash:
		return endpointAPI
	case strings.HasPrefix(requestPath, pathUploadPrefix):
		return endpointUpload
	case strings.HasPrefix(requestPath, pathDownloadPrefix) && len(requestPath) > len(pathDownloadPrefix):
		return endpointDownload
	case requestPath == pathEventSource || requestPath == pathEventSource+pathTrailingSlash:
		return endpointEventSource
	default:
		return endpointUnknown
	}
}

// canonicalPath reports whether the path equals its cleaned form, keeping one trailing slash.
func canonicalPath(requestPath string) bool {
	if !strings.HasPrefix(requestPath, "/") {
		return false
	}

	cleaned := path.Clean(requestPath)
	if strings.HasSuffix(requestPath, pathTrailingSlash) && cleaned != pathTrailingSlash {
		cleaned += pathTrailingSlash
	}

	return cleaned == requestPath
}

// allowedMethods lists the HTTP methods accepted on one endpoint.
func (e endpoint) allowedMethods() []string {
	switch e {
	case endpointSession, endpointDownload, endpointHealth:
		return []string{http.MethodGet, http.MethodHead}
	case endpointAPI, endpointUpload:
		return []string{http.MethodPost}
	case endpointEventSource:
		return []string{http.MethodGet}
	default:
		return nil
	}
}

// allowsMethod reports whether the endpoint accepts the request method.
func (e endpoint) allowsMethod(method string) bool {
	return slices.Contains(e.allowedMethods(), method)
}

// allowHeaderValue renders the Allow header for a 405 response.
func (e endpoint) allowHeaderValue() string {
	return strings.Join(e.allowedMethods(), allowedMethodSeparator)
}

// bodyLimit returns the request body bound for the endpoint.
func (e endpoint) bodyLimit(limits config.JMAPLimitsConfig) int64 {
	if e == endpointUpload {
		return limits.MaxUploadBodyBytes
	}

	return limits.MaxRequestBodyBytes
}
