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

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

const (
	metricLabelBackendPool     = "backend_pool"
	metricLabelDirection       = "direction"
	metricLabelListener        = "listener"
	metricLabelMaintenanceMode = "maintenance_mode"
	metricLabelMechanism       = "mechanism"
	metricLabelMethod          = "method"
	metricLabelOperation       = "operation"
	metricLabelProtocol        = "protocol"
	metricLabelReasonClass     = "reason_class"
	metricLabelRedisMode       = "redis_mode"
	metricLabelResult          = "result"
	metricLabelRoute           = "route"
	metricLabelService         = "service"
	metricLabelShardTag        = "shard_tag"
	metricLabelStatusClass     = "status_class"
	metricLabelTLSMode         = "tls_mode"
	metricLabelTransport       = "transport"

	fieldBackendIdentifier = "backend_identifier"
	fieldBearer            = "bearer"
	fieldClientIP          = "client_ip"
	fieldCredential        = "credential"
	fieldOAuth             = "oauth"
	fieldPasswd            = "passwd"
	fieldPassword          = "password"
	fieldPrivateKey        = "private_key"
	fieldRawError          = "raw_error"
	fieldRecipient         = "recipient"
	fieldRemoteAddr        = "remote_addr"
	fieldRequestID         = "request_id"
	fieldSASL              = "sasl"
	fieldSASLBlob          = "sasl_blob"
	fieldSecret            = "secret"
	fieldSessionID         = "session_id"
	fieldToken             = "token"
	fieldTraceID           = "trace_id"
	fieldUserHash          = "user_hash"
	fieldUsername          = "username"

	reasonClassOK                     = "ok"
	reasonClassOther                  = "other"
	reasonClassRuntimeHardMaintenance = "runtime_hard_maintenance"
	reasonClassRuntimeOut             = "runtime_out"
	reasonClassStaticHardMaintenance  = "static_hard_maintenance"
	reasonClassStaticSoftMaintenance  = "static_soft_maintenance"
)

var allowedMetricLabels = map[string]struct{}{
	metricLabelBackendPool:     {},
	metricLabelDirection:       {},
	metricLabelListener:        {},
	metricLabelMaintenanceMode: {},
	metricLabelMechanism:       {},
	metricLabelMethod:          {},
	metricLabelOperation:       {},
	metricLabelProtocol:        {},
	metricLabelReasonClass:     {},
	metricLabelRedisMode:       {},
	metricLabelResult:          {},
	metricLabelRoute:           {},
	metricLabelService:         {},
	metricLabelShardTag:        {},
	metricLabelStatusClass:     {},
	metricLabelTLSMode:         {},
	metricLabelTransport:       {},
}

var forbiddenMetricLabels = map[string]struct{}{
	fieldBackendIdentifier: {},
	fieldClientIP:          {},
	fieldPassword:          {},
	fieldRawError:          {},
	fieldRecipient:         {},
	fieldRemoteAddr:        {},
	fieldRequestID:         {},
	fieldSASLBlob:          {},
	fieldSessionID:         {},
	fieldToken:             {},
	fieldTraceID:           {},
	fieldUserHash:          {},
	fieldUsername:          {},
}

var secretFieldFragments = []string{
	fieldBearer,
	fieldCredential,
	fieldOAuth,
	fieldPasswd,
	fieldPassword,
	fieldPrivateKey,
	fieldSASL,
	fieldSecret,
	fieldToken,
}

var allowedReasonClasses = map[string]struct{}{
	"active_affinity":                 {},
	"ambiguous_state":                 {},
	"attach_retry":                    {},
	"backend_connect":                 {},
	"backend_runtime":                 {},
	"cleared":                         {},
	"closed":                          {},
	"config":                          {},
	"conflict":                        {},
	"drain":                           {},
	"health":                          {},
	"healthy":                         {},
	"hard_maintenance":                {},
	"initial_placement":               {},
	"invalid_request":                 {},
	"kicked":                          {},
	"max_connections":                 {},
	"moved":                           {},
	"no_backend":                      {},
	"not_found":                       {},
	reasonClassOK:                     {},
	reasonClassOther:                  {},
	"protected_config":                {},
	"reap":                            {},
	"reload_safe":                     {},
	"reload_unsafe":                   {},
	"runtime_drain":                   {},
	reasonClassRuntimeHardMaintenance: {},
	reasonClassRuntimeOut:             {},
	"runtime_soft_maintenance":        {},
	"selected":                        {},
	"session_kill":                    {},
	"soft_maintenance":                {},
	reasonClassStaticHardMaintenance:  {},
	reasonClassStaticSoftMaintenance:  {},
	"unavailable":                     {},
	"unknown":                         {},
	"unhealthy":                       {},
	"weight_zero":                     {},
}

// AllowedMetricLabels returns the stable low-cardinality metric label names.
func AllowedMetricLabels() []string {
	return sortedKeys(allowedMetricLabels)
}

// ForbiddenMetricLabels returns names that must not be used as metric labels.
func ForbiddenMetricLabels() []string {
	return sortedKeys(forbiddenMetricLabels)
}

// IsMetricLabelAllowed reports whether label is in the documented allowlist.
func IsMetricLabelAllowed(label string) bool {
	_, ok := allowedMetricLabels[normalizeFieldName(label)]

	return ok
}

// IsMetricLabelForbidden reports whether label is explicitly forbidden.
func IsMetricLabelForbidden(label string) bool {
	_, ok := forbiddenMetricLabels[normalizeFieldName(label)]

	return ok
}

// ValidateMetricLabels rejects metric labels outside the allowlist.
func ValidateMetricLabels(labels ...string) error {
	for _, label := range labels {
		normalized := normalizeFieldName(label)
		if _, ok := allowedMetricLabels[normalized]; ok {
			continue
		}

		if _, ok := forbiddenMetricLabels[normalized]; ok {
			return fmt.Errorf("metric label %q is forbidden", normalized)
		}

		return fmt.Errorf("metric label %q is not allowlisted", normalized)
	}

	return nil
}

// IsSecretFieldName reports whether a field name is likely to hold credentials.
func IsSecretFieldName(name string) bool {
	normalized := normalizeFieldName(name)
	for _, fragment := range secretFieldFragments {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}

	return false
}

// IsHighCardinalityFieldName reports whether a field is unsuitable for metrics.
func IsHighCardinalityFieldName(name string) bool {
	normalized := normalizeFieldName(name)
	_, forbidden := forbiddenMetricLabels[normalized]

	return forbidden
}

// IsSafeRoutingAttribute reports whether an auth attribute can be echoed safely.
func IsSafeRoutingAttribute(name string) bool {
	return !IsSecretFieldName(name) && !IsHighCardinalityFieldName(name)
}

// NormalizeReasonClass maps runtime reasons into bounded metric-safe classes.
func NormalizeReasonClass(value string) string {
	normalized := normalizeReasonToken(value)
	if _, ok := allowedReasonClasses[normalized]; ok {
		return normalized
	}

	return reasonClassOther
}

// normalizeFieldName canonicalizes diagnostic field names for policy checks.
func normalizeFieldName(name string) string {
	replacer := strings.NewReplacer("-", "_", ".", "_", " ", "_")

	return strings.ToLower(strings.TrimSpace(replacer.Replace(name)))
}

// normalizeReasonToken canonicalizes reason values without preserving raw text.
func normalizeReasonToken(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return reasonClassOther
	}

	normalized, ok := normalizedReasonToken(value)
	if !ok {
		return reasonClassOther
	}

	if normalized == "" || IsSecretFieldName(normalized) || IsHighCardinalityFieldName(normalized) {
		return reasonClassOther
	}

	return normalized
}

// normalizedReasonToken returns a tokenized reason class and rejects raw text.
func normalizedReasonToken(value string) (string, bool) {
	var builder strings.Builder

	lastUnderscore := false

	for _, token := range value {
		switch {
		case token >= 'a' && token <= 'z':
			builder.WriteRune(token)

			lastUnderscore = false
		case token >= '0' && token <= '9':
			builder.WriteRune(token)

			lastUnderscore = false
		case token == '_' || token == '-' || unicode.IsSpace(token):
			if !lastUnderscore && builder.Len() > 0 {
				builder.WriteByte('_')

				lastUnderscore = true
			}
		default:
			return "", false
		}
	}

	normalized := strings.Trim(builder.String(), "_")

	return normalized, true
}

// sortedKeys returns a deterministic sorted list for policy reporting.
func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}
