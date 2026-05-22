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

import "maps"

// MetricLabels contains Prometheus labels after allowlist validation.
type MetricLabels map[string]string

// NewMetricLabels validates and copies labels for metric registration.
func NewMetricLabels(labels map[string]string) (MetricLabels, error) {
	names := make([]string, 0, len(labels))
	for name := range labels {
		names = append(names, name)
	}

	if err := ValidateMetricLabels(names...); err != nil {
		return nil, err
	}

	return cloneLabels(labels), nil
}

// Validate checks that the label set still uses only allowlisted labels.
func (l MetricLabels) Validate() error {
	names := make([]string, 0, len(l))
	for name := range l {
		names = append(names, name)
	}

	return ValidateMetricLabels(names...)
}

// cloneLabels copies labels before callers hand them to metric backends.
func cloneLabels(labels map[string]string) MetricLabels {
	cloned := make(MetricLabels, len(labels))
	maps.Copy(cloned, labels)

	return cloned
}
