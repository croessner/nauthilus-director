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

package nauthilus

import (
	"testing"

	"github.com/croessner/nauthilus-director/internal/config"
)

// TestNewClientSelectsConfiguredTransport verifies authority transport selection.
func TestNewClientSelectsConfiguredTransport(t *testing.T) {
	authority := config.DefaultConfig().Auth.Authorities["default"]

	httpClient, err := NewClient(authority, ClientOptions{})
	if err != nil {
		t.Fatalf("NewClient(http): %v", err)
	}

	if _, ok := httpClient.(*HTTPClient); !ok {
		t.Fatalf("client = %T, want *HTTPClient", httpClient)
	}

	authority.Transport = "grpc"

	grpcClient, err := NewClient(authority, ClientOptions{GRPCService: &recordingGRPCService{}})
	if err != nil {
		t.Fatalf("NewClient(grpc): %v", err)
	}

	if _, ok := grpcClient.(*GRPCClient); !ok {
		t.Fatalf("client = %T, want *GRPCClient", grpcClient)
	}
}
