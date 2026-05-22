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

package adapters

import (
	"context"
	"reflect"
	"testing"

	"github.com/croessner/nauthilus-director/internal/rest/generated"
)

// TestLookupRouteStubHasNoDomainSideEffectDependencies proves the stub cannot mutate runtime state.
func TestLookupRouteStubHasNoDomainSideEffectDependencies(t *testing.T) {
	handler := NewHandler(HandlerOptions{Version: "test"})
	handlerType := reflect.TypeFor[Handler]()

	if handlerType.NumField() != 1 || handlerType.Field(0).Name != "version" {
		t.Fatalf("handler fields changed to %v; route lookup side-effect test must be updated", handlerType.NumField())
	}

	body := generated.LookupRouteJSONRequestBody{
		Protocol: "imap",
		UserKey:  "alice@example.test",
	}

	response, err := handler.LookupRoute(context.Background(), generated.LookupRouteRequestObject{Body: &body})
	if err != nil {
		t.Fatalf("LookupRoute returned error: %v", err)
	}

	if _, ok := response.(generated.LookupRoute501JSONResponse); !ok {
		t.Fatalf("LookupRoute response = %T, want structured 501 stub", response)
	}
}
