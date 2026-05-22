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

package proxy

import (
	"net"
	"sync"
	"time"
)

// deadlineController refreshes idle deadlines on both proxy streams after activity.
type deadlineController struct {
	frontend net.Conn
	backend  net.Conn
	timeout  time.Duration
	mu       sync.Mutex
}

// newDeadlineController creates a deadline owner for both proxy streams.
func newDeadlineController(frontend net.Conn, backend net.Conn, timeout time.Duration) *deadlineController {
	return &deadlineController{frontend: frontend, backend: backend, timeout: timeout}
}

// touch extends both stream deadlines when an idle timeout is configured.
func (d *deadlineController) touch() error {
	if d == nil || d.timeout <= 0 {
		return nil
	}

	deadline := time.Now().Add(d.timeout)

	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.frontend.SetDeadline(deadline); err != nil {
		return err
	}

	return d.backend.SetDeadline(deadline)
}
