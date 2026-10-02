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

package lmtp

import (
	"io"
	"time"
)

// maxDeadlineRefreshInterval caps how long body progress may go without extending deadlines.
const maxDeadlineRefreshInterval = time.Second

// sessionDeadlines owns the phase-dependent I/O deadline of one LMTP session.
//
// Until the first recipient is accepted the session is bound by one absolute
// pre-authentication deadline, so unplaced peers cannot hold a connection open
// by trickling commands. Once a recipient is placed, every command read, body
// progress step and backend reply is bounded by the command idle timeout, and an
// open message body is additionally bounded by the absolute data-phase deadline.
// While the backend processes end-of-data only the data-phase deadline applies,
// because the frontend is silent by protocol until the final replies arrive.
// A zero timeout disables only its own bound.
type sessionDeadlines struct {
	preauth time.Duration
	idle    time.Duration
	data    time.Duration

	preauthUntil  time.Time
	placed        bool
	dataUntil     time.Time
	awaitingFinal bool
	lastApplied   time.Time
}

// newSessionDeadlines creates the deadline policy from listener timeouts.
func newSessionDeadlines(preauth time.Duration, idle time.Duration, data time.Duration) sessionDeadlines {
	return sessionDeadlines{preauth: preauth, idle: idle, data: data}
}

// start opens the absolute pre-authentication window at session start.
func (d *sessionDeadlines) start(now time.Time) {
	if d.preauth > 0 {
		d.preauthUntil = now.Add(d.preauth)
	}
}

// markPlaced ends the pre-authentication window after the first accepted recipient.
func (d *sessionDeadlines) markPlaced() {
	d.placed = true
	d.preauthUntil = time.Time{}
}

// beginData opens the absolute data-phase window once per message body.
func (d *sessionDeadlines) beginData(now time.Time) {
	if d.dataUntil.IsZero() && d.data > 0 {
		d.dataUntil = now.Add(d.data)
	}
}

// awaitFinalReplies switches to the end-of-data wait bounded by the data phase.
func (d *sessionDeadlines) awaitFinalReplies() {
	d.awaitingFinal = true
}

// endData closes the data phase after the final replies or a transaction reset.
func (d *sessionDeadlines) endData() {
	d.dataUntil = time.Time{}
	d.awaitingFinal = false
}

// deadline returns the earliest bound of the current phase, or zero when none applies.
func (d *sessionDeadlines) deadline(now time.Time) time.Time {
	var deadline time.Time

	if !d.placed {
		deadline = earliestDeadline(deadline, d.preauthUntil)
	}

	if d.awaitingFinal && !d.dataUntil.IsZero() {
		return earliestDeadline(deadline, d.dataUntil)
	}

	if d.idle > 0 {
		deadline = earliestDeadline(deadline, now.Add(d.idle))
	}

	return earliestDeadline(deadline, d.dataUntil)
}

// refreshDue reports whether body progress should extend the idle deadline now.
func (d *sessionDeadlines) refreshDue(now time.Time) bool {
	if d.idle <= 0 {
		return false
	}

	interval := min(d.idle/4, maxDeadlineRefreshInterval)

	return now.Sub(d.lastApplied) >= interval
}

// earliestDeadline returns the earlier non-zero deadline.
func earliestDeadline(current time.Time, candidate time.Time) time.Time {
	if candidate.IsZero() {
		return current
	}

	if current.IsZero() || candidate.Before(current) {
		return candidate
	}

	return current
}

// applyDeadlines sets the current phase deadline on the frontend and any open backend stream.
//
// Only a frontend failure is returned. A backend stream that can no longer take a
// deadline is already broken; its next read or write fails and maps to a
// temporary delivery status instead of ending the frontend session.
func (s *Session) applyDeadlines() error {
	now := time.Now()
	deadline := s.deadlines.deadline(now)
	s.deadlines.lastApplied = now

	if err := s.conn.SetDeadline(deadline); err != nil {
		return err
	}

	if s.transaction.backend == nil || s.transaction.backend.connection == nil || s.transaction.backend.connection.Conn() == nil {
		return nil
	}

	_ = s.transaction.backend.connection.Conn().SetDeadline(deadline)

	return nil
}

// currentDeadline returns the deadline a newly attached backend stream must inherit.
func (s *Session) currentDeadline() time.Time {
	return s.deadlines.deadline(time.Now())
}

// refreshProgressDeadlines extends idle deadlines after body progress without a syscall per line.
func (s *Session) refreshProgressDeadlines() error {
	if !s.deadlines.refreshDue(time.Now()) {
		return nil
	}

	return s.applyDeadlines()
}

// beginDataPhase starts the bounded message-body phase for DATA or the first BDAT chunk.
func (s *Session) beginDataPhase() error {
	s.deadlines.beginData(time.Now())

	return s.applyDeadlines()
}

// enterFinalReplyPhase bounds the end-of-data wait by the data phase instead of the idle timeout.
func (s *Session) enterFinalReplyPhase() error {
	s.deadlines.awaitFinalReplies()

	return s.applyDeadlines()
}

// endDataPhase restores idle deadlines before final replies are written to the frontend.
func (s *Session) endDataPhase() {
	s.deadlines.endData()
	_ = s.applyDeadlines()
}

// progressReader returns the frontend reader that extends idle deadlines on body progress.
func (s *Session) progressReader() io.Reader {
	return deadlineProgressReader{reader: s.reader, session: s}
}

type deadlineProgressReader struct {
	reader  io.Reader
	session *Session
}

// Read forwards payload bytes and extends the idle deadline after progress.
func (r deadlineProgressReader) Read(payload []byte) (int, error) {
	read, err := r.reader.Read(payload)
	if read > 0 && err == nil {
		err = r.session.refreshProgressDeadlines()
	}

	return read, err
}
