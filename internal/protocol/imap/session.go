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

package imap

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	greetingLine        = "* OK nauthilus-director IMAP session ready\r\n"
	sessionIDByteLength = 16
)

var (
	// ErrPreauthLineTooLarge reports that a pre-auth input line exceeded the configured boundary.
	ErrPreauthLineTooLarge = errors.New("imap: preauth line exceeds configured limit")
	// ErrPreauthLiteralTooLarge reports that a literal marker exceeded the configured boundary.
	ErrPreauthLiteralTooLarge = errors.New("imap: preauth literal exceeds configured limit")
	// ErrPreauthLiteralUnsupported reports that literal handling is not part of this session slice.
	ErrPreauthLiteralUnsupported = errors.New("imap: preauth literals are not supported yet")
	// ErrPreauthPartialCommand reports a connection closed before a command line was complete.
	ErrPreauthPartialCommand = errors.New("imap: partial preauth command")
)

// Handler creates bounded IMAP sessions for one configured listener.
type Handler struct {
	config SessionConfig
}

// NewHandler creates an IMAP session handler with immutable listener settings.
func NewHandler(config SessionConfig) *Handler {
	return &Handler{config: config}
}

// Serve accepts one frontend connection and enforces the initial pre-auth boundary.
func (h *Handler) Serve(ctx context.Context, conn net.Conn) error {
	session, err := NewSession(h.config, conn)
	if err != nil {
		return err
	}

	return session.Serve(ctx)
}

// Session owns one accepted IMAP frontend stream until auth and proxy handling take over.
type Session struct {
	context Context
	conn    net.Conn
	reader  *bufio.Reader
	writer  *bufio.Writer

	tlsActive bool
	clientID  string
}

// NewSession creates a bounded IMAP session context for an accepted connection.
func NewSession(config SessionConfig, conn net.Conn) (*Session, error) {
	if conn == nil {
		return nil, errors.New("imap: session connection is nil")
	}

	sessionID, err := newSessionID()
	if err != nil {
		return nil, err
	}

	return &Session{
		context: Context{
			ID:                     sessionID,
			ListenerName:           config.ListenerName,
			ServiceName:            config.ServiceName,
			Network:                config.Network,
			TLSMode:                config.TLSMode,
			LocalAddr:              conn.LocalAddr(),
			RemoteAddr:             conn.RemoteAddr(),
			StartedAt:              time.Now().UTC(),
			PreauthTimeout:         config.PreauthTimeout,
			AuthTimeout:            config.AuthTimeout,
			BackendConnectTimeout:  config.BackendConnectTimeout,
			ProxyIdleTimeout:       config.ProxyIdleTimeout,
			MaxPreauthLineBytes:    config.MaxPreauthLineBytes,
			MaxPreauthLiteralBytes: config.MaxPreauthLiteralBytes,
			Capabilities:           append([]string(nil), config.Capabilities...),
			AuthMechanisms:         append([]string(nil), config.AuthMechanisms...),
			MaxBearerTokenBytes:    config.MaxBearerTokenBytes,
			RequireIDBeforeAuth:    config.RequireIDBeforeAuth,
		},
		conn:      conn,
		reader:    bufio.NewReaderSize(conn, config.MaxPreauthLineBytes+1),
		writer:    bufio.NewWriter(conn),
		tlsActive: config.TLSMode == TLSModeImplicit,
	}, nil
}

// Context returns the stable internal session metadata without exposing it as metric labels.
func (s *Session) Context() Context {
	return s.context
}

// Serve writes the initial greeting and processes pre-auth commands in wire order.
func (s *Session) Serve(ctx context.Context) error {
	if err := s.applyPreauthDeadline(); err != nil {
		return err
	}

	if _, err := s.writer.WriteString(greetingLine); err != nil {
		return err
	}

	if err := s.writer.Flush(); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line, err := s.readPreauthLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}

			if errors.Is(err, ErrPreauthPartialCommand) {
				_ = s.writeCommandSyntaxError(tagHintForLine(line))
				_ = s.writer.Flush()

				return err
			}

			return err
		}

		closeSession, err := s.processPreauthLine(line)
		if err != nil {
			return err
		}

		if closeSession {
			return nil
		}
	}
}

// TLSActive reports whether the session has crossed an implicit or STARTTLS boundary.
func (s *Session) TLSActive() bool {
	return s.tlsActive
}

// BufferedProxyHandoff drains bytes already read ahead for later transparent proxy mode.
func (s *Session) BufferedProxyHandoff() ProxyHandoff {
	buffered := make([]byte, s.reader.Buffered())
	if len(buffered) > 0 {
		_, _ = io.ReadFull(s.reader, buffered)
	}

	return ProxyHandoff{frontend: s.conn, buffered: buffered}
}

// ProxyHandoff carries the frontend stream and any bytes buffered during pre-auth parsing.
type ProxyHandoff struct {
	frontend net.Conn
	buffered []byte
}

// Buffered returns a copy of bytes that must be sent to the backend first.
func (h ProxyHandoff) Buffered() []byte {
	copied := make([]byte, len(h.buffered))
	copy(copied, h.buffered)

	return copied
}

// Reader returns a stream that replays buffered bytes before live frontend reads.
func (h ProxyHandoff) Reader() io.Reader {
	if len(h.buffered) == 0 {
		return h.frontend
	}

	return io.MultiReader(bytes.NewReader(h.buffered), h.frontend)
}

// Frontend returns the underlying client connection for later proxy ownership.
func (h ProxyHandoff) Frontend() net.Conn {
	return h.frontend
}

// applyPreauthDeadline sets the initial session read/write deadline.
func (s *Session) applyPreauthDeadline() error {
	if s.context.PreauthTimeout <= 0 {
		return nil
	}

	return s.conn.SetDeadline(time.Now().Add(s.context.PreauthTimeout))
}

// readPreauthLine reads one bounded line without accepting oversized buffers.
func (s *Session) readPreauthLine() ([]byte, error) {
	line, err := s.reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > s.context.MaxPreauthLineBytes {
		return nil, ErrPreauthLineTooLarge
	}

	if errors.Is(err, io.EOF) && len(line) > 0 {
		return line, ErrPreauthPartialCommand
	}

	if err != nil {
		return nil, err
	}

	return line, nil
}

// processPreauthLine parses and dispatches one pre-auth command.
func (s *Session) processPreauthLine(line []byte) (bool, error) {
	tag := tagHintForLine(line)

	if err := s.rejectUnsupportedLiteral(line, tag); err != nil {
		return false, err
	}

	command, err := parsePreauthCommand(line, s.context.MaxPreauthLineBytes)
	if err != nil {
		if writeErr := s.writeCommandSyntaxError(tag); writeErr != nil {
			return false, writeErr
		}

		if flushErr := s.writer.Flush(); flushErr != nil {
			return false, flushErr
		}

		return false, nil
	}

	outcome, err := s.handlePreauthCommand(command)
	if flushErr := s.writer.Flush(); flushErr != nil {
		return false, flushErr
	}

	if errors.Is(err, ErrUnsupportedCommand) {
		return false, nil
	}

	return outcome.closeSession, err
}

// rejectUnsupportedLiteral emits a tagged error and avoids continuation reads.
func (s *Session) rejectUnsupportedLiteral(line []byte, tag string) error {
	size, ok, err := preauthLiteralMarker(line)
	if err != nil {
		_ = s.writeTagged(tag, responseBad, "Unsupported IMAP literal before authentication")
		_ = s.writer.Flush()

		return err
	}

	if !ok {
		return nil
	}

	if size > s.context.MaxPreauthLiteralBytes {
		_ = s.writeTagged(tag, responseBad, "Unsupported IMAP literal before authentication")
		_ = s.writer.Flush()

		return ErrPreauthLiteralTooLarge
	}

	_ = s.writeTagged(tag, responseBad, "Unsupported IMAP literal before authentication")
	_ = s.writer.Flush()

	return ErrPreauthLiteralUnsupported
}

// newSessionID creates a stable opaque session identifier for internal correlation.
func newSessionID() (string, error) {
	var raw [sessionIDByteLength]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("imap: create session id: %w", err)
	}

	return hex.EncodeToString(raw[:]), nil
}
