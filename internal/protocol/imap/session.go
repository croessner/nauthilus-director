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
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
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

// Session owns one accepted IMAP frontend stream until later auth/proxy phases take over.
type Session struct {
	context Context
	conn    net.Conn
	reader  *bufio.Reader
	writer  *bufio.Writer
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
		},
		conn:   conn,
		reader: bufio.NewReaderSize(conn, config.MaxPreauthLineBytes+1),
		writer: bufio.NewWriter(conn),
	}, nil
}

// Context returns the stable internal session metadata without exposing it as metric labels.
func (s *Session) Context() Context {
	return s.context
}

// Serve writes the initial greeting and then holds the pre-auth boundary open.
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

			return err
		}

		if err := s.rejectUnsupportedLiteral(line); err != nil {
			_, _ = s.writer.WriteString("* BAD pre-auth literals are not accepted\r\n")
			_ = s.writer.Flush()

			return err
		}
	}
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

	if err != nil {
		return nil, err
	}

	return line, nil
}

// rejectUnsupportedLiteral enforces literal size limits before later IMAP parsing exists.
func (s *Session) rejectUnsupportedLiteral(line []byte) error {
	size, ok, err := preauthLiteralSize(line)
	if err != nil {
		return err
	}

	if !ok {
		return nil
	}

	if size > s.context.MaxPreauthLiteralBytes {
		return ErrPreauthLiteralTooLarge
	}

	return ErrPreauthLiteralUnsupported
}

// preauthLiteralSize extracts a terminal IMAP literal marker from a pre-auth line.
func preauthLiteralSize(line []byte) (int, bool, error) {
	trimmed := strings.TrimRight(string(line), "\r\n")
	if !strings.HasSuffix(trimmed, "}") {
		return 0, false, nil
	}

	open := strings.LastIndex(trimmed, "{")
	if open < 0 {
		return 0, false, nil
	}

	value := strings.TrimSuffix(trimmed[open+1:len(trimmed)-1], "+")
	if value == "" {
		return 0, true, fmt.Errorf("%w: empty literal size", ErrPreauthLiteralUnsupported)
	}

	size, err := strconv.Atoi(value)
	if err != nil || size < 0 {
		return 0, true, fmt.Errorf("%w: invalid literal size", ErrPreauthLiteralUnsupported)
	}

	return size, true, nil
}

// newSessionID creates a stable opaque session identifier for internal correlation.
func newSessionID() (string, error) {
	var raw [sessionIDByteLength]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("imap: create session id: %w", err)
	}

	return hex.EncodeToString(raw[:]), nil
}
