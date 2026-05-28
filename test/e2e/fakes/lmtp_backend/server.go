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

// Package lmtpbackend provides a deterministic public-socket LMTP backend for E2E tests.
//
//nolint:wsl_v5 // The fake backend keeps protocol transcript blocks compact.
package lmtpbackend

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	commandAUTH     = "AUTH"
	commandBDAT     = "BDAT"
	commandDATA     = "DATA"
	commandLHLO     = "LHLO"
	commandMAIL     = "MAIL"
	commandNOOP     = "NOOP"
	commandQUIT     = "QUIT"
	commandRCPT     = "RCPT"
	commandRSET     = "RSET"
	commandSTARTTLS = "STARTTLS"

	tlsModeImplicit = "implicit"
	tlsModeStartTLS = "starttls"
)

// Status is one LMTP response line without exposing message content.
type Status struct {
	Code     string
	Enhanced string
	Text     string
}

// Options configures a deterministic fake backend instance.
type Options struct {
	Capabilities []string
	FinalStatus  map[string]Status
	TLSConfig    *tls.Config
	TLSMode      string
	HoldFinal    <-chan struct{}
}

// Observation records one backend transaction at protocol boundaries only.
type Observation struct {
	Commands   []string
	Recipients []string
	Body       string
	UsedBDAT   bool
}

// Server owns one fake LMTP backend listener.
type Server struct {
	listener     net.Listener
	options      Options
	observations chan Observation
}

type connectionState struct {
	commands   []string
	recipients []string
	body       strings.Builder
	usedBDAT   bool
}

// Start binds a public loopback LMTP backend socket.
func Start(t testing.TB, options Options) *Server {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake LMTP backend: %v", err)
	}

	server := &Server{
		listener:     ln,
		options:      options,
		observations: make(chan Observation, 16),
	}

	go server.accept()
	t.Cleanup(func() {
		_ = ln.Close()
	})

	return server
}

// Address returns the public backend address.
func (s *Server) Address() string {
	return s.listener.Addr().String()
}

// ExpectObservation returns the next recorded backend transaction.
func (s *Server) ExpectObservation(t testing.TB) Observation {
	t.Helper()

	select {
	case observation := <-s.observations:
		return observation
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for fake LMTP backend observation")
	}

	return Observation{}
}

// accept serves backend connections until the listener closes.
func (s *Server) accept() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}

		go s.serve(conn)
	}
}

// serve executes a minimal LMTP backend command loop.
func (s *Server) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	state := &connectionState{}
	prepared, ok := s.prepare(conn)
	if !ok {
		return
	}
	conn = prepared

	reader := bufio.NewReader(conn)
	if _, err := io.WriteString(conn, "220 fake LMTP backend ready\r\n"); err != nil {
		return
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		var done bool
		conn, reader, done = s.handleLine(conn, reader, state, line)
		if done {
			return
		}
	}
}

// prepare applies implicit TLS when requested by the test.
func (s *Server) prepare(conn net.Conn) (net.Conn, bool) {
	if s.options.TLSMode != tlsModeImplicit || s.options.TLSConfig == nil {
		return conn, true
	}

	tlsConn := tls.Server(conn, s.options.TLSConfig.Clone())
	if err := tlsConn.Handshake(); err != nil {
		return conn, false
	}

	return tlsConn, true
}

// handleLine dispatches one backend command.
func (s *Server) handleLine(conn net.Conn, reader *bufio.Reader, state *connectionState, line string) (net.Conn, *bufio.Reader, bool) {
	command := firstToken(line)
	state.commands = append(state.commands, strings.TrimSpace(line))

	switch command {
	case commandLHLO:
		s.writeLHLO(conn)
	case commandSTARTTLS:
		return s.handleSTARTTLS(conn)
	case commandAUTH:
		_, _ = io.WriteString(conn, "235 2.7.0 authenticated\r\n")
	case commandNOOP:
		_, _ = io.WriteString(conn, "250 2.0.0 noop\r\n")
	case commandRSET:
		state.recipients = nil
		state.body.Reset()
		_, _ = io.WriteString(conn, "250 2.0.0 reset\r\n")
	case commandQUIT:
		_, _ = io.WriteString(conn, "221 2.0.0 bye\r\n")
		return conn, reader, true
	case commandMAIL:
		state.recipients = nil
		state.body.Reset()
		_, _ = io.WriteString(conn, "250 2.1.0 sender ok\r\n")
	case commandRCPT:
		recipient := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "RCPT TO:"))
		state.recipients = append(state.recipients, recipient)
		_, _ = io.WriteString(conn, "250 2.1.5 recipient ok\r\n")
	case commandDATA:
		s.handleDATA(conn, reader, state)
	case commandBDAT:
		s.handleBDAT(conn, reader, state, line)
	default:
		_, _ = io.WriteString(conn, "502 5.5.1 unsupported\r\n")
	}

	return conn, reader, false
}

// writeLHLO advertises the configured backend capability set.
func (s *Server) writeLHLO(conn net.Conn) {
	capabilities := normalizedCapabilities(s.options.Capabilities)
	if len(capabilities) == 0 {
		_, _ = io.WriteString(conn, "250 fake-lmtp-backend\r\n")
		return
	}

	_, _ = io.WriteString(conn, "250-fake-lmtp-backend\r\n")
	for index, capability := range capabilities {
		separator := "-"
		if index == len(capabilities)-1 {
			separator = " "
		}
		_, _ = fmt.Fprintf(conn, "250%s%s\r\n", separator, capability)
	}
}

// handleSTARTTLS upgrades the backend stream when a TLS fixture is configured.
func (s *Server) handleSTARTTLS(conn net.Conn) (net.Conn, *bufio.Reader, bool) {
	if s.options.TLSMode != tlsModeStartTLS || s.options.TLSConfig == nil {
		_, _ = io.WriteString(conn, "454 4.7.0 tls unavailable\r\n")
		return conn, bufio.NewReader(conn), false
	}

	_, _ = io.WriteString(conn, "220 2.0.0 start tls\r\n")
	tlsConn := tls.Server(conn, s.options.TLSConfig.Clone())
	if err := tlsConn.Handshake(); err != nil {
		return conn, bufio.NewReader(conn), true
	}

	return tlsConn, bufio.NewReader(tlsConn), false
}

// handleDATA reads a dot-terminated body and emits per-recipient final statuses.
func (s *Server) handleDATA(conn net.Conn, reader *bufio.Reader, state *connectionState) {
	_, _ = io.WriteString(conn, "354 2.0.0 send data\r\n")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		if strings.TrimRight(line, "\r\n") == "." {
			break
		}
		state.body.WriteString(line)
	}

	s.writeFinalStatuses(conn, state)
}

// handleBDAT reads an exact byte-counted chunk and emits chunk or final statuses.
func (s *Server) handleBDAT(conn net.Conn, reader *bufio.Reader, state *connectionState, line string) {
	size, last, ok := parseBDATLine(line)
	if !ok {
		_, _ = io.WriteString(conn, "501 5.5.4 invalid bdat\r\n")
		return
	}

	state.usedBDAT = true
	if size > 0 {
		payload := make([]byte, int(size))
		if _, err := io.ReadFull(reader, payload); err != nil {
			return
		}
		state.body.Write(payload)
	}

	if !last {
		_, _ = io.WriteString(conn, "250 2.0.0 chunk ok\r\n")
		return
	}

	s.writeFinalStatuses(conn, state)
}

// writeFinalStatuses emits one final status per accepted recipient and records the transaction.
func (s *Server) writeFinalStatuses(conn net.Conn, state *connectionState) {
	if s.options.HoldFinal != nil {
		<-s.options.HoldFinal
	}

	for _, recipient := range state.recipients {
		status := s.finalStatus(recipient)
		_, _ = fmt.Fprintf(conn, "%s %s %s\r\n", status.Code, status.Enhanced, status.Text)
	}

	s.observations <- Observation{
		Commands:   append([]string(nil), state.commands...),
		Recipients: append([]string(nil), state.recipients...),
		Body:       state.body.String(),
		UsedBDAT:   state.usedBDAT,
	}
}

// finalStatus returns the deterministic final status for one recipient.
func (s *Server) finalStatus(recipient string) Status {
	if status, ok := s.options.FinalStatus[recipient]; ok {
		return normalizeStatus(status)
	}

	return Status{Code: "250", Enhanced: "2.1.5", Text: "delivered"}
}

// normalizedCapabilities returns deterministic uppercase backend capabilities.
func normalizedCapabilities(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	capabilities := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.ToUpper(strings.TrimSpace(value))
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		capabilities = append(capabilities, normalized)
	}

	return capabilities
}

// normalizeStatus fills missing status fields with a temporary failure.
func normalizeStatus(status Status) Status {
	if strings.TrimSpace(status.Code) == "" {
		status.Code = "451"
	}
	if strings.TrimSpace(status.Enhanced) == "" {
		status.Enhanced = "4.3.0"
	}
	if strings.TrimSpace(status.Text) == "" {
		status.Text = "temporary failure"
	}

	return status
}

// parseBDATLine parses the subset of BDAT used by public-boundary tests.
func parseBDATLine(line string) (int64, bool, bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 || !strings.EqualFold(fields[0], commandBDAT) {
		return 0, false, false
	}

	size, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || size < 0 {
		return 0, false, false
	}

	last := len(fields) > 2 && strings.EqualFold(fields[2], "LAST")

	return size, last, true
}

// firstToken returns the upper-case command verb from one wire line.
func firstToken(line string) string {
	token := strings.TrimSpace(line)
	if fields := strings.Fields(token); len(fields) > 0 {
		token = fields[0]
	}
	if command, _, ok := strings.Cut(token, ":"); ok {
		token = command
	}

	return strings.ToUpper(strings.TrimSpace(token))
}
