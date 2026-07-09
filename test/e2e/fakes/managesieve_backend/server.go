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

// Package managesievebackend provides a deterministic public-socket
// ManageSieve backend for E2E tests.
//
//nolint:goconst,wsl_v5 // The fake backend keeps wire transcript handling compact.
package managesievebackend

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"maps"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	commandAuthenticate = "AUTHENTICATE"
	commandCapability   = "CAPABILITY"
	commandDeleteScript = "DELETESCRIPT"
	commandGetScript    = "GETSCRIPT"
	commandListScripts  = "LISTSCRIPTS"
	commandLogout       = "LOGOUT"
	commandNoop         = "NOOP"
	commandPutScript    = "PUTSCRIPT"
	commandSetActive    = "SETACTIVE"
	commandStartTLS     = "STARTTLS"

	responseBye = "BYE"
	responseNo  = "NO"
	responseOK  = "OK"

	tlsModeImplicit  = "implicit"
	tlsModeStartTLS  = "starttls"
	proxyPrefix      = "PROXY "
	proxyReadLimit   = 256
	proxyReadTimeout = 500 * time.Millisecond
)

// Status configures one deterministic command response.
type Status struct {
	Condition string
	Code      string
	Text      string
}

// Options configures a fake ManageSieve backend instance.
type Options struct {
	CommandStatus        map[string]Status
	ExpectedScripts      map[string]string
	RequireProxyProtocol bool
	TLSConfig            *tls.Config
	TLSMode              string
}

// Observation records backend activity without raw scripts or credentials.
type Observation struct {
	AuthMechanisms []string
	Commands       []CommandObservation
}

// CommandObservation records one post-auth command with redacted script facts.
type CommandObservation struct {
	Command              string
	ScriptNameMatched    bool
	ScriptContentMatched bool
	ScriptContentBytes   int
}

// Server owns one fake ManageSieve backend listener.
type Server struct {
	listener             net.Listener
	options              Options
	observations         chan Observation
	proxyProtocolHeaders chan string
	connections          atomic.Int64
	missingProxyProtocol atomic.Int64
	proxyProtocolCount   atomic.Int64
}

type connectionState struct {
	authMechanisms []string
	commands       []CommandObservation
	scripts        map[string]string
	activeScript   string
	tlsActive      bool
	mu             sync.Mutex
}

// Start binds a public loopback ManageSieve backend socket.
func Start(t testing.TB, options Options) *Server {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake ManageSieve backend: %v", err)
	}

	server := &Server{
		listener:             ln,
		options:              cloneOptions(options),
		observations:         make(chan Observation, 16),
		proxyProtocolHeaders: make(chan string, 16),
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

// ConnectionCount returns accepted backend sockets.
func (s *Server) ConnectionCount() int64 {
	if s == nil {
		return 0
	}

	return s.connections.Load()
}

// MissingProxyProtocolCount returns how often a required PROXY preface was absent.
func (s *Server) MissingProxyProtocolCount() int64 {
	if s == nil {
		return 0
	}

	return s.missingProxyProtocol.Load()
}

// ProxyProtocolHeaderCount returns how many required PROXY prefaces arrived.
func (s *Server) ProxyProtocolHeaderCount() int64 {
	if s == nil {
		return 0
	}

	return s.proxyProtocolCount.Load()
}

// ExpectObservation returns the next redacted backend observation.
func (s *Server) ExpectObservation(t testing.TB) Observation {
	t.Helper()

	select {
	case observation := <-s.observations:
		return observation
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for fake ManageSieve backend observation")
	}

	return Observation{}
}

// ExpectProxyProtocolHeader verifies a required outbound PROXY preface arrived.
func (s *Server) ExpectProxyProtocolHeader(t testing.TB) string {
	t.Helper()

	select {
	case header := <-s.proxyProtocolHeaders:
		return header
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for fake ManageSieve backend PROXY protocol header")
	}

	return ""
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

// serve executes one minimal ManageSieve backend session.
func (s *Server) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	s.connections.Add(1)
	state := &connectionState{
		scripts:   make(map[string]string),
		tlsActive: strings.EqualFold(strings.TrimSpace(s.options.TLSMode), tlsModeImplicit),
	}

	prepared, ok := s.prepare(conn)
	if !ok {
		return
	}
	conn = prepared
	reader := bufio.NewReader(conn)
	defer s.publishObservation(state)

	if err := s.writeCapabilities(conn, state, "ready"); err != nil {
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

// prepare applies outbound PROXY and implicit TLS policies.
func (s *Server) prepare(conn net.Conn) (net.Conn, bool) {
	if s.options.RequireProxyProtocol && !s.consumeProxyProtocolPreface(conn) {
		return conn, false
	}

	if !strings.EqualFold(strings.TrimSpace(s.options.TLSMode), tlsModeImplicit) || s.options.TLSConfig == nil {
		return conn, true
	}

	tlsConn := tls.Server(conn, s.options.TLSConfig.Clone())
	if err := tlsConn.Handshake(); err != nil {
		return conn, false
	}

	return tlsConn, true
}

// handleLine dispatches one backend command.
func (s *Server) handleLine(
	conn net.Conn,
	reader *bufio.Reader,
	state *connectionState,
	line string,
) (net.Conn, *bufio.Reader, bool) {
	command := strings.ToUpper(firstToken(line))
	if status, ok := s.scriptedStatus(command); ok {
		_ = writeStatus(conn, status)

		return conn, reader, status.closes()
	}

	switch command {
	case commandCapability:
		_ = s.writeCapabilities(conn, state, "capability completed")
	case commandStartTLS:
		return s.handleStartTLS(conn, state)
	case commandAuthenticate:
		s.recordAuth(state, line)
		_ = writeStatus(conn, Status{Condition: responseOK, Text: "authenticated"})
	case commandListScripts:
		s.recordCommand(state, command, "", "")
		s.writeListScripts(conn, state)
	case commandPutScript:
		s.handlePutScript(conn, reader, state, line)
	case commandSetActive:
		s.handleSetActive(conn, state, line)
	case commandGetScript:
		s.handleGetScript(conn, state, line)
	case commandDeleteScript:
		s.handleDeleteScript(conn, state, line)
	case commandNoop:
		_ = writeStatus(conn, Status{Condition: responseOK, Text: "noop"})
	case commandLogout:
		_ = writeStatus(conn, Status{Condition: responseOK, Text: "bye"})

		return conn, reader, true
	default:
		_ = writeStatus(conn, Status{Condition: responseNo, Code: "UNSUPPORTED", Text: "unsupported command"})
	}

	return conn, reader, false
}

// handleStartTLS upgrades the fake backend stream after an advertised STARTTLS.
func (s *Server) handleStartTLS(conn net.Conn, state *connectionState) (net.Conn, *bufio.Reader, bool) {
	if !strings.EqualFold(strings.TrimSpace(s.options.TLSMode), tlsModeStartTLS) || state.tlsActive || s.options.TLSConfig == nil {
		_ = writeStatus(conn, Status{Condition: responseNo, Code: "UNSUPPORTED", Text: "STARTTLS unavailable"})

		return conn, bufio.NewReader(conn), false
	}

	if err := writeStatus(conn, Status{Condition: responseOK, Text: "begin tls"}); err != nil {
		return conn, bufio.NewReader(conn), true
	}

	tlsConn := tls.Server(conn, s.options.TLSConfig.Clone())
	if err := tlsConn.Handshake(); err != nil {
		return conn, bufio.NewReader(conn), true
	}

	state.tlsActive = true
	if err := s.writeCapabilities(tlsConn, state, "tls capability"); err != nil {
		return tlsConn, bufio.NewReader(tlsConn), true
	}

	return tlsConn, bufio.NewReader(tlsConn), false
}

// handlePutScript stores script bytes while exposing only redacted observations.
func (s *Server) handlePutScript(conn net.Conn, reader *bufio.Reader, state *connectionState, line string) {
	name, rest, ok := nextArgument(afterFirstToken(line))
	if !ok {
		_ = writeStatus(conn, Status{Condition: responseNo, Code: "CLIENT-BUG", Text: "invalid putscript"})

		return
	}

	size, ok := literalSize(rest)
	if !ok {
		_ = writeStatus(conn, Status{Condition: responseNo, Code: "CLIENT-BUG", Text: "invalid literal"})

		return
	}

	content := make([]byte, size)
	if _, err := io.ReadFull(reader, content); err != nil {
		_ = writeStatus(conn, Status{Condition: responseNo, Code: "CLIENT-BUG", Text: "invalid literal"})

		return
	}
	consumeOptionalCRLF(reader)

	text := string(content)
	state.mu.Lock()
	state.scripts[name] = text
	state.mu.Unlock()
	s.recordCommand(state, commandPutScript, name, text)
	_ = writeStatus(conn, Status{Condition: responseOK, Text: "putscript completed"})
}

// handleSetActive marks one script active.
func (s *Server) handleSetActive(conn net.Conn, state *connectionState, line string) {
	name, _, ok := nextArgument(afterFirstToken(line))
	if !ok {
		_ = writeStatus(conn, Status{Condition: responseNo, Code: "CLIENT-BUG", Text: "invalid setactive"})

		return
	}

	state.mu.Lock()
	state.activeScript = name
	state.mu.Unlock()
	s.recordCommand(state, commandSetActive, name, "")
	_ = writeStatus(conn, Status{Condition: responseOK, Text: "setactive completed"})
}

// handleGetScript returns stored script content through the client-visible wire only.
func (s *Server) handleGetScript(conn net.Conn, state *connectionState, line string) {
	name, _, ok := nextArgument(afterFirstToken(line))
	if !ok {
		_ = writeStatus(conn, Status{Condition: responseNo, Code: "CLIENT-BUG", Text: "invalid getscript"})

		return
	}

	state.mu.Lock()
	content, exists := state.scripts[name]
	state.mu.Unlock()
	if !exists {
		_ = writeStatus(conn, Status{Condition: responseNo, Code: "NONEXISTENT", Text: "script missing"})

		return
	}

	s.recordCommand(state, commandGetScript, name, "")
	_, _ = fmt.Fprintf(conn, "{%d}\r\n%s\r\n", len(content), content)
	_ = writeStatus(conn, Status{Condition: responseOK, Text: "getscript completed"})
}

// handleDeleteScript removes a stored script.
func (s *Server) handleDeleteScript(conn net.Conn, state *connectionState, line string) {
	name, _, ok := nextArgument(afterFirstToken(line))
	if !ok {
		_ = writeStatus(conn, Status{Condition: responseNo, Code: "CLIENT-BUG", Text: "invalid deletescript"})

		return
	}

	state.mu.Lock()
	delete(state.scripts, name)
	if state.activeScript == name {
		state.activeScript = ""
	}
	state.mu.Unlock()
	s.recordCommand(state, commandDeleteScript, name, "")
	_ = writeStatus(conn, Status{Condition: responseOK, Text: "deletescript completed"})
}

// writeListScripts renders script names only to the authenticated client stream.
func (s *Server) writeListScripts(conn net.Conn, state *connectionState) {
	state.mu.Lock()
	defer state.mu.Unlock()

	for name := range state.scripts {
		if state.activeScript == name {
			_, _ = fmt.Fprintf(conn, "%q ACTIVE\r\n", name)
			continue
		}
		_, _ = fmt.Fprintf(conn, "%q\r\n", name)
	}
	_ = writeStatus(conn, Status{Condition: responseOK, Text: "listscripts completed"})
}

// writeCapabilities writes an RFC 5804-shaped capability response.
func (s *Server) writeCapabilities(conn net.Conn, state *connectionState, statusText string) error {
	lines := []string{
		"\"IMPLEMENTATION\" \"fake-managesieve-backend\"\r\n",
		"\"VERSION\" \"1.0\"\r\n",
		"\"SASL\" \"PLAIN XOAUTH2 OAUTHBEARER\"\r\n",
		"\"SIEVE\" \"fileinto reject\"\r\n",
	}
	if strings.EqualFold(strings.TrimSpace(s.options.TLSMode), tlsModeStartTLS) && !state.tlsActive && s.options.TLSConfig != nil {
		lines = append(lines, "\"STARTTLS\"\r\n")
	}

	for _, line := range lines {
		if _, err := io.WriteString(conn, line); err != nil {
			return err
		}
	}

	return writeStatus(conn, Status{Condition: responseOK, Text: statusText})
}

// scriptedStatus returns a deterministic override for a command.
func (s *Server) scriptedStatus(command string) (Status, bool) {
	status, ok := s.options.CommandStatus[strings.ToUpper(strings.TrimSpace(command))]
	if !ok {
		return Status{}, false
	}

	return status, true
}

// closes reports whether a scripted status should close the connection.
func (s Status) closes() bool {
	return strings.EqualFold(strings.TrimSpace(s.Condition), responseBye)
}

// recordAuth records only the SASL mechanism, never the initial response.
func (s *Server) recordAuth(state *connectionState, line string) {
	mechanism, _, _ := nextArgument(afterFirstToken(line))
	if mechanism == "" {
		mechanism = "unknown"
	}

	state.mu.Lock()
	state.authMechanisms = append(state.authMechanisms, strings.ToLower(mechanism))
	state.mu.Unlock()
}

// recordCommand stores redacted command facts.
func (s *Server) recordCommand(state *connectionState, command string, scriptName string, content string) {
	observation := CommandObservation{Command: strings.ToUpper(command), ScriptContentBytes: len(content)}
	if strings.TrimSpace(scriptName) != "" {
		expected, ok := s.options.ExpectedScripts[scriptName]
		observation.ScriptNameMatched = ok
		observation.ScriptContentMatched = ok && expected == content
	}

	state.mu.Lock()
	state.commands = append(state.commands, observation)
	state.mu.Unlock()
}

// publishObservation exposes redacted connection observations to tests.
func (s *Server) publishObservation(state *connectionState) {
	state.mu.Lock()
	observation := Observation{
		AuthMechanisms: append([]string(nil), state.authMechanisms...),
		Commands:       append([]CommandObservation(nil), state.commands...),
	}
	state.mu.Unlock()

	if len(observation.AuthMechanisms) == 0 && len(observation.Commands) == 0 {
		return
	}

	s.observations <- observation
}

// consumeProxyProtocolPreface requires one HAProxy PROXY line before protocol bytes.
func (s *Server) consumeProxyProtocolPreface(conn net.Conn) bool {
	header, ok := readProxyProtocolPreface(conn)
	if !ok || !strings.HasPrefix(header, proxyPrefix) {
		s.missingProxyProtocol.Add(1)

		return false
	}

	s.proxyProtocolCount.Add(1)
	s.proxyProtocolHeaders <- header

	return true
}

// readProxyProtocolPreface reads one PROXY line without buffering later bytes.
func readProxyProtocolPreface(conn net.Conn) (string, bool) {
	_ = conn.SetReadDeadline(time.Now().Add(proxyReadTimeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	var builder strings.Builder
	var current [1]byte
	for builder.Len() < proxyReadLimit {
		if _, err := conn.Read(current[:]); err != nil {
			return "", false
		}

		builder.WriteByte(current[0])
		if current[0] == '\n' {
			return builder.String(), true
		}
	}

	return builder.String(), false
}

// writeStatus writes a ManageSieve status response line.
func writeStatus(writer io.Writer, status Status) error {
	condition := strings.ToUpper(strings.TrimSpace(status.Condition))
	if condition == "" {
		condition = responseOK
	}

	var builder strings.Builder
	builder.WriteString(condition)
	if code := strings.TrimSpace(status.Code); code != "" {
		builder.WriteString(" (")
		builder.WriteString(strings.ToUpper(code))
		builder.WriteString(")")
	}
	if text := strings.TrimSpace(status.Text); text != "" {
		builder.WriteByte(' ')
		builder.WriteString(quote(text))
	}
	builder.WriteString("\r\n")

	_, err := io.WriteString(writer, builder.String())

	return err
}

// firstToken returns the upper protocol command without arguments.
func firstToken(line string) string {
	token, _, _ := strings.Cut(strings.TrimSpace(line), " ")

	return token
}

// afterFirstToken returns the argument string after one command token.
func afterFirstToken(line string) string {
	_, rest, ok := strings.Cut(strings.TrimSpace(line), " ")
	if !ok {
		return ""
	}

	return rest
}

// nextArgument parses one ManageSieve atom or quoted string.
func nextArgument(input string) (string, string, bool) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", "", false
	}

	if input[0] != '"' {
		value, rest, _ := strings.Cut(input, " ")

		return value, rest, true
	}

	var builder strings.Builder
	escaped := false
	for index := 1; index < len(input); index++ {
		char := input[index]
		if escaped {
			builder.WriteByte(char)
			escaped = false

			continue
		}
		if char == '\\' {
			escaped = true

			continue
		}
		if char == '"' {
			return builder.String(), input[index+1:], true
		}
		builder.WriteByte(char)
	}

	return "", "", false
}

// literalSize parses a final ManageSieve literal marker.
func literalSize(input string) (int, bool) {
	input = strings.TrimSpace(input)
	if !strings.HasPrefix(input, "{") || !strings.HasSuffix(input, "}") {
		return 0, false
	}

	size, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(input, "{"), "}"))
	if err != nil || size < 0 {
		return 0, false
	}

	return size, true
}

// consumeOptionalCRLF consumes the command terminator after a literal payload.
func consumeOptionalCRLF(reader *bufio.Reader) {
	if reader.Buffered() < 2 {
		return
	}

	next, err := reader.Peek(2)
	if err == nil && string(next) == "\r\n" {
		_, _ = reader.Discard(2)
	}
}

// quote renders a safe ManageSieve quoted string.
func quote(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")

	return "\"" + value + "\""
}

// cloneOptions detaches mutable option maps from callers.
func cloneOptions(options Options) Options {
	cloned := options
	cloned.CommandStatus = make(map[string]Status, len(options.CommandStatus))
	for command, status := range options.CommandStatus {
		cloned.CommandStatus[strings.ToUpper(strings.TrimSpace(command))] = status
	}
	cloned.ExpectedScripts = make(map[string]string, len(options.ExpectedScripts))
	maps.Copy(cloned.ExpectedScripts, options.ExpectedScripts)
	if options.TLSConfig != nil {
		cloned.TLSConfig = options.TLSConfig.Clone()
	}

	return cloned
}
