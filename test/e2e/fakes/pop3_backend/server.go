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

// Package pop3backend provides a deterministic public-socket POP3 backend for E2E tests.
//
//nolint:goconst,gocyclo,funlen,wsl_v5 // The fake backend keeps POP3 transcripts compact and reviewable.
package pop3backend

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	commandAuth = "AUTH"
	commandCapa = "CAPA"
	commandDele = "DELE"
	commandList = "LIST"
	commandNoop = "NOOP"
	commandPass = "PASS"
	commandQuit = "QUIT"
	commandRetr = "RETR"
	commandRset = "RSET"
	commandStat = "STAT"
	commandSTLS = "STLS"
	commandUIDL = "UIDL"
	commandUser = "USER"

	responseErr = "-ERR"
	responseOK  = "+OK"

	tlsModeImplicit  = "implicit"
	tlsModeStartTLS  = "starttls"
	proxyPrefix      = "PROXY "
	proxyReadTimeout = 500 * time.Millisecond
	proxyReadLimit   = 256
)

// Status configures one deterministic command response.
type Status struct {
	Code string
	Text string
}

// Message configures one deterministic fake maildrop entry.
type Message struct {
	Number  int
	UIDL    string
	Content string
}

// Options configures one fake POP3 backend instance.
type Options struct {
	CommandStatus        map[string]Status
	Messages             []Message
	RequireProxyProtocol bool
	TLSConfig            *tls.Config
	TLSMode              string
}

// Observation records backend activity without raw mailbox or credential data.
type Observation struct {
	AuthMechanisms       []string
	Commands             []string
	MessageNumberMatched bool
	UIDLMatched          bool
	ContentMatched       bool
	CredentialSeen       bool
}

// Server owns one fake POP3 backend listener.
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
	authMechanisms       []string
	commands             []string
	messageNumberMatched bool
	uidlMatched          bool
	contentMatched       bool
	credentialSeen       bool
	tlsActive            bool
	provisionalUser      string
	authenticated        bool
}

// Start binds a public loopback POP3 backend socket.
func Start(t testing.TB, options Options) *Server {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake POP3 backend: %v", err)
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
		t.Fatal("timed out waiting for fake POP3 backend observation")
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
		t.Fatal("timed out waiting for fake POP3 backend PROXY protocol header")
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

// serve executes one minimal POP3 backend session.
func (s *Server) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	s.connections.Add(1)
	state := &connectionState{tlsActive: strings.EqualFold(strings.TrimSpace(s.options.TLSMode), tlsModeImplicit)}

	prepared, ok := s.prepare(conn)
	if !ok {
		return
	}
	conn = prepared
	reader := bufio.NewReader(conn)
	defer s.publishObservation(state)

	if _, err := io.WriteString(conn, "+OK fake POP3 backend ready\r\n"); err != nil {
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

// consumeProxyProtocolPreface requires one HAProxy PROXY line before POP3 bytes.
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

// handleLine dispatches one POP3 backend command.
func (s *Server) handleLine(
	conn net.Conn,
	reader *bufio.Reader,
	state *connectionState,
	line string,
) (net.Conn, *bufio.Reader, bool) {
	name, args := parseCommand(line)
	if state.authenticated {
		state.commands = append(state.commands, name)
	}

	if status, ok := s.statusFor(name); ok && !status.OK() {
		_, _ = io.WriteString(conn, status.Line()+"\r\n")

		return conn, reader, strings.EqualFold(name, commandQuit)
	}

	switch name {
	case commandCapa:
		s.writeCapabilities(conn, state)
	case commandSTLS:
		upgraded, upgradedReader, done := s.handleStartTLS(conn)
		if !done {
			state.tlsActive = true
		}

		return upgraded, upgradedReader, done
	case commandUser:
		state.credentialSeen = true
		state.provisionalUser = strings.TrimSpace(args)
		_, _ = io.WriteString(conn, "+OK user accepted\r\n")
	case commandPass:
		state.credentialSeen = true
		state.authenticated = true
		state.authMechanisms = append(state.authMechanisms, "userpass")
		_, _ = io.WriteString(conn, "+OK authentication accepted\r\n")
	case commandAuth:
		state.credentialSeen = true
		state.authenticated = true
		state.authMechanisms = append(state.authMechanisms, authMechanism(args))
		_, _ = io.WriteString(conn, "+OK authentication accepted\r\n")
	case commandStat:
		_, _ = fmt.Fprintf(conn, "+OK %d %d\r\n", len(s.messages()), s.totalSize())
	case commandList:
		s.writeLIST(conn, args)
	case commandUIDL:
		s.writeUIDL(conn, state, args)
	case commandRetr:
		s.writeRETR(conn, state, args)
	case commandDele:
		s.noteMessageNumber(state, args)
		_, _ = io.WriteString(conn, "+OK message deleted\r\n")
	case commandRset:
		_, _ = io.WriteString(conn, "+OK deletion marks cleared\r\n")
	case commandNoop:
		_, _ = io.WriteString(conn, "+OK noop\r\n")
	case commandQuit:
		_, _ = io.WriteString(conn, "+OK goodbye\r\n")

		return conn, reader, true
	default:
		_, _ = io.WriteString(conn, "-ERR unsupported\r\n")
	}

	return conn, reader, false
}

// handleStartTLS upgrades a backend stream after a successful STLS response.
func (s *Server) handleStartTLS(conn net.Conn) (net.Conn, *bufio.Reader, bool) {
	if s.options.TLSConfig == nil || !strings.EqualFold(strings.TrimSpace(s.options.TLSMode), tlsModeStartTLS) {
		_, _ = io.WriteString(conn, "-ERR STLS unavailable\r\n")

		return conn, bufio.NewReader(conn), false
	}

	_, _ = io.WriteString(conn, "+OK begin TLS\r\n")
	tlsConn := tls.Server(conn, s.options.TLSConfig.Clone())
	if err := tlsConn.Handshake(); err != nil {
		return conn, bufio.NewReader(conn), true
	}

	return tlsConn, bufio.NewReader(tlsConn), false
}

// writeCapabilities renders a bounded fake POP3 CAPA response.
func (s *Server) writeCapabilities(conn net.Conn, state *connectionState) {
	_, _ = io.WriteString(conn, "+OK capability list follows\r\n")
	if strings.EqualFold(strings.TrimSpace(s.options.TLSMode), tlsModeStartTLS) && !state.tlsActive && s.options.TLSConfig != nil {
		_, _ = io.WriteString(conn, "STLS\r\n")
	}
	_, _ = io.WriteString(conn, "USER\r\n")
	_, _ = io.WriteString(conn, "SASL XOAUTH2 OAUTHBEARER\r\n")
	_, _ = io.WriteString(conn, "UIDL\r\n")
	_, _ = io.WriteString(conn, "TOP\r\n")
	_, _ = io.WriteString(conn, ".\r\n")
}

// writeLIST writes deterministic message sizes without storing frontend data.
func (s *Server) writeLIST(conn net.Conn, arg string) {
	if strings.TrimSpace(arg) != "" {
		message, ok := s.messageByNumber(arg)
		if !ok {
			_, _ = io.WriteString(conn, "-ERR no such message\r\n")

			return
		}

		_, _ = fmt.Fprintf(conn, "+OK %d %d\r\n", message.Number, len(message.Content))

		return
	}

	_, _ = io.WriteString(conn, "+OK scan listing follows\r\n")
	for _, message := range s.messages() {
		_, _ = fmt.Fprintf(conn, "%d %d\r\n", message.Number, len(message.Content))
	}
	_, _ = io.WriteString(conn, ".\r\n")
}

// writeUIDL writes deterministic UIDLs and records only whether a sentinel was served.
func (s *Server) writeUIDL(conn net.Conn, state *connectionState, arg string) {
	if strings.TrimSpace(arg) != "" {
		message, ok := s.messageByNumber(arg)
		if !ok {
			_, _ = io.WriteString(conn, "-ERR no such message\r\n")

			return
		}

		state.messageNumberMatched = true
		state.uidlMatched = true
		_, _ = fmt.Fprintf(conn, "+OK %d %s\r\n", message.Number, message.UIDL)

		return
	}

	state.uidlMatched = true
	_, _ = io.WriteString(conn, "+OK uidl listing follows\r\n")
	for _, message := range s.messages() {
		_, _ = fmt.Fprintf(conn, "%d %s\r\n", message.Number, message.UIDL)
	}
	_, _ = io.WriteString(conn, ".\r\n")
}

// writeRETR writes deterministic message content and records only that content was served.
func (s *Server) writeRETR(conn net.Conn, state *connectionState, arg string) {
	message, ok := s.messageByNumber(arg)
	if !ok {
		_, _ = io.WriteString(conn, "-ERR no such message\r\n")

		return
	}

	state.messageNumberMatched = true
	state.contentMatched = true
	_, _ = io.WriteString(conn, "+OK message follows\r\n")
	_, _ = io.WriteString(conn, message.Content+"\r\n")
	_, _ = io.WriteString(conn, ".\r\n")
}

// messages returns configured messages or a safe default maildrop.
func (s *Server) messages() []Message {
	if len(s.options.Messages) > 0 {
		return s.options.Messages
	}

	return []Message{{Number: 1, UIDL: "fake-pop3-uidl-1", Content: "fake POP3 body"}}
}

// totalSize returns the deterministic total fake maildrop size.
func (s *Server) totalSize() int {
	var total int
	for _, message := range s.messages() {
		total += len(message.Content)
	}

	return total
}

// messageByNumber finds a message by POP3 number.
func (s *Server) messageByNumber(arg string) (Message, bool) {
	number, err := strconv.Atoi(strings.TrimSpace(arg))
	if err != nil {
		return Message{}, false
	}

	for _, message := range s.messages() {
		if message.Number == number {
			return message, true
		}
	}

	return Message{}, false
}

// noteMessageNumber records that a post-auth message number command reached the backend.
func (s *Server) noteMessageNumber(state *connectionState, arg string) {
	if _, ok := s.messageByNumber(arg); ok {
		state.messageNumberMatched = true
	}
}

// statusFor returns deterministic override status for a command.
func (s *Server) statusFor(command string) (Status, bool) {
	status, ok := s.options.CommandStatus[strings.ToUpper(strings.TrimSpace(command))]

	return status, ok
}

// publishObservation reports redacted facts for the completed backend session.
func (s *Server) publishObservation(state *connectionState) {
	if state == nil {
		return
	}

	s.observations <- Observation{
		AuthMechanisms:       append([]string(nil), state.authMechanisms...),
		Commands:             append([]string(nil), state.commands...),
		MessageNumberMatched: state.messageNumberMatched,
		UIDLMatched:          state.uidlMatched,
		ContentMatched:       state.contentMatched,
		CredentialSeen:       state.credentialSeen,
	}
}

// OK reports whether a status is an accepting POP3 status line.
func (s Status) OK() bool {
	return strings.EqualFold(strings.TrimSpace(s.Code), responseOK) || strings.TrimSpace(s.Code) == ""
}

// Line renders a bounded deterministic POP3 status line.
func (s Status) Line() string {
	code := strings.TrimSpace(s.Code)
	if code == "" {
		code = responseOK
	}
	if !strings.HasPrefix(code, responseOK) && !strings.HasPrefix(code, responseErr) {
		code = responseErr
	}
	text := strings.TrimSpace(s.Text)
	if text == "" {
		text = "scripted status"
	}

	return code + " " + text
}

// parseCommand splits one POP3 command line into command and argument text.
func parseCommand(line string) (string, string) {
	line = strings.TrimRight(line, "\r\n")
	command, args, _ := strings.Cut(line, " ")

	return strings.ToUpper(strings.TrimSpace(command)), strings.TrimSpace(args)
}

// authMechanism returns a redacted backend auth mechanism label.
func authMechanism(args string) string {
	mechanism, _, _ := strings.Cut(strings.TrimSpace(args), " ")
	mechanism = strings.ToLower(strings.TrimSpace(mechanism))
	if mechanism == "" {
		return "unknown"
	}

	return mechanism
}

// readProxyProtocolPreface reads one HAProxy PROXY line before POP3 state starts.
func readProxyProtocolPreface(conn net.Conn) (string, bool) {
	_ = conn.SetReadDeadline(time.Now().Add(proxyReadTimeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	reader := bufio.NewReaderSize(conn, proxyReadLimit)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", false
	}

	return strings.TrimRight(line, "\r\n"), true
}

// cloneOptions detaches mutable option maps and slices.
func cloneOptions(options Options) Options {
	cloned := options
	if options.CommandStatus != nil {
		cloned.CommandStatus = make(map[string]Status, len(options.CommandStatus))
		for command, status := range options.CommandStatus {
			cloned.CommandStatus[strings.ToUpper(strings.TrimSpace(command))] = status
		}
	}
	cloned.Messages = append([]Message(nil), options.Messages...)
	cloned.TLSConfig = cloneTLSConfig(options.TLSConfig)

	return cloned
}

// cloneTLSConfig detaches caller-owned TLS configuration.
func cloneTLSConfig(config *tls.Config) *tls.Config {
	if config == nil {
		return nil
	}

	return config.Clone()
}

// BearerPayload renders a simple backend-test SASL bearer payload.
func BearerPayload(username string, token string) string {
	payload := "user=" + username + "\x01auth=Bearer " + token + "\x01\x01"

	return base64.StdEncoding.EncodeToString([]byte(payload))
}
