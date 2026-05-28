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
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/routing"
	"github.com/croessner/nauthilus-director/internal/state"
)

const (
	capabilityAUTH     = "AUTH"
	capabilityCHUNKING = "CHUNKING"
	capabilitySMTPUTF8 = "SMTPUTF8"
	capabilitySTARTTLS = "STARTTLS"

	identitySourceDNSName           = "dns_san"
	identitySourceSubjectCommonName = "subject_common_name"
	identitySourceURI               = "uri_san"

	maxSafePeerIdentityBytes = 256
)

// Session owns one accepted LMTP frontend stream.
type Session struct {
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer

	authenticator     nauthilus.Authenticator
	identityLookuper  nauthilus.IdentityLookuper
	messageSink       MessageSink
	backendConnector  BackendConnector
	frontendTLSConfig *tls.Config

	listenerName           string
	authorityName          string
	authorityTransport     string
	serviceName            string
	network                string
	backendPool            string
	directorInstanceID     string
	defaultTenant          string
	defaultShard           string
	tlsMode                string
	configuredCapabilities []string
	peerAuthMechanisms     []string
	mtlsPeerAuth           MTLSPeerAuthConfig

	preauthTimeout             time.Duration
	authTimeout                time.Duration
	backendConnectTimeout      time.Duration
	sessionLeaseTTL            time.Duration
	sessionIdleGrace           time.Duration
	maxLineBytes               int
	maxBearerTokenBytes        int
	requirePeerAuth            bool
	requireTLSClientCert       bool
	backendChunkingAllowed     bool
	recipientPlacementRequired bool
	routingResolver            routing.RoutingResolver
	sessionStore               state.SessionStore
	backendSelector            backend.Selector

	tlsActive             bool
	tlsClientVerified     bool
	tlsClientCommonName   string
	lhloSeen              bool
	peerAuthenticated     bool
	peerAuthMethod        string
	peerIdentity          string
	effectiveCapabilities []string
	chunkingAdvertised    bool
	transaction           transactionState
}

type transactionState struct {
	mailSeen       bool
	mailFrom       string
	smtpUTF8       bool
	recipientCount int
	recipients     []RecipientPlacement
	body           MessageBody
	backend        *backendTransaction
}

type commandOutcome struct {
	closeSession bool
	flushed      bool
}

// NewSession creates a bounded LMTP session context for an accepted connection.
func NewSession(config SessionConfig, conn net.Conn) (*Session, error) {
	if conn == nil {
		return nil, errNilSessionConnection
	}

	maxLineBytes := effectiveMaxLineBytes(config.MaxLineBytes)

	messageSink := config.MessageSink
	if messageSink == nil && config.BackendConnector == nil {
		messageSink = discardMessageSink{}
	}

	return &Session{
		conn:                       conn,
		reader:                     bufio.NewReaderSize(conn, maxLineBytes+1),
		writer:                     bufio.NewWriter(conn),
		authenticator:              config.Authenticator,
		identityLookuper:           config.IdentityLookuper,
		messageSink:                messageSink,
		backendConnector:           config.BackendConnector,
		frontendTLSConfig:          cloneTLSConfig(config.FrontendTLSConfig),
		listenerName:               config.ListenerName,
		authorityName:              config.AuthorityName,
		authorityTransport:         config.AuthorityTransport,
		serviceName:                config.ServiceName,
		network:                    config.Network,
		backendPool:                config.BackendPool,
		directorInstanceID:         config.DirectorInstanceID,
		defaultTenant:              defaultLookupTenant(config.DefaultTenant),
		defaultShard:               defaultLookupShard(config.DefaultShard),
		tlsMode:                    config.TLSMode,
		configuredCapabilities:     append([]string(nil), config.Capabilities...),
		peerAuthMechanisms:         append([]string(nil), config.PeerAuthMechanisms...),
		mtlsPeerAuth:               config.MTLSPeerAuth,
		preauthTimeout:             config.PreauthTimeout,
		authTimeout:                config.AuthTimeout,
		backendConnectTimeout:      config.BackendConnectTimeout,
		sessionLeaseTTL:            defaultDeliveryLease(config.SessionLeaseTTL),
		sessionIdleGrace:           defaultDeliveryGrace(config.SessionIdleGrace, config.SessionLeaseTTL),
		maxLineBytes:               maxLineBytes,
		maxBearerTokenBytes:        config.MaxBearerTokenBytes,
		requirePeerAuth:            config.RequirePeerAuth,
		requireTLSClientCert:       config.RequireTLSClientCert,
		backendChunkingAllowed:     config.BackendChunkingAllowed,
		recipientPlacementRequired: config.RecipientLookupRequired,
		routingResolver:            config.RoutingResolver,
		sessionStore:               config.SessionStore,
		backendSelector:            config.BackendSelector,
		tlsActive:                  config.TLSMode == TLSModeImplicit,
	}, nil
}

// Serve writes the greeting and processes LMTP commands in wire order.
func (s *Session) Serve(ctx context.Context) error {
	if err := s.startSession(); err != nil {
		return err
	}

	for {
		closeSession, err := s.serveNextCommand(ctx)
		if err != nil {
			return err
		}

		if closeSession {
			return nil
		}
	}
}

// startSession applies initial deadlines, sends the greeting and evaluates implicit mTLS state.
func (s *Session) startSession() error {
	if err := s.applyPreauthDeadline(); err != nil {
		return err
	}

	if s.tlsActive {
		s.refreshMTLSPeerAuth()
	}

	if err := s.writeGreeting(); err != nil {
		return err
	}

	return s.writer.Flush()
}

// serveNextCommand reads and dispatches one command while preserving cleanup behavior.
func (s *Session) serveNextCommand(ctx context.Context) (bool, error) {
	if err := s.contextError(ctx); err != nil {
		return false, err
	}

	line, err := s.readLine()
	if err != nil {
		if err == io.EOF {
			s.resetTransaction(ctx, "eof")

			return true, nil
		}

		return false, s.handleReadError(ctx, err)
	}

	closeSession, err := s.processLine(ctx, line)
	if err != nil {
		s.resetTransaction(ctx, "command_error")

		return false, err
	}

	return closeSession, nil
}

// contextError aborts any active body when the session context is done.
func (s *Session) contextError(ctx context.Context) error {
	select {
	case <-ctx.Done():
		s.resetTransaction(ctx, "context")

		return ctx.Err()
	default:
		return nil
	}
}

// handleReadError maps bounded read failures and aborts any active message body.
func (s *Session) handleReadError(ctx context.Context, err error) error {
	if err == ErrLineTooLarge || err == ErrPartialCommand {
		_ = s.writeEnhanced(responseStatusSyntax, enhancedSyntax, commandSyntaxText)
		_ = s.writer.Flush()
	}

	s.resetTransaction(ctx, "read_error")

	return err
}

// TLSActive reports whether the session has crossed an implicit or STARTTLS boundary.
func (s *Session) TLSActive() bool {
	return s.tlsActive
}

// PeerAuthenticated reports whether SASL or explicit verified mTLS satisfied peer auth.
func (s *Session) PeerAuthenticated() bool {
	return s.peerAuthenticated
}

// PeerIdentity returns the bounded submitter identity recorded for peer auth.
func (s *Session) PeerIdentity() string {
	return s.peerIdentity
}

// applyPreauthDeadline sets the initial session read/write deadline.
func (s *Session) applyPreauthDeadline() error {
	if s.preauthTimeout <= 0 {
		return nil
	}

	return s.conn.SetDeadline(time.Now().Add(s.preauthTimeout))
}

// processLine parses and dispatches one command line.
func (s *Session) processLine(ctx context.Context, line []byte) (bool, error) {
	command, err := parseFrontendCommand(line, s.maxLineBytes)
	if err != nil {
		if writeErr := s.writeEnhanced(responseStatusSyntax, enhancedSyntax, commandSyntaxText); writeErr != nil {
			return false, writeErr
		}

		if flushErr := s.writer.Flush(); flushErr != nil {
			return false, flushErr
		}

		return false, nil
	}

	outcome, err := s.handleCommand(ctx, command)
	if !outcome.flushed {
		if flushErr := s.writer.Flush(); flushErr != nil {
			return false, flushErr
		}
	}

	return outcome.closeSession, err
}

// effectiveCapabilitySet computes the capabilities that are both configured and currently safe.
func (s *Session) effectiveCapabilitySet() []string {
	capabilities := make([]string, 0, len(s.configuredCapabilities))
	seen := make(map[string]struct{}, len(s.configuredCapabilities))

	for _, configured := range s.configuredCapabilities {
		capability := s.effectiveCapability(configured)
		if capability == "" {
			continue
		}

		if _, exists := seen[capability]; exists {
			continue
		}

		seen[capability] = struct{}{}
		capabilities = append(capabilities, capability)
	}

	return capabilities
}

// effectiveCapability returns one configured capability only when implemented and safe now.
func (s *Session) effectiveCapability(configured string) string {
	fields := strings.Fields(strings.ToUpper(strings.TrimSpace(configured)))
	if len(fields) == 0 {
		return ""
	}

	switch fields[0] {
	case capabilitySMTPUTF8:
		return capabilitySMTPUTF8
	case capabilitySTARTTLS:
		if s.startTLSPermitted() {
			return capabilitySTARTTLS
		}

		return ""
	case capabilityAUTH:
		return s.authCapability(strings.Join(fields, " "))
	case capabilityCHUNKING:
		if s.backendChunkingAllowed {
			return capabilityCHUNKING
		}

		return ""
	default:
		return ""
	}
}

// refreshMTLSPeerAuth evaluates explicit verified client-certificate peer auth.
func (s *Session) refreshMTLSPeerAuth() {
	if !s.requirePeerAuth || !s.mtlsPeerAuth.SatisfiesRequired || !s.requireTLSClientCert {
		return
	}

	state, ok := s.connectionState()
	if !ok || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return
	}

	cert := state.PeerCertificates[0]

	identity := certificateIdentity(cert, s.mtlsPeerAuth.IdentitySource)
	if identity == "" {
		return
	}

	s.tlsClientVerified = true
	s.tlsClientCommonName = boundedSafeIdentity(cert.Subject.CommonName)
	s.peerAuthenticated = true
	s.peerAuthMethod = "mtls"
	s.peerIdentity = identity
}

// connectionState returns TLS metadata from connections that expose it.
func (s *Session) connectionState() (tls.ConnectionState, bool) {
	type tlsStateConn interface {
		ConnectionState() tls.ConnectionState
	}

	tlsConn, ok := s.conn.(tlsStateConn)
	if !ok {
		return tls.ConnectionState{}, false
	}

	return tlsConn.ConnectionState(), true
}

// certificateIdentity extracts the configured bounded submitter identity from a verified cert.
func certificateIdentity(cert *x509.Certificate, source string) string {
	if cert == nil {
		return ""
	}

	switch strings.ToLower(strings.TrimSpace(source)) {
	case identitySourceSubjectCommonName:
		return boundedSafeIdentity(cert.Subject.CommonName)
	case identitySourceDNSName:
		if len(cert.DNSNames) == 0 {
			return ""
		}

		return boundedSafeIdentity(cert.DNSNames[0])
	case identitySourceURI:
		if len(cert.URIs) == 0 || cert.URIs[0] == nil {
			return ""
		}

		return boundedSafeIdentity(cert.URIs[0].String())
	default:
		return ""
	}
}

// boundedSafeIdentity removes unsafe controls and enforces the peer-identity bound.
func boundedSafeIdentity(value string) string {
	value = strings.TrimSpace(replaceResponseControls(value))
	if value == "" {
		return ""
	}

	value = strings.Join(strings.Fields(value), " ")

	return truncateResponseText(value, maxSafePeerIdentityBytes)
}

// active reports whether any transaction state is currently present.
func (t *transactionState) active() bool {
	return t.mailSeen || t.recipientCount > 0 || len(t.recipients) > 0 || t.body != nil
}

// snapshot returns bounded transaction facts for streaming sinks.
func (t *transactionState) snapshot() TransactionSnapshot {
	recipients := make([]RecipientSnapshot, 0, len(t.recipients))
	for _, recipient := range t.recipients {
		recipients = append(recipients, RecipientSnapshot{
			WirePath:          recipient.Recipient.WirePath,
			AccountKey:        recipient.AccountKey,
			Tenant:            recipient.Tenant,
			ShardTag:          recipient.SelectedShardTag,
			BackendIdentifier: recipient.Backend.Backend.Identifier,
		})
	}

	return TransactionSnapshot{RecipientCount: t.recipientCount, Recipients: recipients}
}

// reset clears command sequencing state without touching protocol auth state.
func (t *transactionState) reset() {
	t.mailSeen = false
	t.mailFrom = ""
	t.smtpUTF8 = false
	t.recipientCount = 0
	t.recipients = nil
	t.body = nil
	t.backend = nil
}

// acceptsBackend reports whether a recipient can join the current transaction.
func (t *transactionState) acceptsBackend(identifier string) bool {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return false
	}

	for _, recipient := range t.recipients {
		existing := strings.TrimSpace(recipient.Backend.Backend.Identifier)
		if existing == "" {
			continue
		}

		return existing == identifier
	}

	return true
}

// abortActiveBody aborts any open DATA or BDAT sink.
func (s *Session) abortActiveBody(ctx context.Context, reasonClass string) error {
	if s.transaction.body == nil {
		return nil
	}

	body := s.transaction.body
	s.transaction.body = nil

	return body.Abort(ctx, reasonClass)
}

// resetTransaction releases all transaction-owned frontend, backend and lease state.
func (s *Session) resetTransaction(ctx context.Context, reasonClass string) {
	_ = s.abortActiveBody(ctx, reasonClass)
	s.closeBackendTransaction(reasonClass)
	s.closeTransactionHolds(ctx)
	s.transaction.reset()
}

type discardMessageSink struct{}

type discardMessageBody struct{}

// OpenMessage returns a discard writer for frontend-only LMTP state-machine tests.
func (discardMessageSink) OpenMessage(context.Context, TransactionSnapshot) (MessageBody, error) {
	return discardMessageBody{}, nil
}

// Write discards opaque message payload bytes.
func (discardMessageBody) Write(payload []byte) (int, error) {
	return len(payload), nil
}

// Finish reports a successful frontend-only message completion.
func (discardMessageBody) Finish(context.Context) (MessageResult, error) {
	return MessageResult{Status: responseStatusOK, Text: dataQueuedText}, nil
}

// Abort releases the discard body without retaining content.
func (discardMessageBody) Abort(context.Context, string) error {
	return nil
}
