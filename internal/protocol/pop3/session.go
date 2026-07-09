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

//nolint:wsl_v5 // Session construction keeps runtime defaults grouped for auditability.
package pop3

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/placement"
	"github.com/croessner/nauthilus-director/internal/protocol/greeting"
	"github.com/croessner/nauthilus-director/internal/proxy"
	"github.com/croessner/nauthilus-director/internal/routing"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
)

const (
	// ImplementationName is the stable POP3 implementation product name.
	ImplementationName = "nauthilus-director"
	// ProtocolPOP3 is the canonical director protocol value for POP3.
	ProtocolPOP3 = "pop3"
	// TLSModeImplicit marks POP3-over-TLS listeners where TLS is active before greeting.
	TLSModeImplicit = "implicit"
	// TLSModeStartTLS marks cleartext POP3 listeners where STLS may be advertised.
	TLSModeStartTLS = "starttls"

	defaultMaxLineBytes    = 8192
	defaultMaxLiteralBytes = 8192
	defaultMaxBearerBytes  = 8192
	defaultAuthCallTimeout = time.Second
	defaultSessionLeaseTTL = time.Minute
)

var (
	// ErrPreauthLineTooLarge reports that pre-auth input exceeded the configured line boundary.
	ErrPreauthLineTooLarge = errors.New("pop3: preauth line exceeds configured limit")
	// ErrPreauthLiteralTooLarge reports that a continuation payload exceeded the configured boundary.
	ErrPreauthLiteralTooLarge = errors.New("pop3: preauth literal exceeds configured limit")
	// ErrPreauthPartialCommand reports a connection closed before a command line was complete.
	ErrPreauthPartialCommand = errors.New("pop3: partial preauth command")
)

// Session owns one accepted POP3 frontend stream through the authorization boundary.
type Session struct {
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer

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
	authMechanisms         []string
	capabilities           []string
	preauthTimeout         time.Duration
	authTimeout            time.Duration
	maxPreauthLineBytes    int
	maxPreauthLiteralBytes int
	maxBearerTokenBytes    int
	frontendTLSConfig      *tls.Config
	authenticator          nauthilus.Authenticator
	bearerIntrospector     nauthilus.BearerIntrospector
	routingResolver        routing.RoutingResolver
	placementService       placement.SessionPlacer
	placementGate          runtimectl.PlacementGate
	sessionLeaseTTL        time.Duration
	sessionIdleGrace       time.Duration
	backendRetentionTTL    time.Duration
	backendConnectTimeout  time.Duration
	proxyIdleTimeout       time.Duration
	backendConnector       BackendConnector
	proxyRunner            proxy.Runner
	localSessions          *runtimectl.LocalSessionRegistry
	observability          observability.Recorder
	greetingPolicy         greeting.Policy

	tlsActive       bool
	provisionalUser string
	authAttempts    uint
	sessionID       string
	placement       Placement
	placementLease  placement.LeaseHandle
	placed          bool
}

// NewSession creates a bounded POP3 authorization-state session for an accepted connection.
func NewSession(config SessionConfig, conn net.Conn) (*Session, error) {
	if conn == nil {
		return nil, errors.New("pop3: session connection is nil")
	}

	sessionID, err := newSessionID()
	if err != nil {
		return nil, err
	}

	maxLineBytes := effectivePositive(config.MaxPreauthLineBytes, defaultMaxLineBytes)
	maxLiteralBytes := effectivePositive(config.MaxPreauthLiteralBytes, defaultMaxLiteralBytes)
	maxBearerBytes := effectivePositive(config.MaxBearerTokenBytes, defaultMaxBearerBytes)
	leaseTTL := defaultSessionLease(config.SessionLeaseTTL)
	backendConnector := config.BackendConnector
	if backendConnector == nil {
		backendConnector = NewTCPBackendConnector(nil)
	}
	proxyRunner := config.ProxyRunner
	if proxyRunner == nil {
		proxyRunner = proxy.NewPipe()
	}

	return &Session{
		conn:                   conn,
		reader:                 bufio.NewReaderSize(conn, maxLineBytes+1),
		writer:                 bufio.NewWriter(conn),
		listenerName:           strings.TrimSpace(config.ListenerName),
		authorityName:          strings.TrimSpace(config.AuthorityName),
		authorityTransport:     strings.TrimSpace(config.AuthorityTransport),
		serviceName:            strings.TrimSpace(config.ServiceName),
		network:                strings.TrimSpace(config.Network),
		backendPool:            strings.TrimSpace(config.BackendPool),
		directorInstanceID:     strings.TrimSpace(config.DirectorInstanceID),
		defaultTenant:          defaultTenant(config.DefaultTenant),
		defaultShard:           defaultShard(config.DefaultShard),
		tlsMode:                strings.TrimSpace(config.TLSMode),
		authMechanisms:         cloneStrings(config.AuthMechanisms),
		capabilities:           cloneStrings(config.Capabilities),
		preauthTimeout:         config.PreauthTimeout,
		authTimeout:            effectiveDuration(config.AuthTimeout, defaultAuthCallTimeout),
		maxPreauthLineBytes:    maxLineBytes,
		maxPreauthLiteralBytes: maxLiteralBytes,
		maxBearerTokenBytes:    maxBearerBytes,
		frontendTLSConfig:      cloneTLSConfig(config.FrontendTLSConfig),
		authenticator:          config.Authenticator,
		bearerIntrospector:     config.BearerIntrospector,
		routingResolver:        config.RoutingResolver,
		placementService:       config.PlacementService,
		placementGate:          config.PlacementGate,
		sessionLeaseTTL:        leaseTTL,
		sessionIdleGrace:       defaultSessionGrace(config.SessionIdleGrace, config.SessionLeaseTTL),
		backendRetentionTTL:    config.BackendRetentionTTL,
		backendConnectTimeout:  config.BackendConnectTimeout,
		proxyIdleTimeout:       defaultProxyIdleTimeout(config.ProxyIdleTimeout, leaseTTL),
		backendConnector:       backendConnector,
		proxyRunner:            proxyRunner,
		localSessions:          config.LocalSessions,
		observability:          observability.NormalizeRecorder(config.Observability),
		greetingPolicy:         config.GreetingPolicy,
		tlsActive:              strings.EqualFold(strings.TrimSpace(config.TLSMode), TLSModeImplicit),
		sessionID:              sessionID,
	}, nil
}

// Placement returns the director-owned placement facts after shared placement succeeds.
func (s *Session) Placement() (Placement, bool) {
	if s == nil || !s.placed {
		return Placement{}, false
	}

	return s.placement.Clone(), true
}

// Serve writes the greeting and processes authorization-state commands in wire order.
func (s *Session) Serve(ctx context.Context) (err error) {
	ctx, sessionSpan := s.startObservationSpan(ctx, observability.TraceBoundarySession, pop3ObservationOperationSession, pop3ObservationResultStart, "", nil)
	ctx, preAuthSpan := s.startObservationSpan(ctx, observability.TraceBoundaryPOP3PreAuth, pop3ObservationOperationPreAuth, pop3ObservationResultStart, "", nil)

	s.recordSessionStart(ctx)
	defer func() {
		s.recordSessionEnd(ctx, err)
		preAuthSpan.End(pop3ResultLabel(err), pop3ReasonClass(err))
		sessionSpan.End(pop3ResultLabel(err), pop3ReasonClass(err))
	}()

	if err := s.applyPreauthDeadline(); err != nil {
		return err
	}

	if err := s.writeGreeting(); err != nil {
		s.recordGreeting(ctx, pop3ObservationResultFailure, pop3ReasonClass(err))

		return err
	}

	if err := s.writer.Flush(); err != nil {
		s.recordGreeting(ctx, pop3ObservationResultFailure, pop3ReasonClass(err))

		return err
	}

	s.recordGreeting(ctx, pop3ObservationResultOK, pop3ReasonOK)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		closeSession, err := s.serveNextCommand(ctx)
		if err != nil {
			return err
		}

		if closeSession {
			return nil
		}
	}
}

// TLSActive reports whether the session has crossed an implicit TLS or STLS boundary.
func (s *Session) TLSActive() bool {
	if s == nil {
		return false
	}

	return s.tlsActive
}

// ProvisionalUser returns the short-lived USER value kept before Nauthilus accepts credentials.
func (s *Session) ProvisionalUser() string {
	if s == nil {
		return ""
	}

	return s.provisionalUser
}

// serveNextCommand reads and dispatches one authorization-state command.
func (s *Session) serveNextCommand(ctx context.Context) (bool, error) {
	command, closeSession, dispatch, err := s.readCommand(ctx)
	if closeSession || err != nil || !dispatch {
		return closeSession, err
	}

	return s.dispatchCommand(ctx, command)
}

// readCommand reads, parses and resolves one POP3 command from the frontend stream.
func (s *Session) readCommand(ctx context.Context) (preauthCommand, bool, bool, error) {
	line, err := s.readPreauthLine()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return preauthCommand{}, true, false, nil
		}

		if errors.Is(err, ErrPreauthPartialCommand) {
			_ = s.writeERR("Invalid command")
			_ = s.writer.Flush()
			s.recordPreAuth(ctx, "parse", pop3ObservationResultRejected, pop3ReasonClass(err))

			return preauthCommand{}, true, false, err
		}

		if errors.Is(err, ErrPreauthLineTooLarge) {
			_ = s.writeERR("Command line too large")
			_ = s.writer.Flush()
			s.recordPreAuth(ctx, "parse", pop3ObservationResultRejected, pop3ReasonClass(err))

			return preauthCommand{}, true, false, nil
		}

		return preauthCommand{}, false, false, err
	}

	command, err := parsePreauthCommand(line, s.maxPreauthLineBytes)
	if err != nil {
		if writeErr := s.writeERR("Invalid command"); writeErr != nil {
			return preauthCommand{}, false, false, writeErr
		}

		if flushErr := s.writer.Flush(); flushErr != nil {
			return preauthCommand{}, false, false, flushErr
		}

		s.recordPreAuth(ctx, "parse", pop3ObservationResultRejected, pop3ReasonClass(err))

		return preauthCommand{}, false, false, nil
	}

	return command, false, true, nil
}

// dispatchCommand executes one parsed command and flushes its response.
func (s *Session) dispatchCommand(ctx context.Context, command preauthCommand) (bool, error) {
	s.recordPreAuth(ctx, command.name, pop3ObservationResultStart, "")

	outcome, err := s.handlePreauthCommand(ctx, command)
	if !outcome.flushed {
		if flushErr := s.writer.Flush(); flushErr != nil {
			return false, flushErr
		}
	}

	if errors.Is(err, ErrUnsupportedCommand) {
		s.recordPreAuth(ctx, command.name, pop3ObservationResultUnsupported, pop3ReasonClass(err))

		return outcome.closeSession, nil
	}

	if errors.Is(err, ErrBackendReadinessUnavailable) {
		s.recordPreAuth(ctx, command.name, pop3ObservationResultFailure, pop3ReasonClass(err))

		return outcome.closeSession, nil
	}

	if err != nil {
		s.recordPreAuth(ctx, command.name, pop3ObservationResultFailure, pop3ReasonClass(err))
	} else {
		s.recordPreAuth(ctx, command.name, pop3ObservationResultOK, pop3ReasonOK)
	}

	return outcome.closeSession, err
}

// readPreauthLine reads one bounded POP3 command or SASL continuation line.
func (s *Session) readPreauthLine() ([]byte, error) {
	line, err := s.reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > s.maxPreauthLineBytes {
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

// applyPreauthDeadline sets the initial session read/write deadline when configured.
func (s *Session) applyPreauthDeadline() error {
	if s.preauthTimeout <= 0 {
		return nil
	}

	return s.conn.SetDeadline(time.Now().Add(s.preauthTimeout))
}

// effectivePositive returns configured when positive, otherwise fallback.
func effectivePositive(configured int, fallback int) int {
	if configured > 0 {
		return configured
	}

	return fallback
}

// effectiveDuration returns configured when positive, otherwise fallback.
func effectiveDuration(configured time.Duration, fallback time.Duration) time.Duration {
	if configured > 0 {
		return configured
	}

	return fallback
}
