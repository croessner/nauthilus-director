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
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
)

const (
	backendLHLOName          = "nauthilus-director"
	backendLineLimitBytes    = 16 * 1024
	backendResponseLineLimit = 64
	backendTLSDisabled       = "disabled"
	backendTLSImplicit       = "implicit"
	backendTLSPlaintext      = "plaintext"
	backendTLSStartTLS       = "starttls"
	backendTLSMinDefault     = "TLS1.2"
	healthReasonAuth         = "auth"
	healthReasonConnect      = "connect"
	healthReasonProtocol     = "protocol"
	healthReasonTimeout      = "timeout"
	healthReasonTLS          = "tls"
	healthReasonUnknown      = "unknown"
)

var (
	// ErrBackendConnect reports backend TCP connection failures.
	ErrBackendConnect = errors.New("lmtp: backend connect failed")
	// ErrBackendProtocol reports unexpected LMTP backend protocol state.
	ErrBackendProtocol = errors.New("lmtp: backend protocol failed")
	// ErrBackendTLS reports backend TLS setup failures.
	ErrBackendTLS = errors.New("lmtp: backend tls failed")
)

// BackendConnector establishes an LMTP backend stream through LHLO discovery.
type BackendConnector interface {
	Connect(ctx context.Context, target backend.Backend, timeout time.Duration) (*BackendConnection, error)
}

// BackendDialer is the narrow TCP dial boundary used by the connector and tests.
type BackendDialer interface {
	DialContext(ctx context.Context, network string, address string) (net.Conn, error)
}

// TCPBackendConnector connects to configured LMTP backends over TCP only.
type TCPBackendConnector struct {
	dialer BackendDialer
}

// HealthChecker performs protocol-aware backend readiness checks.
type HealthChecker struct {
	connector BackendConnector
}

// BackendConnection owns the backend stream before transaction forwarding begins.
type BackendConnection struct {
	conn                        net.Conn
	reader                      *bufio.Reader
	writer                      *bufio.Writer
	capabilities                backend.CapabilitySet
	tlsActive                   bool
	tlsVerified                 bool
	clientCertificateConfigured bool
}

// NewTCPBackendConnector creates a connector with an optional test dialer.
func NewTCPBackendConnector(dialer BackendDialer) *TCPBackendConnector {
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	return &TCPBackendConnector{dialer: dialer}
}

// NewHealthChecker creates a health checker that reuses production backend TLS rules.
func NewHealthChecker(connector BackendConnector) *HealthChecker {
	if connector == nil {
		connector = NewTCPBackendConnector(nil)
	}

	return &HealthChecker{connector: connector}
}

// CheckBackend performs a bounded LMTP backend check without envelope commands.
func (c *HealthChecker) CheckBackend(ctx context.Context, target backend.Backend, request backend.HealthCheckRequest) backend.HealthCheckResult {
	connector := c.connector
	if connector == nil {
		connector = NewTCPBackendConnector(nil)
	}

	connection, err := connector.Connect(ctx, target, request.Timeout)
	if err != nil {
		return backend.HealthCheckResult{ReasonClass: backendHealthReason(err)}
	}
	defer func() { _ = connection.Conn().Close() }()

	if !request.Deep {
		_ = connection.quit()

		return backend.HealthCheckResult{Healthy: true, Capabilities: connection.CapabilitySet()}
	}

	if err := AuthenticateBackend(connection, target); err != nil {
		_ = connection.quit()

		return backend.HealthCheckResult{ReasonClass: backendHealthReason(err)}
	}

	if err := connection.expectStatus("NOOP", responseStatusOK); err != nil {
		_ = connection.quit()

		return backend.HealthCheckResult{ReasonClass: backendHealthReason(err)}
	}

	if err := connection.expectStatus("RSET", responseStatusOK); err != nil {
		_ = connection.quit()

		return backend.HealthCheckResult{ReasonClass: backendHealthReason(err)}
	}

	if err := connection.quit(); err != nil {
		return backend.HealthCheckResult{ReasonClass: backendHealthReason(err)}
	}

	return backend.HealthCheckResult{Healthy: true, Capabilities: connection.CapabilitySet()}
}

// Conn returns the backend stream for the later transaction-forwarding boundary.
func (c *BackendConnection) Conn() net.Conn {
	if c == nil {
		return nil
	}

	return c.conn
}

// TLSActive reports whether the backend transport is encrypted.
func (c *BackendConnection) TLSActive() bool {
	return c != nil && c.tlsActive
}

// TLSVerified reports whether TLS included certificate hostname verification.
func (c *BackendConnection) TLSVerified() bool {
	return c != nil && c.tlsActive && c.tlsVerified
}

// CapabilitySet returns a detached backend LHLO capability set.
func (c *BackendConnection) CapabilitySet() backend.CapabilitySet {
	if c == nil {
		return backend.CapabilitySet{}
	}

	return backend.NewCapabilitySet(c.capabilities.List()...)
}

// Capabilities returns a detached backend LHLO capability list.
func (c *BackendConnection) Capabilities() []string {
	if c == nil {
		return nil
	}

	return c.capabilities.List()
}

// Connect dials, negotiates configured TLS, and collects backend LHLO capabilities.
func (c *TCPBackendConnector) Connect(
	ctx context.Context,
	target backend.Backend,
	timeout time.Duration,
) (*BackendConnection, error) {
	if err := validateBackendTarget(target); err != nil {
		return nil, err
	}

	dialCtx, cancel := backendConnectContext(ctx, timeout)
	defer cancel()

	raw, err := c.dialer.DialContext(dialCtx, "tcp", target.Address)
	if err != nil {
		return nil, fmt.Errorf("%w: tcp dial", ErrBackendConnect)
	}

	connection := newBackendConnection(raw)
	if err := connection.prepare(dialCtx, target); err != nil {
		_ = raw.Close()

		return nil, err
	}

	return connection, nil
}

// newBackendConnection creates buffered protocol state around a backend stream.
func newBackendConnection(conn net.Conn) *BackendConnection {
	return &BackendConnection{
		conn:   conn,
		reader: bufio.NewReaderSize(conn, backendLineLimitBytes),
		writer: bufio.NewWriter(conn),
	}
}

// prepare performs greeting, configured TLS, and post-TLS LHLO discovery.
func (c *BackendConnection) prepare(ctx context.Context, target backend.Backend) error {
	switch strings.ToLower(strings.TrimSpace(target.TLS.Mode)) {
	case backendTLSDisabled, backendTLSPlaintext:
		if err := c.readGreeting(); err != nil {
			return err
		}

		return c.queryCapabilities()
	case backendTLSStartTLS:
		if err := c.readGreeting(); err != nil {
			return err
		}

		if err := c.queryCapabilities(); err != nil {
			return err
		}

		if err := c.startTLS(ctx, target); err != nil {
			return err
		}

		return c.queryCapabilities()
	case backendTLSImplicit:
		if err := c.wrapTLS(ctx, target); err != nil {
			return err
		}

		if err := c.readGreeting(); err != nil {
			return err
		}

		return c.queryCapabilities()
	default:
		return fmt.Errorf("%w: unsupported backend tls mode", ErrBackendTLS)
	}
}

// readGreeting requires a normal LMTP 220 greeting before backend auth can continue.
func (c *BackendConnection) readGreeting() error {
	response, err := c.readResponse()
	if err != nil {
		return err
	}

	if !response.statusOK(responseStatusReady) {
		return fmt.Errorf("%w: backend greeting was not ready", ErrBackendProtocol)
	}

	return nil
}

// queryCapabilities sends LHLO and stores the safe backend capability tokens.
func (c *BackendConnection) queryCapabilities() error {
	response, err := c.commandResponse("LHLO " + backendLHLOName)
	if err != nil {
		return err
	}

	if !response.statusOK(responseStatusOK) {
		return fmt.Errorf("%w: backend rejected lhlo", ErrBackendProtocol)
	}

	c.capabilities = lmtpCapabilitiesFromLHLO(response)

	return nil
}

// startTLS requests an LMTP STARTTLS upgrade and wraps the existing stream.
func (c *BackendConnection) startTLS(ctx context.Context, target backend.Backend) error {
	if !c.capabilities.Has(capabilitySTARTTLS) {
		return fmt.Errorf("%w: backend did not advertise starttls", ErrBackendTLS)
	}

	if err := c.expectStatus("STARTTLS", responseStatusReady); err != nil {
		return err
	}

	return c.wrapTLS(ctx, target)
}

// wrapTLS performs the backend TLS handshake with configured verification policy.
func (c *BackendConnection) wrapTLS(ctx context.Context, target backend.Backend) error {
	tlsConfig, verified, clientCertificateConfigured, err := backendTLSConfig(target)
	if err != nil {
		return err
	}

	tlsConn := tls.Client(c.conn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("%w: handshake", ErrBackendTLS)
	}

	c.conn = tlsConn
	c.reader = bufio.NewReaderSize(tlsConn, backendLineLimitBytes)
	c.writer = bufio.NewWriter(tlsConn)
	c.tlsActive = true
	c.tlsVerified = verified
	c.clientCertificateConfigured = clientCertificateConfigured

	return nil
}

// commandResponse writes one backend command and reads the SMTP-style response.
func (c *BackendConnection) commandResponse(command string) (backendStatusResponse, error) {
	if err := c.writeCommand(command); err != nil {
		return backendStatusResponse{}, err
	}

	return c.readResponse()
}

// expectStatus requires one command to complete with the exact expected status.
func (c *BackendConnection) expectStatus(command string, status string) error {
	response, err := c.commandResponse(command)
	if err != nil {
		return err
	}

	if !response.statusOK(status) {
		return fmt.Errorf("%w: backend command rejected", ErrBackendProtocol)
	}

	return nil
}

// quit closes the LMTP conversation politely without sending envelope commands.
func (c *BackendConnection) quit() error {
	return c.expectStatus("QUIT", responseStatusClosing)
}

// writeCommand emits one backend command and flushes it immediately.
func (c *BackendConnection) writeCommand(command string) error {
	if _, err := fmt.Fprintf(c.writer, "%s\r\n", command); err != nil {
		return fmt.Errorf("%w: write command", ErrBackendProtocol)
	}

	if err := c.writer.Flush(); err != nil {
		return fmt.Errorf("%w: flush command", ErrBackendProtocol)
	}

	return nil
}

// readResponse reads one bounded SMTP-style response from the backend.
func (c *BackendConnection) readResponse() (backendStatusResponse, error) {
	return readBackendStatusResponse(c.reader)
}

// backendConnectContext derives the configured backend connect deadline.
func backendConnectContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}

	if timeout <= 0 {
		return ctx, func() {}
	}

	return context.WithTimeout(ctx, timeout)
}

// validateBackendTarget checks that backend dialing receives TCP LMTP targets only.
func validateBackendTarget(target backend.Backend) error {
	if strings.ToLower(strings.TrimSpace(target.Protocol)) != protocolLMTP {
		return fmt.Errorf("%w: backend protocol must be lmtp", ErrBackendConnect)
	}

	if looksLikeUnixBackendAddress(target.Address) {
		return fmt.Errorf("%w: unix socket backend addresses are not supported for LMTP backend connectivity", ErrBackendConnect)
	}

	host, port, err := net.SplitHostPort(strings.TrimSpace(target.Address))
	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
		return fmt.Errorf("%w: backend tcp address must be host:port", ErrBackendConnect)
	}

	return nil
}

// looksLikeUnixBackendAddress catches explicit Unix networks and absolute paths.
func looksLikeUnixBackendAddress(address string) bool {
	address = strings.TrimSpace(address)
	lower := strings.ToLower(address)

	return strings.HasPrefix(lower, "unix:") || strings.HasPrefix(address, "/")
}

// backendHealthReason maps backend check errors to low-cardinality reason classes.
func backendHealthReason(err error) string {
	switch {
	case isTimeoutError(err):
		return healthReasonTimeout
	case errors.Is(err, ErrBackendTLS):
		return healthReasonTLS
	case errors.Is(err, ErrBackendConnect):
		return healthReasonConnect
	case errors.Is(err, ErrBackendProtocol):
		return healthReasonProtocol
	case errors.Is(err, ErrBackendAuth), errors.Is(err, ErrBackendAuthPolicy):
		return healthReasonAuth
	default:
		return healthReasonUnknown
	}
}

// isTimeoutError detects context and network timeout errors without exposing details.
func isTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var netErr net.Error

	return errors.As(err, &netErr) && netErr.Timeout()
}

// backendTLSConfig builds a tls.Config from the selected backend policy.
func backendTLSConfig(target backend.Backend) (*tls.Config, bool, bool, error) {
	minVersion, err := backendTLSMinVersion(target.TLS.MinTLSVersion)
	if err != nil {
		return nil, false, false, err
	}

	serverName, err := backendTLSServerName(target)
	if err != nil {
		return nil, false, false, err
	}

	tlsConfig := &tls.Config{
		MinVersion:         minVersion,
		ServerName:         serverName,
		InsecureSkipVerify: target.TLS.InsecureSkipVerify,
	}

	if strings.TrimSpace(target.TLS.CAFile) != "" {
		rootCAs, err := loadRootCAs(target.TLS.CAFile)
		if err != nil {
			return nil, false, false, err
		}

		tlsConfig.RootCAs = rootCAs
	}

	clientCertificateConfigured := false

	if strings.TrimSpace(target.TLS.Cert) != "" || !target.TLS.Key.IsZero() {
		if strings.TrimSpace(target.TLS.Cert) == "" || target.TLS.Key.IsZero() {
			return nil, false, false, fmt.Errorf("%w: backend client certificate and key must be configured together", ErrBackendTLS)
		}

		certificate, err := tls.LoadX509KeyPair(target.TLS.Cert, target.TLS.Key.Value())
		if err != nil {
			return nil, false, false, fmt.Errorf("%w: load client certificate", ErrBackendTLS)
		}

		tlsConfig.Certificates = []tls.Certificate{certificate}
		clientCertificateConfigured = true
	}

	return tlsConfig, !target.TLS.InsecureSkipVerify, clientCertificateConfigured, nil
}

// backendTLSServerName returns the SNI and verification hostname for the backend.
func backendTLSServerName(target backend.Backend) (string, error) {
	if target.TLS.ServerName != "" {
		return target.TLS.ServerName, nil
	}

	host, _, err := net.SplitHostPort(target.Address)
	if err != nil {
		return "", fmt.Errorf("%w: backend tcp address must be host:port", ErrBackendTLS)
	}

	if _, err := netip.ParseAddr(host); err == nil {
		if target.TLS.InsecureSkipVerify {
			return "", nil
		}

		return "", fmt.Errorf("%w: tls.server_name is required when backend address is not the certificate name", ErrBackendTLS)
	}

	return host, nil
}

// backendTLSMinVersion converts config vocabulary into Go TLS constants.
func backendTLSMinVersion(version string) (uint16, error) {
	switch strings.ToUpper(strings.TrimSpace(version)) {
	case "", backendTLSMinDefault, "TLS12", "TLS1_2":
		return tls.VersionTLS12, nil
	case "TLS1.3", "TLS13", "TLS1_3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("%w: unsupported backend tls minimum version", ErrBackendTLS)
	}
}

// loadRootCAs loads a PEM CA bundle for backend certificate verification.
func loadRootCAs(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: load backend ca", ErrBackendTLS)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("%w: backend ca did not contain PEM certificates", ErrBackendTLS)
	}

	return pool, nil
}
