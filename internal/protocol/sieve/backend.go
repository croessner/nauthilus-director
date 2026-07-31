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

//nolint:goconst,wsl_v5 // Wire parser repeats protocol status strings deliberately.
package sieve

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
)

const (
	backendLineLimitBytes              = 16 * 1024
	backendProtocol                    = "sieve"
	backendResponseLineLimit           = 64
	backendResponseBye                 = "BYE"
	backendResponseNo                  = "NO"
	backendResponseOK                  = "OK"
	backendTLSDisabled                 = "disabled"
	backendTLSImplicit                 = "implicit"
	backendTLSNone                     = "none"
	backendTLSPlaintext                = "plaintext"
	backendTLSStartTLS                 = "starttls"
	backendTLSMinDefault               = "TLS1.2"
	healthReasonAuth                   = "auth"
	healthReasonConnect                = "connect"
	healthReasonProtocol               = "protocol"
	healthReasonProxyConfig            = "proxy_config"
	healthReasonProxyMissingAddress    = "proxy_missing_address"
	healthReasonProxyUnsupportedFamily = "proxy_unsupported_family"
	healthReasonProxyWrite             = "proxy_write_failed"
	healthReasonTimeout                = "timeout"
	healthReasonTLS                    = "tls"
	healthReasonUnknown                = "unknown"
)

var (
	// ErrBackendConnect reports backend TCP connection failures.
	ErrBackendConnect = errors.New("sieve: backend connect failed")
	// ErrBackendProtocol reports unexpected ManageSieve backend protocol state.
	ErrBackendProtocol = errors.New("sieve: backend protocol failed")
	// ErrBackendTLS reports backend TLS setup failures.
	ErrBackendTLS = errors.New("sieve: backend tls failed")
)

// BackendConnector establishes the selected ManageSieve backend stream.
type BackendConnector interface {
	Connect(ctx context.Context, request backend.ConnectRequest) (*BackendConnection, error)
}

// BackendDialer is the narrow TCP dial boundary used by the connector and tests.
type BackendDialer interface {
	DialContext(ctx context.Context, network string, address string) (net.Conn, error)
}

// TCPBackendConnector connects to configured ManageSieve backends over TCP only.
type TCPBackendConnector struct {
	dialer BackendDialer
}

// BackendConnection owns the backend stream before proxy handoff can take over.
type BackendConnection struct {
	conn         net.Conn
	reader       *bufio.Reader
	writer       *bufio.Writer
	capabilities backend.CapabilitySet
	tlsActive    bool
	tlsVerified  bool
}

type backendResponse struct {
	condition string
	code      string
}

// NewTCPBackendConnector creates a connector with an optional test dialer.
func NewTCPBackendConnector(dialer BackendDialer) *TCPBackendConnector {
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	return &TCPBackendConnector{dialer: dialer}
}

// Conn returns the backend stream for the later proxy boundary.
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

// CapabilitySet returns a detached backend capability snapshot.
func (c *BackendConnection) CapabilitySet() backend.CapabilitySet {
	if c == nil {
		return backend.CapabilitySet{}
	}

	return backend.NewCapabilitySet(c.capabilities.List()...)
}

// Capabilities returns backend capabilities in observed normalized order.
func (c *BackendConnection) Capabilities() []string {
	if c == nil {
		return nil
	}

	return c.capabilities.List()
}

// Buffered returns already-read backend bytes that belong to proxy mode.
func (c *BackendConnection) Buffered() []byte {
	if c == nil || c.reader == nil {
		return nil
	}

	buffered := make([]byte, c.reader.Buffered())
	if len(buffered) > 0 {
		_, _ = io.ReadFull(c.reader, buffered)
	}

	return buffered
}

// DiscardBufferedAuthenticationResponses removes successful backend login
// responses that arrived after backend authentication but before proxy handoff.
func (c *BackendConnection) DiscardBufferedAuthenticationResponses() bool {
	if c == nil || c.reader == nil || c.reader.Buffered() == 0 {
		return false
	}

	discarded := false
	for c.reader.Buffered() > 0 {
		buffered, err := c.reader.Peek(c.reader.Buffered())
		if err != nil {
			return discarded
		}

		length, response, ok := bufferedResponseLength(buffered)
		if !ok || length <= 0 || response.condition != backendResponseOK {
			return discarded
		}

		_, _ = c.reader.Discard(length)
		discarded = true
	}

	return discarded
}

// Connect dials, negotiates configured TLS, and collects backend capabilities.
func (c *TCPBackendConnector) Connect(
	ctx context.Context,
	request backend.ConnectRequest,
) (*BackendConnection, error) {
	target := request.Target
	if err := validateBackendTarget(target); err != nil {
		return nil, err
	}

	dialCtx, cancel := backendConnectContext(ctx, request.Timeout)
	defer cancel()

	raw, err := c.dialer.DialContext(dialCtx, "tcp", target.Address)
	if err != nil {
		return nil, fmt.Errorf("%w: tcp dial", ErrBackendConnect)
	}

	if err := backend.SetHealthCheckDeadline(dialCtx, raw, request); err != nil {
		_ = raw.Close()

		return nil, fmt.Errorf("%w: health deadline", ErrBackendConnect)
	}

	if _, err := backend.NewTransport().WriteProxyProtocolPreface(ctx, raw, request); err != nil {
		_ = raw.Close()

		return nil, fmt.Errorf("%w: proxy preface: %w", ErrBackendConnect, err)
	}

	connection := newBackendConnection(raw)
	if err := connection.prepare(dialCtx, target); err != nil {
		_ = raw.Close()

		return nil, err
	}

	if err := backend.SetHealthCheckDeadline(dialCtx, raw, request); err != nil {
		_ = raw.Close()

		return nil, fmt.Errorf("%w: health deadline", ErrBackendConnect)
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

// prepare performs greeting, configured TLS, and post-TLS capability discovery.
func (c *BackendConnection) prepare(ctx context.Context, target backend.Backend) error {
	clearDeadline := c.applyContextDeadline(ctx)
	defer clearDeadline()

	switch strings.ToLower(strings.TrimSpace(target.TLS.Mode)) {
	case backendTLSDisabled, backendTLSNone, backendTLSPlaintext:
		if err := c.readGreeting(); err != nil {
			return err
		}

		return c.queryCapabilities()
	case backendTLSStartTLS:
		if err := c.readGreeting(); err != nil {
			return err
		}

		if err := c.startTLS(ctx, target); err != nil {
			return err
		}

		return c.readAutomaticCapabilities()
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

// applyContextDeadline bounds backend setup I/O with the caller's deadline.
func (c *BackendConnection) applyContextDeadline(ctx context.Context) func() {
	if c == nil || c.conn == nil || ctx == nil {
		return func() {}
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		return func() {}
	}

	_ = c.conn.SetDeadline(deadline)

	return func() {
		if c.conn != nil {
			_ = c.conn.SetDeadline(time.Time{})
		}
	}
}

// readGreeting accepts an RFC 5804 greeting and records only bounded capability tokens.
func (c *BackendConnection) readGreeting() error {
	response, err := c.readResponse()
	if err != nil {
		return err
	}

	if response.referral() {
		return fmt.Errorf("%w: backend referral is not supported", ErrBackendProtocol)
	}

	if response.condition != backendResponseOK {
		return fmt.Errorf("%w: backend greeting was not ready", ErrBackendProtocol)
	}

	return nil
}

// readAutomaticCapabilities consumes the RFC 5804 capability update after STARTTLS.
func (c *BackendConnection) readAutomaticCapabilities() error {
	c.capabilities = backend.CapabilitySet{}

	response, err := c.readResponse()
	if err != nil {
		return err
	}

	if response.referral() {
		return fmt.Errorf("%w: backend referral is not supported", ErrBackendProtocol)
	}

	if response.condition != backendResponseOK {
		return fmt.Errorf("%w: backend rejected automatic capability", ErrBackendProtocol)
	}

	return nil
}

// queryCapabilities refreshes the backend capability set after the current TLS state.
func (c *BackendConnection) queryCapabilities() error {
	c.capabilities = backend.CapabilitySet{}
	if err := c.writeCommand(commandCapability); err != nil {
		return err
	}

	response, err := c.readResponse()
	if err != nil {
		return err
	}

	if response.referral() {
		return fmt.Errorf("%w: backend referral is not supported", ErrBackendProtocol)
	}

	if response.condition != backendResponseOK {
		return fmt.Errorf("%w: backend rejected capability", ErrBackendProtocol)
	}

	return nil
}

// startTLS requests a ManageSieve STARTTLS upgrade and wraps the existing stream.
func (c *BackendConnection) startTLS(ctx context.Context, target backend.Backend) error {
	if !c.capabilities.Has(capabilityStartTLS) {
		return fmt.Errorf("%w: backend did not advertise starttls", ErrBackendTLS)
	}

	if err := c.writeCommand(commandStartTLS); err != nil {
		return err
	}

	response, err := c.readResponse()
	if err != nil {
		return err
	}

	if response.condition != backendResponseOK {
		return fmt.Errorf("%w: backend rejected starttls", ErrBackendTLS)
	}

	return c.wrapTLS(ctx, target)
}

// wrapTLS performs the backend TLS handshake with configured verification policy.
func (c *BackendConnection) wrapTLS(ctx context.Context, target backend.Backend) error {
	tlsConfig, verified, err := backendTLSConfig(target)
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

	return nil
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

// readResponse reads capability lines followed by one OK, NO, or BYE response.
func (c *BackendConnection) readResponse() (backendResponse, error) {
	for range backendResponseLineLimit {
		line, err := c.readLine()
		if err != nil {
			return backendResponse{}, err
		}

		line = strings.TrimRight(line, "\r\n")
		if response, ok := parseBackendResponseLine(line); ok {
			return response, nil
		}

		if err := c.addCapabilityLine(line); err != nil {
			return backendResponse{}, err
		}
	}

	return backendResponse{}, fmt.Errorf("%w: backend response too long", ErrBackendProtocol)
}

// readLine reads one bounded CRLF response from the backend.
func (c *BackendConnection) readLine() (string, error) {
	line, err := c.reader.ReadString('\n')
	if len(line) > backendLineLimitBytes {
		return "", fmt.Errorf("%w: backend line too large", ErrBackendProtocol)
	}

	if err != nil {
		return "", fmt.Errorf("%w: read response", ErrBackendProtocol)
	}

	if !strings.HasSuffix(line, "\n") {
		return "", fmt.Errorf("%w: partial backend response", ErrBackendProtocol)
	}

	return line, nil
}

// addCapabilityLine records capability names and SASL mechanisms without script transcript text.
func (c *BackendConnection) addCapabilityLine(line string) error {
	tokens, err := tokenizeArguments(line, backendLineLimitBytes)
	if err != nil {
		return fmt.Errorf("%w: malformed backend capability", ErrBackendProtocol)
	}

	if len(tokens) == 0 {
		return fmt.Errorf("%w: empty backend capability", ErrBackendProtocol)
	}

	name, ok := tokenStringValue(tokens[0])
	if !ok {
		return fmt.Errorf("%w: invalid backend capability", ErrBackendProtocol)
	}

	name = strings.ToUpper(strings.TrimSpace(name))
	if name == "" {
		return fmt.Errorf("%w: invalid backend capability", ErrBackendProtocol)
	}

	c.capabilities.Add(name)
	if name != capabilitySASL || len(tokens) < 2 {
		return nil
	}

	value, ok := tokenStringValue(tokens[1])
	if !ok {
		return fmt.Errorf("%w: invalid backend sasl capability", ErrBackendProtocol)
	}

	for mechanism := range strings.FieldsSeq(value) {
		normalized := strings.ToUpper(strings.TrimSpace(mechanism))
		if normalized != "" {
			c.capabilities.Add(capabilitySASL + "=" + normalized)
		}
	}

	return nil
}

// parseBackendResponseLine detects terminal ManageSieve response lines.
func parseBackendResponseLine(line string) (backendResponse, bool) {
	condition, rest, _ := cutField(line)
	condition = strings.ToUpper(strings.TrimSpace(condition))
	switch condition {
	case backendResponseOK, backendResponseNo, backendResponseBye:
	default:
		return backendResponse{}, false
	}

	return backendResponse{condition: condition, code: backendResponseCode(rest)}, true
}

// backendResponseCode extracts the bounded response-code atom when present.
func backendResponseCode(rest string) string {
	rest = strings.TrimSpace(rest)
	if !strings.HasPrefix(rest, "(") {
		return ""
	}

	rest = strings.TrimPrefix(rest, "(")
	code, _, _ := cutField(rest)
	code = strings.TrimRight(code, ")")

	return strings.ToUpper(strings.TrimSpace(code))
}

// referral reports whether a backend response tried to redirect the client.
func (r backendResponse) referral() bool {
	return strings.EqualFold(r.code, "REFERRAL")
}

// bufferedResponseLength returns one complete buffered ManageSieve response.
func bufferedResponseLength(buffered []byte) (int, backendResponse, bool) {
	remaining := buffered
	total := 0

	for len(remaining) > 0 {
		index := bytes.IndexByte(remaining, '\n')
		if index < 0 {
			return 0, backendResponse{}, false
		}

		lineBytes := remaining[:index+1]
		total += len(lineBytes)
		line := strings.TrimRight(string(lineBytes), "\r\n")

		if response, ok := parseBackendResponseLine(line); ok {
			return total, response, true
		}

		check := &BackendConnection{}
		if err := check.addCapabilityLine(line); err != nil {
			return 0, backendResponse{}, false
		}
		remaining = remaining[index+1:]
	}

	return 0, backendResponse{}, false
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

// validateBackendTarget checks that backend dialing receives TCP Sieve targets only.
func validateBackendTarget(target backend.Backend) error {
	if strings.ToLower(strings.TrimSpace(target.Protocol)) != backendProtocol {
		return fmt.Errorf("%w: backend protocol must be sieve", ErrBackendConnect)
	}

	if looksLikeUnixBackendAddress(target.Address) {
		return fmt.Errorf("%w: unix socket backend addresses are not supported for Sieve backend connectivity", ErrBackendConnect)
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
	case backend.IsTransportReason(err, backend.TransportReasonWriteFailed):
		return healthReasonProxyWrite
	case backend.IsTransportReason(err, backend.TransportReasonMissingAddress):
		return healthReasonProxyMissingAddress
	case backend.IsTransportReason(err, backend.TransportReasonUnsupportedFamily):
		return healthReasonProxyUnsupportedFamily
	case backend.IsTransportReason(err, backend.TransportReasonConfig):
		return healthReasonProxyConfig
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

// isTimeoutError detects context and network timeouts without exposing raw error text.
func isTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var netErr net.Error

	return errors.As(err, &netErr) && netErr.Timeout()
}

// backendTLSConfig builds a tls.Config from the selected backend policy.
func backendTLSConfig(target backend.Backend) (*tls.Config, bool, error) {
	minVersion, err := backendTLSMinVersion(target.TLS.MinTLSVersion)
	if err != nil {
		return nil, false, err
	}

	serverName, err := backendTLSServerName(target)
	if err != nil {
		return nil, false, err
	}

	tlsConfig := &tls.Config{
		MinVersion:         minVersion,
		ServerName:         serverName,
		InsecureSkipVerify: target.TLS.InsecureSkipVerify,
	}

	if strings.TrimSpace(target.TLS.CAFile) != "" {
		rootCAs, err := loadRootCAs(target.TLS.CAFile)
		if err != nil {
			return nil, false, err
		}

		tlsConfig.RootCAs = rootCAs
	}

	if strings.TrimSpace(target.TLS.Cert) != "" || !target.TLS.Key.IsZero() {
		if strings.TrimSpace(target.TLS.Cert) == "" || target.TLS.Key.IsZero() {
			return nil, false, fmt.Errorf("%w: backend client certificate and key must be configured together", ErrBackendTLS)
		}

		certificate, err := tls.LoadX509KeyPair(target.TLS.Cert, target.TLS.Key.Value())
		if err != nil {
			return nil, false, fmt.Errorf("%w: load client certificate", ErrBackendTLS)
		}

		tlsConfig.Certificates = []tls.Certificate{certificate}
	}

	return tlsConfig, !target.TLS.InsecureSkipVerify, nil
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
