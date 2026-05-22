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
	backendCapabilityCommand = "CAPABILITY"
	backendLineLimitBytes    = 16 * 1024
	backendProtocol          = "imap"
	backendTLSDisabled       = "disabled"
	backendTLSImplicit       = "implicit"
	backendTLSPlaintext      = "plaintext"
	backendTLSStartTLS       = "starttls"
	backendTLSMinDefault     = "TLS1.2"
)

var (
	// ErrBackendConnect reports backend TCP connection failures.
	ErrBackendConnect = errors.New("imap: backend connect failed")
	// ErrBackendProtocol reports unexpected IMAP backend protocol state.
	ErrBackendProtocol = errors.New("imap: backend protocol failed")
	// ErrBackendTLS reports backend TLS setup failures.
	ErrBackendTLS = errors.New("imap: backend tls failed")
)

// BackendConnector establishes the selected backend stream up to the auth boundary.
type BackendConnector interface {
	Connect(ctx context.Context, target backend.Backend, timeout time.Duration) (*BackendConnection, error)
}

// BackendDialer is the narrow TCP dial boundary used by the production connector and tests.
type BackendDialer interface {
	DialContext(ctx context.Context, network string, address string) (net.Conn, error)
}

// TCPBackendConnector connects to configured IMAP backends over TCP only.
type TCPBackendConnector struct {
	dialer BackendDialer
}

// NewTCPBackendConnector creates a connector with an optional test dialer.
func NewTCPBackendConnector(dialer BackendDialer) *TCPBackendConnector {
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	return &TCPBackendConnector{dialer: dialer}
}

// BackendConnection owns the backend stream while authentication is established.
type BackendConnection struct {
	conn         net.Conn
	reader       *bufio.Reader
	writer       *bufio.Writer
	capabilities backendCapabilities
	tlsActive    bool
	tlsVerified  bool
	nextTag      int
}

// Conn returns the backend stream for transparent proxy mode.
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

// Capabilities returns a detached backend CAPABILITY snapshot.
func (c *BackendConnection) Capabilities() []string {
	if c == nil {
		return nil
	}

	return c.capabilities.List()
}

// Buffered returns bytes already read from the backend that still belong to proxy mode.
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

// nextCommandTag returns a deterministic backend tag without exposing frontend session data.
func (c *BackendConnection) nextCommandTag() string {
	c.nextTag++

	return fmt.Sprintf("D%04d", c.nextTag)
}

// Connect dials, negotiates configured backend TLS, and collects backend capabilities.
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

// prepare performs greeting, configured TLS, and post-TLS capability discovery.
func (c *BackendConnection) prepare(ctx context.Context, target backend.Backend) error {
	switch strings.ToLower(strings.TrimSpace(target.TLS.Mode)) {
	case backendTLSDisabled, backendTLSPlaintext:
		if err := c.readGreeting(); err != nil {
			return err
		}
	case backendTLSStartTLS:
		if err := c.readGreeting(); err != nil {
			return err
		}

		if err := c.startTLS(ctx, target); err != nil {
			return err
		}
	case backendTLSImplicit:
		if err := c.wrapTLS(ctx, target); err != nil {
			return err
		}

		if err := c.readGreeting(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: unsupported backend tls mode", ErrBackendTLS)
	}

	return c.queryCapabilities()
}

// readGreeting requires a normal IMAP OK greeting before backend auth can continue.
func (c *BackendConnection) readGreeting() error {
	line, err := c.readLine()
	if err != nil {
		return err
	}

	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "* OK") {
		return fmt.Errorf("%w: backend greeting was not OK", ErrBackendProtocol)
	}

	return nil
}

// startTLS requests an IMAP STARTTLS upgrade and wraps the existing stream.
func (c *BackendConnection) startTLS(ctx context.Context, target backend.Backend) error {
	tag := c.nextCommandTag()
	if err := c.writeCommand(tag, "STARTTLS"); err != nil {
		return err
	}

	ok, err := c.readTaggedCompletion(tag)
	if err != nil {
		return err
	}

	if !ok {
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

// queryCapabilities asks the backend for the mechanism set available after TLS policy is settled.
func (c *BackendConnection) queryCapabilities() error {
	tag := c.nextCommandTag()
	if err := c.writeCommand(tag, backendCapabilityCommand); err != nil {
		return err
	}

	ok, err := c.readTaggedCompletion(tag)
	if err != nil {
		return err
	}

	if !ok {
		return fmt.Errorf("%w: backend capability rejected", ErrBackendProtocol)
	}

	return nil
}

// writeCommand emits one backend command and flushes it immediately.
func (c *BackendConnection) writeCommand(tag string, command string) error {
	if _, err := fmt.Fprintf(c.writer, "%s %s\r\n", tag, command); err != nil {
		return fmt.Errorf("%w: write command", ErrBackendProtocol)
	}

	if err := c.writer.Flush(); err != nil {
		return fmt.Errorf("%w: flush command", ErrBackendProtocol)
	}

	return nil
}

// readTaggedCompletion reads until a tagged OK, NO or BAD response completes the command.
func (c *BackendConnection) readTaggedCompletion(tag string) (bool, error) {
	tagPrefix := strings.ToUpper(tag) + " "

	for {
		line, err := c.readLine()
		if err != nil {
			return false, err
		}

		trimmed := strings.TrimSpace(line)

		upper := strings.ToUpper(trimmed)
		if strings.HasPrefix(upper, "* CAPABILITY ") {
			c.capabilities.AddLine(trimmed)

			continue
		}

		if !strings.HasPrefix(upper, tagPrefix) {
			continue
		}

		switch {
		case strings.HasPrefix(upper, tagPrefix+"OK"):
			return true, nil
		case strings.HasPrefix(upper, tagPrefix+"NO"), strings.HasPrefix(upper, tagPrefix+"BAD"):
			return false, nil
		default:
			return false, fmt.Errorf("%w: malformed tagged response", ErrBackendProtocol)
		}
	}
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

// validateBackendTarget checks that backend dialing receives TCP IMAP targets only.
func validateBackendTarget(target backend.Backend) error {
	if strings.ToLower(strings.TrimSpace(target.Protocol)) != backendProtocol {
		return fmt.Errorf("%w: backend protocol must be imap", ErrBackendConnect)
	}

	if looksLikeUnixBackendAddress(target.Address) {
		return fmt.Errorf("%w: unix socket backend addresses are not supported for IMAP backend connectivity", ErrBackendConnect)
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

// backendCapabilities stores backend mechanisms in a case-insensitive set.
type backendCapabilities struct {
	values []string
	set    map[string]struct{}
}

// AddLine merges one untagged CAPABILITY response into the set.
func (c *backendCapabilities) AddLine(line string) {
	text := strings.TrimSpace(line)

	upper := strings.ToUpper(text)
	if strings.HasPrefix(upper, "* CAPABILITY ") {
		text = strings.TrimSpace(text[len("* CAPABILITY "):])
	}

	for field := range strings.FieldsSeq(text) {
		c.Add(field)
	}
}

// Add inserts one capability token if it is not already present.
func (c *backendCapabilities) Add(value string) {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return
	}

	if c.set == nil {
		c.set = make(map[string]struct{})
	}

	if _, exists := c.set[value]; exists {
		return
	}

	c.set[value] = struct{}{}
	c.values = append(c.values, value)
}

// Has reports whether a capability token is present.
func (c backendCapabilities) Has(value string) bool {
	_, ok := c.set[strings.ToUpper(strings.TrimSpace(value))]

	return ok
}

// SupportsMechanism reports whether the backend advertises the selected auth mechanism.
func (c backendCapabilities) SupportsMechanism(mechanism string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(mechanism))
	switch normalized {
	case "LOGIN":
		return c.Has("IMAP4REV1") || c.Has("LOGIN") || c.Has("AUTH=LOGIN")
	default:
		return c.Has("AUTH=" + normalized)
	}
}

// List returns a detached capability list in observed order.
func (c backendCapabilities) List() []string {
	return append([]string(nil), c.values...)
}

// newBackendCapabilities creates a capability set from tokens for tests and fake connectors.
func newBackendCapabilities(values ...string) backendCapabilities {
	var capabilities backendCapabilities

	for _, value := range values {
		capabilities.Add(value)
	}

	return capabilities
}
