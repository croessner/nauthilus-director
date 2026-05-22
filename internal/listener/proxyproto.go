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

package listener

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/config"
	proxyproto "github.com/pires/go-proxyproto"
)

var (
	// ErrProxyProtocolUntrustedPeer reports a connection from an untrusted upstream.
	ErrProxyProtocolUntrustedPeer = errors.New("proxy protocol: untrusted upstream")
	// ErrProxyProtocolUnsupportedCommand reports LOCAL or unspecified PROXY commands.
	ErrProxyProtocolUnsupportedCommand = errors.New("proxy protocol: unsupported command")
	// ErrProxyProtocolUnsupportedFamily reports non-TCP or unspecified address families.
	ErrProxyProtocolUnsupportedFamily = errors.New("proxy protocol: unsupported address family")
)

// proxyProtocolPolicy validates trusted upstreams and consumes exactly one PROXY header.
type proxyProtocolPolicy struct {
	trustedCIDRs  []*net.IPNet
	headerTimeout time.Duration
}

// proxyProtocolConn keeps bytes buffered by header parsing visible to later TLS or IMAP reads.
type proxyProtocolConn struct {
	net.Conn
	reader     *bufio.Reader
	remoteAddr net.Addr
	localAddr  net.Addr
}

// newProxyProtocolPolicy builds the fail-closed PROXY policy for one listener.
func newProxyProtocolPolicy(proxyConfig config.ProxyProtocolConfig, headerTimeout time.Duration) (*proxyProtocolPolicy, error) {
	if !proxyConfig.Enabled {
		return nil, nil
	}

	if len(proxyConfig.TrustedCIDRs) == 0 {
		return nil, fmt.Errorf("proxy_protocol.trusted_cidrs is required when proxy protocol is enabled")
	}

	trustedCIDRs := make([]*net.IPNet, 0, len(proxyConfig.TrustedCIDRs))
	for _, rawCIDR := range proxyConfig.TrustedCIDRs {
		trimmed := strings.TrimSpace(rawCIDR)
		if trimmed == "" {
			return nil, fmt.Errorf("proxy_protocol.trusted_cidrs contains an empty CIDR")
		}

		if !strings.Contains(trimmed, "/") {
			return nil, fmt.Errorf("proxy_protocol.trusted_cidrs entry %q must be a CIDR", trimmed)
		}

		_, cidr, err := net.ParseCIDR(trimmed)
		if err != nil {
			return nil, fmt.Errorf("proxy_protocol.trusted_cidrs entry %q is invalid: %w", trimmed, err)
		}

		trustedCIDRs = append(trustedCIDRs, cidr)
	}

	return &proxyProtocolPolicy{
		trustedCIDRs:  trustedCIDRs,
		headerTimeout: headerTimeout,
	}, nil
}

// apply consumes a trusted PROXY v1/v2 preface before TLS or IMAP greeting.
func (p *proxyProtocolPolicy) apply(conn net.Conn) (net.Conn, error) {
	if !p.trustsPeer(conn.RemoteAddr()) {
		return nil, ErrProxyProtocolUntrustedPeer
	}

	reader := bufio.NewReader(conn)
	if err := setTemporaryReadDeadline(conn, p.headerTimeout); err != nil {
		return nil, err
	}

	header, err := proxyproto.Read(reader)
	clearErr := conn.SetReadDeadline(time.Time{})

	if err != nil {
		return nil, err
	}

	if clearErr != nil {
		return nil, clearErr
	}

	if err := validateProxyHeader(header); err != nil {
		return nil, err
	}

	return &proxyProtocolConn{
		Conn:       conn,
		reader:     reader,
		remoteAddr: header.SourceAddr,
		localAddr:  header.DestinationAddr,
	}, nil
}

// Read drains parser-buffered bytes before reading from the underlying connection.
func (c *proxyProtocolConn) Read(payload []byte) (int, error) {
	if c.reader != nil && c.reader.Buffered() > 0 {
		n, err := c.reader.Read(payload)
		if c.reader.Buffered() == 0 {
			c.reader = nil
		}

		return n, err
	}

	c.reader = nil

	return c.Conn.Read(payload)
}

// RemoteAddr returns the trusted client address from the PROXY header.
func (c *proxyProtocolConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// LocalAddr returns the trusted destination address from the PROXY header.
func (c *proxyProtocolConn) LocalAddr() net.Addr {
	return c.localAddr
}

// trustsPeer reports whether the direct upstream address may supply PROXY metadata.
func (p *proxyProtocolPolicy) trustsPeer(addr net.Addr) bool {
	ip := addrIP(addr)
	if ip == nil {
		return false
	}

	for _, cidr := range p.trustedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

// validateProxyHeader enforces the mail listener subset of PROXY v1/v2.
func validateProxyHeader(header *proxyproto.Header) error {
	if header == nil {
		return proxyproto.ErrNoProxyProtocol
	}

	if !header.Command.IsProxy() {
		return ErrProxyProtocolUnsupportedCommand
	}

	if header.TransportProtocol != proxyproto.TCPv4 && header.TransportProtocol != proxyproto.TCPv6 {
		return ErrProxyProtocolUnsupportedFamily
	}

	source, destination, ok := header.TCPAddrs()
	if !ok || source == nil || destination == nil || source.IP == nil || destination.IP == nil {
		return ErrProxyProtocolUnsupportedFamily
	}

	return nil
}

// setTemporaryReadDeadline bounds the PROXY header read without extending session deadlines.
func setTemporaryReadDeadline(conn net.Conn, timeout time.Duration) error {
	if timeout <= 0 {
		return nil
	}

	return conn.SetReadDeadline(time.Now().Add(timeout))
}

// addrIP extracts the IP address from a TCP-style network address.
func addrIP(addr net.Addr) net.IP {
	switch typed := addr.(type) {
	case *net.TCPAddr:
		return typed.IP
	case *net.UDPAddr:
		return typed.IP
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return nil
		}

		return net.ParseIP(host)
	}
}
