// Copyright (C) 2026 Christian Rößner
//
// SPDX-License-Identifier: AGPL-3.0-only
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, version 3 of the License.

package e2e

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus-director/internal/nauthilus"
)

const (
	e2eAttributeMailShard    = "mailShard"
	e2eAttributeTenant       = "tenant"
	e2eExternalIdentity      = "external@example.test"
	e2eExternalMethod        = "external"
	e2eTLSModeImplicit       = "implicit"
	externalLocalhost        = "localhost"
	externalPEMCertificate   = "CERTIFICATE"
	externalPEMRSAPrivateKey = "RSA PRIVATE KEY"
)

// TestSASLExternalPublicIMAPFlow proves verified certificate authentication through a public socket.
func TestSASLExternalPublicIMAPFlow(t *testing.T) {
	bundle := writeExternalTLSBundle(t)
	authority := &externalE2EAuthority{}
	backendServer := startFakeIMAPBackend(t, fakeBackendOptions{})

	director := startDirector(t, directorOptions{
		Authenticator:       authority,
		BackendAuth:         masterUserBackendAuth(),
		BackendAddress:      backendServer.Address(),
		ExternalAuthEnabled: true,
		ListenerCertPath:    bundle.serverCertPath,
		ListenerClientCA:    bundle.caPath,
		ListenerKeyPath:     bundle.serverKeyPath,
		TLSMode:             e2eTLSModeImplicit,
	})
	defer director.Stop(t)

	assertExternalCapabilityWithoutCertificate(t, director.Address())

	client := dialExternalTLS(t, director.Address(), bundle.clientCertificate)
	defer func() { _ = client.Close() }()

	reader := bufio.NewReader(client)

	expectLine(t, reader, "* OK nauthilus-director IMAP session ready\r\n")
	writeLine(t, client, "A001 CAPABILITY")

	capabilities := readIMAPResponse(t, reader, "A001")
	if !strings.Contains(capabilities, "AUTH=EXTERNAL") {
		t.Fatalf("capability response omitted AUTH=EXTERNAL: %q", capabilities)
	}

	writeLine(t, client, "A002 AUTHENTICATE EXTERNAL =")
	expectLine(t, reader, "A002 OK Authentication completed\r\n")
	writeLine(t, client, "A003 NOOP")
	expectLine(t, reader, "A003 OK backend noop\r\n")

	authority.AssertLookup(t)
	backendServer.ExpectProxyLineWithAuth(t, "A003 NOOP", "AUTHENTICATE PLAIN")
}

// assertExternalCapabilityWithoutCertificate proves advertisement follows the live TLS state.
func assertExternalCapabilityWithoutCertificate(t *testing.T, address string) {
	t.Helper()

	client := dialExternalTLS(t, address, tls.Certificate{})
	defer func() { _ = client.Close() }()

	reader := bufio.NewReader(client)

	expectLine(t, reader, "* OK nauthilus-director IMAP session ready\r\n")
	writeLine(t, client, "N001 CAPABILITY")

	capabilities := readIMAPResponse(t, reader, "N001")
	if strings.Contains(capabilities, "AUTH=EXTERNAL") {
		t.Fatalf("capability response advertised EXTERNAL without a certificate: %q", capabilities)
	}
}

// readIMAPResponse reads one complete tagged response into a bounded transcript.
func readIMAPResponse(t *testing.T, reader *bufio.Reader, tag string) string {
	t.Helper()

	var transcript strings.Builder

	for range 32 {
		line := readLine(t, reader)
		transcript.WriteString(line)

		if strings.HasPrefix(line, tag+" ") {
			return transcript.String()
		}
	}

	t.Fatalf("IMAP response for %s exceeded line bound", tag)

	return ""
}

type externalE2EAuthority struct {
	mu       sync.Mutex
	requests []nauthilus.IdentityLookupRequest
}

// Authenticate rejects credential authentication because this fixture owns identity lookup only.
func (a *externalE2EAuthority) Authenticate(context.Context, nauthilus.AuthRequest) (nauthilus.AuthResult, error) {
	return nauthilus.AuthResult{Decision: nauthilus.DecisionTemporaryFailure}, nil
}

// LookupIdentity resolves the certificate email SAN to one canonical routing account.
func (a *externalE2EAuthority) LookupIdentity(_ context.Context, request nauthilus.IdentityLookupRequest) (nauthilus.AuthResult, error) {
	a.mu.Lock()
	a.requests = append(a.requests, request)
	a.mu.Unlock()

	if request.Context.Username != e2eExternalIdentity || request.Context.Method != e2eExternalMethod {
		return nauthilus.AuthResult{Decision: nauthilus.DecisionRejected}, nil
	}

	return nauthilus.AuthResult{
		Decision: nauthilus.DecisionAuthenticated,
		Account:  e2eExternalIdentity,
		Attributes: map[string][]string{
			e2eAttributeTenant:    {e2eTenant},
			e2eAttributeMailShard: {e2eShardTag},
		},
	}, nil
}

// AssertLookup proves the authority saw the certificate identity with verified TLS facts.
func (a *externalE2EAuthority) AssertLookup(t *testing.T) {
	t.Helper()

	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.requests) != 1 {
		t.Fatalf("identity lookup requests = %d, want 1", len(a.requests))
	}

	request := a.requests[0].Context
	if request.Username != e2eExternalIdentity || request.Method != e2eExternalMethod || request.TLS != "true" || request.TLSClientVerify != "SUCCESS" {
		t.Fatalf("identity lookup context = %#v, want verified EXTERNAL identity", request)
	}
}

type externalTLSBundle struct {
	caPath            string
	serverCertPath    string
	serverKeyPath     string
	clientCertificate tls.Certificate
}

// writeExternalTLSBundle creates a private CA and purpose-specific server and client leaves.
func writeExternalTLSBundle(t *testing.T) externalTLSBundle {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate external CA key: %v", err)
	}

	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "EXTERNAL E2E CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create external CA: %v", err)
	}

	serverCertPath, serverKeyPath := writeExternalLeaf(t, ca, caKey, externalLocalhost, "", x509.ExtKeyUsageServerAuth)
	clientCertPath, clientKeyPath := writeExternalLeaf(t, ca, caKey, "client", e2eExternalIdentity, x509.ExtKeyUsageClientAuth)

	clientCertificate, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		t.Fatalf("load external client certificate: %v", err)
	}

	return externalTLSBundle{
		caPath:            writeTempFile(t, "external-ca-*.pem", pem.EncodeToMemory(&pem.Block{Type: externalPEMCertificate, Bytes: caDER})),
		serverCertPath:    serverCertPath,
		serverKeyPath:     serverKeyPath,
		clientCertificate: clientCertificate,
	}
}

// writeExternalLeaf writes one CA-signed certificate with an optional email SAN.
func writeExternalLeaf(
	t *testing.T,
	ca *x509.Certificate,
	caKey *rsa.PrivateKey,
	commonName string,
	email string,
	usage x509.ExtKeyUsage,
) (string, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate external leaf key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generate external leaf serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     []string{externalLocalhost},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	if email != "" {
		template.EmailAddresses = []string{email}
	}

	certificateDER, err := x509.CreateCertificate(rand.Reader, template, ca, &privateKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create external leaf: %v", err)
	}

	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: externalPEMCertificate, Bytes: certificateDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: externalPEMRSAPrivateKey, Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return writeTempFile(t, "external-leaf-*.crt", certificatePEM), writeTempFile(t, "external-leaf-*.key", keyPEM)
}

// dialExternalTLS connects with an optional client certificate.
func dialExternalTLS(t *testing.T, address string, certificate tls.Certificate) net.Conn {
	t.Helper()

	config := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	if len(certificate.Certificate) > 0 {
		config.Certificates = []tls.Certificate{certificate}
	}

	connection, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, config)
	if err != nil {
		t.Fatalf("dial EXTERNAL TLS %s: %v", address, err)
	}

	return connection
}
