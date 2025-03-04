package auth

import (
	"log/slog"

	"github.com/croessner/nauthilus-director/context"
	"github.com/croessner/nauthilus-director/log"
)

type NauthilusAuthenticator struct {
	userLookup         bool
	tlsVerified        bool
	tlsProtocol        string
	tlsCipherSuite     string
	tlsFingerprint     string
	tlsClientCName     string
	tlsIssuerDN        string
	tlsClientDN        string
	tlsClientNotBefore string
	tlsClientNotAfter  string
	tlsSerial          string
	tlsClientIssuerDN  string
	tlsDNSNames        string
	service            string
	account            string
	localIP            string
	remoteIP           string
	authMechanism      string
	localPort          int
	remotePort         int
}

func (n *NauthilusAuthenticator) Authenticate(ctx *context.Context, service, username, password string) bool {
	logger := log.GetLogger(ctx)

	logger.Debug("Nauthilus authentication",
		slog.String("service", service),
		slog.String("auth_mechanism", n.authMechanism),
		slog.String("username", username),
		slog.String("local_IP", n.localIP),
		slog.Int("local_port", n.localPort),
		slog.String("remote_IP", n.remoteIP),
		slog.Int("remote_port", n.remotePort),
		slog.String("tls_protocol", n.tlsProtocol),
		slog.String("tls_cipher_suite", n.tlsCipherSuite),
		slog.String("tls_fingerprint", n.tlsFingerprint),
		slog.String("tls_client_CName", n.tlsClientCName),
		slog.String("tls_issuer_DN", n.tlsIssuerDN),
		slog.String("tls_client_DN", n.tlsClientDN),
		slog.String("tls_client_not_before", n.tlsClientNotBefore),
		slog.String("tls_client_not_after", n.tlsClientNotAfter),
		slog.String("tls_serial", n.tlsSerial),
		slog.String("tls_client_issuer_DN", n.tlsClientIssuerDN),
		slog.String("tls_DNS_names", n.tlsDNSNames),
	)

	if username != "user@example.com" {
		return false
	} else {
		n.account = username
	}

	if n.userLookup {
		return true
	}

	return password == "pass"
}

func (n *NauthilusAuthenticator) SetUserLookup(flag bool) {
	n.userLookup = flag
}

func (n *NauthilusAuthenticator) GetAccount() string {
	return n.account
}

func (n *NauthilusAuthenticator) SetAuthMechanism(mechanism string) {
	n.authMechanism = mechanism
}

func (n *NauthilusAuthenticator) SetTLSProtocol(protocol string) {
	n.tlsProtocol = protocol
}

func (n *NauthilusAuthenticator) SetTLSCipherSuite(cipherSuite string) {
	n.tlsCipherSuite = cipherSuite
}

func (n *NauthilusAuthenticator) SetTLSFingerprint(fingerprint string) {
	n.tlsFingerprint = fingerprint
}

func (n *NauthilusAuthenticator) SetTLSClientCName(clientCName string) {
	n.tlsClientCName = clientCName
}

func (n *NauthilusAuthenticator) SetTLSVerified(verified bool) {
	n.tlsVerified = verified
}

func (n *NauthilusAuthenticator) SetTLSIssuerDN(issuerDN string) {
	n.tlsIssuerDN = issuerDN
}

func (n *NauthilusAuthenticator) SetTLSClientDN(clientDN string) {
	n.tlsClientDN = clientDN
}

func (n *NauthilusAuthenticator) SetTLSClientNotBefore(notBefore string) {
	n.tlsClientNotBefore = notBefore
}

func (n *NauthilusAuthenticator) SetTLSClientNotAfter(notAfter string) {
	n.tlsClientNotAfter = notAfter
}

func (n *NauthilusAuthenticator) SetTLSSerial(serial string) {
	n.tlsSerial = serial
}

func (n *NauthilusAuthenticator) SetTLSClientIssuerDN(clientIssuerDN string) {
	n.tlsClientIssuerDN = clientIssuerDN
}

func (n *NauthilusAuthenticator) SetTLSDNSNames(dnsNames string) {
	n.tlsDNSNames = dnsNames
}

func (n *NauthilusAuthenticator) SetLocalIP(ip string) {
	n.localIP = ip
}

func (n *NauthilusAuthenticator) SetRemoteIP(ip string) {
	n.remoteIP = ip
}

func (n *NauthilusAuthenticator) SetLocalPort(port int) {
	n.localPort = port
}

func (n *NauthilusAuthenticator) SetRemotePort(port int) {
	n.remotePort = port
}
