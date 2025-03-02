package iface

import (
	"crypto/tls"
	"log/slog"
	"net"
	"sync"

	"github.com/croessner/nauthilus-director/config"
	"github.com/croessner/nauthilus-director/context"
)

// Authenticator defines an interface for verifying username and password credentials.
// The Authenticate method returns true if authentication succeeds and false otherwise.
type Authenticator interface {
	Authenticate(ctx *context.Context, service, username, password string) bool

	SetUserLookup(flag bool)
	GetAccount() string
	SetAuthMechanism(mechanism string)

	/*
		Connection related setter
	*/
	SetLocalIP(ip string)
	SetRemoteIP(ip string)
	SetLocalPort(port int)
	SetRemotePort(port int)

	/*
		TLS-related setters
	*/
	SetTLSVerified(verified bool)
	SetTLSProtocol(protocol string)
	SetTLSCipherSuite(cipherSuite string)
	SetTLSFingerprint(fingerprint string)
	SetTLSClientCName(clientCName string)
	SetTLSIssuerDN(issuerDN string)
	SetTLSClientDN(clientDN string)
	SetTLSClientNotBefore(notBefore string)
	SetTLSClientNotAfter(notAfter string)
	SetTLSSerial(serial string)
	SetTLSClientIssuerDN(clientIssuerDN string)
	SetTLSDNSNames(dnsNames string)
}

// Proxy defines an interface for starting a proxy instance with specified configuration.
type Proxy interface {
	Start(instance config.Listen, handler func(Proxy, net.Conn)) error

	GetListener() net.Listener
	GetWaitGroup() *sync.WaitGroup
	GetContext() *context.Context
	GetTLSConfig() *tls.Config
	GetInstance() config.Listen
	GetListenAddr() string
	GetName() string
}

// IMAPCommand represents an interface for handling and executing IMAP commands within a session.
type IMAPCommand interface {
	Execute(session IMAPSession) error
}

// Session represents an interface that provides a method for retrieving session-specific logging attributes.
type Session interface {
	GetClientContext() *context.Context
	GetBackendContext() *context.Context
	GetClientConn() net.Conn
	GetBackendConn() net.Conn
	Close()

	Session() slog.Attr
}

// IMAPSession defines an interface for managing an IMAP session, including client communication and authentication.
// It provides methods for handling context, connection management, reading and writing data, and logging/debugging.
// IMAPSession defines an interface for managing an IMAP session, including client communication and authentication.
type IMAPSession interface {
	/*
		Context getters
	*/
	GetClientContext() *context.Context
	GetBackendContext() *context.Context

	/*
		Client and backend communication
	*/
	WriteResponse(response string)
	ReadLine() (string, error)
	GetBackendGreeting() string
	GetTLSFlag() bool
	SetTLSFlag(flag bool)
	GetAuthMechs() []string
	GetCapability() []string
	SetClientID(id string)
	GetBackendConn() net.Conn
	LinkClientAndBackend()

	/*
		Connection and session management
	*/
	GetUserLookup() bool
	GetService() string
	GetLocalIP() string
	GetRemoteIP() string
	GetLocalPort() int
	GetRemotePort() int
	SetClientConn(conn net.Conn)
	GetClientConn() net.Conn
	GetStopWatchDog() chan struct{}
	Close()

	/*
		Authentication
	*/
	GetAuthenticator() Authenticator
	SetUser(user string)
	GetUser() string

	ConnectToIMAPBackend(tag, masterUser, masterPass string) error

	/*
		Logging / Debugging
	*/
	Session() slog.Attr

	/*
		TLS-related getters
	*/
	InitializeTLSFields()
	GetTLSVerified() bool
	GetTLSProtocol() string
	GetTLSCipherSuite() string
	GetTLSFingerprint() string
	GetTLSClientCName() string
	GetTLSIssuerDN() string
	GetTLSClientDN() string
	GetTLSClientNotBefore() string
	GetTLSClientNotAfter() string
	GetTLSSerial() string
	GetTLSClientIssuerDN() string
	GetTLSDNSNames() string
}

// IMAPCommandFilter is an interface for filtering IMAP commands based on a given string input.
type IMAPCommandFilter interface {
	Filter(command string) bool
}

// IMAPResponseFilter defines methods for filtering and modifying IMAP response strings in a customizable manner.
type IMAPResponseFilter interface {
	FilterResponse(response []string) []string
}
