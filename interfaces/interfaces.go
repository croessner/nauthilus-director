package iface

import (
	"bufio"
	"log/slog"
	"net"

	"github.com/croessner/nauthilus-director/config"
	"github.com/croessner/nauthilus-director/context"
)

// Authenticator defines an interface for verifying username and password credentials.
// The Authenticate method returns true if authentication succeeds and false otherwise.
type Authenticator interface {
	Authenticate(username, password string) bool
}

// Proxy defines an interface for starting a proxy instance with specified configuration.
type Proxy interface {
	Start(instance config.Listen) error
}

// IMAPCommand represents an interface for handling and executing IMAP commands within a session.
type IMAPCommand interface {
	Execute(session IMAPSession) error
}

// IMAPSession defines an interface for managing an IMAP session, including client communication and authentication.
// It provides methods for handling context, connection management, reading and writing data, and logging/debugging.
type IMAPSession interface {
	/*
		Context getters
	*/
	GetClientContext() *context.Context
	GetServerContext() *context.Context

	/*
		Client and backend communication
	*/
	WriteResponse(response string)
	ReadLine() (string, error)
	GetBackendGreeting() string
	GetTLSFlag() bool
	SetTLSFlag(flag bool)
	GetAuthMechs() []string
	GetCapability() string
	SetClientID(id string)
	GetBackendConn() net.Conn
	LinkClientAndBackend()

	/*
		Connection and session management
	*/
	SetClientConn(conn net.Conn)
	GetClientConn() net.Conn
	SetReader(reader *bufio.Reader)
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
}

// IMAPCommandFilter is an interface for filtering IMAP commands based on a given string input.
type IMAPCommandFilter interface {
	Filter(command string) bool
}

// IMAPResponseFilter defines methods for filtering and modifying IMAP response strings in a customizable manner.
type IMAPResponseFilter interface {
	FilterResponse(response string) string
}
