package iface

import (
	"bufio"
	"log/slog"
	"net"

	"github.com/croessner/nauthilus-director/config"
	"github.com/croessner/nauthilus-director/context"
)

type Authenticator interface {
	Authenticate(username, password string) bool
}

type Proxy interface {
	Start(instance config.Listen) error
}

type IMAPCommand interface {
	Execute(session IMAPSession) error
}

type IMAPSession interface {
	GetClientContext() *context.Context
	GetServerContext() *context.Context
	WriteResponse(response string)
	ReadLine() (string, error)
	ConnectToIMAPBackend(tag, masterUser, masterPass string) error
	ForwardToIMAPServer(data string)
	Close()
	GetAuthenticator() Authenticator
	SetUser(user string)
	GetUser() string
	SetClientConn(conn net.Conn)
	GetClientConn() net.Conn
	SetReader(reader *bufio.Reader)
	GetBackendGreeting() string
	Session() slog.Attr
}

type IMAPCommandFilter interface {
	Filter(command string) bool
}

type IMAPResponseFilter interface {
	FilterResponse(response string) string
}
