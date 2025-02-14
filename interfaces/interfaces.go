package iface

import (
	"bufio"
	"net"
)

type Authenticator interface {
	Authenticate(username, password string) bool
}

type IMAPCommand interface {
	Execute(session IMAPSession) error
}

type IMAPSession interface {
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
}
