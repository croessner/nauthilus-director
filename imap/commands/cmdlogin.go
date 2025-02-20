package commands

import (
	"fmt"
	"io"

	"github.com/croessner/nauthilus-director/interfaces"
	"github.com/croessner/nauthilus-director/log"
)

type Login struct {
	Tag      string
	Username string
	Password string
}

func (c *Login) Execute(session iface.IMAPSession) error {
	auth := session.GetAuthenticator()
	logger := log.GetLogger(session.GetBackendContext())

	if !auth.Authenticate(c.Username, c.Password) {
		session.WriteResponse(c.Tag + " NO Authentication failed\r\n")

		return fmt.Errorf("auth failed")
	}

	session.SetUser(c.Username)

	// TODO: config master user
	_ = "masteruser"
	masterPass := "password"

	err := session.ConnectToIMAPBackend(c.Tag, session.GetUser(), masterPass)
	if err != nil {
		if err == io.EOF {
			session.Close()

			return io.EOF
		}

		session.WriteResponse(c.Tag + " NO Backend authentication failed\r\n")

		return err
	}

	session.WriteResponse(session.GetBackendGreeting())

	logger.Debug("link client and backend", session.Session())

	session.LinkClientAndBackend()

	return nil
}
