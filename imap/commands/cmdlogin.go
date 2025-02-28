package commands

import (
	"fmt"
	"io"
	"log/slog"

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
		session.WriteResponse(c.Tag + " NO Authentication failed")

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

		session.WriteResponse(c.Tag + " NO Backend authentication failed")

		return err
	}

	session.WriteResponse(session.GetBackendGreeting())

	logger.Info("link client and backend", session.Session(), slog.String("user", session.GetUser()))
	session.GetStopWatchDog() <- struct{}{}
	session.LinkClientAndBackend()

	return nil
}
