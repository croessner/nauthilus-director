package commands

import (
	"errors"
	"io"
	"log/slog"

	authenticator "github.com/croessner/nauthilus-director/auth"
	"github.com/croessner/nauthilus-director/imap/proto"
	"github.com/croessner/nauthilus-director/interfaces"
)

type Login struct {
	Tag      string
	Username string
	Password string
}

var _ iface.IMAPCommand = (*Login)(nil)

func (c *Login) Execute(session iface.IMAPSession) error {
	auth := session.GetAuthenticator()

	setupAuthenticator(session, auth)
	auth.SetAuthMechanism(proto.LOGIN + " (RFC3501)")

	isAuthenticated, err := auth.Authenticate(session.GetClientContext(), session.GetService(), c.Username, c.Password)
	if err != nil {
		if !(errors.Is(err, authenticator.ErrAuthenticationFailed) || errors.Is(err, authenticator.ErrUserNotFound)) {
			session.WriteResponse(c.Tag + " NO Internal error")

			session.Close()
		}
	}

	if !isAuthenticated {
		session.WriteResponse(c.Tag + " NO Authentication failed")

		return authenticator.ErrAuthenticationFailed
	}

	session.SetUser(auth.GetAccount())

	// TODO: config master user
	_ = "masteruser"
	masterPass := "password"

	err = session.ConnectToIMAPBackend(c.Tag, session.GetUser(), masterPass)
	if err != nil {
		if err == io.EOF {
			session.Close()

			return io.EOF
		}

		session.WriteResponse(c.Tag + " NO Backend authentication failed")

		return err
	}

	session.WriteResponse(session.GetBackendGreeting())

	session.GetLogger().Info("link client and backend", session.Session(), slog.String("user", session.GetUser()))
	session.GetStopWatchDog() <- struct{}{}
	session.LinkClientAndBackend()

	return nil
}
