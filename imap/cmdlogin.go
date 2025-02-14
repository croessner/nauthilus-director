package imap

import (
	"fmt"
	"io"

	"github.com/croessner/nauthilus-director/interfaces"
)

type LoginCommand struct {
	Tag      string
	Username string
	Password string
}

func (c *LoginCommand) Execute(session iface.IMAPSession) error {
	auth := session.GetAuthenticator()

	if !auth.Authenticate(c.Username, c.Password) {
		session.WriteResponse(c.Tag + " NO Authentication failed\r\n")

		return fmt.Errorf("auth failed")
	}

	session.SetUser(c.Username)

	// TODO: config master user
	masterUser := "masteruser"
	masterPass := "password" // Dovecot docker image accepts all users with the password "password"

	err := session.ConnectToIMAPBackend(c.Tag, masterUser, masterPass)
	if err != nil {
		if err == io.EOF {
			session.Close()

			return io.EOF
		}

		session.WriteResponse(c.Tag + " NO Backend authentication failed\r\n")

		return fmt.Errorf("backend auth failed")
	}

	session.WriteResponse(session.GetBackendGreeting())
	session.WriteResponse(c.Tag + " OK LOGIN completed\r\n")

	return nil
}
