package imap

import (
	"fmt"

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
	masterPass := "masterpass"

	err := session.ConnectToIMAPBackend(masterUser, masterPass)
	if err != nil {
		session.WriteResponse(c.Tag + " NO Backend authentication failed\r\n")
		session.Close()

		return fmt.Errorf("backend auth failed")
	}

	session.WriteResponse(c.Tag + " OK LOGIN completed\r\n")

	return nil
}
