package imap

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/croessner/nauthilus-director/interfaces"
)

type AuthenticateCommand struct {
	Tag    string
	Method string
}

func (c *AuthenticateCommand) Execute(session iface.IMAPSession) error {
	if c.Method != "PLAIN" {
		session.WriteResponse(c.Tag + " NO Unsupported auth method\r\n")

		return fmt.Errorf("unsupported auth method")
	}

	session.WriteResponse("+ \r\n")

	line, err := session.ReadLine()
	if err != nil {
		return err
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.Trim(line, "\r\n"))
	if err != nil {
		session.WriteResponse(c.Tag + " NO Invalid authentication data\r\n")

		return err
	}

	authParts := strings.Split(string(decoded), "\x00")
	if len(authParts) != 3 {
		session.WriteResponse(c.Tag + " NO Invalid authentication format\r\n")

		return fmt.Errorf("invalid auth format")
	}

	user, pass := authParts[1], authParts[2]
	auth := session.GetAuthenticator()
	if !auth.Authenticate(user, pass) {
		session.WriteResponse(c.Tag + " NO Authentication failed\r\n")

		return fmt.Errorf("auth failed")
	}

	session.ForwardToIMAPServer(fmt.Sprintf("%s AUTHENTICATE PLAIN %s\r\n", c.Tag, line))

	return nil
}
