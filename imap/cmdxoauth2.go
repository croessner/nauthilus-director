package imap

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/croessner/nauthilus-director/interfaces"
)

type XOAUTH2Command struct {
	Tag string
}

func (c *XOAUTH2Command) Execute(session iface.IMAPSession) error {
	session.WriteResponse("+ \r\n") // Challenge senden

	line, err := session.ReadLine()
	if err != nil {
		return err
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.Trim(line, "\r\n"))
	if err != nil {
		session.WriteResponse(c.Tag + " NO Invalid authentication data\r\n")

		return err
	}

	authData := strings.Split(string(decoded), "\x01") // ^A ist \x01
	if len(authData) < 2 {
		session.WriteResponse(c.Tag + " NO Invalid XOAUTH2 format\r\n")

		return fmt.Errorf("invalid xoauth2 format")
	}

	var username, token string
	for _, field := range authData {
		if strings.HasPrefix(field, "user=") {
			username = strings.TrimPrefix(field, "user=")
		} else if strings.HasPrefix(field, "auth=Bearer ") {
			token = strings.TrimPrefix(field, "auth=Bearer ")
		}
	}

	if username == "" || token == "" {
		session.WriteResponse(c.Tag + " NO Invalid XOAUTH2 data\r\n")

		return fmt.Errorf("missing user or token")
	}

	auth := session.GetAuthenticator()
	if !auth.Authenticate(username, token) {
		session.WriteResponse(c.Tag + " NO Authentication failed\r\n")

		return fmt.Errorf("auth failed")
	}

	session.ForwardToIMAPServer(fmt.Sprintf("%s AUTHENTICATE XOAUTH2 %s\r\n", c.Tag, line))

	return nil
}
