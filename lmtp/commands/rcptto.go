package commands

import (
	"strings"

	"github.com/croessner/nauthilus-director/interfaces"
)

type RcptTo struct {
	Found    bool
	Username string
}

func NewRcptTo(username string) *RcptTo {
	return &RcptTo{
		Username: username,
	}
}

var _ iface.LMTPCommand = (*RcptTo)(nil)

func (c *RcptTo) Execute(session iface.LMTPSession) error {
	auth := session.GetAuthenticator()

	auth.SetRemoteIP(session.GetRemoteIP())
	auth.SetRemotePort(session.GetRemotePort())
	auth.SetLocalIP(session.GetLocalIP())
	auth.SetLocalPort(session.GetLocalPort())
	auth.SetUserLookup(true)
	auth.SetAuthMechanism("NONE")
	addTlsSessionInfos(session, auth)

	if !auth.Authenticate(session.GetClientContext(), session.GetService(), normalizeUsername(c.Username), "") {
		if err := session.WriteResponse("550 5.1.1 User does not exist"); err != nil {
			return err
		}
	} else {
		c.Found = true
	}

	return nil
}

func normalizeUsername(username string) string {
	if strings.HasPrefix(username, "<") {
		username = strings.TrimPrefix(username, "<")
	}

	if strings.HasSuffix(username, ">") {
		username = strings.TrimSuffix(username, ">")
	}

	return username
}
