package commands

import (
	"errors"
	"strings"

	authenticator "github.com/croessner/nauthilus-director/auth"
	"github.com/croessner/nauthilus-director/interfaces"
)

type RcptTo struct {
	recipient string
}

func NewRcptTo(recipient string) *RcptTo {
	return &RcptTo{
		recipient: recipient,
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
	auth.SetHTTPOptions(session.GetNauthilus().HTTPClient)
	auth.SetTLSOptions(session.GetNauthilus().TLS)
	auth.SetTLSSecured(session.GetTLSFlag())
	auth.SetNauthilusApi(session.GetNauthilus().Url)
	addTlsSessionInfos(session, auth)

	userfound, err := auth.Authenticate(session.GetClientContext(), session.GetService(), normalizeUsername(c.recipient), "")
	if err != nil {
		if !errors.Is(err, authenticator.ErrUserNotFound) {
			return err
		}

		err = nil
	}

	if !userfound {
		if err = session.WriteResponse("550 5.1.1 User does not exist"); err != nil {
			return err
		}
	} else {
		if err = session.WriteResponse("250 2.1.5 OK"); err != nil {
			return err
		}

		session.AddRecipient(c.recipient)
	}

	return nil
}

func normalizeUsername(recipient string) string {
	if strings.HasPrefix(recipient, "<") {
		recipient = strings.TrimPrefix(recipient, "<")
	}

	if strings.HasSuffix(recipient, ">") {
		recipient = strings.TrimSuffix(recipient, ">")
	}

	return recipient
}
