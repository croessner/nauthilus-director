package imap

import (
	"github.com/croessner/nauthilus-director/interfaces"
)

type AuthenticateCommand struct {
	Tag    string
	Method string
}

func (c *AuthenticateCommand) Execute(session iface.IMAPSession) error {
	return nil
}
