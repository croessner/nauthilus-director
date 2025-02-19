package imap

import (
	"github.com/croessner/nauthilus-director/interfaces"
)

type XOAUTH2Command struct {
	Tag string
}

func (c *XOAUTH2Command) Execute(session iface.IMAPSession) error {
	return nil
}
