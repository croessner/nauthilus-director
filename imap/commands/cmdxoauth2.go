package commands

import (
	"github.com/croessner/nauthilus-director/interfaces"
)

type XOAUTH2 struct {
	Tag string
}

func (c *XOAUTH2) Execute(session iface.IMAPSession) error {
	return nil
}
