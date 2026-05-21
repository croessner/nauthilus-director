package commands

import (
	"github.com/croessner/nauthilus-director/interfaces"
)

type XOAUTH2 struct {
	Tag string
}

var _ iface.IMAPCommand = (*XOAUTH2)(nil)

func (c *XOAUTH2) Execute(session iface.IMAPSession) error {
	return nil
}
