package commands

import (
	"github.com/croessner/nauthilus-director/interfaces"
)

type Authenticate struct {
	Tag    string
	Method string
}

func (c *Authenticate) Execute(session iface.IMAPSession) error {
	return nil
}
