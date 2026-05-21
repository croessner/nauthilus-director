package commands

import "github.com/croessner/nauthilus-director/interfaces"

type Logout struct {
	Tag string
}

var _ iface.IMAPCommand = (*Logout)(nil)

func (c *Logout) Execute(session iface.IMAPSession) error {
	session.WriteResponse("* BYE IMAP Proxy logging out")
	session.WriteResponse(c.Tag + " OK LOGOUT completed")

	session.Close()

	return nil
}
