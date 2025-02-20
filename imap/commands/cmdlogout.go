package commands

import "github.com/croessner/nauthilus-director/interfaces"

type Logout struct {
	Tag string
}

func (c *Logout) Execute(session iface.IMAPSession) error {
	session.WriteResponse("* BYE IMAP Proxy logging out\r\n")
	session.WriteResponse(c.Tag + " OK LOGOUT completed\r\n")

	session.Close()

	return nil
}
