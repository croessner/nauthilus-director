package imap

import "github.com/croessner/nauthilus-director/interfaces"

type CapabilityCommand struct {
	Tag string
}

func (c *CapabilityCommand) Execute(session iface.IMAPSession) error {
	session.WriteResponse("* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN AUTH=LOGIN AUTH=XOAUTH2 IDLE\r\n")
	session.WriteResponse(c.Tag + " OK CAPABILITY completed\r\n")

	return nil
}
