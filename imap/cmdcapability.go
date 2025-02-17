package imap

import (
	"github.com/croessner/nauthilus-director/interfaces"
)

type CapabilityCommand struct {
	Tag         string
	UseStartTLS bool
}

func (c *CapabilityCommand) Execute(session iface.IMAPSession) error {
	rawCapabilities := "IMAP4rev1 STARTTLS AUTH=LOGIN AUTH=PLAIN AUTH=XOAUTH2 ID"

	responseFilter := &GenericResponseFilter{}
	if !c.UseStartTLS {
		responseFilter.AddResponseFilter(&StartTLSResponseFilter{})
	}

	filteredCapabilities := responseFilter.ApplyFilters(rawCapabilities)

	session.WriteResponse("* CAPABILITY " + filteredCapabilities + "\r\n")
	session.WriteResponse(c.Tag + " OK CAPABILITY completed\r\n")

	return nil
}
