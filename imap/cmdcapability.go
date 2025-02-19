package imap

import (
	"github.com/croessner/nauthilus-director/interfaces"
)

type CapabilityCommand struct {
	UseStartTLS bool
	Tag         string
}

func (c *CapabilityCommand) Execute(session iface.IMAPSession) error {
	rawCapabilities := "IMAP4rev1 STARTTLS AUTH=LOGIN AUTH=PLAIN AUTH=XOAUTH2 ID"

	capabilityFilter := NewResponseFilterManager()
	if !c.UseStartTLS || session.GetTLSFlag() {
		capabilityFilter.AddFilter(NewStartTLSResponseFilter())
	}

	filteredCapabilities := capabilityFilter.ApplyFilters(rawCapabilities)

	session.WriteResponse("* CAPABILITY " + filteredCapabilities + "\r\n")
	session.WriteResponse(c.Tag + " OK CAPABILITY completed\r\n")

	return nil
}
