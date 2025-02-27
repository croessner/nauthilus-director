package commands

import (
	"github.com/croessner/nauthilus-director/imap/commands/filter"
	"github.com/croessner/nauthilus-director/imap/proto"
	"github.com/croessner/nauthilus-director/interfaces"
)

const DefaultCapabilities = "IMAP4rev1 ID ENABLE IDLE STARTTLS AUTH=PLAIN AUTH=LOGIN AUTH=XOAUTH2"

type Capability struct {
	UseStartTLS bool
	Tag         string
}

func (c *Capability) Execute(session iface.IMAPSession) error {
	filteredCapabilities := GenerateCapabilities(c.UseStartTLS, session.GetTLSFlag(), session.GetAuthMechs(), session.GetCapability())

	session.WriteResponse("* CAPABILITY " + filteredCapabilities)
	session.WriteResponse(c.Tag + " OK CAPABILITY completed")

	return nil
}

func GenerateCapabilities(useStartTLS, tlsFlag bool, mechanisms []string, rawCapability string) string {
	capabilityFilter := filter.NewResponseFilterManager()
	if !useStartTLS || tlsFlag {
		capabilityFilter.AddFilter(filter.NewStartTLSResponseFilter())
	}

	allMechanisms := []string{proto.LOGIN, proto.PLAIN, proto.XOAUTH2}
	disallowedMechanisms := CalculateDisallowedMechanisms(allMechanisms, mechanisms)

	capabilityFilter.AddFilter(filter.NewAuthMechanismResponseFilter(disallowedMechanisms))

	if rawCapability == "" {
		rawCapability = DefaultCapabilities
	}

	filteredCapabilities := capabilityFilter.ApplyFilters(rawCapability)

	return filteredCapabilities
}
