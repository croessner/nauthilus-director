package imap

import (
	"github.com/croessner/nauthilus-director/imap/proto"
	"github.com/croessner/nauthilus-director/interfaces"
)

const DefaultCapabilities = "IMAP4rev1 LOGIN-REFERRALS ENABLE IDLE SASL-IR LITERAL+ STARTTLS AUTH=PLAIN AUTH=LOGIN AUTH=XOAUTH2"

type CapabilityCommand struct {
	UseStartTLS bool
	Tag         string
}

func (c *CapabilityCommand) Execute(session iface.IMAPSession) error {
	filteredCapabilities := generateCapabilities(c.UseStartTLS, session.GetTLSFlag(), session.GetAuthMechs(), session.GetCapability())

	session.WriteResponse("* CAPABILITY " + filteredCapabilities + "\r\n")
	session.WriteResponse(c.Tag + " OK CAPABILITY completed\r\n")

	return nil
}

func generateCapabilities(useStartTLS, tlsFlag bool, mechanisms []string, rawCapability string) string {
	capabilityFilter := NewResponseFilterManager()
	if !useStartTLS || tlsFlag {
		capabilityFilter.AddFilter(NewStartTLSResponseFilter())
	}

	allMechanisms := []string{proto.LOGIN, proto.PLAIN, proto.XOAUTH2}
	disallowedMechanisms := calculateDisallowedMechanisms(allMechanisms, mechanisms)

	capabilityFilter.AddFilter(NewAuthMechanismResponseFilter(disallowedMechanisms))

	if rawCapability == "" {
		rawCapability = DefaultCapabilities
	}

	filteredCapabilities := capabilityFilter.ApplyFilters(rawCapability)

	return filteredCapabilities
}
