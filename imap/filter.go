package imap

import (
	"strings"

	"github.com/croessner/nauthilus-director/interfaces"
)

type StartTLSResponseFilter struct{}

func (f *StartTLSResponseFilter) FilterResponse(response string) string {
	response = strings.ReplaceAll(response, "STARTTLS", "")
	response = strings.Join(strings.Fields(response), " ")

	return response
}

type GenericResponseFilter struct {
	responseFilters []iface.IMAPResponseFilter
}

func (g *GenericResponseFilter) AddResponseFilter(filter iface.IMAPResponseFilter) {
	g.responseFilters = append(g.responseFilters, filter)
}

func (g *GenericResponseFilter) ApplyFilters(response string) string {
	for _, filter := range g.responseFilters {
		response = filter.FilterResponse(response)
	}

	return response
}

type StartTLSFilter struct{}

func (f *StartTLSFilter) Filter(command string) bool {
	return strings.EqualFold(strings.TrimSpace(command), "STARTTLS")
}

type GenericCommandFilter struct {
	filters []iface.IMAPCommandFilter
}

func (g *GenericCommandFilter) AddFilter(filter iface.IMAPCommandFilter) {
	g.filters = append(g.filters, filter)
}

func (g *GenericCommandFilter) ShouldBlock(command string) bool {
	for _, filter := range g.filters {
		if filter.Filter(command) {
			return true
		}
	}

	return false
}
