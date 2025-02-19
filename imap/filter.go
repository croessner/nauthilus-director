package imap

import (
	"strings"

	"github.com/croessner/nauthilus-director/imap/proto"
	"github.com/croessner/nauthilus-director/interfaces"
)

type ResponseFilterManager struct {
	responseFilters []iface.IMAPResponseFilter
}

func NewResponseFilterManager() *ResponseFilterManager {
	return &ResponseFilterManager{}
}

func (r *ResponseFilterManager) AddFilter(filter iface.IMAPResponseFilter) {
	r.responseFilters = append(r.responseFilters, filter)
}

func (r *ResponseFilterManager) ApplyFilters(response string) string {
	for _, filter := range r.responseFilters {
		response = filter.FilterResponse(response)
	}
	return response
}

type CommandFilterManager struct {
	commandFilters []iface.IMAPCommandFilter
}

func NewCommandFilterManager() *CommandFilterManager {
	return &CommandFilterManager{}
}

func (c *CommandFilterManager) AddFilter(filter iface.IMAPCommandFilter) {
	c.commandFilters = append(c.commandFilters, filter)
}

func (c *CommandFilterManager) ShouldBlock(command string) bool {
	for _, filter := range c.commandFilters {
		if filter.Filter(command) {
			return true
		}
	}

	return false
}

type StartTLSResponseFilter struct{}

func NewStartTLSResponseFilter() *StartTLSResponseFilter {
	return &StartTLSResponseFilter{}
}

func (f *StartTLSResponseFilter) FilterResponse(response string) string {
	response = strings.ReplaceAll(response, proto.STARTTLS, "")
	response = strings.Join(strings.Fields(response), " ")

	return response
}

type StartTLSFilter struct{}

func NewStartTLSFilter() *StartTLSFilter {
	return &StartTLSFilter{}
}

func (f *StartTLSFilter) Filter(command string) bool {
	return strings.EqualFold(strings.TrimSpace(command), proto.STARTTLS)
}

type IDFilter struct{}

func NewIDFilter() *IDFilter {
	return &IDFilter{}
}

func (f *IDFilter) Filter(command string) bool {
	return strings.EqualFold(strings.TrimSpace(command), proto.ID)
}
