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

type AuthMechanismResponseFilter struct {
	mechanisms []string
}

func NewAuthMechanismResponseFilter(mechanisms []string) *AuthMechanismResponseFilter {
	return &AuthMechanismResponseFilter{
		mechanisms: mechanisms,
	}
}

func (a *AuthMechanismResponseFilter) FilterResponse(response string) string {
	fields := strings.Fields(response)
	remainingFields := make([]string, 0)

	for _, field := range fields {
		forbidden := false

		for _, mechanism := range a.mechanisms {
			if strings.EqualFold(field, "AUTH="+strings.ToUpper(mechanism)) {
				forbidden = true

				break
			}
		}

		if !forbidden {
			remainingFields = append(remainingFields, field)
		}
	}

	return strings.Join(remainingFields, " ")
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

type AuthMechanismFilter struct {
	mechanisms []string
}

func NewAuthMechanismFilter(mechanisms []string) *AuthMechanismFilter {
	return &AuthMechanismFilter{
		mechanisms: mechanisms,
	}
}

func (a *AuthMechanismFilter) Filter(command string) bool {
	trimmedCommand := strings.ToUpper(strings.TrimSpace(command))

	for _, mechanism := range a.mechanisms {
		expectedPrefix := "AUTHENTICATE " + strings.ToUpper(mechanism)
		if strings.HasPrefix(trimmedCommand, expectedPrefix) {
			return true
		}
	}

	return false
}
