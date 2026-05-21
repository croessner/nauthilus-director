package filter

import (
	"strings"

	"github.com/croessner/nauthilus-director/interfaces"
	"github.com/croessner/nauthilus-director/lmtp/proto"
)

type ResponseFilterManager struct {
	responseFilters []iface.LMTPResponseFilter
}

func NewResponseFilterManager() *ResponseFilterManager {
	return &ResponseFilterManager{}
}

func (r *ResponseFilterManager) AddFilter(filter iface.IMAPResponseFilter) {
	r.responseFilters = append(r.responseFilters, filter)
}

func (r *ResponseFilterManager) ApplyFilters(response []string) []string {
	for _, filter := range r.responseFilters {
		response = filter.FilterResponse(response)
	}

	return response
}

type StartTLSResponseFilter struct{}

func NewStartTLSResponseFilter() *StartTLSResponseFilter {
	return &StartTLSResponseFilter{}
}

func (f *StartTLSResponseFilter) FilterResponse(response []string) []string {
	allowedCaps := make([]string, 0)

	for _, item := range response {
		if strings.EqualFold(item, proto.STARTTLS) {
			continue
		}

		allowedCaps = append(allowedCaps, strings.TrimSpace(item))
	}

	return allowedCaps
}

type PipelingingResponseFilter struct{}

func NewPipelingingResponseFilter() *PipelingingResponseFilter {
	return &PipelingingResponseFilter{}
}

func (f *PipelingingResponseFilter) FilterResponse(response []string) []string {
	allowedCaps := make([]string, 0)

	for _, item := range response {
		if strings.EqualFold(item, proto.PIPELINING) {
			continue
		}

		allowedCaps = append(allowedCaps, strings.TrimSpace(item))
	}

	return allowedCaps
}
