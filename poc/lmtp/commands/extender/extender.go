package extender

import (
	"github.com/croessner/nauthilus-director/interfaces"
	"github.com/croessner/nauthilus-director/lmtp/proto"
)

type ResponseExtenderManager struct {
	responseExtenders []iface.LMTPResponseExtender
}

func NewResponseExtenderManager() *ResponseExtenderManager {
	return &ResponseExtenderManager{}
}

func (r *ResponseExtenderManager) AddExtender(extender iface.LMTPResponseExtender) {
	r.responseExtenders = append(r.responseExtenders, extender)
}

func (r *ResponseExtenderManager) ApplyExtenders(response []string) []string {
	uniqueResponse := make(map[string]struct{}, len(response))
	result := make([]string, 0, len(response))

	for _, item := range response {
		uniqueResponse[item] = struct{}{}
		result = append(result, item)
	}

	for _, extender := range r.responseExtenders {
		newItems := extender.ExtendResponse()
		for _, item := range newItems {
			if _, exists := uniqueResponse[item]; !exists {
				uniqueResponse[item] = struct{}{}
				result = append(result, item)
			}
		}
	}

	return result
}

type EightbitMimeResponseExtender struct{}

func NewEightbitMimeResponseExtender() *EightbitMimeResponseExtender {
	return &EightbitMimeResponseExtender{}
}

func (f *EightbitMimeResponseExtender) ExtendResponse() []string {
	return []string{
		proto.EIGHTBITMIME,
	}
}

type SMTPUTF8ResponseExtender struct{}

func NewSMTPUTF8ResponseExtender() *SMTPUTF8ResponseExtender {
	return &SMTPUTF8ResponseExtender{}
}

func (f *SMTPUTF8ResponseExtender) ExtendResponse() []string {
	return []string{
		proto.SMTPUTF8,
	}
}

type EnhancedStatusCodesResponseExtender struct{}

func NewEnhancedStatusCodesResponseExtender() *EnhancedStatusCodesResponseExtender {
	return &EnhancedStatusCodesResponseExtender{}
}

func (f *EnhancedStatusCodesResponseExtender) ExtendResponse() []string {
	return []string{
		proto.ENHANCEDSTATUSCODES,
	}
}
