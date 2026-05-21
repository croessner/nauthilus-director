package commands

import (
	"github.com/croessner/nauthilus-director/interfaces"
	"github.com/croessner/nauthilus-director/version"
)

type ID struct {
	Tag  string
	Data string
}

var _ iface.IMAPCommand = (*ID)(nil)

func (id *ID) Execute(session iface.IMAPSession) error {
	session.WriteResponse("* ID (\"name\" \"Nauthilus director\" \"version\" \"" + version.Version + "\")")
	session.WriteResponse(id.Tag + " OK ID completed")

	session.SetClientID(id.Data)

	return nil
}
