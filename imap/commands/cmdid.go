package commands

import (
	"github.com/croessner/nauthilus-director/interfaces"
	"github.com/croessner/nauthilus-director/version"
)

type ID struct {
	Tag  string
	Data string
}

func (id *ID) Execute(session iface.IMAPSession) error {
	session.WriteResponse("* ID (\"name\" \"Nauthilus director\" \"version\" \"" + version.Version + "\")\r\n")
	session.WriteResponse(id.Tag + " OK ID completed\r\n")

	session.SetClientID(id.Data)

	return nil
}
