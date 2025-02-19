package imap

import (
	"github.com/croessner/nauthilus-director/interfaces"
	"github.com/croessner/nauthilus-director/version"
)

type IDCommand struct {
	Tag  string
	Data string
}

func (id *IDCommand) Execute(session iface.IMAPSession) error {
	session.WriteResponse("* ID (\"name\" \"Nauthilus director\" \"version\" \"" + version.Version + "\")\r\n")
	session.WriteResponse(id.Tag + " OK ID completed\r\n")

	session.SetClientID(id.Data)

	return nil
}
