package imap

import "github.com/croessner/nauthilus-director/interfaces"

type IDCommand struct {
	Tag  string
	Data string
}

func (id *IDCommand) Execute(session iface.IMAPSession) error {
	session.WriteResponse("* ID (\"name\" \"IMAPProxy\" \"version\" \"1.0\")\r\n")
	session.WriteResponse(id.Tag + " OK ID completed\r\n")

	return nil
}
