package link

import (
	"io"

	"github.com/croessner/nauthilus-director/interfaces"
	"github.com/croessner/nauthilus-director/log"
)

func ConnectClientWithBackend(session iface.Session) {
	logger := log.GetLogger(session.GetBackendContext())

	clientDone := make(chan struct{})
	backendDone := make(chan struct{})

	go func() {
		_, _ = io.Copy(session.GetBackendConn(), session.GetClientConn())
		logger.Debug("Connection closed by client", session.Session())

		close(clientDone)
	}()

	go func() {
		_, _ = io.Copy(session.GetClientConn(), session.GetBackendConn())
		logger.Debug("Connection closed by backend", session.Session())

		close(backendDone)
	}()

	select {
	case <-session.GetBackendContext().Done():
		session.Close()
	case <-session.GetClientContext().Done():
		session.Close()
	case <-clientDone:
		session.Close()
	case <-backendDone:
		session.Close()
	}
}
