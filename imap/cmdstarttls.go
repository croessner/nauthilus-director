package imap

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log/slog"

	"github.com/croessner/nauthilus-director/interfaces"
	"github.com/croessner/nauthilus-director/log"
)

type StartTLSCommand struct {
	TLSConfig *tls.Config
	Tag       string
}

func (s *StartTLSCommand) Execute(session iface.IMAPSession) error {
	logger := log.GetLogger(session.GetServerContext())

	if s.TLSConfig == nil {
		session.WriteResponse(s.Tag + " NO TLS configuration not available\r\n")
		logger.Error("TLS config is nil", session.Session())

		return fmt.Errorf("tls config is nil")
	}

	session.WriteResponse(s.Tag + " OK Begin TLS negotiation now\r\n")

	tlsConn := tls.Server(session.GetClientConn(), s.TLSConfig)
	err := tlsConn.Handshake()
	if err != nil {
		logger.Error("TLS-Handshake failed", slog.String(log.Error, err.Error()), session.Session())
		session.Close()

		return err
	}

	session.SetClientConn(tlsConn)
	session.SetReader(bufio.NewReader(tlsConn))

	logger.Info("TLS-connection established", slog.String("client", tlsConn.RemoteAddr().String()), session.Session())

	return nil
}
