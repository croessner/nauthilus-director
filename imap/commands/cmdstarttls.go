package commands

import (
	"crypto/tls"
	"fmt"
	"log/slog"

	"github.com/croessner/nauthilus-director/interfaces"
	"github.com/croessner/nauthilus-director/log"
)

type StartTLS struct {
	TLSConfig *tls.Config
	Tag       string
}

func (s *StartTLS) Execute(session iface.IMAPSession) error {
	logger := log.GetLogger(session.GetBackendContext())

	if s.TLSConfig == nil {
		session.WriteResponse(s.Tag + " NO TLS configuration not available")
		logger.Error("TLS config is nil", session.Session())

		return fmt.Errorf("tls config is nil")
	}

	session.WriteResponse(s.Tag + " OK Begin TLS negotiation now")

	tlsConn := tls.Server(session.GetClientConn(), s.TLSConfig)
	err := tlsConn.Handshake()
	if err != nil {
		logger.Error("TLS-Handshake failed", slog.String(log.Error, err.Error()), session.Session())
		session.Close()

		return err
	}

	session.SetClientConn(tlsConn)
	session.SetTLSFlag(true)
	session.InitializeTLSFields()

	logger.Info("TLS connection established",
		slog.String(log.LogKeyClient, session.GetClientConn().RemoteAddr().String()),
		session.Session(),
		slog.String(log.LogKeyTLSProtocol, session.GetTLSProtocol()),
		slog.String(log.LogKeyTLSCipherSuite, session.GetTLSCipherSuite()),
		slog.String(log.LogKeyTLSClientCName, session.GetTLSClientCName()),
		slog.String(log.LogKeyTLSIssuerDN, session.GetTLSIssuerDN()),
		slog.String(log.LogKeyTLSClientDN, session.GetTLSClientDN()),
		slog.String(log.LogKeyTLSClientNotBefore, session.GetTLSClientNotBefore()),
		slog.String(log.LogKeyTLSClientNotAfter, session.GetTLSClientNotAfter()),
		slog.String(log.LogKeyTLSSerial, session.GetTLSSerial()),
		slog.String(log.LogKeyTLSClientIssuerDN, session.GetTLSClientIssuerDN()),
		slog.String(log.LogKeyTLSDNSNames, session.GetTLSDNSNames()),
		slog.String(log.LogKeyTLSFingerprint, session.GetTLSFingerprint()),
		slog.Bool(log.LogKeyTLSVerified, session.GetTLSVerified()),
	)

	return nil
}
