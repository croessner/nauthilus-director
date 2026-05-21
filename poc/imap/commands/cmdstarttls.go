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

var _ iface.IMAPCommand = (*StartTLS)(nil)

func (s *StartTLS) Execute(session iface.IMAPSession) error {
	if s.TLSConfig == nil {
		session.WriteResponse(s.Tag + " NO TLS configuration not available")
		session.GetLogger().Error("TLS config is nil", session.Session())

		return fmt.Errorf("tls config is nil")
	}

	session.WriteResponse(s.Tag + " OK Begin TLS negotiation now")

	tlsConn := tls.Server(session.GetClientConn(), s.TLSConfig)
	err := tlsConn.Handshake()
	if err != nil {
		session.GetLogger().Error("TLS-Handshake failed", slog.String(log.KeyError, err.Error()), session.Session())
		session.Close()

		return err
	}

	session.SetClientConn(tlsConn)
	session.SetTLSFlag(true)
	session.InitializeTLSFields()

	session.GetLogger().Info("TLS connection established",
		slog.String(log.KeyLocal, session.GetClientConn().LocalAddr().String()),
		slog.String(log.KeyRemote, session.GetClientConn().RemoteAddr().String()),
		session.Session(),
		slog.String(log.KeyTLSProtocol, session.GetTLSProtocol()),
		slog.String(log.KeyTLSCipherSuite, session.GetTLSCipherSuite()),
		slog.String(log.KeyTLSClientCName, session.GetTLSClientCName()),
		slog.String(log.KeyTLSIssuerDN, session.GetTLSIssuerDN()),
		slog.String(log.KeyTLSClientDN, session.GetTLSClientDN()),
		slog.String(log.KeyTLSClientNotBefore, session.GetTLSClientNotBefore()),
		slog.String(log.KeyTLSClientNotAfter, session.GetTLSClientNotAfter()),
		slog.String(log.KeyTLSSerial, session.GetTLSSerial()),
		slog.String(log.KeyTLSClientIssuerDN, session.GetTLSClientIssuerDN()),
		slog.String(log.KeyTLSDNSNames, session.GetTLSDNSNames()),
		slog.String(log.KeyTLSFingerprint, session.GetTLSFingerprint()),
		slog.Bool(log.KeyTLSVerified, session.GetTLSVerified()),
	)

	return nil
}
