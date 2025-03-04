package lmtp

import (
	"crypto/tls"
	"log/slog"
	"net"
	"net/textproto"
	"time"

	"github.com/croessner/nauthilus-director/auth"
	"github.com/croessner/nauthilus-director/interfaces"
	"github.com/croessner/nauthilus-director/log"
	"github.com/segmentio/ksuid"
)

func Handler(proxy iface.Proxy, rawClientConn net.Conn) {
	logger := log.GetLogger(proxy.GetContext())

	defer func() {
		_ = rawClientConn.Close()
	}()

	if conn, ok := rawClientConn.(*net.TCPConn); ok {
		_ = conn.SetNoDelay(true)
		_ = conn.SetLinger(0)
	}

	if conn, ok := rawClientConn.(*tls.Conn); ok {
		_ = conn.NetConn().(*net.TCPConn).SetNoDelay(true)
		_ = conn.NetConn().(*net.TCPConn).SetLinger(0)
	}

	session := &SessionImpl{
		authenticator:     &auth.NauthilusAuthenticator{},
		service:           proxy.GetInstance().ServiceName,
		rawClientConn:     rawClientConn,
		tpClientConn:      textproto.NewConn(rawClientConn),
		clientCtx:         proxy.GetContext().Copy(),
		instance:          proxy.GetInstance(),
		logger:            logger,
		state:             StateWaitingMailFrom,
		sessionID:         ksuid.New().String(),
		lastActivity:      make(chan struct{}),
		stopWatchdog:      make(chan struct{}),
		recipients:        []string{},
		inactivityTimeout: 60 * time.Second,
	}

	go session.StartWatchdog()

	remoteAddr := rawClientConn.RemoteAddr().(*net.TCPAddr)
	localAddr := rawClientConn.LocalAddr().(*net.TCPAddr)

	session.remoteIP = remoteAddr.IP.String()
	session.remotePort = remoteAddr.Port
	session.localIP = localAddr.IP.String()
	session.localPort = localAddr.Port

	session.InitializeTLSFields()

	logger.Info("New connection",
		slog.String(log.KeyLocal, rawClientConn.LocalAddr().String()),
		slog.String(log.KeyRemote, rawClientConn.RemoteAddr().String()),
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

	if err := session.WriteResponse("220 LMTP Server Ready"); err != nil {
		logger.Error(ErrWriteRespone, slog.String(log.KeyError, err.Error()), session.Session())
		session.Close()

		return
	}

	session.Process()

	logger.Info("Connection closed",
		slog.String(log.KeyLocal, rawClientConn.LocalAddr().String()),
		slog.String(log.KeyRemote, rawClientConn.RemoteAddr().String()),
		session.Session(),
	)
}
