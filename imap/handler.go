package imap

import (
	"crypto/tls"
	"log/slog"
	"net"
	"net/textproto"
	"time"

	"github.com/croessner/nauthilus-director/auth"
	"github.com/croessner/nauthilus-director/imap/commands"
	iface "github.com/croessner/nauthilus-director/interfaces"
	"github.com/croessner/nauthilus-director/log"
	"github.com/segmentio/ksuid"
)

func Handler(proxy iface.Proxy, rawClientConn net.Conn) {
	var tlsFlag bool

	logger := log.GetLogger(proxy.GetContext())

	if proxy.GetTLSConfig() != nil && !proxy.GetInstance().TLS.StartTLS {
		tlsConn, ok := rawClientConn.(*tls.Conn)
		if !ok {
			tlsConn = tls.Server(rawClientConn, proxy.GetTLSConfig())

			if err := tlsConn.Handshake(); err != nil {
				logger.Error("Could not handshake with client", slog.String(log.KeyError, err.Error()))

				return
			}

			rawClientConn = tlsConn
		}
	}

	if conn, ok := rawClientConn.(*net.TCPConn); ok {
		_ = conn.SetNoDelay(true)
		_ = conn.SetLinger(0)
	}

	if conn, ok := rawClientConn.(*tls.Conn); ok {
		_ = conn.NetConn().(*net.TCPConn).SetNoDelay(true)
		_ = conn.NetConn().(*net.TCPConn).SetLinger(0)

		tlsFlag = true
	}

	session := &SessionImpl{
		sessionID:         ksuid.New().String(),
		service:           proxy.GetInstance().ServiceName,
		instance:          proxy.GetInstance(),
		nauthilus:         proxy.GetNauthilus(),
		rawClientConn:     rawClientConn,
		tpClientConn:      textproto.NewConn(rawClientConn),
		tlsFlag:           tlsFlag,
		tlsConfig:         proxy.GetTLSConfig(),
		backendCtx:        proxy.GetContext().Copy(),
		clientCtx:         proxy.GetContext().Copy(),
		authenticator:     &auth.NauthilusAuthenticator{},
		logger:            logger,
		lastActivity:      make(chan struct{}),
		stopWatchdog:      make(chan struct{}),
		inactivityTimeout: 60 * time.Second,
	}

	// TODO: HAproxy...
	remoteAddr := rawClientConn.RemoteAddr().(*net.TCPAddr)
	localAddr := rawClientConn.LocalAddr().(*net.TCPAddr)

	session.remoteIP = remoteAddr.IP.String()
	session.remotePort = remoteAddr.Port
	session.localIP = localAddr.IP.String()
	session.localPort = localAddr.Port

	session.InitializeTLSFields()

	filteredCapabilities := commands.GenerateCapabilities(
		proxy.GetInstance().TLS.Enabled && proxy.GetInstance().TLS.StartTLS,
		session.tlsFlag,
		proxy.GetInstance().AuthMechs,
		proxy.GetInstance().Capability,
	)

	session.WriteResponse("* OK [CAPABILITY " + filteredCapabilities + "] IMAP Ready")

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

	go session.StartWatchdog()

	for {
		line, err := session.ReadLine()
		if err != nil {
			break
		}

		session.lastActivity <- struct{}{}

		session.Process(line)
	}

	session.stopWatchdog <- struct{}{}

	session.Close()

	logger.Info("Connection closed",
		slog.String(log.KeyLocal, rawClientConn.LocalAddr().String()),
		slog.String(log.KeyRemote, rawClientConn.RemoteAddr().String()),
		session.Session(),
	)
}
