package imap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/croessner/nauthilus-director/auth"
	"github.com/croessner/nauthilus-director/config"
	"github.com/croessner/nauthilus-director/context"
	"github.com/croessner/nauthilus-director/enc"
	"github.com/croessner/nauthilus-director/imap/commands"
	"github.com/croessner/nauthilus-director/log"
	"github.com/segmentio/ksuid"
)

type Proxy struct {
	listener   net.Listener
	wg         *sync.WaitGroup
	ctx        *context.Context
	tlsConfig  *tls.Config
	instance   config.Listen
	listenAddr string
	name       string
}

func NewProxy(ctx *context.Context, instance config.Listen, wg *sync.WaitGroup) *Proxy {
	logger := log.GetLogger(ctx)

	tlsConfig, err := enc.GetTLSConfig(instance)
	if err != nil {
		logger.Error("Could not get TLS config", slog.String(log.KeyError, err.Error()))

		return nil
	}

	return &Proxy{tlsConfig: tlsConfig, ctx: ctx, wg: wg, instance: instance}
}

func (p *Proxy) Start(instance config.Listen) error {
	var (
		mode     int64
		conn     net.Conn
		fileInfo os.FileInfo
		err      error
	)

	logger := log.GetLogger(p.ctx)

	if instance.TLS.Enabled && p.tlsConfig != nil {
		p.listener = tls.NewListener(p.listener, p.tlsConfig)
	}

	conn, err = net.DialTimeout(instance.Type, p.listenAddr, 1*time.Second)
	if err == nil {
		_ = conn.Close()

		return fmt.Errorf("address %s is already in use", p.listener)
	}

	if instance.Type == "unix" {
		p.listenAddr = instance.Address

		if fileInfo, err = os.Stat(instance.Address); err == nil && fileInfo.Mode()&os.ModeSocket != 0 {
			if err = os.Remove(instance.Address); err != nil {
				return err
			}
		}
	} else {
		p.listenAddr = fmt.Sprintf("%s:%d", instance.Address, instance.Port)
	}

	if instance.Name != "" {
		p.name = instance.Name
	}

	p.listener, err = net.Listen(instance.Type, p.listenAddr)
	if err != nil {
		return fmt.Errorf("could not start server: %w", err)
	}

	if instance.Type == "unix" && instance.Mode != "" {
		mode, err = strconv.ParseInt(instance.Mode, 8, 64)
		if err != nil {
			logger.Error("Could not parse socket mode", slog.String("error", err.Error()))
		}

		if err = os.Chmod(instance.Address, os.FileMode(mode)); err != nil {
			logger.Error("Could not set permissions on socket", slog.String("error", err.Error()))
		}
	}

	logger.Info("Server is listening", slog.String("type", instance.Type), slog.String("address", p.listenAddr), slog.String("name", p.name), slog.String("kind", instance.Kind))

	for {
		conn, err = p.listener.Accept()
		if errors.Is(err, net.ErrClosed) {
			logger.Info("Server is shutting down", slog.String("address", p.listenAddr), slog.String("name", p.name))

			return nil
		}

		if err != nil {
			logger.Error("Error accepting connection", slog.String("error", err.Error()))

			continue
		}

		p.wg.Add(1)

		go p.handleConnection(conn)
	}
}

func (p *Proxy) handleConnection(rawClientConn net.Conn) {
	logger := log.GetLogger(p.ctx)

	if p.tlsConfig != nil && !p.instance.TLS.StartTLS {
		tlsConn, ok := rawClientConn.(*tls.Conn)
		if !ok {
			tlsConn = tls.Server(rawClientConn, p.tlsConfig)

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
	}

	inactivityTimeout := 60 * time.Second

	lastActivity := make(chan struct{})
	stopWatchdog := make(chan struct{})

	session := &SessionImpl{
		authenticator: &auth.NauthilusAuthenticator{},
		service:       p.instance.Name,
		stopWatchDog:  stopWatchdog,
		tpClientConn:  textproto.NewConn(rawClientConn),
		rawClientConn: rawClientConn,
		tlsConfig:     p.tlsConfig,
		backendCtx:    p.ctx.Copy(),
		clientCtx:     p.ctx.Copy(),
		session:       ksuid.New().String(),
		instance:      p.instance,
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
		p.instance.TLS.Enabled && p.instance.TLS.StartTLS,
		session.tlsFlag,
		p.instance.AuthMechs,
		p.instance.Capability,
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

	go func() {
		for {
			select {
			case <-lastActivity:
				continue
			case <-time.After(inactivityTimeout):
				session.WriteResponse("* BYE Timeout: closing connection")
				logger.Warn("Session timed out due to inactivity", slog.String("client", rawClientConn.RemoteAddr().String()), session.Session())
				session.Close()

				return
			case <-stopWatchdog:
				return
			}
		}
	}()

	for {
		line, err := session.ReadLine()
		if err != nil {
			if err != io.EOF {
				logger.Error("Error reading IMAP command", slog.String(log.KeyError, err.Error()), session.Session())
			} else {
				logger.Info("Client disconnected", slog.String("client", rawClientConn.RemoteAddr().String()), session.Session())
			}

			stopWatchdog <- struct{}{}

			session.Close()

			return
		}

		lastActivity <- struct{}{}

		session.handleCommand(line)
	}
}
