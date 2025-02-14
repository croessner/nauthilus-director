package imap

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"

	"github.com/croessner/nauthilus-director/interfaces"
)

type Proxy struct {
	listenAddr    string
	authenticator iface.Authenticator
	tlsConfig     *tls.Config
	ctx           context.Context
}

func NewProxy(ctx context.Context, addr string, auth iface.Authenticator) *Proxy {
	tlsConfig, err := getTLSConfig() // TLS-Konfiguration einmal laden
	if err != nil {
		fmt.Println("Fehler beim Laden der TLS-Konfiguration:", err)

		return nil
	}

	return &Proxy{
		listenAddr:    addr,
		authenticator: auth,
		tlsConfig:     tlsConfig,
		ctx:           ctx,
	}
}

func (p *Proxy) Start() error {
	listener, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		return fmt.Errorf("fehler beim Start des IMAP-Proxys: %v", err)
	}

	defer func(listener net.Listener) {
		_ = listener.Close()
	}(listener)

	fmt.Println("IMAP Proxy läuft auf", p.listenAddr)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			fmt.Println("Fehler beim Annehmen einer Verbindung:", err)

			continue
		}

		go p.handleConnection(clientConn) // Neue Verbindung in Goroutine
	}
}

func (p *Proxy) handleConnection(clientConn net.Conn) {
	defer func(clientConn net.Conn) {
		_ = clientConn.Close()
	}(clientConn)

	session := &SessionImpl{
		clientConn:    clientConn,
		reader:        bufio.NewReader(clientConn),
		authenticator: p.authenticator,
		tlsConfig:     p.tlsConfig,
		serverCtx:     p.ctx,
		clientCtx:     p.ctx,
	}

	// TODO: config greeting
	session.WriteResponse("* OK IMAP Proxy Ready\r\n")

	fmt.Println("New connection: ", clientConn.RemoteAddr())

	for {
		line, err := session.ReadLine()
		if err != nil {
			if err != io.EOF {
				fmt.Println("Error reading IMAP command:", err)
			} else {
				fmt.Println("Client disconnected: ", clientConn.RemoteAddr())
			}

			return
		}

		session.handleCommand(line)
	}
}
