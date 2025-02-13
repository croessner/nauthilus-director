package imap

import (
	"bufio"
	"crypto/tls"
	"fmt"

	"github.com/croessner/nauthilus-director/interfaces"
)

func getTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		return nil, fmt.Errorf("fehler beim Laden des Zertifikats oder Schlüssels: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12, // Sicherstellen, dass nur moderne Verschlüsselung verwendet wird
	}, nil
}

type StartTLSCommand struct {
	Tag       string
	TLSConfig *tls.Config
}

func (s *StartTLSCommand) Execute(session iface.IMAPSession) error {
	if s.TLSConfig == nil {
		session.WriteResponse(s.Tag + " NO TLS configuration not available\r\n")
		fmt.Println("TLS config is nil")

		return fmt.Errorf("tls config is nil")
	}

	session.WriteResponse(s.Tag + " OK Begin TLS negotiation now\r\n")

	tlsConn := tls.Server(session.GetClientConn(), s.TLSConfig)
	err := tlsConn.Handshake()
	if err != nil {
		fmt.Println("TLS-Handshake failed:", err)
		session.Close()

		return err
	}

	session.SetClientConn(tlsConn)
	session.SetReader(bufio.NewReader(tlsConn)) // Aktualisiere den Reader für die verschlüsselte Verbindung

	fmt.Println("TLS-connection established")

	return nil
}
