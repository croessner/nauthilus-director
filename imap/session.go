package imap

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/croessner/nauthilus-director/interfaces"
)

type SessionImpl struct {
	clientConn     net.Conn
	serverConn     net.Conn
	reader         *bufio.Reader
	authenticator  iface.Authenticator
	clientUsername string
	tlsConfig      *tls.Config
	ctx            context.Context
}

func (s *SessionImpl) WriteResponse(response string) {
	_, err := s.clientConn.Write([]byte(response))
	if err != nil {
		fmt.Println("Fehler beim Senden der Antwort:", err)
	}
}

func (s *SessionImpl) ReadLine() (string, error) {
	line, err := s.reader.ReadString('\n')
	if err != nil {
		fmt.Println("Fehler beim Lesen der Client-Daten:", err)

		return "", err
	}

	return line, nil
}

func (s *SessionImpl) initializeIMAPConnection() error {
	if s.serverConn != nil {
		return nil // Verbindung existiert bereits
	}

	conn, err := net.Dial("tcp", "127.0.0.1:1143")
	if err != nil {
		s.WriteResponse("* BYE Internal server error\r\n")
		fmt.Println("Error while connecting to the backend server:", err)

		return err
	}

	s.serverConn = conn

	// TODO: Support ctx with cancel to interrupt connections on behalf
	go copyWithContext(s.ctx, s.serverConn, s.clientConn) // Data transfer client -> server
	go copyWithContext(s.ctx, s.clientConn, s.serverConn) // Data transfer server -> client

	return nil
}

func (s *SessionImpl) ForwardToIMAPServer(data string) {
	// Initialisiere Verbindung, falls nicht vorhanden
	if err := s.initializeIMAPConnection(); err != nil {
		return
	}

	_, _ = s.serverConn.Write([]byte(data)) // Weiterleitung der Anfrage
}

func (s *SessionImpl) ConnectToIMAPBackend(username, password string) error {
	// Initialisiere Verbindung, falls nicht vorhanden
	if err := s.initializeIMAPConnection(); err != nil {
		return err
	}

	// Sende das Master-Login an das Backend
	backendLogin := fmt.Sprintf("A0 LOGIN %s*%s %s\r\n", s.GetUser(), username, password)
	if _, err := s.serverConn.Write([]byte(backendLogin)); err != nil {
		fmt.Println("Fehler beim Senden des Backend-Logins:", err)

		return err
	}

	// Warte auf die Antwort des Backends
	reader := bufio.NewReader(s.serverConn)
	response, _ := reader.ReadString('\n')

	fmt.Println("IMAP-Backend Antwort:", response)

	if !strings.Contains(response, "OK") {
		return fmt.Errorf("backend login failed")
	}

	return nil
}

func (s *SessionImpl) GetAuthenticator() iface.Authenticator {
	return s.authenticator
}

func (s *SessionImpl) handleCommand(line string) {
	var command iface.IMAPCommand

	parts := strings.Fields(line)
	if len(parts) < 2 {
		s.WriteResponse("* BAD Invalid command\r\n")

		return
	}

	tag, cmd := parts[0], strings.ToUpper(parts[1])

	fmt.Println("Tag:", tag)
	fmt.Println("Command:", cmd)

	switch cmd {
	case "LOGIN":
		command = &LoginCommand{Tag: tag, Username: parts[2], Password: parts[3]}
	case "LOGOUT":
		command = &LogoutCommand{Tag: tag}
	case "AUTHENTICATE":
		// TODO: Lot of things are pending...

		if len(parts) < 3 {
			s.WriteResponse(tag + " BAD Syntax error\r\n")

			return
		}

		switch strings.ToUpper(parts[2]) {
		case "PLAIN":
			command = &AuthenticateCommand{Tag: tag, Method: "PLAIN"}
		case "XOAUTH2":
			command = &XOAUTH2Command{Tag: tag}
		default:
			s.WriteResponse(tag + " NO Unsupported auth method\r\n")

			return
		}
	case "CAPABILITY":
		command = &CapabilityCommand{Tag: tag}
	case "ID":
		command = &IDCommand{Tag: tag}
	case "STARTTLS":
		command = &StartTLSCommand{
			Tag:       tag,
			TLSConfig: s.tlsConfig, // TLS-Konfiguration aus dem Proxy
		}

	default:
		s.ForwardToIMAPServer(line)

		return
	}

	_ = command.Execute(s)
}

func (s *SessionImpl) Close() {
	if s.serverConn != nil {
		_ = s.serverConn.Close()
		s.serverConn = nil
	}

	if s.clientConn != nil {
		_ = s.clientConn.Close()
		s.clientConn = nil
	}
}

func (s *SessionImpl) SetUser(username string) {
	s.clientUsername = username
}

func (s *SessionImpl) GetUser() string {
	return s.clientUsername
}

func (s *SessionImpl) SetClientConn(conn net.Conn) {
	s.clientConn = conn
}

func (s *SessionImpl) GetClientConn() net.Conn {
	return s.clientConn
}

func (s *SessionImpl) SetReader(reader *bufio.Reader) {
	s.reader = reader
}

func copyWithContext(ctx context.Context, dst net.Conn, src net.Conn) {
	done := make(chan struct{})

	go func() {
		_, err := io.Copy(dst, src)
		if err != nil {
			fmt.Println("Error:", err)
		}

		close(done)
	}()

	select {
	case <-ctx.Done(): // Kontext wurde abgebrochen
		fmt.Println("Copy aborted")

		// Verbindungen explizit schließen
		_ = dst.Close()
		_ = src.Close()

	case <-done: // Kopieren beendet
		fmt.Println("Copy aborted")
	}
}
