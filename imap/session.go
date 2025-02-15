package imap

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/croessner/nauthilus-director/interfaces"
)

type SessionImpl struct {
	clientConn      net.Conn
	serverCtx       context.Context
	serverConn      net.Conn
	clientCtx       context.Context
	reader          *bufio.Reader
	authenticator   iface.Authenticator
	clientUsername  string
	backendGreeting string
	tlsConfig       *tls.Config
}

func (s *SessionImpl) WriteResponse(response string) {
	if s.clientConn == nil {
		return
	}

	_, err := s.clientConn.Write([]byte(response))
	if err != nil {
		fmt.Println("Error while sending the response:", err)
	}
}

func (s *SessionImpl) ReadLine() (string, error) {
	if s.clientConn == nil {
		return "", io.EOF
	}

	line, err := s.reader.ReadString('\n') // Lesen einer Zeile
	if err != nil {
		var opErr *net.OpError

		if errors.As(err, &opErr) && opErr.Err.Error() == "use of closed network connection" {
			return "", io.EOF
		}

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
	go s.copyWithContext()

	return nil
}

func (s *SessionImpl) ForwardToIMAPServer(data string) {
	// Initialisiere Verbindung, falls nicht vorhanden
	if err := s.initializeIMAPConnection(); err != nil {
		return
	}

	_, _ = s.serverConn.Write([]byte(data)) // Weiterleitung der Anfrage
}

func (s *SessionImpl) ConnectToIMAPBackend(tag, username, password string) error {
	// TODO: Add master user later...
	_ = username

	if err := s.initializeIMAPConnection(); err != nil {
		return err
	}

	reader := bufio.NewReader(s.serverConn)
	greeting, err := reader.ReadString('\n')

	if err != nil {
		return fmt.Errorf("error reading IMAP server greeting: %w", err)
	}

	if !strings.Contains(greeting, "OK") {
		return fmt.Errorf("backend server did not send expected OK greeting: %s", greeting)
	}

	backendLogin := fmt.Sprintf("%s LOGIN %s %s\r\n", tag, s.GetUser(), password)

	if _, err = s.serverConn.Write([]byte(backendLogin)); err != nil {
		fmt.Println("Error when sending the login to the backend server:", err)

		return err
	}

	response, err := reader.ReadString('\n')
	if err != nil {
		if err == io.EOF {
			return io.EOF
		}

		return fmt.Errorf("error reading IMAP login response: %w", err)
	}

	if !strings.Contains(response, "OK") {
		return fmt.Errorf("backend login failed: %s", response)
	}

	s.backendGreeting = response

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
			TLSConfig: s.tlsConfig, // TLS-config from the proxy
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

func (s *SessionImpl) GetBackendGreeting() string {
	return s.backendGreeting
}

func (s *SessionImpl) copyWithContext() {
	clientDone := make(chan struct{})
	backendDone := make(chan struct{})

	go func() {
		_, _ = io.Copy(s.serverConn, s.clientConn)
		fmt.Println("Connection closed by client")

		close(clientDone)
	}()

	go func() {
		_, _ = io.Copy(s.clientConn, s.serverConn)
		fmt.Println("Connection closed by backend")

		close(backendDone)
	}()

	select {
	case <-s.serverCtx.Done():
		s.Close()
	case <-s.clientCtx.Done():
		s.Close()
	case <-clientDone:
		s.Close()
	case <-backendDone:
		s.Close()
	}
}
