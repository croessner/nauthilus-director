package imap

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"

	"github.com/croessner/nauthilus-director/config"
	"github.com/croessner/nauthilus-director/context"
	"github.com/croessner/nauthilus-director/imap/proto"
	"github.com/croessner/nauthilus-director/interfaces"
	"github.com/croessner/nauthilus-director/log"
)

type SessionImpl struct {
	tlsFlag         bool
	reader          *bufio.Reader
	clientConn      net.Conn
	backendConn     net.Conn
	authenticator   iface.Authenticator
	tlsConfig       *tls.Config
	backendCtx      *context.Context
	clientCtx       *context.Context
	clientUsername  string
	backendGreeting string
	session         string
	instance        config.Listen
}

func (s *SessionImpl) WriteResponse(response string) {
	logger := log.GetLogger(s.backendCtx)

	if s.clientConn == nil {
		return
	}

	_, err := s.clientConn.Write([]byte(response))
	if err != nil {
		logger.Error("Error while sending the response:", slog.String(log.Error, err.Error()), s.Session())
	}
}

func (s *SessionImpl) ReadLine() (string, error) {
	if s.clientConn == nil {
		return "", io.EOF
	}

	line, err := s.reader.ReadString('\n')
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
	logger := log.GetLogger(s.backendCtx)

	if s.backendConn != nil {
		return nil
	}

	conn, err := net.Dial("tcp", "127.0.0.1:1143")
	if err != nil {
		s.WriteResponse("* BYE Internal server error\r\n")
		logger.Error("Error while connecting to the backend server:", slog.String(log.Error, err.Error()))

		return err
	}

	s.backendConn = conn

	// TODO: Support ctx with cancel to interrupt connections on behalf
	go s.copyWithContext()

	return nil
}

func (s *SessionImpl) ForwardToIMAPServer(data string) {
	if err := s.initializeIMAPConnection(); err != nil {
		return
	}

	_, _ = s.backendConn.Write([]byte(data))
}

func (s *SessionImpl) ConnectToIMAPBackend(tag, username, password string) error {
	logger := log.GetLogger(s.backendCtx)

	// TODO: Add master user later...
	_ = username

	if err := s.initializeIMAPConnection(); err != nil {
		return err
	}

	reader := bufio.NewReader(s.backendConn)
	greeting, err := reader.ReadString('\n')

	if err != nil {
		return fmt.Errorf("error reading IMAP server greeting: %w", err)
	}

	if !strings.Contains(greeting, "OK") {
		return fmt.Errorf("backend server did not send expected OK greeting: %s", greeting)
	}

	backendLogin := fmt.Sprintf("%s LOGIN %s %s\r\n", tag, s.GetUser(), password)

	if _, err = s.backendConn.Write([]byte(backendLogin)); err != nil {
		logger.Error("Error when sending the login to the backend server:", slog.String(log.Error, err.Error()), s.Session())

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
	commandFilter := s.setupCommandFilters()

	if commandFilter.ShouldBlock(cmd) {
		s.WriteResponse(tag + " NO Command is not allowed\r\n")

		return
	}

	switch cmd {
	case proto.LOGIN:
		command = &LoginCommand{Tag: tag, Username: parts[2], Password: parts[3]}
	case proto.LOGOUT:
		command = &LogoutCommand{Tag: tag}
	case proto.AUTHENTICATE:
		// TODO: Lot of things are pending...

		if len(parts) < 3 {
			s.WriteResponse(tag + " BAD Syntax error\r\n")

			return
		}

		switch strings.ToUpper(parts[2]) {
		case proto.PLAIN:
			command = &AuthenticateCommand{Tag: tag, Method: proto.PLAIN}
		case proto.XOAUTH2:
			command = &XOAUTH2Command{Tag: tag}
		default:
			s.WriteResponse(tag + " NO Unsupported auth method\r\n")

			return
		}
	case proto.CAPABILITY:
		command = &CapabilityCommand{Tag: tag, UseStartTLS: s.instance.TLS.Enabled && s.instance.TLS.StartTLS}
	case proto.ID:
		command = &IDCommand{Tag: tag}
	case proto.STARTTLS:
		command = &StartTLSCommand{Tag: tag, TLSConfig: s.tlsConfig}
	default:
		s.ForwardToIMAPServer(line)

		return
	}

	_ = command.Execute(s)
}

func (s *SessionImpl) Close() {
	if s.backendConn != nil {
		_ = s.backendConn.Close()
		s.backendConn = nil
	}

	if s.clientConn != nil {
		_ = s.clientConn.Close()
		s.clientConn = nil
	}
}

func (s *SessionImpl) copyWithContext() {
	logger := log.GetLogger(s.backendCtx)

	clientDone := make(chan struct{})
	backendDone := make(chan struct{})

	go func() {
		_, _ = io.Copy(s.backendConn, s.clientConn)
		logger.Debug("Connection closed by client", s.Session())

		close(clientDone)
	}()

	go func() {
		_, _ = io.Copy(s.clientConn, s.backendConn)
		logger.Debug("Connection closed by backend", s.Session())

		close(backendDone)
	}()

	select {
	case <-s.backendCtx.Done():
		s.Close()
	case <-s.clientCtx.Done():
		s.Close()
	case <-clientDone:
		s.Close()
	case <-backendDone:
		s.Close()
	}
}

func (s *SessionImpl) Session() slog.Attr {
	return slog.String("session", s.session)
}

func (s *SessionImpl) setupCommandFilters() *CommandFilterManager {
	commandFilter := NewCommandFilterManager()

	if !(s.instance.TLS.Enabled && s.instance.TLS.StartTLS) || s.tlsFlag {
		commandFilter.AddFilter(NewStartTLSFilter())
	}

	if s.backendConn == nil {
		commandFilter.AddFilter(NewIDFilter())
	}

	return commandFilter
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

func (s *SessionImpl) GetClientContext() *context.Context {
	return s.clientCtx
}

func (s *SessionImpl) GetServerContext() *context.Context {
	return s.backendCtx
}

func (s *SessionImpl) GetTLSFlag() bool {
	return s.tlsFlag
}

func (s *SessionImpl) SetTLSFlag(flag bool) {
	s.tlsFlag = flag
}
