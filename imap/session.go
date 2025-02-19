package imap

import (
	"bufio"
	stdcontext "context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/config"
	"github.com/croessner/nauthilus-director/context"
	"github.com/croessner/nauthilus-director/imap/proto"
	"github.com/croessner/nauthilus-director/interfaces"
	"github.com/croessner/nauthilus-director/log"
)

type SessionImpl struct {
	reader          *bufio.Reader
	clientConn      net.Conn
	backendConn     net.Conn
	authenticator   iface.Authenticator
	tlsConfig       *tls.Config
	backendCtx      *context.Context
	clientCtx       *context.Context
	clientUsername  string
	clientID        string
	backendGreeting string
	session         string
	instance        config.Listen
	tlsFlag         bool
	errorCounter    uint8
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

	tpReader := textproto.NewReader(s.reader)

	line, err := tpReader.ReadLine()

	if line == "" {
		return "", io.EOF
	}

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

	return nil
}

func (s *SessionImpl) startResponseReader(ctx stdcontext.Context, reader *bufio.Reader, responseChan chan string, errorChan chan error) {
	go func() {
		logger := log.GetLogger(s.backendCtx)
		tpReader := textproto.NewReader(reader)

		for {
			select {
			case <-ctx.Done():
				return
			default:
				line, err := tpReader.ReadLine()
				logger.Debug("Received line from backend server", slog.String("line", line))

				if line == "" {
					return
				}

				if err != nil {
					if err == io.EOF {
						return
					}

					errorChan <- err

					return
				}

				responseChan <- line
			}
		}
	}()
}

func (s *SessionImpl) waitForResponse(tag string, responseChan chan string, errorChan chan error, expected string, timeout time.Duration, maxLoops int) (string, error) {
	var fullResponse strings.Builder

	loopCount := 0
	timer := time.NewTimer(timeout)

	defer timer.Stop()

	for {
		if loopCount >= maxLoops {
			return "", fmt.Errorf("max loop iterations (%d) exceeded while waiting for response", maxLoops)
		}

		select {
		case <-timer.C:
			return "", fmt.Errorf("timeout (%s) reached while waiting for response", timeout)
		case line := <-responseChan:
			if line == "" {
				return "", fmt.Errorf("response channel closed unexpectedly")
			}

			fullResponse.WriteString(line + "\r\n")

			if strings.HasPrefix(line, tag) && strings.Contains(line, expected) {
				return fullResponse.String(), nil
			}
		case err := <-errorChan:
			if err != nil {
				return "", fmt.Errorf("error reading response: %w", err)
			}
		}

		loopCount++
	}
}

func (s *SessionImpl) ConnectToIMAPBackend(tag, username, password string) error {
	const timeout = 5 * time.Second
	const maxLoops = 10

	var backendLogin string

	logger := log.GetLogger(s.backendCtx)

	if err := s.initializeIMAPConnection(); err != nil {
		return err
	}

	responseChan := make(chan string)
	errorChan := make(chan error)

	ctx, cancel := stdcontext.WithCancel(s.backendCtx)

	defer cancel()

	s.startResponseReader(ctx, bufio.NewReader(s.backendConn), responseChan, errorChan)

	greeting, err := s.waitForResponse("*", responseChan, errorChan, "OK", timeout, maxLoops)
	if err != nil {
		return fmt.Errorf("error reading IMAP server greeting: %w", err)
	}

	logger.Debug("Received greeting from server", slog.String("greeting", greeting))

	_, err = s.backendConn.Write([]byte(fmt.Sprintf("%s CAPABILITY\r\n", tag)))
	if err != nil {
		logger.Error("Error when sending the CAPABILITY command", slog.String(log.Error, err.Error()), s.Session())

		return err
	}

	capabilityResponse, err := s.waitForResponse(tag, responseChan, errorChan, "OK", timeout, maxLoops)
	if err != nil {
		return fmt.Errorf("error reading CAPABILITY response: %w", err)
	}

	logger.Debug("Received CAPABILITY response", slog.String("response", capabilityResponse))

	authPlain := strings.Contains(capabilityResponse, "AUTH=PLAIN")
	authLogin := strings.Contains(capabilityResponse, "AUTH=LOGIN")

	if authPlain {
		plainCredentials := fmt.Sprintf("\x00%s\x00%s", username, password)
		base64PlainCredentials := base64.StdEncoding.EncodeToString([]byte(plainCredentials))
		backendLogin = fmt.Sprintf("%s AUTHENTICATE PLAIN %s\r\n", tag, base64PlainCredentials)
	} else if authLogin {
		backendLogin = fmt.Sprintf("%s AUTHENTICATE LOGIN\r\n", tag)

		if _, err = s.backendConn.Write([]byte(backendLogin)); err != nil {
			logger.Error("Error when starting AUTH=LOGIN:", slog.String(log.Error, err.Error()), s.Session())

			return err
		}

		loginPrompt, err := s.waitForResponse(tag, responseChan, errorChan, "+", timeout, maxLoops)
		if err != nil || !strings.Contains(loginPrompt, "+") {
			return fmt.Errorf("unexpected response during AUTH=LOGIN username step: %s", loginPrompt)
		}

		base64Username := base64.StdEncoding.EncodeToString([]byte(s.GetUser()))
		if _, err = s.backendConn.Write([]byte(base64Username + "\r\n")); err != nil {
			return fmt.Errorf("error sending username during AUTH=LOGIN: %w", err)
		}

		passwordPrompt, err := s.waitForResponse(tag, responseChan, errorChan, "+", timeout, maxLoops)
		if err != nil || !strings.Contains(passwordPrompt, "+") {
			return fmt.Errorf("unexpected response during AUTH=LOGIN password step: %s", passwordPrompt)
		}

		base64Password := base64.StdEncoding.EncodeToString([]byte(password))
		if _, err = s.backendConn.Write([]byte(base64Password + "\r\n")); err != nil {
			return fmt.Errorf("error sending password during AUTH=LOGIN: %w", err)
		}

		loginResponse, err := s.waitForResponse(tag, responseChan, errorChan, "OK", timeout, maxLoops)
		if err != nil {
			return fmt.Errorf("error reading AUTH=LOGIN response: %w", err)
		}

		if !strings.Contains(loginResponse, "OK") {
			return fmt.Errorf("AUTH=LOGIN authentication failed: %s", loginResponse)
		}

		s.backendGreeting = loginResponse

		return nil
	} else {
		backendLogin = fmt.Sprintf("%s LOGIN %s %s\r\n", tag, username, password)
	}

	if _, err = s.backendConn.Write([]byte(backendLogin)); err != nil {
		logger.Error("Error when sending the login/authenticate command to the backend server:", slog.String(log.Error, err.Error()), s.Session())

		return err
	}

	response, err := s.waitForResponse(tag, responseChan, errorChan, "OK", timeout, maxLoops)
	if err != nil {
		return fmt.Errorf("error reading IMAP authentication response: %w", err)
	}

	logger.Debug("Received IMAP authentication response", slog.String("response", response))

	if !strings.Contains(response, "OK") {
		return fmt.Errorf("backend authentication failed: %s", response)
	}

	s.backendGreeting = response

	return nil
}

func (s *SessionImpl) GetAuthenticator() iface.Authenticator {
	return s.authenticator
}

func (s *SessionImpl) handleCommand(line string) {
	var command iface.IMAPCommand

	logger := log.GetLogger(s.backendCtx)

	if s.errorCounter >= 5 {
		s.WriteResponse("* BAD Too many errors\r\n")
		s.Close()

		return
	}

	parts := strings.Fields(line)
	if len(parts) < 2 {
		s.WriteResponse("* BAD Invalid command\r\n")
		s.errorCounter++

		return
	}

	tag, cmd := parts[0], strings.ToUpper(parts[1])
	commandFilter := s.setupCommandFilters()

	if commandFilter.ShouldBlock(cmd) {
		s.WriteResponse(tag + " NO Command is not allowed\r\n")
		s.errorCounter++

		return
	}

	switch cmd {
	case proto.LOGIN:
		if len(parts) < 4 {
			s.WriteResponse(tag + " BAD Syntax error\r\n")
			s.errorCounter++

			return
		}

		command = &LoginCommand{Tag: tag, Username: parts[2], Password: parts[3]}
	case proto.LOGOUT:
		command = &LogoutCommand{Tag: tag}
	case proto.AUTHENTICATE:
		if len(parts) < 3 {
			s.WriteResponse(tag + " BAD Syntax error\r\n")
			s.errorCounter++

			return
		}

		switch strings.ToUpper(parts[2]) {
		case proto.PLAIN:
			// TODO: Lot of things are pending...
			command = &AuthenticateCommand{Tag: tag, Method: proto.PLAIN}
		case proto.LOGIN:
			// TODO: Lot of things are pending...
			command = &AuthenticateCommand{Tag: tag, Method: proto.LOGIN}
		case proto.XOAUTH2:
			// TODO: Lot of things are pending...
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
		s.WriteResponse(tag + " BAD Unsupported command\r\n")
		s.errorCounter++

		return
	}

	if err := command.Execute(s); err != nil {
		logger.Error("Error while executing the command:", slog.String(log.Error, err.Error()), s.Session())
	}
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

func (s *SessionImpl) LinkClientAndBackend() {
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

	allMechanisms := []string{proto.LOGIN, proto.PLAIN, proto.XOAUTH2}
	disallowedMechanisms := calculateDisallowedMechanisms(allMechanisms, s.instance.AuthMechs)

	commandFilter.AddFilter(NewAuthMechanismFilter(disallowedMechanisms))

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

func (s *SessionImpl) GetAuthMechs() []string {
	return s.instance.AuthMechs
}

func (s *SessionImpl) SetClientID(id string) {
	s.clientID = id
}

func (s *SessionImpl) GetBackendConn() net.Conn {
	return s.backendConn
}

func (s *SessionImpl) GetCapability() string {
	return s.instance.Capability
}

func calculateDisallowedMechanisms(allMechanisms, allowedMechanisms []string) []string {
	disallowed := make([]string, 0, len(allMechanisms))

	for _, mechanism := range allMechanisms {
		found := false

		for _, allowed := range allowedMechanisms {
			if strings.EqualFold(mechanism, allowed) {
				found = true

				break
			}
		}

		if !found {
			disallowed = append(disallowed, mechanism)
		}
	}

	return disallowed
}
