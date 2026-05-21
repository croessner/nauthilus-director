package imap

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/auth"
	"github.com/croessner/nauthilus-director/config"
	"github.com/croessner/nauthilus-director/context"
	"github.com/croessner/nauthilus-director/imap/commands"
	"github.com/croessner/nauthilus-director/imap/commands/filter"
	"github.com/croessner/nauthilus-director/imap/proto"
	"github.com/croessner/nauthilus-director/interfaces"
	"github.com/croessner/nauthilus-director/link"
	"github.com/croessner/nauthilus-director/log"
)

const ErrWriteRespone = "Error writing response"

type SessionImpl struct {
	authenticator  iface.Authenticator
	tlsConfig      *tls.Config
	rawBackendConn net.Conn
	rawClientConn  net.Conn
	tpBackendConn  *textproto.Conn
	tpClientConn   *textproto.Conn
	clientCtx      *context.Context
	backendCtx     *context.Context
	logger         *slog.Logger

	service            string
	clientUsername     string
	clientID           string
	backendGreeting    string
	sessionID          string
	tlsProtocol        string
	tlsCipherSuite     string
	tlsFingerprint     string
	tlsClientCName     string
	tlsIssuerDN        string
	tlsClientDN        string
	tlsClientNotBefore string
	tlsClientNotAfter  string
	tlsSerial          string
	tlsClientIssuerDN  string
	tlsDNSNames        string
	localIP            string
	remoteIP           string

	instance          config.Listen
	nauthilus         config.Nauthilus
	inactivityTimeout time.Duration

	localPort    int
	remotePort   int
	errorCounter uint8

	tlsVerified bool
	tlsFlag     bool

	lastActivity chan struct{}
	stopWatchdog chan struct{}
}

var _ iface.Session = (*SessionImpl)(nil)
var _ iface.IMAPSession = (*SessionImpl)(nil)

func (s *SessionImpl) WriteResponse(response string) {
	if s.tpClientConn == nil {
		return
	}

	if err := s.tpClientConn.PrintfLine(response); err != nil {
		s.logger.Error(ErrWriteRespone, slog.String(log.KeyError, err.Error()), s.Session())
	}
}

func (s *SessionImpl) ReadLine() (string, error) {
	if s.tpClientConn == nil {
		return "", io.EOF
	}

	line, err := s.tpClientConn.ReadLine()
	if err != nil {
		return "", err
	}

	return line, nil
}

func (s *SessionImpl) StartWatchdog() {
	for {
		select {
		case <-s.lastActivity:
			continue
		case <-time.After(s.inactivityTimeout):
			s.logger.Warn("Session timed out due to inactivity",
				slog.String(log.KeyLocal, s.rawClientConn.LocalAddr().String()),
				slog.String(log.KeyRemote, s.rawClientConn.RemoteAddr().String()),
				s.Session(),
			)

			s.Close()

			return
		case <-s.stopWatchdog:
			s.logger.Debug("Watchdog stopped", s.Session())

			return
		}
	}
}

func (s *SessionImpl) InitializeTLSFields() {
	tlsConn, ok := s.rawClientConn.(*tls.Conn)
	if !ok {
		return
	}

	connectionState := tlsConn.ConnectionState()

	s.tlsProtocol = versionToString(connectionState.Version)
	s.tlsCipherSuite = tls.CipherSuiteName(connectionState.CipherSuite)

	if len(connectionState.PeerCertificates) > 0 {
		clientCert := connectionState.PeerCertificates[0]

		s.tlsFingerprint = fingerprint(clientCert)
		s.tlsClientCName = clientCert.Subject.CommonName
		s.tlsIssuerDN = clientCert.Issuer.String()
		s.tlsClientDN = clientCert.Subject.String()
		s.tlsClientNotBefore = clientCert.NotBefore.String()
		s.tlsClientNotAfter = clientCert.NotAfter.String()
		s.tlsSerial = clientCert.SerialNumber.String()

		if len(clientCert.DNSNames) > 0 {
			s.tlsDNSNames = strings.Join(clientCert.DNSNames, ", ")
		}
	}

	s.tlsVerified = connectionState.VerifiedChains != nil && len(connectionState.VerifiedChains) > 0
}

func versionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}

func fingerprint(cert *x509.Certificate) string {
	h := sha256.New()
	h.Write(cert.Raw)

	return hex.EncodeToString(h.Sum(nil))
}

func (s *SessionImpl) initializeIMAPConnection() error {
	if s.tpBackendConn != nil {
		return nil
	}

	conn, err := net.Dial("tcp", "127.0.0.1:1143")
	if err != nil {
		s.WriteResponse("* BYE Internal server error")
		s.logger.Error("Error while connecting to the backend server:", slog.String(log.KeyError, err.Error()))

		return err
	}

	_ = conn.(*net.TCPConn).SetKeepAlive(true)
	_ = conn.(*net.TCPConn).SetKeepAlivePeriod(30 * time.Second)

	s.rawBackendConn = conn
	s.tpBackendConn = textproto.NewConn(conn)

	return nil
}

func (s *SessionImpl) ConnectToIMAPBackend(tag, username, password string) error {
	// Initialize the IMAP backend connection
	if err := s.initializeIMAPConnection(); err != nil {
		return err
	}

	greeting, err := s.tpBackendConn.ReadLine()
	if err != nil {
		return fmt.Errorf("error reading the server greeting: %w", err)
	}

	s.logger.Debug("Received server greeting", slog.String("greeting", greeting))

	// Check supported authentication mechanisms
	hasSASLIR := strings.Contains(greeting, "SASL-IR")
	authPlain := strings.Contains(greeting, "AUTH=PLAIN")
	authLogin := strings.Contains(greeting, "AUTH=LOGIN")

	// AUTH=PLAIN mechanism
	if authPlain {
		if err = s.AuthPlain(tag, username, password, hasSASLIR); err != nil {
			return fmt.Errorf("AUTH=PLAIN failed: %w", err)
		}

		return nil
	}

	// AUTH=LOGIN mechanism
	if authLogin {
		if err = s.AuthLogin(tag, username, password); err != nil {
			return fmt.Errorf("AUTH=LOGIN failed: %w", err)
		}

		return nil
	}

	// Fallback to standard LOGIN command
	if err = s.AuthLegacyLogin(tag, username, password); err != nil {
		return fmt.Errorf("legacy LOGIN failed: %w", err)
	}

	return nil
}

func (s *SessionImpl) AuthLegacyLogin(tag, username, password string) error {
	id, err := s.tpBackendConn.Cmd("%s LOGIN %s %s", tag, username, password)
	if err != nil {
		return fmt.Errorf("error sending LOGIN command: %w", err)
	}

	// Read the LOGIN command response
	s.tpBackendConn.StartResponse(id)

	loginResponse, err := s.tpBackendConn.ReadLine()
	if err == nil && strings.HasPrefix(loginResponse, "*") {
		loginResponse, err = s.tpBackendConn.ReadLine()
		if err == nil && !strings.HasPrefix(loginResponse, tag) {
			return fmt.Errorf("unexpected response for LOGIN: %s", loginResponse)
		}
	}

	s.tpBackendConn.EndResponse(id)

	if err != nil {
		return fmt.Errorf("error reading LOGIN response: %w", err)
	}

	if !strings.Contains(loginResponse, "OK") {
		return fmt.Errorf("LOGIN failed: %s", loginResponse)
	}

	s.backendGreeting = loginResponse

	s.logger.Debug("Successful LOGIN authentication", slog.String("response", loginResponse))

	return nil
}

func (s *SessionImpl) AuthPlain(tag, username, password string, hasSASLIR bool) error {
	var (
		id  uint
		err error
	)

	// Prepare credentials in PLAIN authentication format
	plainCredentials := fmt.Sprintf("\x00%s\x00%s", username, password)
	base64PlainCredentials := base64.StdEncoding.EncodeToString([]byte(plainCredentials))

	// If the server supports SASL-IR, send AUTHENTICATE PLAIN with credentials directly
	if hasSASLIR {
		id, err = s.tpBackendConn.Cmd("%s AUTHENTICATE PLAIN %s", tag, base64PlainCredentials)
		if err != nil {
			return fmt.Errorf("error during AUTH=PLAIN with SASL-IR: %w", err)
		}
	} else {
		// Send the AUTHENTICATE PLAIN command without credentials
		id, err = s.tpBackendConn.Cmd("%s AUTHENTICATE PLAIN", tag)
		if err != nil {
			return fmt.Errorf("error sending AUTH=PLAIN command: %w", err)
		}

		// Wait for the server's response, expecting "+"
		s.tpBackendConn.StartResponse(id)
		line, err := s.tpBackendConn.ReadLine()
		s.tpBackendConn.EndResponse(id)

		if err != nil {
			return fmt.Errorf("error waiting for AUTH=PLAIN response: %w", err)
		}

		// Check if the server response starts with "+"
		if !strings.HasPrefix(line, "+") {
			return fmt.Errorf("unexpected response during AUTH=PLAIN negotiation: %s", line)
		}

		// Send the Base64 encoded credentials after the server's "+" response
		id, err = s.tpBackendConn.Cmd(base64PlainCredentials)
		if err != nil {
			return fmt.Errorf("error sending AUTH=PLAIN credentials: %w", err)
		}
	}

	// Process the server's response after sending credentials
	s.tpBackendConn.StartResponse(id)

	plainAuthResponse, err := s.tpBackendConn.ReadLine()
	if err == nil && strings.HasPrefix(plainAuthResponse, "*") {
		plainAuthResponse, err = s.tpBackendConn.ReadLine()
		if err == nil && !strings.HasPrefix(plainAuthResponse, tag) {
			return fmt.Errorf("unexpected response for AUTH=PLAIN: %s", plainAuthResponse)
		}
	}

	s.tpBackendConn.EndResponse(id)

	if err != nil {
		return fmt.Errorf("error reading AUTH=PLAIN response: %w", err)
	}

	if !strings.Contains(plainAuthResponse, "OK") {
		return fmt.Errorf("AUTH=PLAIN failed: %s", plainAuthResponse)
	}

	s.backendGreeting = plainAuthResponse

	s.logger.Debug("Successful AUTH=PLAIN authentication", slog.String("response", plainAuthResponse))

	return nil
}

func (s *SessionImpl) AuthLogin(tag, username, password string) error {
	// Step 1: Start AUTH=LOGIN process
	id, err := s.tpBackendConn.Cmd("%s AUTHENTICATE LOGIN", tag)
	if err != nil {
		return fmt.Errorf("error starting AUTH=LOGIN: %w", err)
	}

	// Read the initial response (expecting "+ Ready to accept username")
	s.tpBackendConn.StartResponse(id)
	line, err := s.tpBackendConn.ReadLine()
	s.tpBackendConn.EndResponse(id)

	if err != nil {
		return fmt.Errorf("error reading response for AUTH=LOGIN step: %w", err)
	}

	if !strings.HasPrefix(line, "+") {
		return fmt.Errorf("unexpected response for AUTH=LOGIN: %s", line)
	}

	// Step 2: Send the username (Base64 encoded)
	base64Username := base64.StdEncoding.EncodeToString([]byte(username))

	id, err = s.tpBackendConn.Cmd(base64Username)
	if err != nil {
		return fmt.Errorf("error sending username during AUTH=LOGIN: %w", err)
	}

	// Read the next response (expecting "+ Ready to accept password")
	s.tpBackendConn.StartResponse(id)
	line, err = s.tpBackendConn.ReadLine()
	s.tpBackendConn.EndResponse(id)

	if err != nil {
		return fmt.Errorf("error reading response for username step: %w", err)
	}

	if !strings.HasPrefix(line, "+") {
		return fmt.Errorf("unexpected response after sending username: %s", line)
	}

	// Step 3: Send the password (Base64 encoded)
	base64Password := base64.StdEncoding.EncodeToString([]byte(password))

	id, err = s.tpBackendConn.Cmd(base64Password)
	if err != nil {
		return fmt.Errorf("error sending password during AUTH=LOGIN: %w", err)
	}

	// Read the final response (expecting "OK" for successful login)
	s.tpBackendConn.StartResponse(id)
	line, err = s.tpBackendConn.ReadLine()

	if err == nil && strings.HasPrefix(line, "*") {
		line, err = s.tpBackendConn.ReadLine()
	}

	s.tpBackendConn.EndResponse(id)

	if err != nil {
		return fmt.Errorf("error reading final AUTH=LOGIN response: %w", err)
	}

	if !strings.Contains(line, "OK") {
		return fmt.Errorf("AUTH=LOGIN failed: %s", line)
	}

	s.backendGreeting = line

	s.logger.Debug("Successful AUTH=LOGIN authentication", slog.String("response", line))

	return nil
}

func (s *SessionImpl) GetAuthenticator() iface.Authenticator {
	return s.authenticator
}

func (s *SessionImpl) Process(line string) {
	var command iface.IMAPCommand

	if s.errorCounter >= 5 {
		s.WriteResponse("* BAD Too many errors")
		s.Close()

		return
	}

	parts := strings.Fields(line)
	if len(parts) < 2 {
		s.WriteResponse("* BAD Invalid command")
		s.errorCounter++

		return
	}

	tag, cmd := parts[0], strings.ToUpper(parts[1])
	commandFilter := s.setupCommandFilters()

	if commandFilter.ShouldBlock(cmd) {
		s.WriteResponse(tag + " NO Command is not allowed")
		s.errorCounter++

		return
	}

	switch cmd {
	case proto.LOGIN:
		if len(parts) < 4 {
			s.WriteResponse(tag + " BAD Syntax error")
			s.errorCounter++

			return
		}

		command = &commands.Login{Tag: tag, Username: parts[2], Password: parts[3]}
	case proto.LOGOUT:
		command = &commands.Logout{Tag: tag}
	case proto.AUTHENTICATE:
		if len(parts) < 3 {
			s.WriteResponse(tag + " BAD Syntax error")
			s.errorCounter++

			return
		}

		method := strings.ToUpper(parts[2])
		initialResponse := ""

		if len(parts) > 3 {
			initialResponse = parts[3]
		}

		switch method {
		case proto.PLAIN, proto.LOGIN:
			command = &commands.Authenticate{Tag: tag, Method: method, InitialResponse: initialResponse}
		default:
			s.WriteResponse(tag + " NO Unsupported auth method")

			return
		}
	case proto.CAPABILITY:
		command = &commands.Capability{Tag: tag, UseStartTLS: s.instance.TLS.Enabled && s.instance.TLS.StartTLS}
	case proto.ID:
		command = &commands.ID{Tag: tag}
	case proto.STARTTLS:
		command = &commands.StartTLS{Tag: tag, TLSConfig: s.tlsConfig}
	default:
		s.WriteResponse(tag + " BAD Unsupported command")
		s.errorCounter++

		return
	}

	if err := command.Execute(s); err != nil {
		msg := "Error while executing the command"
		if errors.Is(err, auth.ErrInternalServer) {
			msg = "Error talking to Nauthilus"
		}

		s.logger.Error(msg, slog.String(log.KeyError, err.Error()), s.Session(), slog.String("command", cmd))
	}
}

func (s *SessionImpl) Close() {
	if s.tpBackendConn != nil {
		_ = s.tpBackendConn.Close()
		s.tpBackendConn = nil
	}

	if s.rawBackendConn != nil {
		_ = s.rawBackendConn.Close()
		s.rawBackendConn = nil
	}

	if s.tpClientConn != nil {
		_ = s.tpClientConn.Close()
		s.tpClientConn = nil
	}

	if s.rawClientConn != nil {
		_ = s.rawClientConn.Close()
		s.rawClientConn = nil
	}
}

func (s *SessionImpl) LinkClientAndBackend() {
	reader := io.TeeReader(s.rawClientConn, s.rawBackendConn) // Track client activity

	go func() {
		buf := make([]byte, 1024)

		for {
			n, err := reader.Read(buf)
			if err != nil {
				break
			}

			// TODO: Refresh Valkey data
			s.logger.Debug("Client active", slog.String("data", string(buf[:n])), s.Session())
		}
	}()

	link.ConnectClientWithBackend(s)
}

func (s *SessionImpl) Session() slog.Attr {
	return slog.String("session", s.sessionID)
}

func (s *SessionImpl) setupCommandFilters() *filter.CommandFilterManager {
	commandFilter := filter.NewCommandFilterManager()

	if !(s.instance.TLS.Enabled && s.instance.TLS.StartTLS) || s.tlsFlag {
		commandFilter.AddFilter(filter.NewStartTLSFilter())
	}

	if s.tpBackendConn == nil {
		commandFilter.AddFilter(filter.NewIDFilter())
	}

	allMechanisms := []string{proto.LOGIN, proto.PLAIN, proto.XOAUTH2}
	disallowedMechanisms := commands.CalculateDisallowedMechanisms(allMechanisms, s.instance.AuthMechs)

	commandFilter.AddFilter(filter.NewAuthMechanismFilter(disallowedMechanisms))

	return commandFilter
}

func (s *SessionImpl) GetService() string {
	return s.service
}

func (s *SessionImpl) SetUser(username string) {
	s.clientUsername = username
}

func (s *SessionImpl) GetUser() string {
	return s.clientUsername
}

func (s *SessionImpl) SetClientConn(conn net.Conn) {
	s.rawClientConn = conn
	s.tpClientConn = textproto.NewConn(conn)
}

func (s *SessionImpl) GetClientConn() net.Conn {
	return s.rawClientConn
}

func (s *SessionImpl) GetBackendGreeting() string {
	return s.backendGreeting
}

func (s *SessionImpl) GetClientContext() *context.Context {
	return s.clientCtx
}

func (s *SessionImpl) GetBackendContext() *context.Context {
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
	return s.rawBackendConn
}

func (s *SessionImpl) GetCapability() []string {
	return s.instance.Capability
}

func (s *SessionImpl) GetStopWatchDog() chan struct{} {
	return s.stopWatchdog
}

func (s *SessionImpl) GetTLSVerified() bool {
	return s.tlsVerified
}

func (s *SessionImpl) GetTLSProtocol() string {
	return s.tlsProtocol
}

func (s *SessionImpl) GetTLSCipherSuite() string {
	return s.tlsCipherSuite
}

func (s *SessionImpl) GetTLSFingerprint() string {
	return s.tlsFingerprint
}

func (s *SessionImpl) GetTLSClientCName() string {
	return s.tlsClientCName
}

func (s *SessionImpl) GetTLSIssuerDN() string {
	return s.tlsIssuerDN
}

func (s *SessionImpl) GetTLSClientDN() string {
	return s.tlsClientDN
}

func (s *SessionImpl) GetTLSClientNotBefore() string {
	return s.tlsClientNotBefore
}

func (s *SessionImpl) GetTLSClientNotAfter() string {
	return s.tlsClientNotAfter
}

func (s *SessionImpl) GetTLSSerial() string {
	return s.tlsSerial
}

func (s *SessionImpl) GetTLSClientIssuerDN() string {
	return s.tlsClientIssuerDN
}

func (s *SessionImpl) GetTLSDNSNames() string {
	return s.tlsDNSNames
}

func (s *SessionImpl) GetLocalIP() string {
	return s.localIP
}

func (s *SessionImpl) GetRemoteIP() string {
	return s.remoteIP
}

func (s *SessionImpl) GetLocalPort() int {
	return s.localPort
}

func (s *SessionImpl) GetRemotePort() int {
	return s.remotePort
}

func (s *SessionImpl) GetLogger() *slog.Logger {
	return s.logger
}

func (s *SessionImpl) GetNauthilus() config.Nauthilus {
	return s.nauthilus
}

func (s *SessionImpl) GetClientID() string {
	return s.clientID
}
