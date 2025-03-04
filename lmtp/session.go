package lmtp

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/textproto"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/config"
	iface "github.com/croessner/nauthilus-director/interfaces"
	"github.com/croessner/nauthilus-director/lmtp/proto"
	"github.com/croessner/nauthilus-director/log"
)

type State uint

const (
	StateWaitingMailFrom State = iota
	StateWaitingRcptTo
	StateReceivingData
)

const ErrWriteRespone = "Error writing response"

type SessionImpl struct {
	authenticator      iface.Authenticator
	tpClientConn       *textproto.Conn
	rawClientConn      net.Conn
	logger             *slog.Logger
	state              State
	recipients         []string
	lastActivity       chan struct{}
	stopWatchdog       chan struct{}
	sessionID          string
	inactivityTimeout  time.Duration
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
	tlsVerified        bool
	tlsFlag            bool
	errorCounter       uint8
	remoteIP           string
	localIP            string
	remotePort         int
	localPort          int
	instance           config.Listen
}

var _ iface.LMTPSession = (*SessionImpl)(nil)

func (s *SessionImpl) WriteResponse(response string) error {
	return s.tpClientConn.PrintfLine(response)
}

func (s *SessionImpl) ReadCommand() (string, error) {
	return s.tpClientConn.ReadLine()
}

func (s *SessionImpl) Session() slog.Attr {
	return slog.String("session", s.sessionID)
}

func (s *SessionImpl) InitializeTLSFields() {
	tlsConn, ok := s.rawClientConn.(*tls.Conn)
	if !ok {
		return
	}

	connectionState := tlsConn.ConnectionState()

	// TLS Versions-Protokoll und Cipher Suite
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

func (s *SessionImpl) StartWatchdog() {
	for {
		select {
		case <-s.lastActivity:
			continue
		case <-time.After(s.inactivityTimeout):
			if err := s.WriteResponse("421 Timeout: closing connection"); err != nil {
				s.logger.Error(ErrWriteRespone, slog.String(log.KeyError, err.Error()), s.Session())
			}

			s.logger.Warn("Session timed out due to inactivity",
				slog.String(log.KeyLocal, s.rawClientConn.LocalAddr().String()),
				slog.String(log.KeyRemote, s.rawClientConn.RemoteAddr().String()),
				slog.String("session", s.sessionID),
			)

			s.Close()

			return
		case <-s.stopWatchdog:
			return
		}
	}
}

func (s *SessionImpl) handleLHLO() error {
	cmd, err := s.ReadCommand()
	if err != nil {
		return nil
	}

	if strings.HasPrefix(strings.ToUpper(cmd), proto.LHLO) {
		// TODO: Filter unsupported caps
		capabilities := s.instance.Capability
		if len(capabilities) == 0 {
			capabilities = []string{
				"8BITMIME",
				"SMTPUTF8",
				"ENHANCEDSTATUSCODES",
			}
		}

		for index, item := range capabilities {
			sep := "-"
			if index == len(s.instance.Capability)-1 {
				sep = " "
			}

			if err = s.WriteResponse("250" + sep + item); err != nil {
				return err
			}
		}
	} else {
		if err = s.WriteResponse("501 5.5.4 LHLO expected"); err != nil {
			return err
		}

		return fmt.Errorf("expected LHLO but got: %s", cmd)
	}

	return nil
}

func (s *SessionImpl) Process() {
	defer func() {
		s.stopWatchdog <- struct{}{}

		s.Close()
	}()

	if err := s.handleLHLO(); err != nil {
		s.logger.Error(ErrWriteRespone, slog.String(log.KeyError, err.Error()), s.Session())

		return
	}

	for {
		if s.errorCounter > 5 {
			if err := s.WriteResponse("521 5.7.0 Too many errors: closing connection"); err != nil {
				s.logger.Error(ErrWriteRespone, slog.String(log.KeyError, err.Error()), s.Session())
			}

			break
		}

		cmd, err := s.ReadCommand()
		if err != nil {
			break
		}

		s.lastActivity <- struct{}{}

		if strings.EqualFold(cmd, proto.NOOP) {
			if err = s.WriteResponse("250 OK"); err != nil {
				s.logger.Error(ErrWriteRespone, slog.String(log.KeyError, err.Error()), s.Session())

				break
			}

			continue
		} else if strings.EqualFold(cmd, proto.RSET) {
			s.state = StateWaitingMailFrom
			s.recipients = []string{}

			if err = s.WriteResponse("250 OK"); err != nil {
				s.logger.Error(ErrWriteRespone, slog.String(log.KeyError, err.Error()), s.Session())

				break
			}

			continue
		}

		switch s.state {
		case StateWaitingMailFrom:
			if strings.HasPrefix(cmd, proto.MAILFROM+":") {
				if err = s.WriteResponse("250 OK"); err != nil {
					s.logger.Error(ErrWriteRespone, slog.String(log.KeyError, err.Error()), s.Session())

					break
				}

				s.state = StateWaitingRcptTo
				s.recipients = []string{} // New message, reset recipients
			} else if strings.HasPrefix(cmd, proto.QUIT) {
				if err = s.WriteResponse("221 Bye"); err != nil {
					s.logger.Error(ErrWriteRespone, slog.String(log.KeyError, err.Error()), s.Session())
				}

				break
			} else {
				if err = s.WriteResponse("500 5.5.1 Syntax error, MAIL FROM or QUIT expected"); err != nil {
					s.logger.Error(ErrWriteRespone, slog.String(log.KeyError, err.Error()), s.Session())

					break
				}

				s.errorCounter++
			}

		case StateWaitingRcptTo:
			if strings.HasPrefix(cmd, proto.RCPTTO+":") {
				recipient := strings.TrimSpace(strings.TrimPrefix(cmd, "RCPT TO:"))
				s.recipients = append(s.recipients, recipient)

				if err = s.WriteResponse("250 OK"); err != nil {
					s.logger.Error(ErrWriteRespone, slog.String(log.KeyError, err.Error()), s.Session())

					break
				}
			} else if strings.EqualFold(cmd, proto.DATA) || strings.EqualFold(cmd, proto.BDAT) {
				if len(s.recipients) == 0 {
					if err = s.WriteResponse("503 5.5.2 Bad sequence of commands: RCPT TO required before DATA"); err != nil {
						s.logger.Error(ErrWriteRespone, slog.String(log.KeyError, err.Error()), s.Session())

						break
					}

					s.errorCounter++
				} else {
					if err = s.WriteResponse("354 Start mail input"); err != nil {
						s.logger.Error(ErrWriteRespone, slog.String(log.KeyError, err.Error()), s.Session())

						break
					}

					s.state = StateReceivingData
				}
			} else if strings.HasPrefix(cmd, proto.QUIT) {
				if err = s.WriteResponse("221 Bye"); err != nil {
					s.logger.Error(ErrWriteRespone, slog.String(log.KeyError, err.Error()), s.Session())
				}

				break
			} else {
				if err = s.WriteResponse("500 5.5.1 Syntax error, RCPT TO, DATA or QUIT expected"); err != nil {
					s.logger.Error(ErrWriteRespone, slog.String(log.KeyError, err.Error()), s.Session())

					break
				}

				s.errorCounter++
			}

		case StateReceivingData:
			if cmd == "." {
				queueID := "12345"

				if err = s.WriteResponse("250 2.0.0 OK: queued as " + queueID); err != nil {
					s.logger.Error(ErrWriteRespone, slog.String(log.KeyError, err.Error()), s.Session())

					break
				}

				s.logger.Debug("Email processed for recipients", slog.String("recipients", strings.Join(s.recipients, ", ")), slog.String("session", s.sessionID))
				s.state = StateWaitingMailFrom
			} else {
				s.logger.Debug("Received email data", slog.String("command", cmd), slog.String("session", s.sessionID))
			}
		}
	}
}

func (s *SessionImpl) Close() {
	if s.tpClientConn != nil {
		_ = s.tpClientConn.Close()
		s.tpClientConn = nil
	}

	if s.rawClientConn != nil {
		_ = s.rawClientConn.Close()
		s.rawClientConn = nil
	}
}

func (s *SessionImpl) GetTLSProtocol() string {
	return s.tlsProtocol
}

func (s *SessionImpl) GetTLSCipherSuite() string {
	return s.tlsCipherSuite
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

func (s *SessionImpl) GetTLSDNSNames() string {
	return s.tlsDNSNames
}

func (s *SessionImpl) GetTLSVerified() bool {
	return s.tlsVerified
}

func (s *SessionImpl) GetTLSClientIssuerDN() string {
	return s.tlsClientIssuerDN
}

func (s *SessionImpl) GetTLSFingerprint() string {
	return s.tlsFingerprint
}
