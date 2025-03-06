package commands

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	authenticator "github.com/croessner/nauthilus-director/auth"
	"github.com/croessner/nauthilus-director/imap/proto"
	"github.com/croessner/nauthilus-director/interfaces"
)

type Authenticate struct {
	Tag             string
	Method          string
	InitialResponse string // Holds the SASL-IR if provided
}

var _ iface.IMAPCommand = (*Authenticate)(nil)

func (c *Authenticate) Execute(session iface.IMAPSession) error {
	switch strings.ToUpper(c.Method) {
	case proto.PLAIN:
		if c.InitialResponse != "" {
			// Client with SASL-IR
			if err := c.handlePlainAuthWithInitialResponse(session); err != nil {
				session.GetLogger().Error("PLAIN authentication with SASL-IR failed", session.Session(), slog.String("error", err.Error()))

				return err
			}
		} else {
			if err := c.handlePlainAuth(session); err != nil {
				session.GetLogger().Error("PLAIN authentication failed", session.Session(), slog.String("error", err.Error()))

				return err
			}
		}
	case proto.LOGIN:
		if c.InitialResponse != "" {
			session.WriteResponse(c.Tag + " NO SASL-IR not supported with AUTH LOGIN")

			return fmt.Errorf("AUTH LOGIN does not support SASL-IR")
		}

		if err := c.handleLoginAuth(session); err != nil {
			session.GetLogger().Error("LOGIN authentication failed", session.Session(), slog.String("error", err.Error()))

			return err
		}
	default:
		session.WriteResponse(c.Tag + " NO Unsupported authentication method")

		return fmt.Errorf("unsupported auth method: %s", c.Method)
	}

	// Verbindung zum Backend herstellen
	masterPass := "password" // TODO: Masterpassword...
	err := session.ConnectToIMAPBackend(c.Tag, session.GetUser(), masterPass)
	if err != nil {
		if err == io.EOF {
			session.Close()

			return io.EOF
		}

		session.WriteResponse(c.Tag + " NO Backend authentication failed")

		return err
	}

	session.WriteResponse(session.GetBackendGreeting())

	session.GetLogger().Info("link client and backend", session.Session(), slog.String("user", session.GetUser()))
	session.GetStopWatchDog() <- struct{}{}
	session.LinkClientAndBackend()

	return nil
}

func (c *Authenticate) handlePlainAuthWithInitialResponse(session iface.IMAPSession) error {
	decoded, err := base64.StdEncoding.DecodeString(c.InitialResponse)
	if err != nil {
		session.WriteResponse(c.Tag + " NO Invalid base64 encoded credentials")

		return fmt.Errorf("invalid base64: %w", err)
	}

	// \x00username\x00password
	parts := strings.Split(string(decoded), "\x00")
	if len(parts) != 3 {
		session.WriteResponse(c.Tag + " NO Invalid PLAIN authentication format")

		return fmt.Errorf("invalid PLAIN auth format: %s", string(decoded))
	}

	username := parts[1]
	password := parts[2]

	auth := session.GetAuthenticator()

	setupAuthenticator(session, auth)
	auth.SetAuthMechanism(strings.ToUpper(c.Method) + " (SASL)")

	isAuthenticated, err := auth.Authenticate(session.GetClientContext(), session.GetService(), username, password)
	if err != nil {
		if !(errors.Is(err, authenticator.ErrAuthenticationFailed) || errors.Is(err, authenticator.ErrUserNotFound)) {
			session.WriteResponse(c.Tag + " NO Internal error")

			return err
		}
	}

	if !isAuthenticated {
		session.WriteResponse(c.Tag + " NO Authentication failed")

		return authenticator.ErrAuthenticationFailed
	}

	session.SetUser(auth.GetAccount())

	return nil
}

func (c *Authenticate) handlePlainAuth(session iface.IMAPSession) error {
	session.WriteResponse("+")

	line, err := session.ReadLine()
	if err != nil {
		session.WriteResponse(c.Tag + " NO Failed to read credentials")

		return fmt.Errorf("error reading PLAIN credentials: %w", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		session.WriteResponse(c.Tag + " NO Invalid base64 encoded credentials")

		return fmt.Errorf("invalid base64: %w", err)
	}

	// \x00username\x00password
	parts := strings.Split(string(decoded), "\x00")
	if len(parts) != 3 {
		session.WriteResponse(c.Tag + " NO Invalid PLAIN authentication format")

		return fmt.Errorf("invalid PLAIN auth format: %s", string(decoded))
	}

	username := parts[1]
	password := parts[2]

	auth := session.GetAuthenticator()

	setupAuthenticator(session, auth)
	auth.SetAuthMechanism(strings.ToUpper(c.Method) + " (SASL)")

	isAuthenticated, err := auth.Authenticate(session.GetClientContext(), session.GetService(), username, password)
	if err != nil {
		if !(errors.Is(err, authenticator.ErrAuthenticationFailed) || errors.Is(err, authenticator.ErrUserNotFound)) {
			session.WriteResponse(c.Tag + " NO Internal error")

			return err
		}
	}

	if !isAuthenticated {
		session.WriteResponse(c.Tag + " NO Authentication failed")

		return authenticator.ErrAuthenticationFailed
	}

	session.SetUser(auth.GetAccount())

	return nil
}

func (c *Authenticate) handleLoginAuth(session iface.IMAPSession) error {
	session.WriteResponse("+ Ready for username")

	usernameLine, err := session.ReadLine()
	if err != nil {
		session.WriteResponse(c.Tag + " NO Failed to read username")

		return fmt.Errorf("error reading username: %w", err)
	}

	usernameBytes, err := base64.StdEncoding.DecodeString(usernameLine)
	if err != nil {
		session.WriteResponse(c.Tag + " NO Invalid base64 encoded username")

		return fmt.Errorf("invalid base64 username: %w", err)
	}

	username := string(usernameBytes)

	session.WriteResponse("+ Ready for password")

	passwordLine, err := session.ReadLine()
	if err != nil {
		session.WriteResponse(c.Tag + " NO Failed to read password")

		return fmt.Errorf("error reading password: %w", err)
	}

	passwordBytes, err := base64.StdEncoding.DecodeString(passwordLine)
	if err != nil {
		session.WriteResponse(c.Tag + " NO Invalid base64 encoded password")

		return fmt.Errorf("invalid base64 password: %w", err)
	}

	password := string(passwordBytes)

	auth := session.GetAuthenticator()

	setupAuthenticator(session, auth)
	auth.SetAuthMechanism(strings.ToUpper(c.Method) + " (SASL)")

	isAuthenticated, err := auth.Authenticate(session.GetClientContext(), session.GetService(), username, password)
	if err != nil {
		if !(errors.Is(err, authenticator.ErrAuthenticationFailed) || errors.Is(err, authenticator.ErrUserNotFound)) {
			session.WriteResponse(c.Tag + " NO Internal error")

			return err
		}
	}

	if !isAuthenticated {
		session.WriteResponse(c.Tag + " NO Authentication failed")

		return authenticator.ErrAuthenticationFailed
	}

	session.SetUser(auth.GetAccount())

	return nil
}
