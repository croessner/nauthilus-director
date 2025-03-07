package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/croessner/nauthilus-director/auth/nauthilus"
	"github.com/croessner/nauthilus-director/config"
	"github.com/croessner/nauthilus-director/context"
	"github.com/croessner/nauthilus-director/enc"
	"github.com/croessner/nauthilus-director/interfaces"
	"github.com/croessner/nauthilus-director/log"
)

var (
	ErrAuthenticationFailed = errors.New("authentication failed")
	ErrUserNotFound         = errors.New("user not found")
	ErrInternalServer       = errors.New("internal server error")
)

func NewHTTPClient(httpOptions config.HTTPClient, tlsOptions config.TLS) (*http.Client, error) {
	var proxyFunc func(*http.Request) (*url.URL, error)

	if httpOptions.Proxy != "" {
		proxyURL, err := url.Parse(httpOptions.Proxy)
		if err != nil {
			proxyFunc = http.ProxyFromEnvironment
		} else {
			proxyFunc = http.ProxyURL(proxyURL)
		}
	} else {
		proxyFunc = http.ProxyFromEnvironment
	}

	tlsConfig, err := enc.GetClientTLSConfig(tlsOptions)

	httpClient := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			Proxy:               proxyFunc,
			MaxConnsPerHost:     httpOptions.MaxConnsPerHost,
			MaxIdleConns:        httpOptions.MaxIdleConns,
			MaxIdleConnsPerHost: httpOptions.MaxIdleConnsPerHost,
			IdleConnTimeout:     httpOptions.IdleConnTimeout,
			TLSClientConfig:     tlsConfig,
		},
	}

	return httpClient, err
}

type NauthilusAuthenticator struct {
	userLookup         bool
	tlsSecured         bool
	tlsVerified        bool
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
	service            string
	account            string
	localIP            string
	remoteIP           string
	authMechanism      string
	nauthilusApi       string
	clientID           string
	localPort          int
	remotePort         int
	httpOptions        config.HTTPClient
	tlsOptions         config.TLS
}

var _ iface.Authenticator = (*NauthilusAuthenticator)(nil)

func (n *NauthilusAuthenticator) generatePayload(service, username, password string) *nauthilus.Request {
	return &nauthilus.Request{
		Username:           username,
		Password:           password,
		ClientIP:           n.remoteIP,
		ClientPort:         strconv.Itoa(n.remotePort),
		ClientID:           n.clientID,
		LocalIP:            n.localIP,
		LocalPort:          strconv.Itoa(n.localPort),
		Service:            service,
		Method:             n.authMechanism,
		AuthLoginAttempt:   0, // ignored
		SSL:                fmt.Sprintf("%t", n.tlsSecured),
		SSLSessionID:       "", // ignored
		SSLClientVerify:    fmt.Sprintf("%t", n.tlsVerified),
		SSLClientDN:        n.tlsClientDN,
		SSLClientCN:        n.tlsClientCName,
		SSLIssuer:          "", // ignored
		SSLClientNotBefore: n.tlsClientNotBefore,
		SSLClientNotAfter:  n.tlsClientNotAfter,
		SSLSubjectDN:       "", // ignored
		SSLIssuerDN:        n.tlsIssuerDN,
		SSLClientSubjectDN: "", // ignored
		SSLClientIssuerDN:  n.tlsClientIssuerDN,
		SSLProtocol:        n.tlsProtocol,
		SSLCipher:          n.tlsCipherSuite,
		SSLSerial:          n.tlsSerial,
		SSLFingerprint:     n.tlsFingerprint,
	}
}

func (n *NauthilusAuthenticator) logFaeildRequest(ctx *context.Context, service, username string) {
	logger := log.GetLogger(ctx)

	logger.Warn("Nauthilus authentication failure",
		slog.String("service", service),
		slog.String("auth_mechanism", n.authMechanism),
		slog.String("username", username),
		slog.String("local_IP", n.localIP),
		slog.Int("local_port", n.localPort),
		slog.String("remote_IP", n.remoteIP),
		slog.Int("remote_port", n.remotePort),
		slog.String("tls_protocol", n.tlsProtocol),
		slog.String("tls_cipher_suite", n.tlsCipherSuite),
		slog.String("tls_fingerprint", n.tlsFingerprint),
		slog.String("tls_client_CName", n.tlsClientCName),
		slog.String("tls_issuer_DN", n.tlsIssuerDN),
		slog.String("tls_client_DN", n.tlsClientDN),
		slog.String("tls_client_not_before", n.tlsClientNotBefore),
		slog.String("tls_client_not_after", n.tlsClientNotAfter),
		slog.String("tls_serial", n.tlsSerial),
		slog.String("tls_client_issuer_DN", n.tlsClientIssuerDN),
		slog.String("tls_DNS_names", n.tlsDNSNames),
	)
}

func (n *NauthilusAuthenticator) Authenticate(ctx *context.Context, service, username, password string) (bool, error) {
	var incorrectResponse bool

	httpClient, err := NewHTTPClient(n.httpOptions, n.tlsOptions)
	if err != nil {
		return false, err
	}

	defer httpClient.CloseIdleConnections()

	payload := n.generatePayload(service, username, password)
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("failed to marshal payload: %w", err)
	}

	mode := ""
	if n.userLookup {
		mode = "?mode=no-auth"
	}

	response, err := httpClient.Post(n.nauthilusApi+mode, "application/json", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return false, err
	}

	defer func() {
		_ = response.Body.Close()

		if incorrectResponse {
			n.logFaeildRequest(ctx, service, username)
		}
	}()

	if response.StatusCode == http.StatusOK {
		var (
			responseBytes []byte
			userInfo      map[string]any
		)

		responseBytes, err = io.ReadAll(response.Body)
		if err != nil {
			return false, err
		}

		err = json.Unmarshal(responseBytes, &userInfo)
		if err != nil {
			return false, err
		}

		if accountField, okay := userInfo["account_field"].(string); okay {
			if attributes, okay := userInfo["attributes"].(map[string]any); okay {
				if accounts, okay := attributes[accountField].([]any); okay {
					if len(accounts) == 1 {
						if account, okay := accounts[0].(string); okay {
							n.account = account

							return true, nil
						}
					}
				}
			}
		}

		incorrectResponse = true

		return false, ErrUserNotFound
	} else if response.StatusCode == http.StatusUnauthorized {
		return false, ErrAuthenticationFailed
	} else if response.StatusCode == http.StatusForbidden {
		if n.userLookup {
			return false, ErrUserNotFound
		}

		return false, ErrAuthenticationFailed
	} else {
		incorrectResponse = true

		return false, ErrInternalServer
	}
}

func (n *NauthilusAuthenticator) SetUserLookup(flag bool) {
	n.userLookup = flag
}

func (n *NauthilusAuthenticator) GetAccount() string {
	return n.account
}

func (n *NauthilusAuthenticator) SetAuthMechanism(mechanism string) {
	n.authMechanism = mechanism
}

func (n *NauthilusAuthenticator) SetTLSSecured(secured bool) {
	n.tlsSecured = secured
}

func (n *NauthilusAuthenticator) SetTLSProtocol(protocol string) {
	n.tlsProtocol = protocol
}

func (n *NauthilusAuthenticator) SetTLSCipherSuite(cipherSuite string) {
	n.tlsCipherSuite = cipherSuite
}

func (n *NauthilusAuthenticator) SetTLSFingerprint(fingerprint string) {
	n.tlsFingerprint = fingerprint
}

func (n *NauthilusAuthenticator) SetTLSClientCName(clientCName string) {
	n.tlsClientCName = clientCName
}

func (n *NauthilusAuthenticator) SetTLSVerified(verified bool) {
	n.tlsVerified = verified
}

func (n *NauthilusAuthenticator) SetTLSIssuerDN(issuerDN string) {
	n.tlsIssuerDN = issuerDN
}

func (n *NauthilusAuthenticator) SetTLSClientDN(clientDN string) {
	n.tlsClientDN = clientDN
}

func (n *NauthilusAuthenticator) SetTLSClientNotBefore(notBefore string) {
	n.tlsClientNotBefore = notBefore
}

func (n *NauthilusAuthenticator) SetTLSClientNotAfter(notAfter string) {
	n.tlsClientNotAfter = notAfter
}

func (n *NauthilusAuthenticator) SetTLSSerial(serial string) {
	n.tlsSerial = serial
}

func (n *NauthilusAuthenticator) SetTLSClientIssuerDN(clientIssuerDN string) {
	n.tlsClientIssuerDN = clientIssuerDN
}

func (n *NauthilusAuthenticator) SetTLSDNSNames(dnsNames string) {
	n.tlsDNSNames = dnsNames
}

func (n *NauthilusAuthenticator) SetLocalIP(ip string) {
	n.localIP = ip
}

func (n *NauthilusAuthenticator) SetRemoteIP(ip string) {
	n.remoteIP = ip
}

func (n *NauthilusAuthenticator) SetLocalPort(port int) {
	n.localPort = port
}

func (n *NauthilusAuthenticator) SetRemotePort(port int) {
	n.remotePort = port
}

func (n *NauthilusAuthenticator) SetHTTPOptions(options config.HTTPClient) {
	n.httpOptions = options
}

func (n *NauthilusAuthenticator) SetTLSOptions(options config.TLS) {
	n.tlsOptions = options
}

func (n *NauthilusAuthenticator) SetNauthilusApi(api string) {
	n.nauthilusApi = api
}

func (n *NauthilusAuthenticator) SetClientID(id string) {
	n.clientID = id
}
