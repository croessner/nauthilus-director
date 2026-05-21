package enc

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/croessner/nauthilus-director/config"
)

var cipherSuiteMap = map[string]uint16{
	// TLSv1.3 CipherSuites (High Security)
	"TLS_AES_128_GCM_SHA256":       tls.TLS_AES_128_GCM_SHA256,
	"TLS_AES_256_GCM_SHA384":       tls.TLS_AES_256_GCM_SHA384,
	"TLS_CHACHA20_POLY1305_SHA256": tls.TLS_CHACHA20_POLY1305_SHA256,

	// TLSv1.2 CipherSuites (Medium-High Security)
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,

	// TLSv1.2 Fallback CipherSuites (Medium Security, for limited compatibility)
	"TLS_RSA_WITH_AES_128_GCM_SHA256": tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_RSA_WITH_AES_256_GCM_SHA384": tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
}

func mapCipherSuites(names []string) ([]uint16, error) {
	var cipherSuites []uint16

	for _, name := range names {
		if id, found := cipherSuiteMap[name]; found {
			cipherSuites = append(cipherSuites, id)
		} else {
			return nil, fmt.Errorf("unsupported cipher suite: %s", name)
		}
	}

	return cipherSuites, nil
}

func getTLSVersion(version string) (minVersion uint16, err error) {
	switch version {
	case "TLSv1.2":
		minVersion = tls.VersionTLS12
	case "TLSv1.3":
		minVersion = tls.VersionTLS13
	case "":
		minVersion = tls.VersionTLS12 // Default
	default:
		return 0, fmt.Errorf("unsupported TLS version: %s", version)
	}

	return
}

func GetServerTLSConfig(tlsSettings config.TLS) (*tls.Config, error) {
	var rootCAs *x509.CertPool

	if !tlsSettings.Enabled {
		return nil, nil
	}

	if tlsSettings.Cert == "" || tlsSettings.Key == "" {
		return nil, fmt.Errorf("no TLS certificate or key specified")
	}

	cert, err := tls.LoadX509KeyPair(tlsSettings.Cert, tlsSettings.Key)
	if err != nil {
		return nil, fmt.Errorf("error while loading TLS certificate or key: %v", err)
	}

	// Parse and set MinVersion
	minVersion, err := getTLSVersion(tlsSettings.MinVersion)
	if err != nil {
		return nil, err
	}

	// Parse and set MaxVersion
	maxVersion, err := getTLSVersion(tlsSettings.MaxVersion)
	if err != nil {
		return nil, err
	}

	// Check if minVersion > maxVersion and adjust
	if maxVersion != 0 && minVersion > maxVersion {
		minVersion = maxVersion
	}

	// Use provided CipherSuites or default if not specified
	cipherSuites, err := mapCipherSuites(tlsSettings.CipherSuite)
	if err != nil {
		return nil, err
	}

	// Load CA certificate if CA is provided
	if tlsSettings.CAFile != "" {
		caCert, err := os.ReadFile(tlsSettings.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA certificate: %v", err)
		}

		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to append CA certificate")
		}
	}

	// Build tls.Config
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
		InsecureSkipVerify: tlsSettings.SkipVerify,
		CipherSuites:       cipherSuites,
		RootCAs:            rootCAs,
	}

	// If ServerName is provided, use it
	if tlsSettings.ServerName != "" {
		tlsConfig.ServerName = tlsSettings.ServerName
	}

	return tlsConfig, nil
}

func GetClientTLSConfig(tlsSettings config.TLS) (*tls.Config, error) {
	var (
		err  error
		cert tls.Certificate
	)

	if !tlsSettings.Enabled {
		return nil, nil
	}

	if tlsSettings.Cert != "" || tlsSettings.Key != "" {
		cert, err = tls.LoadX509KeyPair(tlsSettings.Cert, tlsSettings.Key)
		if err != nil {
			return nil, fmt.Errorf("error while loading TLS certificate or key: %v", err)
		}
	}

	// Parse and set MinVersion
	minVersion, err := getTLSVersion(tlsSettings.MinVersion)
	if err != nil {
		return nil, err
	}

	// Parse and set MaxVersion
	maxVersion, err := getTLSVersion(tlsSettings.MaxVersion)
	if err != nil {
		return nil, err
	}

	// Check if minVersion > maxVersion and adjust
	if maxVersion != 0 && minVersion > maxVersion {
		minVersion = maxVersion
	}

	// Build tls.Config
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
		InsecureSkipVerify: tlsSettings.SkipVerify,
	}

	return tlsConfig, nil
}
