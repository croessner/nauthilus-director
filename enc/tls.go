package enc

import (
	"crypto/tls"
	"fmt"

	"github.com/croessner/nauthilus-director/config"
)

func GetTLSConfig(instance config.Listen) (*tls.Config, error) {
	if instance.TLS.Enabled == false {
		return nil, nil
	}

	if instance.TLS.Cert == "" || instance.TLS.Key == "" {
		return nil, fmt.Errorf("no TLS certificate or key specified")
	}

	cert, err := tls.LoadX509KeyPair(instance.TLS.Cert, instance.TLS.Key)
	if err != nil {
		return nil, fmt.Errorf("error while loading TLS certificate or key: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}
