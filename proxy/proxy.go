package proxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/croessner/nauthilus-director/config"
	"github.com/croessner/nauthilus-director/context"
	"github.com/croessner/nauthilus-director/enc"
	"github.com/croessner/nauthilus-director/interfaces"
	"github.com/croessner/nauthilus-director/log"
)

type Proxy struct {
	listener   net.Listener
	wg         *sync.WaitGroup
	ctx        *context.Context
	tlsConfig  *tls.Config
	instance   config.Listen
	listenAddr string
	name       string
}

func NewProxy(ctx *context.Context, instance config.Listen, wg *sync.WaitGroup) *Proxy {
	logger := log.GetLogger(ctx)

	tlsConfig, err := enc.GetTLSConfig(instance)
	if err != nil {
		logger.Error("Could not get TLS config", slog.String(log.KeyError, err.Error()))

		return nil
	}

	return &Proxy{tlsConfig: tlsConfig, ctx: ctx, wg: wg, instance: instance}
}

func (p *Proxy) Start(instance config.Listen, handler func(iface.Proxy, net.Conn)) error {
	var (
		mode     int64
		conn     net.Conn
		fileInfo os.FileInfo
		err      error
	)

	logger := log.GetLogger(p.ctx)

	if instance.TLS.Enabled && p.tlsConfig != nil {
		p.listener = tls.NewListener(p.listener, p.tlsConfig)
	}

	conn, err = net.DialTimeout(instance.Type, p.listenAddr, 1*time.Second)
	if err == nil {
		_ = conn.Close()

		return fmt.Errorf("address %s is already in use", p.listener)
	}

	if instance.Type == "unix" {
		p.listenAddr = instance.Address

		if fileInfo, err = os.Stat(instance.Address); err == nil && fileInfo.Mode()&os.ModeSocket != 0 {
			if err = os.Remove(instance.Address); err != nil {
				return err
			}
		}
	} else {
		p.listenAddr = fmt.Sprintf("%s:%d", instance.Address, instance.Port)
	}

	if instance.Name != "" {
		p.name = instance.Name
	}

	p.listener, err = net.Listen(instance.Type, p.listenAddr)
	if err != nil {
		return fmt.Errorf("could not start server: %w", err)
	}

	if instance.Type == "unix" && instance.Mode != "" {
		mode, err = strconv.ParseInt(instance.Mode, 8, 64)
		if err != nil {
			logger.Error("Could not parse socket mode", slog.String("error", err.Error()))
		}

		if err = os.Chmod(instance.Address, os.FileMode(mode)); err != nil {
			logger.Error("Could not set permissions on socket", slog.String("error", err.Error()))
		}
	}

	logger.Info("Server is listening", slog.String("type", instance.Type), slog.String("address", p.listenAddr), slog.String("name", p.name), slog.String("kind", instance.Kind))

	for {
		conn, err = p.listener.Accept()
		if errors.Is(err, net.ErrClosed) {
			logger.Info("Server is shutting down", slog.String("address", p.listenAddr), slog.String("name", p.name))

			return nil
		}

		if err != nil {
			logger.Error("Error accepting connection", slog.String("error", err.Error()))

			continue
		}

		p.wg.Add(1)

		go handler(p, conn)
	}
}

func (p *Proxy) GetListener() net.Listener {
	return p.listener
}

func (p *Proxy) GetWaitGroup() *sync.WaitGroup {
	return p.wg
}

func (p *Proxy) GetContext() *context.Context {
	return p.ctx
}

func (p *Proxy) GetTLSConfig() *tls.Config {
	return p.tlsConfig
}

func (p *Proxy) GetInstance() config.Listen {
	return p.instance
}

func (p *Proxy) GetListenAddr() string {
	return p.listenAddr
}

func (p *Proxy) GetName() string {
	return p.name
}
