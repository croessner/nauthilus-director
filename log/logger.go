package log

import (
	stdcontext "context"
	"log/slog"
	"os"

	"github.com/croessner/nauthilus-director/config"
	"github.com/croessner/nauthilus-director/context"
)

const loggerKey context.CtxKey = "logging"

const (
	KeyError              = "error"
	KeyLocal              = "local"
	KeyRemote             = "remote"
	KeyTLSProtocol        = "tls_protocol"
	KeyTLSCipherSuite     = "tls_cipher_suite"
	KeyTLSClientCName     = "tls_client_cname"
	KeyTLSIssuerDN        = "tls_issuer_dn"
	KeyTLSClientDN        = "tls_client_dn"
	KeyTLSClientNotBefore = "tls_client_not_before"
	KeyTLSClientNotAfter  = "tls_client_not_after"
	KeyTLSSerial          = "tls_serial"
	KeyTLSClientIssuerDN  = "tls_client_issuer_dn"
	KeyTLSDNSNames        = "tls_dns_names"
	KeyTLSFingerprint     = "tls_fingerprint"
	KeyTLSVerified        = "tls_verified"
)

type WrappedHandler struct {
	fields  []slog.Attr
	handler slog.Handler
}

func (w *WrappedHandler) Enabled(ctx stdcontext.Context, level slog.Level) bool {
	return w.handler.Enabled(ctx, level)
}

func (w *WrappedHandler) Handle(ctx stdcontext.Context, record slog.Record) error {
	record.AddAttrs(w.fields...)

	return w.handler.Handle(ctx, record)
}

func (w *WrappedHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &WrappedHandler{
		handler: w.handler.WithAttrs(attrs),
		fields:  w.fields,
	}
}

// WithGroup ermöglicht die Gruppierung von Logs.
func (w *WrappedHandler) WithGroup(name string) slog.Handler {
	return &WrappedHandler{
		handler: w.handler.WithGroup(name),
		fields:  w.fields,
	}
}

func SetupLogging(ctx *context.Context, cfg *config.Config) {
	var (
		baseHandler    slog.Handler
		wrappedHandler slog.Handler
	)

	handlerOpts := &slog.HandlerOptions{
		AddSource: false,
		Level:     slog.LevelInfo,
	}

	if cfg != nil {
		switch cfg.Server.Logging.Level {
		case "debug":
			handlerOpts.Level = slog.LevelDebug
			handlerOpts.AddSource = true
		case "info":
			handlerOpts.Level = slog.LevelInfo
		case "warn":
			handlerOpts.Level = slog.LevelWarn
		case "error":
			handlerOpts.Level = slog.LevelError
		default:
			handlerOpts.Level = slog.LevelInfo
		}

		if cfg.Server.Logging.JSON {
			baseHandler = slog.NewJSONHandler(os.Stdout, handlerOpts)
		} else {
			baseHandler = slog.NewTextHandler(os.Stdout, handlerOpts)
		}

		if cfg.Server.InstanceID == "" {
			cfg.Server.InstanceID = "default"
		}

		defaultFields := []slog.Attr{
			slog.String("instance", cfg.Server.InstanceID),
		}

		wrappedHandler = &WrappedHandler{
			handler: baseHandler,
			fields:  defaultFields,
		}
	} else {
		wrappedHandler = slog.NewTextHandler(
			os.Stdout,
			&slog.HandlerOptions{
				AddSource: false,
				Level:     slog.LevelInfo,
			},
		)
	}

	ctx.Set(loggerKey, slog.New(wrappedHandler))
}

func GetLogger(ctx *context.Context) *slog.Logger {
	return ctx.Value(loggerKey).(*slog.Logger)
}
