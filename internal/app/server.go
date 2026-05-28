// Copyright (C) 2026 Christian Rößner
//
// SPDX-License-Identifier: AGPL-3.0-only
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/listener"
	"github.com/croessner/nauthilus-director/internal/nauthilus"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/protocol/imap"
	"github.com/croessner/nauthilus-director/internal/protocol/lmtp"
	"github.com/croessner/nauthilus-director/internal/proxy"
	"github.com/croessner/nauthilus-director/internal/rest"
	"github.com/croessner/nauthilus-director/internal/rest/adapters"
	"github.com/croessner/nauthilus-director/internal/routing"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
	"github.com/croessner/nauthilus-director/internal/state"
	"github.com/redis/go-redis/v9"
	"go.uber.org/fx"
)

const (
	defaultReapInterval = 5 * time.Second
	defaultReapLimit    = 100
	protocolIMAP        = "imap"
	protocolLMTP        = "lmtp"
)

// Options configures one production server process instance.
type Options struct {
	ConfigPath string
	Version    string
	Loader     *config.Loader
	Recorder   observability.Recorder
}

type composedApplication struct {
	app             *fx.App
	shutdownTimeout time.Duration
}

type runtimeOptions struct {
	ConfigPath           string
	Version              string
	Loader               *config.Loader
	Snapshot             *config.Snapshot
	ObservabilityRuntime *observability.Runtime
	Recorder             observability.Recorder
	ShutdownTimeout      time.Duration
}

type controlHandle struct {
	server *controlServer
}

type healthRunnerHandle struct {
	runner *backend.HealthRunner
}

type reaperHandle struct {
	reaper *runtimectl.Reaper
}

type protocolHealthChecker struct {
	imap backend.HealthChecker
	lmtp backend.HealthChecker
}

type backendCapabilityReader interface {
	PoolSupportsCapability(ctx context.Context, backendPool string, capability string) (bool, error)
}

// CheckBackend dispatches health checks to the matching protocol checker.
func (c protocolHealthChecker) CheckBackend(ctx context.Context, target backend.Backend, request backend.HealthCheckRequest) backend.HealthCheckResult {
	switch strings.ToLower(strings.TrimSpace(target.Protocol)) {
	case protocolIMAP:
		return c.imap.CheckBackend(ctx, target, request)
	case protocolLMTP:
		return c.lmtp.CheckBackend(ctx, target, request)
	default:
		return backend.HealthCheckResult{ReasonClass: "protocol"}
	}
}

// Run starts the production Fx application and blocks until the context is cancelled.
func Run(ctx context.Context, options Options) error {
	if ctx == nil {
		ctx = context.Background()
	}

	application, err := newApplication(options)
	if err != nil {
		return err
	}

	if err := application.app.Start(ctx); err != nil {
		return err
	}

	<-ctx.Done()

	stopCtx, cancel := contextWithTimeout(context.Background(), application.shutdownTimeout)
	defer cancel()

	stopErr := application.app.Stop(stopCtx)
	if errors.Is(ctx.Err(), context.Canceled) {
		return stopErr
	}

	return errors.Join(ctx.Err(), stopErr)
}

// newApplication loads config once and builds the production Fx graph.
func newApplication(options Options) (composedApplication, error) {
	runtime, err := runtimeOptionsFor(options)
	if err != nil {
		return composedApplication{}, err
	}

	application := fx.New(
		fx.WithLogger(newFxEventLogger),
		fx.StartTimeout(runtime.ShutdownTimeout),
		fx.StopTimeout(runtime.ShutdownTimeout),
		fx.Supply(runtime),
		Module(),
	)
	if err := application.Err(); err != nil {
		return composedApplication{}, err
	}

	return composedApplication{app: application, shutdownTimeout: runtime.ShutdownTimeout}, nil
}

// runtimeOptionsFor prepares immutable process inputs for Fx providers.
func runtimeOptionsFor(options Options) (runtimeOptions, error) {
	loader := options.Loader
	if loader == nil {
		loader = config.NewLoader()
	}

	snapshot, err := loader.Load(config.LoadOptions{Path: options.ConfigPath})
	if err != nil {
		return runtimeOptions{}, err
	}

	shutdownTimeout := snapshot.Config.Runtime.Process.ShutdownTimeout.Std()
	if shutdownTimeout <= 0 {
		shutdownTimeout = config.DefaultConfig().Runtime.Process.ShutdownTimeout.Std()
	}

	observabilityRuntime, err := observability.NewRuntime(
		snapshot.Config.Observability,
		observability.WithAdditionalRecorder(options.Recorder),
		observability.WithProcessInfo("nauthilus-director", options.Version),
	)
	if err != nil {
		return runtimeOptions{}, err
	}

	return runtimeOptions{
		ConfigPath:           options.ConfigPath,
		Version:              options.Version,
		Loader:               loader,
		Snapshot:             snapshot,
		ObservabilityRuntime: observabilityRuntime,
		Recorder:             observabilityRuntime.Recorder(),
		ShutdownTimeout:      shutdownTimeout,
	}, nil
}

// provideLoader exposes the already-created config loader to Fx providers.
func provideLoader(options runtimeOptions) *config.Loader {
	return options.Loader
}

// provideSnapshot exposes the immutable loaded config snapshot to Fx providers.
func provideSnapshot(options runtimeOptions) *config.Snapshot {
	return options.Snapshot
}

// provideConfig exposes the normalized typed config value to Fx providers.
func provideConfig(snapshot *config.Snapshot) config.Config {
	return snapshot.Config
}

// provideObservabilityRuntime exposes the process-local observability owner to Fx.
func provideObservabilityRuntime(options runtimeOptions) *observability.Runtime {
	return options.ObservabilityRuntime
}

// provideRecorder exposes the runtime-owned observability recorder to Fx providers.
func provideRecorder(runtime *observability.Runtime) observability.Recorder {
	return runtime.Recorder()
}

// provideMetricsProvider exposes the runtime-owned Prometheus provider to REST.
func provideMetricsProvider(runtime *observability.Runtime) observability.MetricsProvider {
	return runtime.MetricsProvider()
}

// provideRedisClient creates the configured Redis topology client.
func provideRedisClient(cfg config.Config) (redis.UniversalClient, error) {
	return newRedisClient(cfg.Storage.Redis)
}

// provideRedisStore creates the Redis-backed runtime state store.
func provideRedisStore(client redis.UniversalClient, cfg config.Config, recorder observability.Recorder) (*state.RedisSessionStore, error) {
	return newRedisStore(client, cfg.Storage.Redis, recorder)
}

// provideBackendRegistry builds the immutable backend inventory.
func provideBackendRegistry(cfg config.Config) (*backend.StaticRegistry, error) {
	return backend.NewStaticRegistry(cfg.Director)
}

// provideRuntimeSelector builds the runtime-aware backend selector.
func provideRuntimeSelector(
	cfg config.Config,
	registry *backend.StaticRegistry,
	store *state.RedisSessionStore,
) (*backend.RuntimeSelector, error) {
	return backend.NewRuntimeSelector(registry, store, selectionPolicy(cfg))
}

// provideRoutingResolver builds the shared account-to-shard resolver chain.
func provideRoutingResolver(cfg config.Config, registry *backend.StaticRegistry) (routing.RoutingResolver, error) {
	return routingResolver(cfg, registry)
}

// provideLocalSessionRegistry creates the process-local active-session accelerator.
func provideLocalSessionRegistry() *runtimectl.LocalSessionRegistry {
	return runtimectl.NewLocalSessionRegistry()
}

// provideListenerManager creates public protocol listeners with production handlers.
func provideListenerManager(
	cfg config.Config,
	resolver routing.RoutingResolver,
	store *state.RedisSessionStore,
	selector *backend.RuntimeSelector,
	localSessions *runtimectl.LocalSessionRegistry,
	recorder observability.Recorder,
) (*listener.Manager, error) {
	return listener.NewManagerWithConfig(
		cfg,
		listener.WithLocalSessionRegistry(localSessions),
		listener.WithObservabilityRecorder(recorder),
		listener.WithSessionHandlerFactory(sessionHandlerFactory(resolver, store, selector, selector, recorder)),
	)
}

// provideBackendReadService creates the runtime-effective backend inventory reader.
func provideBackendReadService(
	cfg config.Config,
	registry *backend.StaticRegistry,
	store *state.RedisSessionStore,
	recorder observability.Recorder,
) (*runtimectl.BackendReadService, error) {
	return backendReadService(cfg, registry, store, recorder)
}

// provideRouteLookupService creates the side-effect-free route diagnostic service.
func provideRouteLookupService(
	cfg config.Config,
	registry *backend.StaticRegistry,
	selector *backend.RuntimeSelector,
	reader *runtimectl.BackendReadService,
	store *state.RedisSessionStore,
	recorder observability.Recorder,
) (*runtimectl.RouteLookupService, error) {
	return routeLookupService(cfg, registry, selector, reader, store, recorder)
}

// provideControlHandle creates the optional in-process REST control listener.
func provideControlHandle(
	cfg config.Config,
	snapshot *config.Snapshot,
	options runtimeOptions,
	loader *config.Loader,
	recorder observability.Recorder,
	metrics observability.MetricsProvider,
	backendReader *runtimectl.BackendReadService,
	registry *backend.StaticRegistry,
	store *state.RedisSessionStore,
	localSessions *runtimectl.LocalSessionRegistry,
	listenerManager *listener.Manager,
	routeLookup *runtimectl.RouteLookupService,
) (controlHandle, error) {
	if !cfg.Runtime.Servers.Control.Enabled {
		return controlHandle{}, nil
	}

	runtimeReader := runtimectl.NewRedisRuntimeReader(store)
	handler := rest.NewServer(rest.Options{
		Version:    options.Version,
		ConfigPath: options.ConfigPath,
		HandlerOptions: adapters.HandlerOptions{
			Version:        options.Version,
			ConfigPath:     options.ConfigPath,
			Loader:         loader,
			Snapshot:       snapshot,
			BackendReader:  backendReader,
			BackendMutator: runtimectl.NewBackendService(store, localSessions, runtimectl.WithObservabilityRecorder(recorder)),
			SessionReader:  runtimeReader,
			SessionMutator: runtimectl.NewSessionService(store, localSessions, runtimectl.WithObservabilityRecorder(recorder)),
			UserReader:     runtimeReader,
			UserMutator:    runtimectl.NewUserService(store, localSessions, runtimectl.WithObservabilityRecorder(recorder)),
			RouteLookup:    routeLookup,
			Reload:         safeReloadService(cfg, loader, options.ConfigPath, recorder, registry, listenerManager),
			Metrics:        metrics,
			Observability:  recorder,
		},
	})

	server, err := newControlServer(cfg, handler)
	if err != nil {
		return controlHandle{}, err
	}

	return controlHandle{server: server}, nil
}

// registerObservabilityLifecycle starts observability first and flushes it last.
func registerObservabilityLifecycle(lifecycle fx.Lifecycle, runtime *observability.Runtime) {
	lifecycle.Append(fx.Hook{
		OnStart: runtime.Start,
		OnStop:  runtime.Shutdown,
	})
}

// provideHealthRunnerHandle creates the optional backend health worker.
func provideHealthRunnerHandle(
	cfg config.Config,
	registry *backend.StaticRegistry,
	store *state.RedisSessionStore,
	recorder observability.Recorder,
) (healthRunnerHandle, error) {
	runner, err := healthRunner(cfg, registry, store, recorder)
	if err != nil {
		return healthRunnerHandle{}, err
	}

	return healthRunnerHandle{runner: runner}, nil
}

// provideReaperHandle creates the periodic stale-session repair worker.
func provideReaperHandle(
	cfg config.Config,
	store *state.RedisSessionStore,
	localSessions *runtimectl.LocalSessionRegistry,
	recorder observability.Recorder,
) (reaperHandle, error) {
	reaper, err := reaper(cfg, store, localSessions, recorder)
	if err != nil {
		return reaperHandle{}, err
	}

	return reaperHandle{reaper: reaper}, nil
}

// registerRedisLifecycle checks Redis readiness on start and closes it last on stop.
func registerRedisLifecycle(lifecycle fx.Lifecycle, client redis.UniversalClient, cfg config.Config) {
	lifecycle.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			return pingRedis(ctx, client, cfg.Storage.Redis)
		},
		OnStop: func(context.Context) error {
			return client.Close()
		},
	})
}

// registerControlLifecycle starts the control API before public protocol listeners.
func registerControlLifecycle(lifecycle fx.Lifecycle, handle controlHandle) {
	if handle.server == nil {
		return
	}

	lifecycle.Append(fx.Hook{
		OnStart: handle.server.Start,
		OnStop:  handle.server.Stop,
	})
}

// registerListenerLifecycle starts public protocol listeners after control readiness.
func registerListenerLifecycle(lifecycle fx.Lifecycle, manager *listener.Manager) {
	lifecycle.Append(fx.Hook{
		OnStart: manager.Start,
		OnStop:  manager.Stop,
	})
}

// registerHealthRunnerLifecycle starts the backend health loop when configured.
func registerHealthRunnerLifecycle(lifecycle fx.Lifecycle, handle healthRunnerHandle) {
	if handle.runner == nil {
		return
	}

	lifecycle.Append(fx.Hook{
		OnStart: handle.runner.Start,
		OnStop:  handle.runner.Stop,
	})
}

// registerReaperLifecycle starts the expired-session repair loop.
func registerReaperLifecycle(lifecycle fx.Lifecycle, handle reaperHandle) {
	if handle.reaper == nil {
		return
	}

	lifecycle.Append(fx.Hook{
		OnStart: handle.reaper.Start,
		OnStop:  handle.reaper.Stop,
	})
}

// backendReadService creates the runtime-effective backend inventory reader.
func backendReadService(
	cfg config.Config,
	registry backend.Registry,
	store backend.RuntimeSnapshotReader,
	recorder observability.Recorder,
) (*runtimectl.BackendReadService, error) {
	return runtimectl.NewBackendReadService(runtimectl.BackendReadServiceOptions{
		Registry:      registry,
		Snapshots:     store,
		Policy:        backend.NewEffectiveBackendPolicy(cfg.Director),
		Observability: recorder,
	})
}

// reaper creates the periodic Redis session repair worker.
func reaper(
	cfg config.Config,
	store *state.RedisSessionStore,
	localSessions *runtimectl.LocalSessionRegistry,
	recorder observability.Recorder,
) (*runtimectl.Reaper, error) {
	reaper, err := runtimectl.NewReaper(
		runtimectl.NewSessionService(store, localSessions, runtimectl.WithObservabilityRecorder(recorder)),
		runtimectl.ReaperConfig{
			Interval: defaultReapInterval,
			Limit:    defaultReapLimit,
			Reason:   "periodic session reap",
			Actor:    runtimectl.Actor{ID: cfg.Runtime.InstanceName, AuthMethod: "system", Authenticated: true},
		},
	)
	if err != nil {
		return nil, err
	}

	return reaper, nil
}

// sessionHandlerFactory dispatches configured listener protocols to protocol-owned handlers.
func sessionHandlerFactory(
	resolver routing.RoutingResolver,
	store state.SessionStore,
	selector backend.Selector,
	capabilities backendCapabilityReader,
	recorder observability.Recorder,
) listener.SessionHandlerFactory {
	return func(options listener.SessionOptions) listener.SessionHandler {
		switch strings.ToLower(strings.TrimSpace(options.Config.Protocol)) {
		case protocolIMAP:
			return imapSessionHandler(options, resolver, store, selector, recorder)
		case protocolLMTP:
			return lmtpSessionHandler(options, resolver, store, selector, capabilities)
		default:
			return unsupportedProtocolHandler{protocol: options.Config.Protocol}
		}
	}
}

type unsupportedProtocolHandler struct {
	protocol string
}

// Serve rejects streams for protocols that passed neither config validation nor dispatch.
func (h unsupportedProtocolHandler) Serve(context.Context, net.Conn) error {
	return errors.New("unsupported listener protocol " + h.protocol)
}

// imapSessionHandler builds the production IMAP pre-auth and proxy pipeline.
func imapSessionHandler(
	options listener.SessionOptions,
	resolver routing.RoutingResolver,
	store state.SessionStore,
	selector backend.Selector,
	recorder observability.Recorder,
) listener.SessionHandler {
	capabilities, mechanisms, requireID := imapListenerOptions(options.Config)

	return imap.NewHandler(imap.SessionConfig{
		ListenerName:           options.ListenerName,
		AuthorityName:          options.Config.Authority,
		AuthorityTransport:     options.AuthorityTransport,
		ServiceName:            options.Config.ServiceName,
		Network:                options.Config.Network,
		BackendPool:            options.Config.BackendPool,
		DirectorInstanceID:     options.DirectorInstanceID,
		DefaultTenant:          options.DefaultTenant,
		DefaultShard:           options.DefaultShard,
		TLSMode:                options.Config.TLS.Mode,
		Capabilities:           capabilities,
		AuthMechanisms:         mechanisms,
		MaxBearerTokenBytes:    options.BearerTokenMaxBytes,
		RequireIDBeforeAuth:    requireID,
		SessionLeaseTTL:        options.SessionLeaseTTL,
		SessionIdleGrace:       options.SessionIdleGrace,
		PreauthTimeout:         options.Timeouts.Preauth.Std(),
		AuthTimeout:            options.Timeouts.Auth.Std(),
		BackendConnectTimeout:  options.Timeouts.BackendConnect.Std(),
		ProxyIdleTimeout:       options.Timeouts.ProxyIdle.Std(),
		MaxPreauthLineBytes:    options.Security.MaxPreauthLineBytes,
		MaxPreauthLiteralBytes: options.Security.MaxPreauthLiteralBytes,
		FrontendTLSConfig:      options.FrontendTLSConfig,
		Authenticator:          options.Authenticator,
		RoutingResolver:        resolver,
		SessionStore:           store,
		BackendSelector:        selector,
		BackendConnector:       imap.NewTCPBackendConnector(nil),
		ProxyRunner:            proxy.NewPipe(),
		LocalSessions:          options.LocalSessions,
		Observability:          recorder,
	})
}

// lmtpSessionHandler builds the LMTP frontend protocol boundary.
func lmtpSessionHandler(
	options listener.SessionOptions,
	resolver routing.RoutingResolver,
	store state.SessionStore,
	selector backend.Selector,
	capabilityReader backendCapabilityReader,
) listener.SessionHandler {
	var (
		listenerCapabilities []string
		peerAuth             config.LMTPClientAuthConfig
	)

	if options.Config.LMTP != nil {
		listenerCapabilities = options.Config.LMTP.Capabilities
		peerAuth = options.Config.LMTP.ClientAuth
	}

	return lmtp.NewHandler(lmtp.SessionConfig{
		ListenerName:            options.ListenerName,
		AuthorityName:           options.Config.Authority,
		AuthorityTransport:      options.AuthorityTransport,
		ServiceName:             options.Config.ServiceName,
		Network:                 options.Config.Network,
		BackendPool:             options.Config.BackendPool,
		DirectorInstanceID:      options.DirectorInstanceID,
		DefaultTenant:           options.DefaultTenant,
		DefaultShard:            options.DefaultShard,
		TLSMode:                 options.Config.TLS.Mode,
		Capabilities:            listenerCapabilities,
		PreauthTimeout:          options.Timeouts.Preauth.Std(),
		AuthTimeout:             options.Timeouts.Auth.Std(),
		BackendConnectTimeout:   options.Timeouts.BackendConnect.Std(),
		SessionLeaseTTL:         options.SessionLeaseTTL,
		SessionIdleGrace:        options.SessionIdleGrace,
		MaxLineBytes:            options.Security.MaxPreauthLineBytes,
		MaxBearerTokenBytes:     options.BearerTokenMaxBytes,
		RequirePeerAuth:         peerAuth.Required,
		RequireTLSClientCert:    options.Config.TLS.RequireClientCert,
		PeerAuthMechanisms:      peerAuth.Mechanisms,
		FrontendTLSConfig:       options.FrontendTLSConfig,
		Authenticator:           options.Authenticator,
		IdentityLookuper:        options.IdentityLookuper,
		RoutingResolver:         resolver,
		SessionStore:            store,
		BackendSelector:         selector,
		BackendConnector:        lmtp.NewTCPBackendConnector(nil),
		BackendChunkingAllowed:  lmtpBackendChunkingAllowed(capabilityReader, options.Config.BackendPool),
		RecipientLookupRequired: true,
		MTLSPeerAuth: lmtp.MTLSPeerAuthConfig{
			SatisfiesRequired: peerAuth.MTLS.SatisfiesRequired,
			IdentitySource:    peerAuth.MTLS.IdentitySource,
		},
	})
}

// lmtpBackendChunkingAllowed checks fresh backend-pool proof before advertising BDAT.
func lmtpBackendChunkingAllowed(capabilities backendCapabilityReader, backendPool string) bool {
	if capabilities == nil {
		return false
	}

	allowed, err := capabilities.PoolSupportsCapability(context.Background(), backendPool, "CHUNKING")
	if err != nil {
		return false
	}

	return allowed
}

// imapListenerOptions extracts IMAP-specific values from a listener config.
func imapListenerOptions(listener config.ListenerConfig) ([]string, []string, bool) {
	if listener.IMAP == nil {
		return nil, nil, false
	}

	return listener.IMAP.Capabilities, listener.IMAP.AuthMechanisms, listener.IMAP.RequireIDBeforeAuth
}

// routeLookupService builds the read-only diagnostic service from production dependencies.
func routeLookupService(
	cfg config.Config,
	registry backend.Registry,
	selector backend.ExplainingSelector,
	reader *runtimectl.BackendReadService,
	store state.AffinityStore,
	recorder observability.Recorder,
) (*runtimectl.RouteLookupService, error) {
	resolver, err := routingResolver(cfg, registry)
	if err != nil {
		return nil, err
	}

	return runtimectl.NewRouteLookupService(runtimectl.RouteLookupServiceOptions{
		Resolver:         resolver,
		Selector:         selector,
		BackendRead:      reader,
		AffinityRead:     store,
		IdentityLookup:   routeLookupIdentityLookuper(cfg),
		ListenerContexts: routeLookupListenerContexts(cfg),
		DefaultPool:      defaultBackendPool(cfg),
		DefaultShard:     cfg.Director.Routing.EffectiveDefaultShard(),
		DefaultTenant:    "default",
		Observability:    recorder,
	})
}

// routeLookupIdentityLookuper returns the default authority lookup client when it is locally constructible.
func routeLookupIdentityLookuper(cfg config.Config) runtimectl.RouteLookupIdentityLookuper {
	listenerNames := make([]string, 0, len(cfg.Director.Listeners))
	for listenerName := range cfg.Director.Listeners {
		listenerNames = append(listenerNames, listenerName)
	}

	for _, listenerName := range sortedStrings(listenerNames) {
		listener := cfg.Director.Listeners[listenerName]
		if !strings.EqualFold(listener.Protocol, protocolLMTP) {
			continue
		}

		authority, ok := cfg.Auth.Authorities[listener.Authority]
		if !ok {
			continue
		}

		client, err := nauthilus.NewClient(authority, nauthilus.ClientOptions{})
		if err == nil {
			return nauthilusRouteLookupIdentity{lookuper: client}
		}
	}

	return nil
}

type nauthilusRouteLookupIdentity struct {
	lookuper nauthilus.IdentityLookuper
}

// LookupRouteIdentity adapts runtime recipient diagnostics to the Nauthilus no-auth lookup boundary.
func (l nauthilusRouteLookupIdentity) LookupRouteIdentity(
	ctx context.Context,
	request runtimectl.RouteLookupIdentityLookupRequest,
) (runtimectl.RouteLookupIdentityLookupResult, error) {
	if l.lookuper == nil {
		return runtimectl.RouteLookupIdentityLookupResult{}, errors.New("identity lookup unavailable")
	}

	result, err := l.lookuper.LookupIdentity(ctx, nauthilus.IdentityLookupRequest{
		Context: nauthilus.RequestContext{
			Username: request.Username,
			ClientIP: request.ClientIP,
			Protocol: request.Protocol,
			Method:   request.Method,
		},
	})
	if err != nil {
		return runtimectl.RouteLookupIdentityLookupResult{}, err
	}

	return runtimectl.RouteLookupIdentityLookupResult{
		Authenticated: result.Decision == nauthilus.DecisionAuthenticated,
		Account:       result.Account,
		Attributes:    result.Attributes,
	}, nil
}

// routingResolver builds the shared account-to-shard resolver chain.
func routingResolver(cfg config.Config, registry backend.Registry) (routing.RoutingResolver, error) {
	authResolver, err := routing.NewAuthAttributeResolver(routing.AuthAttributeResolverConfig{
		AccountKeyAttribute: "account",
		TenantAttribute:     "tenant",
		ShardTagAttribute:   "mailShard",
		Sticky:              true,
	})
	if err != nil {
		return nil, err
	}

	hashResolver, err := routing.NewHashResolver(routing.HashResolverConfig{
		ShardTags: shardTags(cfg, registry),
		Sticky:    true,
	})
	if err != nil {
		return nil, err
	}

	return routing.NewChainResolver(authResolver, hashResolver)
}

// shardTags returns deterministic IMAP shard names from the backend registry.
func shardTags(cfg config.Config, registry backend.Registry) []string {
	shards := make(map[string]struct{})

	if registry != nil {
		if backends, err := registry.AllBackends(context.Background()); err == nil {
			for _, entry := range backends {
				if shard := strings.TrimSpace(entry.ShardTag); shard != "" {
					shards[shard] = struct{}{}
				}
			}
		}
	}

	if len(shards) == 0 {
		shards[cfg.Director.Routing.EffectiveDefaultShard()] = struct{}{}
	}

	result := make([]string, 0, len(shards))
	for shard := range shards {
		result = append(result, shard)
	}

	return sortedStrings(result)
}

// routeLookupListenerContexts adapts listener config into route lookup defaults.
func routeLookupListenerContexts(cfg config.Config) []runtimectl.RouteLookupListenerContext {
	contexts := make([]runtimectl.RouteLookupListenerContext, 0, len(cfg.Director.Listeners))
	for name, configured := range cfg.Director.Listeners {
		contexts = append(contexts, runtimectl.RouteLookupListenerContext{
			Name:        name,
			Protocol:    configured.Protocol,
			ServiceName: configured.ServiceName,
			BackendPool: configured.BackendPool,
		})
	}

	return contexts
}

// defaultBackendPool returns the first configured IMAP backend pool.
func defaultBackendPool(cfg config.Config) string {
	for _, configured := range cfg.Director.Listeners {
		if strings.EqualFold(configured.Protocol, protocolIMAP) && strings.TrimSpace(configured.BackendPool) != "" {
			return configured.BackendPool
		}
	}

	return ""
}

// selectionPolicy maps typed config into the runtime selector policy.
func selectionPolicy(cfg config.Config) backend.SelectionPolicy {
	effective := backend.NewEffectiveBackendPolicy(cfg.Director)

	return backend.SelectionPolicy{
		SoftAllowsActivePins:       cfg.Director.Maintenance.SoftAllowsActivePins,
		DefaultShard:               cfg.Director.Routing.EffectiveDefaultShard(),
		EffectiveBackend:           effective,
		AllowHardDownFailover:      cfg.Director.Affinity.ActiveUserPinning.Failover.AllowOnHardDown,
		AllowHardMaintenanceMove:   cfg.Director.Affinity.ActiveUserPinning.Failover.AllowOnHardMaintenance,
		HealthStartupGrace:         cfg.Director.Health.Interval.Std(),
		HealthEnforcementStartedAt: time.Now().UTC(),
	}
}

// healthRunner creates the optional backend health loop for configured checks.
func healthRunner(
	cfg config.Config,
	registry backend.Registry,
	store *state.RedisSessionStore,
	recorder observability.Recorder,
) (*backend.HealthRunner, error) {
	if !hasEnabledHealthCheck(cfg) {
		return nil, nil
	}

	return backend.NewHealthRunner(
		registry,
		store,
		protocolHealthChecker{
			imap: imap.NewHealthChecker(imap.NewTCPBackendConnector(nil)),
			lmtp: lmtp.NewHealthChecker(lmtp.NewTCPBackendConnector(nil)),
		},
		backend.HealthRunnerConfig{
			InstanceID: cfg.Runtime.InstanceName,
			Interval:   cfg.Director.Health.Interval.Std(),
			Timeout:    cfg.Director.Health.Timeout.Std(),
			Jitter:     cfg.Director.Health.Jitter.Std(),
			Thresholds: backend.HealthThresholds{
				UnhealthyAfter: cfg.Director.Health.UnhealthyAfter,
				HealthyAfter:   cfg.Director.Health.HealthyAfter,
			},
			Observability: recorder,
		},
	)
}

// hasEnabledHealthCheck reports whether any backend needs background health probing.
func hasEnabledHealthCheck(cfg config.Config) bool {
	for _, configured := range cfg.Director.Backends {
		if configured.HealthCheck.Enabled {
			return true
		}
	}

	return false
}

// safeReloadService creates the config-only reload validator for the control API.
func safeReloadService(
	current config.Config,
	loader *config.Loader,
	configPath string,
	recorder observability.Recorder,
	registry *backend.StaticRegistry,
	listenerManager *listener.Manager,
) *runtimectl.SafeReloadService {
	return runtimectl.NewSafeReloadService(current, func(context.Context) (config.Config, error) {
		snapshot, err := loader.Load(config.LoadOptions{Path: configPath})
		if err != nil {
			return config.Config{}, err
		}

		return snapshot.Config, nil
	}, runtimectl.WithObservabilityRecorder(recorder), runtimectl.WithSafeReloadApplier(runtimectl.SafeReloadApplierFunc(
		func(ctx context.Context, _ config.Config, next config.Config) error {
			if registry != nil {
				if _, err := backend.NewStaticRegistry(next.Director); err != nil {
					return err
				}
			}

			if listenerManager != nil {
				if err := listenerManager.Reload(ctx, next); err != nil {
					return err
				}
			}

			if registry != nil {
				return registry.Reload(next.Director)
			}

			return nil
		},
	)))
}

// contextWithTimeout adds a shutdown deadline when none exists already.
func contextWithTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}

	if _, ok := ctx.Deadline(); ok || timeout <= 0 {
		return ctx, func() {}
	}

	return context.WithTimeout(ctx, timeout)
}

// serverHandler adapts the REST server into a standard HTTP handler.
func serverHandler(server *rest.Server) http.Handler {
	if server == nil {
		return http.NotFoundHandler()
	}

	return server
}
