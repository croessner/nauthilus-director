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
	"net/http"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/backend"
	"github.com/croessner/nauthilus-director/internal/config"
	"github.com/croessner/nauthilus-director/internal/listener"
	"github.com/croessner/nauthilus-director/internal/observability"
	"github.com/croessner/nauthilus-director/internal/protocol/imap"
	"github.com/croessner/nauthilus-director/internal/proxy"
	"github.com/croessner/nauthilus-director/internal/rest"
	"github.com/croessner/nauthilus-director/internal/rest/adapters"
	"github.com/croessner/nauthilus-director/internal/routing"
	runtimectl "github.com/croessner/nauthilus-director/internal/runtime"
	"github.com/croessner/nauthilus-director/internal/state"
	"github.com/redis/go-redis/v9"
)

const (
	defaultReapInterval = 5 * time.Second
	defaultReapLimit    = 100
)

// Options configures one production server process instance.
type Options struct {
	ConfigPath string
	Version    string
	Loader     *config.Loader
	Recorder   observability.Recorder
}

// Server owns the production process lifecycle assembled from typed config.
type Server struct {
	configPath     string
	version        string
	loader         *config.Loader
	snapshot       *config.Snapshot
	recorder       observability.Recorder
	redisClient    redis.UniversalClient
	listeners      *listener.Manager
	control        *controlServer
	healthRunner   *backend.HealthRunner
	reaper         *runtimectl.Reaper
	shutdownPeriod time.Duration
}

type runtimeCore struct {
	redisClient   redis.UniversalClient
	store         *state.RedisSessionStore
	registry      *backend.StaticRegistry
	selector      *backend.RuntimeSelector
	localSessions *runtimectl.LocalSessionRegistry
	listeners     *listener.Manager
	backendReader *runtimectl.BackendReadService
	routeLookup   *runtimectl.RouteLookupService
}

// NewServer loads configuration and assembles runtime dependencies for one process.
func NewServer(options Options) (*Server, error) {
	loader := options.Loader
	if loader == nil {
		loader = config.NewLoader()
	}

	snapshot, err := loader.Load(config.LoadOptions{Path: options.ConfigPath})
	if err != nil {
		return nil, err
	}

	recorder := observability.NormalizeRecorder(options.Recorder)

	assembled, err := assembleRuntime(snapshot, options.ConfigPath, options.Version, loader, recorder)
	if err != nil {
		return nil, err
	}

	return assembled, nil
}

// Run starts the production server and blocks until the context is cancelled.
func Run(ctx context.Context, options Options) error {
	server, err := NewServer(options)
	if err != nil {
		return err
	}

	if err := server.Start(ctx); err != nil {
		return err
	}

	<-ctx.Done()

	stopErr := server.Stop(context.Background())
	if errors.Is(ctx.Err(), context.Canceled) {
		return stopErr
	}

	return errors.Join(ctx.Err(), stopErr)
}

// Start binds public listeners and starts runtime background workers.
func (s *Server) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := pingRedis(ctx, s.redisClient, s.snapshot.Config.Storage.Redis); err != nil {
		return err
	}

	var started []func(context.Context) error

	if s.control != nil {
		if err := s.control.Start(ctx); err != nil {
			return err
		}

		started = append(started, s.control.Stop)
	}

	if err := s.listeners.Start(ctx); err != nil {
		return rollbackStarted(started, err)
	}

	started = append(started, s.listeners.Stop)

	if s.healthRunner != nil {
		if err := s.healthRunner.Start(ctx); err != nil {
			return rollbackStarted(started, err)
		}

		started = append(started, s.healthRunner.Stop)
	}

	if s.reaper != nil {
		if err := s.reaper.Start(ctx); err != nil {
			return rollbackStarted(started, err)
		}
	}

	return nil
}

// Stop drains process listeners, workers and Redis connections.
func (s *Server) Stop(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	stopCtx, cancel := contextWithTimeout(ctx, s.shutdownPeriod)
	defer cancel()

	err := errors.Join(
		stopIfPresent(stopCtx, s.reaper),
		stopIfPresent(stopCtx, s.healthRunner),
		stopIfPresent(stopCtx, s.listeners),
		stopControlIfPresent(stopCtx, s.control),
	)

	if s.redisClient != nil {
		err = errors.Join(err, s.redisClient.Close())
	}

	return err
}

// assembleRuntime creates the shared routing, Redis, control and listener objects.
func assembleRuntime(
	snapshot *config.Snapshot,
	configPath string,
	version string,
	loader *config.Loader,
	recorder observability.Recorder,
) (*Server, error) {
	cfg := snapshot.Config

	core, err := assembleRuntimeCore(cfg, recorder)
	if err != nil {
		return nil, err
	}

	control, err := controlServerForConfig(cfg, snapshot, configPath, version, loader, recorder, core)
	if err != nil {
		_ = core.redisClient.Close()

		return nil, err
	}

	healthRunner, err := healthRunner(cfg, core.registry, core.store, recorder)
	if err != nil {
		_ = core.redisClient.Close()

		return nil, err
	}

	reaper, err := reaper(cfg, core.store, core.localSessions, recorder)
	if err != nil {
		_ = core.redisClient.Close()

		return nil, err
	}

	return &Server{
		configPath:     configPath,
		version:        version,
		loader:         loader,
		snapshot:       snapshot,
		recorder:       recorder,
		redisClient:    core.redisClient,
		listeners:      core.listeners,
		control:        control,
		healthRunner:   healthRunner,
		reaper:         reaper,
		shutdownPeriod: cfg.Runtime.Process.ShutdownTimeout.Std(),
	}, nil
}

// assembleRuntimeCore creates Redis, routing, backend and listener dependencies.
func assembleRuntimeCore(cfg config.Config, recorder observability.Recorder) (runtimeCore, error) {
	redisClient, err := newRedisClient(cfg.Storage.Redis)
	if err != nil {
		return runtimeCore{}, err
	}

	store, err := newRedisStore(redisClient, cfg.Storage.Redis)
	if err != nil {
		_ = redisClient.Close()

		return runtimeCore{}, err
	}

	core, err := assembleDirectorCore(cfg, store, recorder)
	if err != nil {
		_ = redisClient.Close()

		return runtimeCore{}, err
	}

	core.redisClient = redisClient
	core.store = store

	return core, nil
}

// assembleDirectorCore creates config-backed director runtime services.
func assembleDirectorCore(
	cfg config.Config,
	store *state.RedisSessionStore,
	recorder observability.Recorder,
) (runtimeCore, error) {
	registry, err := backend.NewStaticRegistry(cfg.Director)
	if err != nil {
		return runtimeCore{}, err
	}

	selector, err := backend.NewRuntimeSelector(registry, store, selectionPolicy(cfg))
	if err != nil {
		return runtimeCore{}, err
	}

	resolver, err := routingResolver(cfg, registry)
	if err != nil {
		return runtimeCore{}, err
	}

	localSessions := runtimectl.NewLocalSessionRegistry()

	manager, err := listener.NewManagerWithConfig(
		cfg,
		listener.WithLocalSessionRegistry(localSessions),
		listener.WithObservabilityRecorder(recorder),
		listener.WithSessionHandlerFactory(sessionHandlerFactory(resolver, store, selector, recorder)),
	)
	if err != nil {
		return runtimeCore{}, err
	}

	backendReader, err := backendReadService(cfg, registry, store, recorder)
	if err != nil {
		return runtimeCore{}, err
	}

	routeLookup, err := routeLookupService(cfg, registry, selector, backendReader, store, recorder)
	if err != nil {
		return runtimeCore{}, err
	}

	return runtimeCore{
		registry:      registry,
		selector:      selector,
		localSessions: localSessions,
		listeners:     manager,
		backendReader: backendReader,
		routeLookup:   routeLookup,
	}, nil
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

// controlServerForConfig creates the optional in-process REST control listener.
func controlServerForConfig(
	cfg config.Config,
	snapshot *config.Snapshot,
	configPath string,
	version string,
	loader *config.Loader,
	recorder observability.Recorder,
	core runtimeCore,
) (*controlServer, error) {
	if !cfg.Runtime.Servers.Control.Enabled {
		return nil, nil
	}

	return newControlServer(cfg, rest.NewServer(rest.Options{
		Version:    version,
		ConfigPath: configPath,
		HandlerOptions: adapters.HandlerOptions{
			Version:        version,
			ConfigPath:     configPath,
			Loader:         loader,
			Snapshot:       snapshot,
			BackendReader:  core.backendReader,
			BackendMutator: runtimectl.NewBackendService(core.store, core.localSessions, runtimectl.WithObservabilityRecorder(recorder)),
			SessionMutator: runtimectl.NewSessionService(core.store, core.localSessions, runtimectl.WithObservabilityRecorder(recorder)),
			UserMutator:    runtimectl.NewUserService(core.store, core.localSessions, runtimectl.WithObservabilityRecorder(recorder)),
			RouteLookup:    core.routeLookup,
			Reload:         safeReloadService(cfg, loader, configPath, recorder),
			Observability:  recorder,
		},
	}))
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

// sessionHandlerFactory injects runtime routing state into listener-owned IMAP sessions.
func sessionHandlerFactory(
	resolver routing.RoutingResolver,
	store state.SessionStore,
	selector backend.Selector,
	recorder observability.Recorder,
) listener.SessionHandlerFactory {
	return func(options listener.SessionOptions) listener.SessionHandler {
		capabilities, mechanisms, requireID := imapListenerOptions(options.Config)

		return imap.NewHandler(imap.SessionConfig{
			ListenerName:           options.ListenerName,
			AuthorityName:          options.Config.Authority,
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
		ListenerContexts: routeLookupListenerContexts(cfg),
		DefaultPool:      defaultBackendPool(cfg),
		DefaultShard:     cfg.Director.Routing.EffectiveDefaultShard(),
		DefaultTenant:    "default",
		Observability:    recorder,
	})
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
				if entry.Protocol != "imap" {
					continue
				}

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
		if strings.EqualFold(configured.Protocol, "imap") && strings.TrimSpace(configured.BackendPool) != "" {
			return configured.BackendPool
		}
	}

	return ""
}

// selectionPolicy maps typed config into the runtime selector policy.
func selectionPolicy(cfg config.Config) backend.SelectionPolicy {
	effective := backend.NewEffectiveBackendPolicy(cfg.Director)

	return backend.SelectionPolicy{
		SoftAllowsActivePins:     cfg.Director.Maintenance.SoftAllowsActivePins,
		DefaultShard:             cfg.Director.Routing.EffectiveDefaultShard(),
		EffectiveBackend:         effective,
		AllowHardDownFailover:    cfg.Director.Affinity.ActiveUserPinning.Failover.AllowOnHardDown,
		AllowHardMaintenanceMove: cfg.Director.Affinity.ActiveUserPinning.Failover.AllowOnHardMaintenance,
		HealthStartupGrace:       cfg.Director.Health.Interval.Std(),
		HealthEnforcementStartedAt: time.Now().
			UTC(),
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
		imap.NewHealthChecker(imap.NewTCPBackendConnector(nil)),
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
) *runtimectl.SafeReloadService {
	return runtimectl.NewSafeReloadService(current, func(context.Context) (config.Config, error) {
		snapshot, err := loader.Load(config.LoadOptions{Path: configPath})
		if err != nil {
			return config.Config{}, err
		}

		return snapshot.Config, nil
	}, runtimectl.WithObservabilityRecorder(recorder))
}

// rollbackStarted stops already-started components after a later startup failure.
func rollbackStarted(stops []func(context.Context) error, cause error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var stopErrs []error
	for index := len(stops) - 1; index >= 0; index-- {
		stopErrs = append(stopErrs, stops[index](ctx))
	}

	return errors.Join(cause, errors.Join(stopErrs...))
}

// stopIfPresent stops a lifecycle component when it exists.
func stopIfPresent(ctx context.Context, target interface{ Stop(context.Context) error }) error {
	if target == nil {
		return nil
	}

	return target.Stop(ctx)
}

// stopControlIfPresent stops the control server when it exists.
func stopControlIfPresent(ctx context.Context, target *controlServer) error {
	if target == nil {
		return nil
	}

	return target.Stop(ctx)
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
