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

package backend

import (
	"context"
	"strings"
	"sync"
	"time"
)

// HealthStatus describes the published backend health result.
type HealthStatus string

const (
	// HealthStatusHealthy permits placement when health enforcement is active.
	HealthStatusHealthy HealthStatus = "healthy"
	// HealthStatusStale excludes placement because the result is no longer fresh.
	HealthStatusStale HealthStatus = "stale"
	// HealthStatusUnknown excludes placement when health is required but absent.
	HealthStatusUnknown HealthStatus = "unknown"
	// HealthStatusUnhealthy excludes placement because checks failed.
	HealthStatusUnhealthy HealthStatus = "unhealthy"
)

// HealthState carries one secret-safe backend health observation.
type HealthState struct {
	Enabled     bool
	Status      HealthStatus
	ReasonClass string
	CheckedAt   time.Time
	ExpiresAt   time.Time
	Generation  string
}

// HealthOwnershipRequest describes one fenced health-owner lease request.
type HealthOwnershipRequest struct {
	InstanceID        string
	BackendIdentifier string
	LeaseTTL          time.Duration
	FencingToken      int64
}

// HealthOwnershipRecord describes the current owner lease state for a backend.
type HealthOwnershipRecord struct {
	Status            string
	InstanceID        string
	OwnerInstanceID   string
	BackendIdentifier string
	FencingToken      int64
	Owned             bool
	ServerTime        time.Time
	ExpiresAt         time.Time
}

// HealthPublishRequest describes one fenced deep-health state publication.
type HealthPublishRequest struct {
	InstanceID        string
	BackendIdentifier string
	FencingToken      int64
	State             HealthState
	TTL               time.Duration
}

// HealthCheckRequest describes a backend health check attempt.
type HealthCheckRequest struct {
	Deep    bool
	Timeout time.Duration
}

// HealthCheckResult is a secret-safe backend health check outcome.
type HealthCheckResult struct {
	Healthy     bool
	ReasonClass string
}

// HealthChecker performs protocol-specific backend health checks.
type HealthChecker interface {
	CheckBackend(ctx context.Context, target Backend, request HealthCheckRequest) HealthCheckResult
}

// HealthCoordinator owns Redis-backed health ownership and publication.
type HealthCoordinator interface {
	PublishInstanceHeartbeat(ctx context.Context, instanceID string, ttl time.Duration) error
	AcquireHealthOwner(ctx context.Context, request HealthOwnershipRequest) (HealthOwnershipRecord, error)
	RenewHealthOwner(ctx context.Context, request HealthOwnershipRequest) (HealthOwnershipRecord, error)
	PublishHealthState(ctx context.Context, request HealthPublishRequest) (HealthState, error)
}

// HealthThresholds configures consecutive success and failure transitions.
type HealthThresholds struct {
	UnhealthyAfter int
	HealthyAfter   int
}

// HealthRunnerConfig controls lifecycle-managed backend health checks.
type HealthRunnerConfig struct {
	InstanceID    string
	Interval      time.Duration
	Timeout       time.Duration
	Jitter        time.Duration
	OwnerLeaseTTL time.Duration
	StateTTL      time.Duration
	Thresholds    HealthThresholds
}

// HealthRunner owns periodic backend health checks for one director instance.
type HealthRunner struct {
	registry    Registry
	coordinator HealthCoordinator
	checker     HealthChecker
	config      HealthRunnerConfig
	mu          sync.RWMutex
	local       map[string]HealthState
	transitions map[string]*HealthTransitionTracker
	cancel      context.CancelFunc
	done        chan error
}

// HealthTransitionTracker applies consecutive success and failure thresholds.
type HealthTransitionTracker struct {
	thresholds          HealthThresholds
	status              HealthStatus
	consecutiveFailures int
	consecutiveSuccess  int
}

// Normalize validates health state and marks expired results stale.
func (s HealthState) Normalize(now time.Time) (HealthState, error) {
	status := HealthStatus(strings.ToLower(strings.TrimSpace(string(s.Status))))
	if status == "" {
		status = HealthStatusUnknown
	}

	switch status {
	case HealthStatusHealthy, HealthStatusUnhealthy, HealthStatusUnknown, HealthStatusStale:
		s.Status = status
	default:
		return HealthState{}, newBackendError(ErrorKindAmbiguous, "effective_state", "unsupported health status", nil)
	}

	if now.IsZero() {
		now = time.Now().UTC()
	}

	if s.Enabled && !s.ExpiresAt.IsZero() && now.After(s.ExpiresAt) {
		s.Status = HealthStatusStale
	}

	s.ReasonClass = strings.TrimSpace(s.ReasonClass)
	s.Generation = strings.TrimSpace(s.Generation)

	return s, nil
}

// AllowsNewPlacement reports whether health permits a new backend placement.
func (s HealthState) AllowsNewPlacement(enforce bool) bool {
	if !enforce || !s.Enabled {
		return true
	}

	return s.Status == HealthStatusHealthy
}

// NewHealthTransitionTracker creates a threshold tracker with fail-closed defaults.
func NewHealthTransitionTracker(thresholds HealthThresholds, initial HealthStatus) *HealthTransitionTracker {
	thresholds = thresholds.Normalize()

	status := HealthStatus(strings.ToLower(strings.TrimSpace(string(initial))))
	if status == "" {
		status = HealthStatusUnknown
	}

	return &HealthTransitionTracker{thresholds: thresholds, status: status}
}

// Observe records one check outcome and returns the thresholded health state.
func (t *HealthTransitionTracker) Observe(healthy bool, reasonClass string, now time.Time, ttl time.Duration) HealthState {
	if t == nil {
		t = NewHealthTransitionTracker(HealthThresholds{}, HealthStatusUnknown)
	}

	if now.IsZero() {
		now = time.Now().UTC()
	}

	if healthy {
		t.consecutiveSuccess++

		t.consecutiveFailures = 0
		if t.consecutiveSuccess >= t.thresholds.HealthyAfter {
			t.status = HealthStatusHealthy
		}
	} else {
		t.consecutiveFailures++

		t.consecutiveSuccess = 0
		if t.consecutiveFailures >= t.thresholds.UnhealthyAfter {
			t.status = HealthStatusUnhealthy
		}
	}

	return HealthState{
		Enabled:     true,
		Status:      t.status,
		ReasonClass: strings.TrimSpace(reasonClass),
		CheckedAt:   now.UTC(),
		ExpiresAt:   now.Add(ttl).UTC(),
	}
}

// Normalize fills safe one-check threshold defaults.
func (t HealthThresholds) Normalize() HealthThresholds {
	if t.UnhealthyAfter <= 0 {
		t.UnhealthyAfter = 1
	}

	if t.HealthyAfter <= 0 {
		t.HealthyAfter = 1
	}

	return t
}

// NewHealthRunner creates a lifecycle-managed health runner.
func NewHealthRunner(registry Registry, coordinator HealthCoordinator, checker HealthChecker, config HealthRunnerConfig) (*HealthRunner, error) {
	if registry == nil {
		return nil, newBackendError(ErrorKindConfig, "health_runner", "registry required", nil)
	}

	if coordinator == nil {
		return nil, newBackendError(ErrorKindConfig, "health_runner", "health coordinator required", nil)
	}

	if checker == nil {
		return nil, newBackendError(ErrorKindConfig, "health_runner", "health checker required", nil)
	}

	config = config.Normalize()
	if strings.TrimSpace(config.InstanceID) == "" {
		return nil, newBackendError(ErrorKindConfig, "health_runner", "instance id required", nil)
	}

	return &HealthRunner{
		registry:    registry,
		coordinator: coordinator,
		checker:     checker,
		config:      config,
		local:       make(map[string]HealthState),
		transitions: make(map[string]*HealthTransitionTracker),
	}, nil
}

// Normalize fills safe health-runner timing defaults.
func (c HealthRunnerConfig) Normalize() HealthRunnerConfig {
	c.InstanceID = strings.TrimSpace(c.InstanceID)
	if c.Interval <= 0 {
		c.Interval = 5 * time.Second
	}

	if c.Timeout <= 0 {
		c.Timeout = c.Interval
	}

	if c.OwnerLeaseTTL <= 0 {
		c.OwnerLeaseTTL = c.Interval + c.Timeout
	}

	if c.StateTTL <= 0 {
		c.StateTTL = c.OwnerLeaseTTL + c.Interval
	}

	c.Thresholds = c.Thresholds.Normalize()

	return c
}

// Start begins the background health loop for lifecycle wiring.
func (r *HealthRunner) Start(ctx context.Context) error {
	if r == nil {
		return newBackendError(ErrorKindConfig, "health_runner", "runner unavailable", nil)
	}

	if ctx == nil {
		ctx = context.Background()
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cancel != nil {
		return nil
	}

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	r.cancel = cancel
	r.done = done

	go func() {
		done <- r.Run(runCtx)
	}()

	return nil
}

// Stop cancels the background health loop and waits for completion.
func (r *HealthRunner) Stop(ctx context.Context) error {
	if r == nil {
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	r.mu.Lock()
	cancel := r.cancel
	done := r.done
	r.cancel = nil
	r.done = nil
	r.mu.Unlock()

	if cancel == nil || done == nil {
		return nil
	}

	cancel()

	select {
	case err := <-done:
		if err == context.Canceled {
			return nil
		}

		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Run executes health checks until the context is cancelled.
func (r *HealthRunner) Run(ctx context.Context) error {
	if r == nil {
		return newBackendError(ErrorKindConfig, "health_runner", "runner unavailable", nil)
	}

	for {
		if err := r.RunOnce(ctx); err != nil {
			return err
		}

		timer := time.NewTimer(r.nextDelay())
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// RunOnce performs one bounded health pass over configured IMAP backends.
func (r *HealthRunner) RunOnce(ctx context.Context) error {
	if r == nil {
		return newBackendError(ErrorKindConfig, "health_runner", "runner unavailable", nil)
	}

	if err := r.coordinator.PublishInstanceHeartbeat(ctx, r.config.InstanceID, r.config.OwnerLeaseTTL); err != nil {
		return err
	}

	backends, err := r.registry.AllBackends(ctx)
	if err != nil {
		return err
	}

	for _, candidate := range backends {
		if err := r.checkBackend(ctx, candidate); err != nil {
			return err
		}
	}

	return nil
}

// LocalState returns the latest local light or owned deep health observation.
func (r *HealthRunner) LocalState(identifier string) (HealthState, bool) {
	if r == nil {
		return HealthState{}, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	state, ok := r.local[strings.TrimSpace(identifier)]

	return state, ok
}

// checkBackend evaluates local light checks and owned deep checks for one backend.
func (r *HealthRunner) checkBackend(ctx context.Context, candidate Backend) error {
	if !candidate.Health.Enabled || candidate.Protocol != protocolIMAP {
		return nil
	}

	if !candidate.Health.DeepCheck {
		result := r.checker.CheckBackend(ctx, candidate, HealthCheckRequest{Timeout: r.config.Timeout})
		r.storeLocal(candidate.Identifier, result)

		return nil
	}

	owner, err := r.coordinator.AcquireHealthOwner(ctx, HealthOwnershipRequest{
		InstanceID:        r.config.InstanceID,
		BackendIdentifier: candidate.Identifier,
		LeaseTTL:          r.config.OwnerLeaseTTL,
	})
	if err != nil {
		return err
	}

	if !owner.Owned {
		return nil
	}

	result := r.checker.CheckBackend(ctx, candidate, HealthCheckRequest{Deep: true, Timeout: r.config.Timeout})
	state := r.storeLocal(candidate.Identifier, result)

	_, err = r.coordinator.PublishHealthState(ctx, HealthPublishRequest{
		InstanceID:        r.config.InstanceID,
		BackendIdentifier: candidate.Identifier,
		FencingToken:      owner.FencingToken,
		State:             state,
		TTL:               r.config.StateTTL,
	})

	return err
}

// storeLocal thresholds and stores one local health observation.
func (r *HealthRunner) storeLocal(identifier string, result HealthCheckResult) HealthState {
	now := time.Now().UTC()

	r.mu.Lock()
	defer r.mu.Unlock()

	tracker := r.transitions[identifier]
	if tracker == nil {
		tracker = NewHealthTransitionTracker(r.config.Thresholds, HealthStatusUnknown)
		r.transitions[identifier] = tracker
	}

	state := tracker.Observe(result.Healthy, result.ReasonClass, now, r.config.StateTTL)
	r.local[identifier] = state

	return state
}

// nextDelay returns a bounded interval with deterministic per-process jitter.
func (r *HealthRunner) nextDelay() time.Duration {
	delay := r.config.Interval
	if r.config.Jitter <= 0 {
		return delay
	}

	offset := time.Duration(time.Now().UnixNano() % int64(r.config.Jitter))

	return delay + offset
}
