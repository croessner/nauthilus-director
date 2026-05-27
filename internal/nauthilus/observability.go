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

package nauthilus

import (
	"context"
	"errors"
	"maps"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/observability"
)

const (
	authObservationFieldAuthority   = "authority"
	authObservationFieldBackendPool = "backend_pool"
	authObservationFieldErrorKind   = "error_kind"
	authObservationFieldListener    = "listener"
	authObservationFieldMechanism   = "mechanism"
	authObservationFieldOperation   = "operation"
	authObservationFieldProtocol    = "protocol"
	authObservationFieldReasonClass = "reason_class"
	authObservationFieldResult      = "result"
	authObservationFieldService     = "service"
	authObservationFieldStatusCode  = "status_code"
	authObservationFieldTransport   = "transport"
	authObservationResultFailure    = "failure"
	authObservationResultOK         = "ok"
	authObservationResultRejected   = "rejected"
	authObservationReasonAmbiguous  = "ambiguous_state"
	authObservationReasonDenied     = "denied"
	authObservationReasonTemporary  = "temporary_failure"
	authObservationReasonTimeout    = "timeout"
	authObservationTransportUnknown = "unknown"
)

// ObservationConfig carries static listener authority facts for auth observations.
type ObservationConfig struct {
	AuthorityName string
	BackendPool   string
	ListenerName  string
	Recorder      observability.Recorder
	ServiceName   string
	Transport     string
}

// ObserveAuthenticator wraps an authority client with secret-safe telemetry.
func ObserveAuthenticator(next Authenticator, config ObservationConfig) Authenticator {
	if next == nil {
		return nil
	}

	return &observedAuthenticator{
		next:   next,
		config: config.normalize(),
	}
}

type observedAuthenticator struct {
	next   Authenticator
	config ObservationConfig
}

// Authenticate records one bounded authority-call observation around the next client.
func (a *observedAuthenticator) Authenticate(ctx context.Context, request AuthRequest) (AuthResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	recorder := observability.NormalizeRecorder(a.config.Recorder)
	startFields := a.observationFields(request, authObservationResultOK, "")
	ctx, span := observability.StartSpan(ctx, recorder, observability.TraceBoundaryNauthilusAuth, startFields)

	started := time.Now()
	result, err := a.next.Authenticate(ctx, request)
	duration := time.Since(started)

	observationResult, reasonClass := authObservationOutcome(result, err)
	fields := a.observationFields(request, observationResult, reasonClass)
	labels := a.observationLabels(request, observationResult, reasonClass)

	if authErr := authError(err); authErr != nil {
		fields[authObservationFieldErrorKind] = string(authErr.Kind)
		if authErr.StatusCode > 0 {
			fields[authObservationFieldStatusCode] = strconv.Itoa(authErr.StatusCode)
		}
	}

	event, eventErr := observability.NewEvent(observability.EventNauthilusAuth, observability.TraceBoundaryNauthilusAuth, fields, labels)
	if eventErr == nil {
		event.Measurements = observability.NewMetricMeasurements(map[string]float64{
			observability.MetricMeasurementDurationSeconds: duration.Seconds(),
		})
		recorder.Record(ctx, event)
	}

	span.SetAttributes(fields)
	span.End(observationResult, reasonClass)

	return result, err
}

// normalize trims static auth observation labels and applies safe fallbacks.
func (c ObservationConfig) normalize() ObservationConfig {
	c.AuthorityName = strings.TrimSpace(c.AuthorityName)
	c.BackendPool = strings.TrimSpace(c.BackendPool)
	c.ListenerName = strings.TrimSpace(c.ListenerName)
	c.ServiceName = strings.TrimSpace(c.ServiceName)

	c.Transport = strings.ToLower(strings.TrimSpace(c.Transport))
	if c.Transport == "" {
		c.Transport = authObservationTransportUnknown
	}

	c.Recorder = observability.NormalizeRecorder(c.Recorder)

	return c
}

// observationFields returns log and trace attributes without credential material.
func (a *observedAuthenticator) observationFields(request AuthRequest, result string, reasonClass string) map[string]string {
	fields := map[string]string{}
	maps.Copy(fields, request.LogFields())

	fields[authObservationFieldAuthority] = a.config.AuthorityName
	fields[authObservationFieldBackendPool] = a.config.BackendPool
	fields[authObservationFieldListener] = a.config.ListenerName
	fields[authObservationFieldMechanism] = authObservationMechanism(request)
	fields[authObservationFieldOperation] = string(operationAuthenticate)
	fields[authObservationFieldProtocol] = strings.ToLower(strings.TrimSpace(request.Context.Protocol))
	fields[authObservationFieldReasonClass] = reasonClass
	fields[authObservationFieldResult] = result
	fields[authObservationFieldService] = a.config.ServiceName
	fields[authObservationFieldTransport] = a.config.Transport

	return fields
}

// observationLabels returns the low-cardinality metric labels for one auth call.
func (a *observedAuthenticator) observationLabels(request AuthRequest, result string, reasonClass string) map[string]string {
	return map[string]string{
		authObservationFieldBackendPool: a.config.BackendPool,
		authObservationFieldListener:    a.config.ListenerName,
		authObservationFieldMechanism:   authObservationMechanism(request),
		authObservationFieldProtocol:    strings.ToLower(strings.TrimSpace(request.Context.Protocol)),
		authObservationFieldReasonClass: reasonClass,
		authObservationFieldResult:      result,
		authObservationFieldService:     a.config.ServiceName,
		authObservationFieldTransport:   a.config.Transport,
	}
}

// authObservationMechanism normalizes frontend auth mechanisms for labels.
func authObservationMechanism(request AuthRequest) string {
	return strings.ToLower(strings.TrimSpace(request.Context.Method))
}

// authObservationOutcome classifies one authority result without raw errors.
func authObservationOutcome(result AuthResult, err error) (string, string) {
	if err != nil {
		return authObservationResultFailure, authObservationReasonClass(err)
	}

	switch result.Decision {
	case DecisionAuthenticated:
		return authObservationResultOK, authObservationResultOK
	case DecisionRejected:
		return authObservationResultRejected, authObservationReasonDenied
	case DecisionTemporaryFailure:
		return authObservationResultFailure, authObservationReasonTemporary
	default:
		return authObservationResultFailure, authObservationReasonAmbiguous
	}
}

// authObservationReasonClass maps authority errors into bounded reason classes.
func authObservationReasonClass(err error) string {
	switch {
	case err == nil:
		return authObservationResultOK
	case errors.Is(err, context.DeadlineExceeded):
		return authObservationReasonTimeout
	case errors.Is(err, context.Canceled):
		return "canceled"
	}

	authErr := authError(err)
	if authErr == nil {
		return string(ErrorKindTransport)
	}

	switch authErr.Kind {
	case ErrorKindConfig:
		return string(ErrorKindConfig)
	case ErrorKindMalformedResponse:
		return string(ErrorKindMalformedResponse)
	case ErrorKindTemporaryFailure:
		return authObservationReasonTemporary
	case ErrorKindTransport:
		return string(ErrorKindTransport)
	default:
		return "other"
	}
}

// authError extracts the classified authority error when one is present.
func authError(err error) *AuthError {
	var authErr *AuthError
	if errors.As(err, &authErr) {
		return authErr
	}

	return nil
}
