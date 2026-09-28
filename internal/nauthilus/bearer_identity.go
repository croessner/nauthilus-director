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
	"strings"
	"time"

	"github.com/croessner/nauthilus-director/internal/observability"
)

// IdentityLookupMethod is the method value the director sends with every no-auth identity lookup
// that resolves an already-established account into its authority attributes.
const IdentityLookupMethod = "recipient_lookup"

const (
	bearerIdentityReasonAccountMismatch = "bearer_account_mismatch"
	bearerIdentityReasonRejected        = "bearer_identity_rejected"
	bearerIdentityReasonShardMissing    = "bearer_shard_missing"
	bearerIdentityOperation             = "bearer_identity"
)

// BearerIdentityConfig configures how introspected bearer principals are bound to authority identities.
type BearerIdentityConfig struct {
	// Lookuper resolves the token account through the authority's no-auth identity lookup.
	Lookuper IdentityLookuper
	// ShardTagAttribute names the routing attribute whose absence is reported distinctly.
	ShardTagAttribute string
	// Observation carries static listener facts; Transport names the authority transport.
	Observation ObservationConfig
}

// bearerIdentityBinder resolves every successful introspection through the authority lookup.
type bearerIdentityBinder struct {
	next              BearerIntrospector
	lookuper          IdentityLookuper
	shardTagAttribute string
	config            ObservationConfig
}

// BindBearerIdentity wraps an introspector so that a valid token only yields a principal after the
// authority confirmed the token's account and supplied its routing attributes.
//
// Introspection proves who the token belongs to; it does not carry the directory facts, such as
// the shard tag, that a password login receives from Nauthilus. The binder therefore performs one
// no-auth identity lookup for the token's account with the listener's request context and merges
// the returned attributes over the token claims. The token account stays authoritative: a lookup
// that names another account refuses the login, a lookup failure is a temporary failure, and no
// path falls back to routing on token claims alone.
func BindBearerIdentity(next BearerIntrospector, config BearerIdentityConfig) (BearerIntrospector, error) {
	if next == nil {
		return nil, configError("bearer identity binding requires an introspector")
	}

	if config.Lookuper == nil {
		return nil, configError("bearer identity binding requires an identity lookup")
	}

	return &bearerIdentityBinder{
		next:              next,
		lookuper:          config.Lookuper,
		shardTagAttribute: strings.TrimSpace(config.ShardTagAttribute),
		config:            config.Observation.normalize(),
	}, nil
}

// Introspect validates the token and binds its account to the authority identity.
func (b *bearerIdentityBinder) Introspect(ctx context.Context, request BearerIntrospectionRequest) (AuthResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	token, err := b.next.Introspect(ctx, request)
	if err != nil || token.Decision != DecisionAuthenticated {
		return token, err
	}

	request = request.normalized()

	account := strings.TrimSpace(token.Account)
	if account == "" {
		return resultWithDecision(DecisionTemporaryFailure, "", "", "", nil),
			malformedResponseError(operationLookupIdentity, "bearer account unavailable", nil)
	}

	lookupRequest := IdentityLookupRequest{Context: b.lookupContext(request, account)}

	started := time.Now()
	identity, err := b.lookuper.LookupIdentity(ctx, lookupRequest)
	duration := time.Since(started)

	result, reasonClass, err := b.bind(token, account, identity, err)
	b.record(ctx, lookupRequest, result, reasonClass, err, duration)

	return result, err
}

// lookupContext reuses the frontend request context so the lookup carries client, TLS and protocol facts.
func (b *bearerIdentityBinder) lookupContext(request BearerIntrospectionRequest, account string) RequestContext {
	lookupContext := request.Context
	lookupContext.Username = account
	lookupContext.Method = IdentityLookupMethod

	if strings.TrimSpace(lookupContext.Protocol) == "" {
		lookupContext.Protocol = request.Protocol
	}

	return lookupContext
}

// bind maps one lookup outcome into the principal used for routing and a bounded reason class.
func (b *bearerIdentityBinder) bind(
	token AuthResult,
	account string,
	identity AuthResult,
	lookupErr error,
) (AuthResult, string, error) {
	if lookupErr != nil {
		return resultWithDecision(DecisionTemporaryFailure, "", "", "", nil), authObservationReasonClass(lookupErr), lookupErr
	}

	switch identity.Decision {
	case DecisionAuthenticated:
	case DecisionRejected:
		return resultWithDecision(DecisionRejected, "", "", "", nil), bearerIdentityReasonRejected, nil
	default:
		return resultWithDecision(DecisionTemporaryFailure, "", "", "", nil), authObservationReasonTemporary,
			tempfailError(operationLookupIdentity, 0, "bearer identity lookup unavailable")
	}

	lookupAccount := strings.TrimSpace(identity.Account)
	if lookupAccount == "" {
		return resultWithDecision(DecisionTemporaryFailure, "", "", "", nil), string(ErrorKindMalformedResponse),
			malformedResponseError(operationLookupIdentity, "bearer identity lookup returned no account", nil)
	}

	if !strings.EqualFold(lookupAccount, account) {
		return resultWithDecision(DecisionRejected, "", "", "", nil), bearerIdentityReasonAccountMismatch, nil
	}

	bound := resultWithDecision(
		DecisionAuthenticated,
		token.Account,
		token.SessionID,
		"",
		mergeBearerIdentityAttributes(token.Attributes, identity.Attributes),
	)

	if !b.shardTagPresent(bound.Attributes) {
		return bound, bearerIdentityReasonShardMissing, nil
	}

	return bound, authObservationResultOK, nil
}

// shardTagPresent reports whether the bound principal carries a non-empty shard routing attribute.
func (b *bearerIdentityBinder) shardTagPresent(attributes map[string][]string) bool {
	if b.shardTagAttribute == "" {
		return true
	}

	for _, value := range attributes[b.shardTagAttribute] {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}

	return false
}

// mergeBearerIdentityAttributes overlays authority attributes on token claims; the directory wins
// for every attribute it returns, token-only claims are kept.
func mergeBearerIdentityAttributes(token map[string][]string, identity map[string][]string) map[string][]string {
	merged := make(map[string][]string, len(token)+len(identity))
	for name, values := range token {
		merged[name] = append([]string(nil), values...)
	}

	for name, values := range identity {
		merged[name] = append([]string(nil), values...)
	}

	if len(merged) == 0 {
		return nil
	}

	return merged
}

// record emits one secret-free observation for the bearer identity lookup.
func (b *bearerIdentityBinder) record(
	ctx context.Context,
	request IdentityLookupRequest,
	result AuthResult,
	reasonClass string,
	err error,
	duration time.Duration,
) {
	observationResult, _ := authObservationOutcome(result, err)
	protocol := request.Context.Protocol

	fields := observationFieldsFromSafe(b.config, request.LogFields(), IdentityLookupMethod, protocol, observationResult, reasonClass)
	fields[authObservationFieldOperation] = bearerIdentityOperation

	if authErr := authError(err); authErr != nil {
		fields[authObservationFieldErrorKind] = string(authErr.Kind)
	}

	labels := observationLabelsFromValues(b.config, IdentityLookupMethod, protocol, observationResult, reasonClass)

	event, eventErr := observability.NewEvent(observability.EventNauthilusAuth, observability.TraceBoundaryNauthilusAuth, fields, labels)
	if eventErr != nil {
		return
	}

	event.Measurements = observability.NewMetricMeasurements(map[string]float64{
		observability.MetricMeasurementDurationSeconds: duration.Seconds(),
	})
	b.config.Recorder.Record(ctx, event)
}
