# M8 Runtime Session Holder Control Follow-up

Status: completed.

This follow-up tightens the operational semantics around active session
holders, user kicks, session kills, route-lookup diagnostics and control API
transport diagnostics. It is motivated by a real mailbox migration drill where
an operator backend pin was correctly applied across IMAP, ManageSieve and
LMTP, but one active IMAP holder remained visible after a user kick and a
targeted session kill returned `ambiguous_state`.

The observed holder does not prove that route lookup creates sessions. The
current source code defines route lookup as a side-effect-free diagnostic, wires
it through read-only Redis interfaces, and has focused tests that fail if route
lookup opens, heartbeats, closes, kicks, kills, moves, pins, clears or reserves
runtime state. Active holders are still allowed to appear in route-lookup
output when they already exist.

The operational gap is narrower: when the runtime read surface lists a holder,
the control surface must either mark that holder for controlled shutdown or
return a deterministic, bounded explanation that the holder is already gone,
stale, or corrupt. Operators must not have to infer whether `ambiguous_state`
means a real active stream, a stale secondary index, an expired session hash, or
a malformed authoritative record.

A second operator-facing gap surfaced during the same investigation: running
`nauthilus-directorctl` inside the production pod without transport flags uses
the compiled default `http://127.0.0.1:9090`, while the live control listener is
HTTPS. Runtime list commands then failed with `HTTP 400: Bad Request`; server
logs showed `client sent an HTTP request to an HTTPS server`. Retrying with an
`https://` address changed the result to the expected authentication failure,
which proves the list routes themselves were not the immediate source of that
400 response. The CLI and docs must make this transport mismatch obvious.

The follow-up must preserve the existing architecture boundaries:

- Nauthilus remains the authentication and identity authority only.
- `nauthilus-director` owns routing, affinity, backend selection, runtime state
  and proxy lifecycle decisions.
- Redis remains the production source of truth for active affinity and session
  coordination.
- Runtime control mutates Redis-backed runtime state only.
- Route lookup remains director-only and side-effect-free.

## Source Documents

This follow-up is governed by:

- `AGENTS.md`
- `POLICY.md`
- `docs/ARCHITECTURE_ROADMAP.md`
- `docs/specs/implementation/M0_FOUNDATION_SPEC.md`
- `docs/specs/implementation/M2_M3_BACKEND_RUNTIME_CONTROL_SPEC.md`
- `docs/specs/implementation/M2_M3_RUNTIME_STATE_MILLION_SCALE_CHANGE_SPEC.md`
- `docs/specs/implementation/M3_ROUTE_LOOKUP_FOLLOWUP.md`
- `docs/specs/implementation/M3_USER_PLACEMENT_HOLD_FOLLOWUP.md`
- `docs/specs/implementation/M5_CROSS_PROTOCOL_BACKEND_AFFINITY_FOLLOWUP.md`
- `docs/specs/implementation/M8_MULTI_PROTOCOL_BACKEND_PINNING_FOLLOWUP.md`
- `docs/developer/AFFINITY_SESSION_HANDLING.md`
- `docs/operations/security.md`
- `docs/specs/openapi/nauthilus-director.yaml`
- `docs/man/nauthilus-directorctl.1`
- `Makefile`

If this document conflicts with those source documents, fix the drift before
implementation continues.

## Confirmed Current Behavior

Route lookup:

- uses `runtime.RouteLookupService`;
- reads affinity with `LookupAffinity`;
- reads backend pins with `ListUserBackendPins`;
- reads placement holds with `CheckUserHold`;
- uses only director-owned runtime state for LMTP recipient diagnostics when
  the caller supplies a recipient instead of an account key;
- explains backend selection without calling placement `OpenSession`,
  `HeartbeatSession`, `CloseSession`, `KickUser`, `KillSession`,
  `ClearUserAffinity`, backend reservation or backend mutation paths.

User kick:

- calls `RedisSessionStore.KickUser`;
- increments the per-affinity control generation;
- marks active sessions for controlled shutdown;
- closes streams only in the local process when the current process owns their
  local session handles;
- otherwise relies on proxy heartbeats or lease expiry for remote holders.

Session kill:

- calls `RedisSessionStore.KillSession`;
- resolves the session hash through the repairable session locator index;
- marks the single session hash with a session-scoped control action;
- closes a local stream only when the current process owns that session handle;
- otherwise relies on the target stream heartbeat or lease expiry.

Affinity clear:

- correctly fails closed while active holders exist unless an explicit
  active-clear path is intentionally used by code.

Control transport:

- `nauthilus-directorctl` defaults to `http://127.0.0.1:9090`;
- the production control listener may be HTTPS and authenticated;
- an HTTP request to that HTTPS listener returns a generic HTTP `400`;
- using `https://127.0.0.1:9090` with appropriate TLS flags reaches the control
  authenticator and returns the expected `401` when no credentials are supplied.

These semantics are generally correct, but the operator-facing behavior is
still too ambiguous for migration runbooks.

## Observed Gap

During a controlled migration drill, an all-scope backend pin selected the
target backend node for IMAP, ManageSieve and LMTP while target backends had
runtime weight `0`. Route lookup correctly reported `operator_backend_pin`
while the user hold was active.

After the hold was cleared, the account had a visible active IMAP holder.
`users kick` accepted the request, but the holder remained visible. A follow-up
`sessions kill <session-id>` returned `ambiguous_state`. From an operator point
of view, that result is not actionable enough:

- The session might be genuinely active on a different Director replica and
  still waiting for heartbeat-controlled closure.
- The session might already have ended, leaving a stale repairable index entry.
- The session locator might point to a missing or expired session hash.
- The authoritative session hash might be present but malformed.
- The control command might have reached a replica that does not own the local
  stream handle.

The current code intentionally treats malformed authoritative state as
ambiguous and fail-closed. That must stay. The missing piece is deterministic
separation between corrupt authoritative state and stale repairable indexes or
normal remote-holder delay.

The live control-list investigation added a separate transport problem. These
commands, run inside the Director pod without TLS/auth flags, failed before
useful runtime evidence could be gathered:

```text
nauthilus-directorctl sessions list --all --output json
nauthilus-directorctl users list --output json
nauthilus-directorctl users sessions de10037@srvint.net
```

The operator saw only `HTTP 400: Bad Request`. The server-side log identified
the real cause as an HTTP client talking to an HTTPS listener. Retrying a list
command with `--address https://127.0.0.1:9090 --tls-insecure-skip-verify`
reached authentication and returned `HTTP 401: authentication required`, which
is an expected control-plane response without credentials.

## Expected Behavior

Route lookup must remain read-only:

- repeated route lookups for the same account must not change active session or
  holder counts;
- route lookup may show `active_affinity` only when Redis state already has
  active holders or retained binding;
- route lookup must never be used as a cleanup mechanism.

User kick must be explicit about its lifecycle:

- a successful kick marks all currently active sessions for the affinity key;
- locally owned streams close promptly;
- remotely owned streams close on heartbeat or expire by lease;
- CLI and REST output must make this cooperative lifecycle clear enough for
  runbooks.

Session kill must be deterministic:

- killing a session that was just returned by `sessions list` or
  `users sessions` must either mark that session or return a bounded
  non-ambiguous missing/stale result after repairing stale secondary indexes;
- stale repairable indexes may be removed as a repair action;
- corrupt authoritative session hashes must still fail closed as
  `ambiguous_state`;
- the REST status and CLI output must distinguish `marked`, `missing`,
  `stale_index_repaired` and `ambiguous_state`.

Affinity clear must stay conservative:

- active holders block normal clear;
- runbooks should use hold, kick/kill, wait/reap, then clear;
- active clear remains an explicit exceptional operation, not a default
  migration path.

Control CLI diagnostics must make transport failures actionable:

- list/read commands must not hide an HTTP-to-HTTPS mismatch behind a generic
  `HTTP 400: Bad Request`;
- non-JSON control responses must still produce a bounded, operator-useful
  diagnostic;
- docs and examples must show HTTPS, TLS and auth flags when the listener is
  configured that way;
- local pod usage must have a documented way to inherit or pass the correct
  control address and auth material without printing secret values.

## Goal

Make holder cleanup and diagnostics migration-safe:

```text
route lookup       -> explain only, never mutate
users kick         -> mark all active sessions, close local streams, report lifecycle
sessions kill      -> mark one active session or explain missing/stale/corrupt
sessions list      -> avoid returning stale sessions after bounded repair
control CLI reads  -> fail clearly on TLS/auth/address mismatches
users affinity clear -> succeed only after holders are inactive
```

The implementation is complete when an operator can answer these questions from
REST/CLI evidence without inspecting Redis manually:

- Did route lookup create a holder? The answer must remain no.
- Is a holder still active, retained, stale, or already gone?
- Was a kick delivered as a runtime mark?
- Was a session kill delivered to the target session, or was the target stale?
- Did a control read fail because of runtime state, auth, or transport setup?
- Is it safe to clear affinity or continue with the next migration step?

## Scope

In scope:

- Add failing reproducers for repeated route lookup not changing holder counts
  in the production Redis-backed service wiring.
- Add failing reproducers for killing a visible session whose repairable index
  is stale or whose session hash has expired.
- Keep corrupt authoritative session data fail-closed.
- Repair stale session locator and user/backend membership indexes where the
  code can prove the authoritative session hash is gone.
- Return bounded domain states for session kill results:
  `marked`, `missing`, `stale_index_repaired`, and `ambiguous_state`.
- Map missing/stale session control results to deterministic REST responses and
  CLI text/JSON output.
- Preserve local-session acceleration for streams owned by the current process.
- Document cooperative kick/kill behavior in the manpage and affinity session
  handling developer guide.
- Detect or clearly explain HTTP-to-HTTPS control API mismatches in
  `nauthilus-directorctl`.
- Add tests for `sessions list`, `users list` and user-scoped runtime reads
  against HTTPS/authenticated control listeners.
- Document production-safe `nauthilus-directorctl` transport and authentication
  invocation, including local pod execution.
- Add public-boundary E2E coverage for kick/kill observability where practical.

Out of scope:

- Making route lookup mutate Redis or open backend sockets.
- Adding cross-replica imperative stream-kill RPC.
- Deleting authoritative active session hashes without a protocol close,
  heartbeat observation, expiry, or explicit tested repair rule.
- Weakening fail-closed behavior for malformed authoritative state.
- Rewriting YAML configuration from runtime control commands.
- Adding raw usernames, recipients, session IDs or backend identifiers as metric
  labels.
- Changing backend-pin placement semantics.
- Embedding bearer tokens, private keys or generated dummy secrets into CLI
  defaults or examples.

## Implementation Slices

Implement this follow-up as seven focused slices.

1. Reproducer and evidence boundary

   Add tests that prove repeated route lookup through the production service
   wiring does not change Redis active holder counts, session indexes, backend
   reservations or control generations.

   Add a state-level reproducer where a session appears in a repairable
   secondary index but the authoritative session hash is gone. The read path
   must repair the stale index and avoid returning the session; the kill path
   must not collapse this case into the same error class as corrupt
   authoritative state.

2. Runtime state classification

   Extend `RedisSessionStore.KillSession` and the underlying Lua/script
   boundary so it can return a bounded missing/stale result when the session
   locator or hash is absent. Removing a stale repairable locator is allowed.

   Keep malformed authoritative hash fields, invalid control generations and
   cross-key contradictions as `ambiguous_state`.

3. Domain and REST mapping

   Extend `runtime.SessionMutationResult` so the domain layer can carry the
   kill outcome without overloading all non-marked states as internal errors.

   Map outcomes consistently:

   ```text
   marked               -> 202 Accepted
   missing              -> 404 Not Found
   stale_index_repaired -> 404 Not Found with bounded stale reason
   ambiguous_state      -> fail-closed runtime error
   ```

   The exact status for stale repair can be adjusted during implementation, but
   it must not be indistinguishable from corrupt authoritative state.

4. CLI output and operator UX

   Update `nauthilus-directorctl sessions kill`, `users kick`,
   `users sessions`, `sessions list` and relevant JSON renderers so operators
   can see whether a session was marked, missing, stale-repaired, or
   fail-closed.

   Keep scriptable output deterministic. Do not print secrets or raw operator
   reason text in metric labels.

5. Control transport diagnostics

   Add focused tests for HTTPS control listener usage from
   `nauthilus-directorctl`. The tests must cover:

   - HTTP client address pointed at an HTTPS listener;
   - HTTPS address without credentials returning an authentication error;
   - successful authenticated `sessions list` and `users list`;
   - non-JSON control responses producing bounded CLI diagnostics.

   Improve CLI diagnostics so an operator can distinguish transport mismatch,
   TLS verification failure, authentication failure and runtime API failure.
   If environment defaults are added for address or TLS options, keep them
   explicit, documented and secret-safe.

6. Documentation

   Update:

   - `docs/developer/AFFINITY_SESSION_HANDLING.md`
   - `docs/operations/security.md`
   - `docs/man/nauthilus-directorctl.1`
   - operator FAQ/runbook material that describes route lookup, hold, kick,
     session kill, reap, affinity clear ordering and control API transport.

   The docs must state that route lookup is not an auth test, not a protocol
   login and not a cleanup action. The docs must also state that the compiled
   CLI default address is only correct for a plain HTTP control listener.

7. Public-boundary proof

   Add or extend E2E coverage so a real server process and
   `nauthilus-directorctl` prove the operator workflow from the public control
   API:

   ```text
   route lookup with include-affinity does not create a session
   protocol login creates a holder
   users kick marks the holder
   heartbeat/proxy closure or expiry removes the holder
   sessions kill on a stale/missing session reports a bounded non-corrupt result
   sessions list and users list work against the configured HTTPS/auth control path
   affinity clear succeeds only after no active holder remains
   ```

## Acceptance

- Route lookup side-effect freedom is covered by unit and public-boundary tests.
- A visible active session can be killed or deterministically reported as gone.
- Stale repairable indexes do not make `sessions kill` look like corrupt
  authoritative state.
- Corrupt authoritative session state still fails closed.
- `users kick` and `sessions kill` docs explain local-stream versus remote
  heartbeat behavior.
- REST and CLI output provide bounded, scriptable holder-control state.
- `nauthilus-directorctl` reports HTTPS/auth/address mismatches distinctly from
  runtime API failures.
- `sessions list`, `users list` and user-scoped runtime reads are covered
  against the configured control transport.
- Metrics labels remain low-cardinality and secret-safe.
- `make guardrails` passes before the change is merged.

## Completion Evidence

- `SessionKillResponse` is part of the generated OpenAPI contract and is used
  by REST and `nauthilus-directorctl` for `marked`, `missing`,
  `stale_index_repaired` and fail-closed `ambiguous_state` outcomes.
- `SessionDetail` now exposes bounded `holder_kind=session` on public session
  read surfaces; delivery holders remain hidden from session lists.
- Runtime state tests cover stale repairable session locators separately from
  corrupt authoritative session hashes.
- Route lookup tests cover repeated diagnostics without session creation,
  lease refresh, backend reservation or Redis mutation.
- `TestServerBinarySessionHolderControlPublicWorkflow` runs the production
  `nauthilus-director` binary with Valkey, fake Nauthilus, a fake IMAP backend,
  an HTTPS/authenticated control listener and `nauthilus-directorctl`. It proves
  baseline empty reads, repeated read-only route lookup, protocol-login holder
  creation, active-affinity diagnostics without mutation, active-clear refusal,
  `sessions kill` marked and missing/stale outcomes, `users kick` cooperative
  closure, post-close empty reads and successful inactive affinity clear.
- CLI tests cover HTTPS control reads for `sessions list`, `users list`,
  `users sessions` and actionable HTTP-to-HTTPS mismatch diagnostics.
- Operator documentation now states that route lookup is not an auth test, not
  a protocol login and not a cleanup action, and explains the hold, kick/kill,
  wait/reap, verify and affinity-clear migration order.

## Review And Target-State Comparison

| Area | Target | Current | Status | Notes |
| --- | --- | --- | --- | --- |
| Route lookup | Side-effect-free diagnostic | Unit and public-boundary E2E prove repeated lookup does not create sessions, refresh leases, reserve backend capacity or mutate runtime state | Completed | Lookup can report pre-existing active affinity only. |
| Holder origin | Holders come from protocol placement/delivery | Public protocol login creates a visible `holder_kind=session`; LMTP delivery holders stay hidden from session lists | Completed | Diagnostics do not create holders. |
| User kick | Mark all sessions and clearly report cooperative closure | CLI reports cooperative local-stream or heartbeat/lease lifecycle and E2E observes closure | Completed | No cross-replica imperative stream-kill RPC was added. |
| Session kill | Mark active session or return bounded missing/stale/corrupt result | Active kill returns `marked`; missing or stale locators return bounded non-corrupt outcomes; malformed authoritative state remains `ambiguous_state` | Completed | Repairable indexes are separated from corrupt authoritative state. |
| Affinity clear | Fail while active holders exist | Public REST and CLI proof shows active clear refusal and inactive clear success | Completed | Fail-closed default preserved. |
| REST/CLI | Deterministic scriptable cleanup evidence | Generated REST DTOs and CLI text/JSON report holder kind, kill outcome, lifecycle and stale repair state | Completed | Output remains bounded and secret-safe. |
| Control transport | CLI read failures identify address/TLS/auth causes | HTTPS/auth read tests and mismatch diagnostics cover sessions, users and user-scoped reads | Completed | Plain HTTP default remains documented for plain listeners only. |
| Tests | Unit plus public-boundary proof | Unit, generated-contract, CLI and E2E coverage exercise the shipped public boundaries | Completed | Docker interop remains an additive lane with explicit skip rules. |
