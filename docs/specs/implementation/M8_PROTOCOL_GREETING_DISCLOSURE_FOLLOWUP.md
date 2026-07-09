# M8 Protocol Greeting Disclosure Follow-up

Status: completed.

This follow-up defines a small hardening and configuration slice for frontend
protocol greetings and pre-auth capability identities in `nauthilus-director`.

The immediate trigger is the ManageSieve greeting: the current Sieve
`IMPLEMENTATION` capability includes the process version. That is useful for
operator diagnostics, but it also gives unauthenticated clients a precise
software-version fingerprint. The same design question should be settled once
for all public mail protocols instead of being fixed ad hoc in the Sieve
package.

The goal is not to make protocol greetings arbitrary. Operators must be able to
set a bounded display identity and reduce version disclosure per protocol
without writing raw transcript lines that can become invalid IMAP, LMTP,
ManageSieve or POP3 output.

## Source Documents

This follow-up is governed by:

- `AGENTS.md`
- `POLICY.md`
- `docs/ARCHITECTURE_ROADMAP.md`
- `docs/specs/implementation/M0_FOUNDATION_SPEC.md`
- `docs/specs/implementation/M1_IMAP_MVP_SPEC.md`
- `docs/specs/implementation/M5_LMTP_PRODUCTION_SPEC.md`
- `docs/specs/implementation/M5_LMTP_PLAINTEXT_AND_CAPABILITY_FOLLOWUP.md`
- `docs/specs/implementation/M6_MANAGESIEVE_PROXY_SPEC.md`
- `docs/specs/implementation/M7_POP3_PROXY_SPEC.md`
- `docs/specs/implementation/M8_PRODUCTION_HARDENING_SPEC.md`
- `docs/config/nauthilus-director.target.yml`
- `docs/config/metadata.yml`
- `docs/reference/config-defaults.yaml`
- `docs/reference/config-paths.md`
- `docs/man/nauthilus-director.yaml.5`
- `test/e2e/README.md`
- `test/e2e/interop/README.md`
- `Makefile`
- RFC 3501, `Internet Message Access Protocol - Version 4rev1`
- RFC 2033, `Local Mail Transfer Protocol`
- RFC 5804, `A Protocol for Remotely Managing Sieve Scripts`
- RFC 1939, `Post Office Protocol - Version 3`
- RFC 2449, `POP3 Extension Mechanism`

If this document conflicts with those source documents, fix the drift before
implementation continues. In particular, do not weaken stable config path
rules, metric-label policy, secret-safe diagnostics, protocol correctness,
typed config validation or generated config references to make greeting
configuration easier.

## Starting State

The current implementation has four different frontend greeting shapes:

- IMAP sends a fixed greeting from `internal/protocol/imap/session.go`:
  `* OK nauthilus-director IMAP session ready`.
- LMTP sends a fixed enhanced greeting from
  `internal/protocol/lmtp/responses.go`:
  `220 2.0.0 nauthilus-director LMTP ready`.
- ManageSieve sends an RFC 5804 capability greeting from
  `internal/protocol/sieve/capability.go`. Its `IMPLEMENTATION` capability is
  built in `internal/app/server.go` by calling
  `sieve.ImplementationCapability(processVersion)`, so unauthenticated clients
  can see the process version. Its `VERSION` capability is the ManageSieve
  protocol version `1.0`, not the software version.
- POP3 sends a fixed greeting from `internal/protocol/pop3/responses.go`:
  `+OK nauthilus-director POP3 ready`.

The Sieve config already rejects operator-supplied `implementation` and
`version` capability fields. That is the right safety direction: operator
configuration must express typed intent, not raw wire lines. This follow-up
must preserve that invariant.

The existing generated config defaults do not contain greeting policy paths.
The existing docs also contain older M6 wording that mentions
`director.listeners.*.sieve.capabilities.implementation` and `.version`, but
the current typed config and tests intentionally reject those fields. This
follow-up supersedes that stale wording with a safer explicit greeting
disclosure policy.

## Goal

Add a typed, validated, per-listener protocol greeting disclosure policy that:

- lets operators suppress software version disclosure in public greetings and
  capability identities;
- lets operators replace the public display identity, for example
  `nauthilus-director` with `Norbert`, through one validated field;
- preserves current wire behavior by default unless this follow-up explicitly
  chooses a breaking hardening default;
- prevents raw transcript injection, multiline output, invalid status text and
  invalid quoted strings;
- keeps protocol packages responsible for protocol-specific rendering;
- centralizes version-disclosure semantics in one small value object instead of
  duplicating boolean/string checks across IMAP, LMTP, ManageSieve and POP3;
- updates generated config references, target config comments and manpages with
  the new stable paths;
- proves behavior through unit tests and public-socket E2E coverage.

## Non-goals

This follow-up must not:

- let operators configure arbitrary greeting or capability transcript lines;
- let operators override the ManageSieve RFC `VERSION` protocol capability;
- let operators configure per-protocol raw status codes, response conditions,
  capability names or multiline text;
- change authentication, placement, affinity, backend selection or route lookup
  behavior;
- log configured greeting values or process versions as metric labels;
- add dependencies for simple validation or rendering;
- introduce a second protocol value such as `managesieve`;
- move protocol rendering into `internal/config` or `internal/app`.

## Configuration Shape

Add the same typed `greeting` subtree under each protocol-specific listener
sub-config:

```yaml
director:
  listeners:
    imap:
      imap:
        greeting:
          display_name: nauthilus-director
          software_version: default
    lmtp:
      lmtp:
        greeting:
          display_name: nauthilus-director
          software_version: default
    sieve:
      sieve:
        greeting:
          display_name: nauthilus-director
          software_version: default
    pop3:
      pop3:
        greeting:
          display_name: nauthilus-director
          software_version: default
```

`display_name` is the public product identity used by all protocol renderers.
Its default is `nauthilus-director`. Operators may set a different bounded
identity such as `Norbert`, but the value is still inserted into protocol-owned
response templates rather than used as raw wire output.

Valid `software_version` values:

- `default`: preserve the protocol's current public behavior.
  - Sieve includes the process version in `IMPLEMENTATION`.
  - IMAP, LMTP and POP3 do not include the process version.
- `include`: include the normalized process version in the public greeting or
  pre-auth capability identity for this listener, rendered through the
  protocol's own safe formatter.
- `suppress`: never include the process version in the public greeting or
  pre-auth capability identity for that listener.

`include` is an explicit operator disclosure choice. It must not become an
implicit default for protocols that do not currently expose the process version.

Defaults may stay compatible by setting `software_version: default`. If the
maintainer chooses the stricter security default during implementation, the
change must be documented as an operator-visible behavior change and the
generated defaults must set every public listener to `suppress`.

Default `display_name` must remain `nauthilus-director` unless the operator
explicitly configures another value.

## Typed Model

Add a small shared value object for disclosure semantics. The exact package name
may be adjusted during implementation, but the boundary should look like this:

```text
internal/protocol/greeting/
  policy.go
```

Responsibilities:

- Own the `SoftwareVersionDisclosure` enum and validation.
- Own the `DisplayName` value object and validation.
- Normalize empty config to the protocol's default behavior.
- Accept the process version as input from `internal/app`, normalize whitespace
  and expose either the normalized version or no version according to policy.
- Expose immutable methods such as `DisplayName()`, `SoftwareVersion()`,
  `IncludeSoftwareVersion()` and `DisplayIdentity(protocol string)`.
- Build display identities from the validated display name plus optional
  software version.
- Treat `include` consistently across all frontend protocols while leaving the
  exact wire syntax to protocol-local renderers.
- Never render full IMAP, LMTP, ManageSieve or POP3 wire lines.

Protocol packages remain responsible for protocol grammar:

- `internal/protocol/imap` renders the final IMAP greeting.
- `internal/protocol/lmtp` renders the final LMTP enhanced status line and LHLO
  domain text.
- `internal/protocol/sieve` renders RFC 5804 quoted capability lines.
- `internal/protocol/pop3` renders the final POP3 `+OK` status line.

`internal/app` should convert typed listener config plus process build version
into the shared policy and pass it through each protocol's `SessionConfig`.
`internal/config` should own typed config structs, defaults, normalization and
validation only.

This keeps the object boundaries narrow:

- config owns schema and validation;
- app owns wiring from process facts to immutable session settings;
- protocol sessions own wire output;
- the shared greeting policy owns cross-protocol disclosure semantics.

## Protocol Behavior

### IMAP

Default behavior remains:

```text
* OK nauthilus-director IMAP session ready
```

With `display_name: Norbert`, default behavior becomes:

```text
* OK Norbert IMAP session ready
```

`software_version: suppress` must produce the same output.

`software_version: include` must produce a protocol-valid greeting with the
normalized process version, for example:

```text
* OK Norbert <process-version> IMAP session ready
```

### LMTP

Default behavior remains:

```text
220 2.0.0 nauthilus-director LMTP ready
```

With `display_name: Norbert`, default behavior becomes:

```text
220 2.0.0 Norbert LMTP ready
```

`software_version: suppress` must produce the same output.

`software_version: include` must produce a protocol-valid enhanced greeting with
the normalized process version, for example:

```text
220 2.0.0 Norbert <process-version> LMTP ready
```

`LHLO` capability domain text must use the same validated display identity
unless implementation review finds a protocol compatibility reason to keep it
fixed. If it stays fixed, document that as a deliberate exception with tests.

### ManageSieve

Default behavior remains compatible:

```text
"IMPLEMENTATION" "nauthilus-director <process-version>"
"VERSION" "1.0"
...
OK
```

With `display_name: Norbert`, default `IMPLEMENTATION` becomes:

```text
"IMPLEMENTATION" "Norbert <process-version>"
```

With `software_version: suppress`, `IMPLEMENTATION` must become:

```text
"IMPLEMENTATION" "Norbert"
```

`software_version: include` must produce the same `IMPLEMENTATION` value as
current default behavior.

The `VERSION` capability must remain `1.0` because it is the RFC 5804 protocol
version, not the process version.

### POP3

Default behavior remains:

```text
+OK nauthilus-director POP3 ready
```

With `display_name: Norbert`, default behavior becomes:

```text
+OK Norbert POP3 ready
```

`software_version: suppress` must produce the same output.

`software_version: include` must produce a protocol-valid greeting with the
normalized process version, for example:

```text
+OK Norbert <process-version> POP3 ready
```

## Validation Rules

Config validation must reject:

- empty `display_name` values after trimming and normalization;
- `display_name` values longer than the project-defined maximum, initially
  64 bytes after normalization;
- `display_name` values containing CR, LF, control characters, DEL, quotes,
  backslashes or non-printable bytes;
- `display_name` values outside the accepted character set, initially letters,
  digits, single spaces, dots, underscores and hyphens;
- unknown `software_version` values;
- any raw greeting text field if an operator attempts to add one by typo or
  stale documentation;
- Sieve `capabilities.implementation` and `capabilities.version`, preserving
  the current rejection tests;
- protocol-specific greeting policy under the wrong protocol subtree;
- duplicate or conflicting future aliases if more values are later added.

Validation must not treat process version as secret material, but it must avoid
including the raw process version in validation error text where the configured
policy suppresses it.

Validation must treat `display_name` as non-secret operator text, but it must
not permit the value to become a response-injection or multiline transcript
surface.

No map keys are expanded, and scalar environment placeholder expansion must
continue to happen before typed validation if a future scalar value is added to
this subtree.

## Documentation And Generated References

Implementation must update:

- `docs/config/nauthilus-director.target.yml`
- `docs/config/metadata.yml`
- `docs/reference/config-defaults.yaml`
- `docs/reference/config-paths.md`
- `docs/man/nauthilus-director.yaml.5`

Documentation must clearly state:

- `display_name` changes the public identity token inserted into all supported
  protocol greetings through safe renderers;
- `default` preserves current protocol behavior;
- `include` explicitly publishes the normalized process version for that
  listener;
- `suppress` hides the software version where the protocol would otherwise
  expose it;
- ManageSieve `VERSION` remains visible because it is a protocol version;
- raw greeting lines are intentionally unsupported.

If generated references are produced from code, use the existing Makefile docs
target instead of hand-editing generated output.

## Implementation Slices

Implement this follow-up as small slices:

1. Add typed config fields, defaults, metadata and validation for
   `greeting.display_name` and `greeting.software_version`.
2. Add the shared greeting display/disclosure value objects and focused unit
   tests.
3. Thread the policy through `internal/app` into IMAP, LMTP, ManageSieve and
   POP3 session configs.
4. Update protocol rendering so IMAP, LMTP, ManageSieve and POP3 all honor
   `default`, `include` and `suppress`.
5. Refresh generated config docs and manpages.
6. Add public-boundary E2E proof for `default`, `include`, `suppress` and a
   custom `display_name` across IMAP, LMTP, ManageSieve and POP3.

The slices may be committed separately, but the follow-up is not complete until
all configured protocol listeners start from typed config and every frontend
protocol has a public-socket proof for the new disclosure policy.

## Tests

Minimum unit coverage:

- Config defaulting keeps `software_version: default` for every generated
  protocol listener.
- Config defaulting keeps `display_name: nauthilus-director` for every
  generated protocol listener.
- Config validation rejects empty, overlong, control-bearing, quoted,
  backslash-bearing and otherwise malformed display names.
- Config validation rejects unknown `software_version` values.
- Config loading still rejects Sieve `capabilities.implementation` and
  `capabilities.version`.
- The shared policy normalizes blank process versions and whitespace safely.
- Sieve default greeting includes the configured display name and normalized
  process version.
- Sieve `suppress` greeting omits the process version and keeps
  `IMPLEMENTATION` valid.
- ManageSieve `VERSION` remains `1.0` under both policies.
- IMAP, LMTP and POP3 greetings remain unchanged under `default` and
  `suppress` when `display_name` is left at the default.
- IMAP, LMTP and POP3 `include` greetings contain the normalized process version
  in protocol-valid response text.
- IMAP, LMTP, ManageSieve and POP3 render `display_name: Norbert` through
  protocol-valid output without changing status codes or response conditions.
- Renderer tests include control-character and newline attempts against the
  display name path.

Minimum E2E coverage:

- Start a Director process with default Sieve greeting policy and assert the
  first public greeting contains `IMPLEMENTATION` with the configured process
  version.
- Start or reload a Director process with Sieve `software_version: suppress`
  and assert the public greeting contains `IMPLEMENTATION` without the process
  version.
- Assert `VERSION` remains the ManageSieve protocol version.
- Assert IMAP, LMTP and POP3 public greetings remain valid under `default`,
  `suppress` and `include`.
- Assert one public listener per protocol can use `display_name: Norbert`
  without invalid greeting syntax.

Run focused protocol tests while iterating, then:

```text
make check-docs
make test
make e2e
make build-check
git diff --check
```

Run `make guardrails` before committing or opening a pull request.

## Acceptance Criteria

- Operators can configure version disclosure for IMAP, LMTP, ManageSieve and
  POP3 without writing raw protocol text.
- Operators can configure the public display identity for IMAP, LMTP,
  ManageSieve and POP3 without writing raw protocol text.
- Current default wire behavior is preserved unless the implementation
  deliberately documents and tests a stricter default.
- Invalid greeting policy values fail config validation before sockets bind.
- No frontend protocol has to disclose the process version.
- Every frontend protocol can explicitly include the process version with
  protocol-valid formatting when an operator chooses that disclosure.
- Every frontend protocol can replace `nauthilus-director` with a validated
  display name such as `Norbert`.
- Sieve `IMPLEMENTATION` no longer has to disclose the process version.
- Sieve `VERSION` remains protocol-correct and is not confused with software
  version disclosure.
- IMAP, LMTP and POP3 default greetings do not regress.
- The implementation uses one shared greeting disclosure value object and
  protocol-local renderers instead of duplicated per-package policy checks.
- Generated config references and manpages document the new stable paths.
- Public-boundary E2E proves the disclosure policy for every frontend protocol.

## Completion Evidence

Public-boundary greeting proof was added on 2026-07-09 through real
`nauthilus-director` test binaries and public loopback sockets.

- `go test -mod=vendor -run 'TestServerBinaryPublic(IMAP|LMTP|Sieve|POP3)GreetingDisclosurePolicy|TestServerBinaryRejectsInvalidGreetingDisplayNameBeforeListenersBind' ./test/e2e`
  passed and proved IMAP, LMTP, ManageSieve and POP3 greetings through process
  and socket boundaries.
- IMAP public proof covers compatible default output, explicit
  `software_version: include`, `software_version: suppress` and
  `display_name: Norbert`.
- LMTP public proof covers compatible default output, explicit
  `software_version: include`, `software_version: suppress`,
  `display_name: Norbert` and matching `LHLO` display identity.
- ManageSieve public proof covers compatible default `IMPLEMENTATION`, explicit
  `software_version: include`, `software_version: suppress`,
  `display_name: Norbert` and `VERSION` remaining `1.0` under default, include
  and suppress.
- POP3 public proof covers compatible default output, explicit
  `software_version: include`, `software_version: suppress` and
  `display_name: Norbert`.
- A process-level invalid `display_name` proof exits during config validation,
  omits the unsafe raw value from process output and verifies IMAP, LMTP,
  ManageSieve and POP3 listener sockets were not bound.
- Final validation on 2026-07-09 passed with `make generate-docs`,
  `make check-docs`, `make test`, `make race`, `make e2e`,
  `make build-check`, `make guardrails` and `git diff --check`.

## Review Checklist

- [x] No raw greeting transcript strings are accepted from config.
- [x] No process version is logged as a metric label.
- [x] Protocol packages still own wire rendering.
- [x] `internal/app` only wires process version into immutable session config.
- [x] `internal/config` does not import protocol packages for rendering.
- [x] `display_name` cannot inject CRLF, quotes, backslashes, raw protocol
      tokens or multiline output.
- [x] IMAP, LMTP, ManageSieve and POP3 all honor `default`, `include` and
      `suppress`.
- [x] Sieve `VERSION` remains the RFC protocol version.
- [x] Sieve `capabilities.implementation` and `.version` remain rejected.
- [x] Generated docs are fresh after config metadata changes.
- [x] Focused unit tests and public-socket E2E cover default, included and
      suppressed behavior for all frontend protocols.
