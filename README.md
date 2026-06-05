[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](https://go.dev/)

# nauthilus-director

`nauthilus-director` is a production-oriented mail protocol director and
transparent proxy for Nauthilus-backed deployments. It authenticates frontend
protocol sessions through Nauthilus, resolves routing facts inside the director,
selects healthy backend services, keeps active user affinity in Redis and then
proxies the established connection to the selected backend.

The project exists for mail stacks where backend placement, maintenance and
session movement must be explicit, observable and controllable. It is not a
mailbox server and it is not a general-purpose load balancer. Its job is to own
the narrow director responsibilities between clients, Nauthilus and backend
mail services.

## Table of Contents

- [Overview](#overview)
- [Core Capabilities](#core-capabilities)
- [Architecture At A Glance](#architecture-at-a-glance)
- [Project Layout](#project-layout)
- [Build And Test](#build-and-test)
- [Running The Binaries](#running-the-binaries)
- [Configuration](#configuration)
- [Operations](#operations)
- [Demo And Proof Paths](#demo-and-proof-paths)
- [Development](#development)
- [Documentation Map](#documentation-map)
- [Support Nauthilus](#support-nauthilus)
- [Commercial Support](#commercial-support)
- [License](#license)

## Overview

`nauthilus-director` sits in front of stateful mail backends. During the
pre-authentication phase it speaks only the protocol surface needed for secure
authentication, routing and handoff. Once a backend is selected, traffic is
proxied transparently and mailbox semantics stay with the backend service.

The director owns these decisions:

- frontend listener lifecycle, TLS and optional HAProxy PROXY protocol handling
- Nauthilus authentication transport over HTTP or gRPC
- director-local routing fact resolution and backend selection
- Redis-backed active affinity, session leases and runtime coordination
- backend health, maintenance, runtime drains and placement overrides
- OpenAPI-first REST control surface and generated operator client transport
- low-cardinality metrics, structured events and OpenTelemetry tracing

Nauthilus remains the authentication authority. It may return identity and
routing facts, but it does not choose concrete director backends.

## Core Capabilities

- IMAP and IMAPS pre-authentication, placement and transparent proxy handoff
- POP3 and POP3S pre-authentication, placement and transparent proxy handoff
- LMTP and LMTPS delivery routing with recipient-aware placement
- ManageSieve and implicit-TLS Sieve proxying with safe authentication gates
- Redis-backed session affinity and active session coordination
- Runtime control for listeners, backends, sessions, users and route lookups
- Side-effect-free route diagnostics that do not authenticate or mutate Redis
- Safe configuration inspection with redaction by default and explicit
  protected output
- Control-plane authentication modes for static bearer, mTLS and OIDC bearer
  validation through Nauthilus
- Production packaging paths for binaries, manpages, Docker and systemd

The implementation is actively developed. Stable public behavior is documented
in the OpenAPI contract, manpages, operations docs and implementation specs.

## Architecture At A Glance

```text
client
  -> nauthilus-director
      -> listener TLS / STARTTLS / PROXY protocol handling
      -> protocol-specific pre-auth state machine
      -> Nauthilus authentication and identity lookup
      -> director-owned routing resolver
      -> Redis-backed affinity or deterministic initial placement
      -> backend health, maintenance and runtime-state checks
      -> transparent proxy pipe
          -> selected mail backend
```

Important boundaries:

- Protocol handlers stay separate from backend selection, Nauthilus clients,
  REST management and observability.
- Generated OpenAPI types stay at the REST and generated-client boundary.
- Runtime mutation commands change Redis-backed runtime state only; they do not
  rewrite YAML configuration.
- Authentication material, bearer tokens, passwords and private keys must not
  appear in logs, metrics or ordinary config dumps.

See [`docs/ARCHITECTURE_ROADMAP.md`](docs/ARCHITECTURE_ROADMAP.md) for the
full target model and milestone history.

## Project Layout

```text
.
├── cmd/
│   ├── nauthilus-director/      Server binary
│   └── nauthilus-directorctl/   Operator CLI using the generated REST client
├── internal/
│   ├── app/                     Fx composition, server lifecycle and reload
│   ├── backend/                 Backend inventory, health and selection
│   ├── config/                  Typed config loading, validation and redaction
│   ├── listener/                Frontend listener lifecycle
│   ├── nauthilus/               HTTP, gRPC and OIDC authority clients
│   ├── protocol/                IMAP, LMTP, POP3 and Sieve protocol handlers
│   ├── rest/                    Control API adapters and generated server edge
│   ├── routing/                 Director-owned routing resolution
│   ├── runtime/                 Operator-facing runtime control domain
│   └── state/                   Redis-backed affinity and session state
├── docs/
│   ├── config/                  Target production configuration examples
│   ├── man/                     Manual pages for binaries and config format
│   ├── operations/              Deployment, security, failure and migration docs
│   ├── reference/               Generated config defaults and path reference
│   └── specs/                   Architecture and implementation specifications
├── packaging/                   Production Docker and systemd artifacts
├── contrib/demo-stack/          Interoperability and public proof environment
├── test/e2e/                    Public-boundary E2E tests and interop lane
├── AGENTS.md                    Repository engineering rules
├── Makefile                     Build, generation, test and guardrail targets
└── README.md                    Project overview
```

## Build And Test

Requirement: Go 1.26.

Build the production binaries:

```bash
make build
```

Compile the production module without writing binaries:

```bash
make build-check
```

Run the normal test lanes:

```bash
make test
make race
make e2e
```

Run the complete local quality gate before commits or pull requests:

```bash
make guardrails
```

`make guardrails` runs documentation checks, packaging checks, copyright header
checks, OpenAPI stale-output checks, Go fix/vet/lint, unit tests, race tests,
deterministic E2E tests and a build check.

Generated artifacts are guarded by dedicated targets:

```bash
make generate-openapi
make check-openapi
make generate-docs
make check-docs
```

Vendored dependencies are part of the production module. After dependency
updates, run `go mod tidy` and `go mod vendor`, then validate through the
Makefile targets.

## Running The Binaries

Inspect versions:

```bash
./bin/nauthilus-director --version
./bin/nauthilus-directorctl --version
```

Dump canonical defaults with redaction:

```bash
./bin/nauthilus-director config dump -d --format yaml
```

Dump the non-default effective config for a selected file:

```bash
./bin/nauthilus-director --config ./docs/config/nauthilus-director.target.yml \
  config dump -n --format yaml
```

Start the server process:

```bash
./bin/nauthilus-director --config /etc/nauthilus-director/nauthilus-director.yml serve
```

Query the default local control listener:

```bash
./bin/nauthilus-directorctl --address http://127.0.0.1:9090 status
./bin/nauthilus-directorctl --address http://127.0.0.1:9090 runtime summary
```

Use [`docs/man/nauthilus-director.1`](docs/man/nauthilus-director.1) and
[`docs/man/nauthilus-directorctl.1`](docs/man/nauthilus-directorctl.1) for the
full command reference.

## Configuration

The canonical target configuration lives at
[`docs/config/nauthilus-director.target.yml`](docs/config/nauthilus-director.target.yml).
Generated references are kept under [`docs/reference/`](docs/reference/).

Configuration is loaded through Viper, decoded into typed config, expanded for
Nauthilus-style scalar placeholders and then validated. Placeholder expansion is
fail-closed for missing variables and does not expand map keys. Redaction is the
default for config dumps; protected values are printed only when explicitly
requested with `-P` or `--protected`.

Important config roots include:

- `runtime`: process lifecycle, control listener and shared timeouts
- `observability`: logs, metrics, tracing and protected profiling
- `storage.redis`: Redis connection, topology, auth, TLS and key namespaces
- `auth`: Nauthilus authority definitions and transport selection
- `director`: frontend listeners, routing, affinity, health, maintenance,
  backend pools and backends

See [`docs/man/nauthilus-director.yaml.5`](docs/man/nauthilus-director.yaml.5)
for the config-format reference.

## Operations

Production deployment and operator workflows start under
[`docs/operations/`](docs/operations/):

- [`production-deployment.md`](docs/operations/production-deployment.md):
  binaries, Docker, systemd, health probes and upgrade shape
- [`security.md`](docs/operations/security.md): control-plane auth,
  authorization, protected config and diagnostics
- [`oidc-nauthilus.md`](docs/operations/oidc-nauthilus.md): Nauthilus OIDC
  caller auth, client credentials, scopes and token cache behavior
- [`reload-upgrade.md`](docs/operations/reload-upgrade.md): safe reload,
  restart-required changes, shutdown and rolling upgrades
- [`failure-modes.md`](docs/operations/failure-modes.md): observable symptoms,
  likely causes, safe commands and rollback guidance
- [`migration-workflows.md`](docs/operations/migration-workflows.md):
  runtime-only user, backend and listener migration workflows

Production delivery artifacts live under [`packaging/`](packaging/). The Docker
and systemd paths are intentionally separate from the demo stack:

```bash
make check-packaging
make docker-build
make docker-smoke
make systemd-verify
```

Docker and systemd proof targets are optional environment-specific checks and
are not required by the normal guardrail lane.

## Demo And Proof Paths

[`contrib/demo-stack/`](contrib/demo-stack/) is a runnable interoperability and
operator-proof environment. It exercises the production director code with
multiple protocol listeners, Nauthilus authority traffic, Redis-backed runtime
state, backend shards and public smoke scripts.

Start the demo stack on a Docker-capable host:

```bash
cd contrib/demo-stack
cp .env.example .env
docker compose up --build -d
```

Run public proof scripts from the demo directory:

```bash
./scripts/send-mail.sh alice@example.test
./scripts/fetch-mail.sh alice@example.test
./scripts/prove-affinity.sh
./scripts/prove-user-hold.sh
./scripts/prove-user-backend-pin.sh
./scripts/prove-managesieve.sh
./scripts/prove-pop3.sh
```

The deterministic E2E lane is under [`test/e2e/`](test/e2e/) and is part of
`make guardrails`. The Docker-backed real interoperability lane is under
[`test/e2e/interop/`](test/e2e/interop/) and can be run separately with:

```bash
make e2e-interop
```

## Development

Read [`AGENTS.md`](AGENTS.md) before changing code. It defines the repository's
engineering contract: Go 1.26 alignment, Makefile-first validation,
security-by-default behavior, strict domain boundaries, generated OpenAPI edges,
vendored dependency discipline, E2E proof expectations and commit-message
format.

Common development rules:

- Prefer typed domain objects, narrow interfaces and composition over shared
  mutable package state.
- Keep protocol handling separate from routing, backend selection, Nauthilus
  transport, REST control and observability.
- Add focused regression tests before changing bug-prone production behavior
  when a stable reproducer is practical.
- Keep generated REST server/client artifacts reproducible through
  `make check-openapi`.
- Keep generated config references reproducible through `make docs-check`.
- Keep local planning, scratch and prompt artifacts under ignored `temp/`.

The repository uses structured commit messages with prefixes such as `Add`,
`Fix`, `Docs`, `Build`, `Security` and `Refactor`; see
[`AGENTS.md`](AGENTS.md) for the full format.

## Documentation Map

- [`docs/ARCHITECTURE_ROADMAP.md`](docs/ARCHITECTURE_ROADMAP.md): production
  target architecture and milestone roadmap
- [`docs/specs/implementation/`](docs/specs/implementation/): implementation
  specs for milestone slices
- [`docs/specs/openapi/nauthilus-director.yaml`](docs/specs/openapi/nauthilus-director.yaml):
  public REST control contract
- [`docs/reference/config-defaults.yaml`](docs/reference/config-defaults.yaml):
  generated default config
- [`docs/reference/config-paths.md`](docs/reference/config-paths.md): generated
  config path reference
- [`docs/man/`](docs/man/): command and configuration manpages
- [`docs/operations/`](docs/operations/): production operator documentation
- [`docs/FAQ.md`](docs/FAQ.md): practical runtime-control FAQ
- [`packaging/`](packaging/): production delivery inventory and artifacts
- [`contrib/demo-stack/`](contrib/demo-stack/): demo and interoperability proof

## Support Nauthilus

Nauthilus is maintained as an open source project. If it saves you time or runs in your infrastructure, you can support ongoing development through:

- GitHub Sponsors: [one-time or recurring sponsorships](https://github.com/sponsors/croessner)
- PayPal: [one-time or recurring donations](https://www.paypal.com/donate/?hosted_button_id=3XLD5KEJD7AQ8)

Sponsorships and donations are appreciated, but never required to use Nauthilus under the GPLv3 license.

## Commercial Support

Commercial support for Nauthilus is available for integration, customization, deployment guidance, and production troubleshooting.

For commercial inquiries, contact [support@nauthilus.com](mailto:support@nauthilus.com) or visit [https://nauthilus.org](https://nauthilus.org).

## License

`nauthilus-director` is licensed under the GNU Affero General Public License
version 3. See [`LICENSE`](LICENSE) for details.
