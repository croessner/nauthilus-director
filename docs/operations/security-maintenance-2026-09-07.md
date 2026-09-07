# Security maintenance review — 2026-09-07

## Scope and provenance

Reviewed `croessner/nauthilus-director`, local `main` at
`7a2a5cba7b656f3be3272cfb1486475913bef3e8`. The SSH origin matches that
repository; GitHub's current main SHA matches the checkout. The initial working
tree contained only untracked `.codex/`, which was preserved. The supplied
snapshot was treated as untrusted leads; advisory data, package versions,
Dockerfiles, runtime imports and release metadata were independently checked.

## Findings and disposition

| Reported finding | Verified scope | Result in this working tree |
| --- | --- | --- |
| GHSA-r277-6w6q-xmqw (critical) | kin-openapi's default authentication middleware; no `openapi3filter` runtime import | Dependency fixed with kin-openapi 0.144.0; reported runtime path not applicable |
| CVE-2026-56854 (critical) | SSH server authentication callbacks; no SSH runtime import | Dependency fixed with x/crypto 0.56.0; reported runtime path not applicable |
| CVE-2026-76905, CVE-2026-77354 (high) | kin-openapi multipart/deepObject request decoding | Dependency fixed with kin-openapi 0.144.0; middleware not used by production binaries |
| CVE-2026-56864, CVE-2026-56865 (high) | x/mod checksum database validation and Go build tool | x/mod updated to 0.40.0; Go build pins updated from affected 1.26.5 to 1.26.8 |
| CVE-2026-84304 (high) | gRPC HTTP/2 data buffering; gRPC is a production dependency | Fixed with gRPC 1.83.1; existing real-process HTTP/gRPC E2E lane retained |
| DS-0002, demo CLI (high) | Bootstrap image ran as root | Fixed: executable under `/usr/local/bin`, UID/GID 10001, owned bootstrap state directory |
| DS-0002, vendor TOML and OTel Dockerfiles (high) | Upstream CLI/contributor image definitions, unused by project builds | Not applicable to shipped project containers; vendor source retained unchanged by hand |
| Go 1.26.5 pin / Go 1.26 baseline | Project policy explicitly requires Go 1.26 | Patch pins synchronized to 1.26.8 across module, CI, Docker, Makefile, helper and operator docs; 1.27 migration not applicable to this maintenance scope |
| CVE-2026-73502 (medium) | kin-openapi request parameter validation | Dependency fixed with kin-openapi 0.144.0; middleware not used by production binaries |
| CVE-2026-56855, CVE-2026-78662 (medium) | SSH channel deadlocks | Dependency fixed with x/crypto 0.56.0; SSH not imported by production binaries |
| GO-2026-5932 (medium) | Unmaintained OpenPGP subpackages; no fixed version | Not applicable to current runtime imports; remains visible in module-level Trivy output, not suppressed |
| GHSA-rjwr-m7qx-3fjr (low) | Malicious OpenAPI server descriptions can escape generated comments | Fixed with oapi-codegen 2.7.1; generation/check pins and documented generator updated together; regenerated server/client output changes only the version header |
| DS-0026, demo Director (low) | No Dockerfile HEALTHCHECK | Not applicable at image layer: both Director Compose services already define authenticated TLS status checks |
| DS-0026, production server (low) | No Dockerfile HEALTHCHECK | Deployment responsibility: `/healthz` and `/readyz` probes depend on configured control address/TLS; live deployment probe coverage remains unverified |
| DS-0026, production CLI and demo CLI (low) | No Dockerfile HEALTHCHECK | Not applicable to commands that exit; command exit status is the success signal |
| DS-0026, vendor TOML and OTel Dockerfiles (low) | Upstream image definitions | Not applicable to project builds |

The dependency update also brings the transitive versions required by those
upstreams, including x/net 0.58.0. `go mod tidy` and `go mod vendor` were run.
No application authentication, TLS policy or scanner exclusions were weakened.
No hand-written vendor patches or blanket vulnerability suppressions were added.

## Original sources

- [kin-openapi authentication advisory](https://github.com/getkin/kin-openapi/security/advisories/GHSA-r277-6w6q-xmqw)
- [kin-openapi multipart advisory](https://github.com/getkin/kin-openapi/security/advisories/GHSA-mmfr-pmjx-hw9w)
- [kin-openapi deepObject advisory](https://github.com/getkin/kin-openapi/security/advisories/GHSA-xhj3-7xw9-vr34)
- [kin-openapi parameter advisory](https://github.com/getkin/kin-openapi/security/advisories/GHSA-jpcw-4wr7-c3vq)
- [Go SSH authentication record](https://vuln.go.dev/ID/GO-2026-6303.json)
- [Go SSH channel records](https://vuln.go.dev/ID/GO-2026-6354.json) and [established-channel record](https://vuln.go.dev/ID/GO-2026-6355.json)
- [Go checksum tile record](https://vuln.go.dev/ID/GO-2026-6179.json) and [lookup record](https://vuln.go.dev/ID/GO-2026-6180.json)
- [Go OpenPGP record](https://vuln.go.dev/ID/GO-2026-5932.json)
- [gRPC advisory](https://github.com/grpc/grpc-go/security/advisories/GHSA-vp52-pcj8-j9qc)
- [oapi-codegen advisory](https://github.com/oapi-codegen/oapi-codegen/security/advisories/GHSA-rjwr-m7qx-3fjr)
- [Go downloads](https://go.dev/dl/?mode=json): 1.26.8 and 1.27.1 were available at review time.
- [Trivy root rule](https://github.com/aquasecurity/trivy-checks/blob/main/checks/docker/root_user.rego) and [healthcheck rule](https://github.com/aquasecurity/trivy-checks/blob/main/checks/docker/no_healthcheck_instruction.rego)

## Coverage and release readiness

GitHub confirms [v1.0.1](https://github.com/croessner/nauthilus-director/releases/tag/v1.0.1)
as the latest published release and main as identical to that tag before these
edits. A patch release **v1.0.2** is proposed after review and final release
validation. This is a stable maintenance change, not a release-candidate promotion.
The v1.0.1 release source still pins the affected dependency/build versions.
Published binary contents and running deployments remain unverified; local fixes
do not update either of them.

GitHub reports Dependabot alerts disabled (HTTP 403). Security-alert coverage is
therefore incomplete; no repository settings or authorization scopes were changed.
The code-scanning and secret-scanning APIs were accessible and each returned
zero open alerts. Those counts describe published scan evidence, not a fresh
secret scan of this working tree.
The latest main CodeQL run (September 6) and Docker refresh (September 7) passed.
The latest main vulnerability, guardrail and unit-test runs are from August 11;
those historic green results do not validate these edits or today's advisories.
Release workflows had no main-branch runs in the per-workflow query, consistent
with their release-event triggers; no new release workflow has been executed.
The one open issue, #12 (Keycloak integration), is not evidence of a regression
introduced here. Container image contents and production deployments were not
claimed safe based on filesystem scanning.

Existing partially initialized demo bootstrap volumes may need their directory
ownership migrated to UID/GID 10001 before retrying initialization. Preserve
markers and data; do not reset volumes. Fresh-volume writes were verified,
including an empty volume first mounted by a root peer. No existing stack state
was modified.

Local raw logs and API responses are under ignored `temp/maintenance/`; they
are not release artifacts.

## Validation results

- **Passed:** `GOTOOLCHAIN=go1.26.8 make release-guardrails`, including generated
  docs/OpenAPI checks, packaging, headers, Go fix/vet, lint (zero issues), unit
  tests, race tests, public-socket E2E with a real server binary, build and
  package-level govulncheck. The final standalone E2E run completed in 95.628s.
- **Passed:** `make docker-smoke-all` for the production server and client,
  built locally with the Go 1.26.8 image. Both real version commands succeeded;
  the client manpage was present. Local image tags only; no registry push.
- **Passed:** new `make demo-cli-smoke`, including the real CLI version command,
  UID/GID checks and marker writes under a read-only root filesystem with no
  network. Compose configuration validation also passed.
- **Passed:** `go mod verify`; a second `go mod vendor` produced byte-for-byte
  identical files. Runtime dependency lists explicitly contain zero imports of
  openapi3filter, SSH, OpenPGP and x/mod/sumdb for both production commands.
- **Revalidated:** Trivy 0.74.0 with a newly downloaded database and check bundle
  in a fresh cache. Only GO-2026-5932 and the eight Docker findings classified
  above remain. No exclusions for individual advisories or Docker rules were
  added. This was a filesystem vulnerability/misconfiguration scan, not an
  image-content or secret scan.
- **Qualified:** `git diff --check` passes outside `vendor/`. The canonical
  regenerated vendor tree contains 34 upstream whitespace warnings; these were
  retained to preserve reproducible vendoring rather than patched by hand.
- **Not run:** optional external Redis integration tests (no Redis test address
  supplied), full demo mail-flow interoperability and deployment validation.
  The required deterministic E2E lane did run successfully.

The first local attempt could not bind test sockets in the sandbox. Another
attempt overlapped race compilation with vendor regeneration. Both attempts
were discarded as validation evidence; the final full run used allowed local
sockets and an unchanged vendor tree and exited successfully.

## Changed surfaces and remaining work

- Dependencies: `go.mod`, `go.sum`, regenerated `vendor/`.
- OpenAPI tooling: `scripts/generate-openapi.sh`, `scripts/check-openapi.sh`,
  generated REST server and CLI client; generator references in `AGENTS.md`,
  `POLICY.md`, architecture and foundation documentation.
- Go pins: seven workflows under `.github/workflows/`, `Makefile`, all three
  Go builder Dockerfiles, `scripts/docker-base-digests.sh`, packaging and
  deployment documentation.
- Demo hardening: `contrib/demo-stack/Dockerfile.stalwart-cli`, its README,
  `scripts/check-demo-cli-image.sh` and the Makefile smoke target.
- Review/probe documentation: this report, the operations index and production
  deployment guide.

No confirmed dependency fix remains outstanding in this working tree. Before
releasing v1.0.2, review and commit the intended changes, rerun the release gate
on the exact clean release commit, and complete the separately authorized
release workflow. Dependabot coverage remains unresolved. Any upgrade of an
existing partially initialized demo volume needs an ownership check first.
Production/image vulnerability coverage and live deployment probe coverage
remain unverified and must not be inferred from these local checks.

At completion of the initial review, no commit, push, tag, release, archive
operation or deployment had been performed. The maintainer subsequently
authorized publication of v1.0.2. Release validation must cover the exact
committed content; the local `.codex/` directory stays outside the release.
