# Operations Documentation

This directory owns operator-facing production deployment, security,
failure-mode and migration documentation for `nauthilus-director`.

Start here:

| Topic | Document |
| --- | --- |
| Production artifacts, Docker and systemd | [`production-deployment.md`](production-deployment.md) |
| Control-plane authentication, authorization and diagnostics | [`security.md`](security.md) |
| Nauthilus OIDC caller auth and control OIDC | [`oidc-nauthilus.md`](oidc-nauthilus.md) |
| Reload, shutdown and upgrade flow | [`reload-upgrade.md`](reload-upgrade.md) |
| Failure-mode diagnosis | [`failure-modes.md`](failure-modes.md) |
| Runtime-only migration workflows | [`migration-workflows.md`](migration-workflows.md) |

Command syntax stays in the manpages under `docs/man/`. These operations docs
show how to combine those commands safely in production. Runtime commands
manage Redis-backed runtime state only; they do not rewrite YAML configuration.

Documentation in this directory must use redacted examples or file-path
references for credentials and tokens. It must not include secret values.
