# Production systemd Packaging

This directory owns the production systemd host-service artifacts for
`nauthilus-director`. The unit is separate from `contrib/demo-stack/` and does
not depend on demo Compose services, demo TLS generators or demo entrypoints.

## Files

| File | Purpose |
| --- | --- |
| `nauthilus-director.service` | Hardened production service unit. |
| `nauthilus-director.env.example` | Optional non-secret environment file template for YAML placeholder paths. |

## Service Contract

- Run `/usr/local/bin/nauthilus-director` built with Go 1.26.4.
- Start with `/etc/nauthilus-director/nauthilus-director.yml`.
- Reload through `/usr/local/bin/nauthilus-directorctl --address http://127.0.0.1:9090 --timeout 10s reload`.
- Stop gracefully with `SIGTERM`; the unit timeout is aligned with the default
  `runtime.process.shutdown_timeout` of `30s`.
- Run as the dedicated `nauthilus-director` user and group.
- Keep `/etc/nauthilus-director` read-only inside the service namespace.
- Keep writable host paths limited to systemd-managed runtime and private
  temporary directories by default.
- Send logs to journald through stdout and stderr.
- Restart on service failure without treating reload as a signal shortcut.

The unit does not embed bearer tokens, passwords, private keys or authorization
headers. Secret-bearing configuration values must point to host-managed files,
usually under `/etc/nauthilus-director/`, readable by the service user and not
world-readable.

## Host Layout

Recommended host paths:

| Path | Owner | Mode | Purpose |
| --- | --- | --- | --- |
| `/usr/local/bin/nauthilus-director` | `root:root` | `0755` | Server binary. |
| `/usr/local/bin/nauthilus-directorctl` | `root:root` | `0755` | Public control-plane CLI used by `ExecReload`. |
| `/etc/nauthilus-director/` | `root:nauthilus-director` | `0750` | YAML configuration, control token files, password files and TLS material. |
| `/etc/nauthilus-director/nauthilus-director.yml` | `root:nauthilus-director` | `0640` | Production configuration loaded by `ExecStart`. |
| `/etc/default/nauthilus-director` | `root:root` | `0644` | Optional non-secret environment placeholders for config expansion. |
| `/run/nauthilus-director/` | `nauthilus-director:nauthilus-director` | `0750` | Runtime directory created by systemd. |

If deployment policy keeps secrets in a separate root-only location, use group
read ACLs or a systemd drop-in with additional read-only bind paths. Do not put
secret bytes in the unit or environment file.

## Optional Environment File

`nauthilus-director.env.example` can be copied to
`/etc/default/nauthilus-director` when the YAML file uses `${NAME}`
placeholders for file paths. The template intentionally contains path values
only. For example, the YAML may use
`${NAUTHILUS_DIRECTOR_REDIS_PASSWORD_FILE}`, while the actual Redis password is
stored in the file named by that variable.

Changing the server config path or control address is a service command change,
not an environment-template change. Use a systemd drop-in for those cases.

## Overrides

Use `systemctl edit nauthilus-director.service` for deployment-specific
changes.

Low protocol ports should be explicit:

```ini
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

Custom config paths must keep startup read-only:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/nauthilus-director --config /etc/nauthilus-director/site.yml serve
ReadOnlyPaths=
ReadOnlyPaths=/etc/nauthilus-director
```

Custom control listeners used by reload must stay on the public CLI path:

```ini
[Service]
ExecReload=
ExecReload=/usr/local/bin/nauthilus-directorctl --address https://127.0.0.1:9090 --timeout 10s reload
```

Additional writable paths should be narrow and purpose-specific:

```ini
[Service]
ReadWritePaths=/run/nauthilus-director /var/lib/nauthilus-director
```

## Reload, Restart and Upgrade

`systemctl reload nauthilus-director.service` runs `nauthilus-directorctl
reload`, which calls the public REST reload endpoint. A rejected reload leaves
the running process and its previously accepted config snapshot in place. M8.7
continues the runtime implementation, but the host contract is already fixed:
reload must not edit YAML and must not be implemented as `SIGHUP` in the unit.

Safe reload accepts listener additions/removals plus `director.backends.*` and
`director.backend_pools.*` changes for new sessions. It preserves existing
sessions, active affinities, backend pins and placement holds. Restart remains
required for `runtime.*`, `auth.*`, `storage.redis.*`, `observability.*`,
director routing, affinity, runtime override, health, maintenance and security
policy changes, and edits to existing listener definitions.

Restart for changes that affect process identity, binary path, listener
privileges, systemd hardening, local file permissions or config classes that
the safe-reload service reports as restart-required. The normal upgrade flow is
to install new binaries, run validation, then use `systemctl restart
nauthilus-director.service` during the chosen maintenance window.

## Validation

`make check-packaging` validates the unit shape statically without installing
or starting it. `make systemd-verify` runs `systemd-analyze verify
packaging/systemd/nauthilus-director.service` when the tool is available and
skips with a stable message otherwise. The optional verification target is not
part of `make guardrails`.
