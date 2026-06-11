# Reload, Shutdown And Upgrade

This runbook documents the production lifecycle model for
`nauthilus-director`.

## Safe Reload Model

Reload is explicit and goes through the same safe-reload service whether it is
called by REST, CLI or systemd:

```sh
nauthilus-directorctl --address http://127.0.0.1:9090 reload
systemctl reload nauthilus-director.service
```

systemd `ExecReload` uses `nauthilus-directorctl reload`. It is not `SIGHUP`,
does not patch YAML and does not bypass control-plane authentication.

A rejected reload is atomic. The old process keeps serving with its previous
accepted config snapshot, active sessions remain attached to their existing
backend/proxy objects, and Redis-backed runtime state is not cleared.

## Reloadable Changes

Safe reload accepts only configuration classes with a live owner in the running
process:

| Config class | Reload behavior |
| --- | --- |
| Listener additions | New listener starts for future connections. |
| Listener removals | Removed listener stops accepting new connections. Existing sessions close through normal lifecycle or explicit drain/kick. |
| `director.backends.*` registry changes | New sessions use the accepted backend registry snapshot. Existing sessions keep established backend objects. |
| `director.backend_pools.*` changes | New sessions use the accepted pool snapshot after validation. |

Reload does not move existing sessions, clear active affinity, clear retained
backend bindings, clear backend pins, clear placement holds or rewrite YAML.

## Restart-Required Changes

Restart is required for process-owned or security-sensitive configuration:

| Config class | Why restart is required |
| --- | --- |
| `runtime.*` | Process identity, control listener and shutdown behavior are process-owned. |
| `auth.*` | Authority transports, OIDC caller auth and mechanism policy are security-sensitive. |
| `storage.redis.*` | Redis connection and namespace shape own the runtime state backend. |
| `observability.*` | Logging, tracing, metrics and pprof profile route/sampler behavior are process-wide. |
| `director.routing`, `director.affinity` | Routing and backend-node affinity invariants affect placement correctness. |
| `director.runtime_overrides` | Operator permissions must not change through an ambiguous partial reload. |
| `director.health`, `director.maintenance`, `director.security` | Health and maintenance policy affects fail-closed placement. |
| Existing `director.listeners.*` edits | Socket, TLS, authority, protocol and backend-pool settings belong to the existing listener object. |

If safe reload reports a restart-required reason, choose a restart window or
roll back the config edit and reload again.

## Breaking Config Changes

The Redis Cluster replica-read switch is named for the routing behavior it
enables. Replace the old ambiguous path:

```yaml
storage:
  redis:
    cluster:
      read_only: true
```

with:

```yaml
storage:
  redis:
    cluster:
      route_reads_to_replicas: true
```

The old `storage.redis.cluster.read_only` path is not accepted. Redis connection
settings are restart-required, so apply this change during a Director restart.

## Graceful Shutdown

`SIGTERM` and `SIGINT` are graceful shutdown signals. The default systemd unit
uses `KillSignal=SIGTERM` and aligns its timeout with
`runtime.process.shutdown_timeout`.

During shutdown, the process stops accepting new connections, closes managed
listeners and gives active sessions a bounded window to close. Runtime state is
lease-based in Redis; cleanup converges through normal close, heartbeat expiry
and reaper behavior. Do not clear Redis keys as a shutdown shortcut while
production sessions may still exist.

## Upgrade Preflight

Before changing binaries or restart-required config, collect a small,
secret-safe baseline:

```sh
nauthilus-director --version
nauthilus-directorctl --version
nauthilus-director config dump -n --format yaml
nauthilus-directorctl --address http://127.0.0.1:9090 status
nauthilus-directorctl --address http://127.0.0.1:9090 runtime summary
```

Use `config dump -P` only when protected output is required and authorized.

## Rolling Upgrade Flow

For each Director instance behind an external load balancer:

1. Check runtime state:

   ```sh
   CTL='nauthilus-directorctl --address http://127.0.0.1:9090'
   $CTL status
   $CTL runtime summary
   $CTL listeners list
   ```

2. Drain public listeners on the instance:

   ```sh
   $CTL listeners drain imap --mode soft --reason "upgrade director instance"
   $CTL listeners drain pop3 --mode soft --reason "upgrade director instance"
   $CTL listeners drain sieve --mode soft --reason "upgrade director instance"
   ```

3. For backends hosted behind the same maintenance window, use soft backend
   maintenance or drain rather than editing YAML:

   ```sh
   $CTL backends maintenance enable mailstore-a-imap \
     --mode soft \
     --reason "preserve active sessions during backend maintenance"
   ```

4. Wait for active sessions to drain naturally, or use explicit user/session
   kicks when the maintenance window requires it:

   ```sh
   $CTL sessions list --limit 100
   $CTL users sessions alice@example.org
   ```

5. Install the new binaries and restart:

   ```sh
   make build
   install -m 0755 bin/nauthilus-director /usr/local/bin/nauthilus-director
   install -m 0755 bin/nauthilus-directorctl /usr/local/bin/nauthilus-directorctl
   systemctl restart nauthilus-director.service
   ```

6. Verify readiness and routing:

   ```sh
   $CTL status
   $CTL runtime summary
   $CTL route lookup --protocol imap --user alice@example.org --backend-pool imap-default
   ```

7. Resume listeners and clear temporary runtime maintenance state:

   ```sh
   $CTL listeners resume imap --reason "upgrade complete"
   $CTL backends maintenance disable mailstore-a-imap --reason "maintenance complete"
   ```

## Container Upgrade Flow

For container deployments, build or pull an immutable image tag, mount the same
reviewed config and secret files, then replace one Director instance at a time.
Keep the root filesystem read-only and provide writable `/tmp` and
`/run/nauthilus-director` tmpfs mounts.

Preflight:

```sh
make docker-build IMAGE_TAG=registry.example.org/nauthilus-director:v1.0.0
make docker-smoke IMAGE_TAG=registry.example.org/nauthilus-director:v1.0.0
```

The optional Docker targets skip with stable messages when Docker is not
available. They are not part of `make guardrails`.

## Rollback

Reload rollback is usually another safe reload with the last accepted
reloadable config. Restart rollback uses the previously installed binary and
reviewed config snapshot. Runtime state cleanup is explicit:

```sh
nauthilus-directorctl users hold clear alice@example.org --reason "rollback cleanup"
nauthilus-directorctl users backend-pin clear alice@example.org --reason "rollback cleanup"
nauthilus-directorctl users affinity clear alice@example.org --reason "clear inactive stale affinity after rollback"
```

Use `users affinity clear` only when no active sessions remain and the durable
routing source is already correct.
