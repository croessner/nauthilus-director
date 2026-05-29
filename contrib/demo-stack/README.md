# Nauthilus Director Demo Stack

This stack is a runnable integration playground for the production Director path. The Director image is built from this repository; every other image is pinned through `.env.example`.

## Topology

- HAProxy publishes SMTP, IMAP, IMAPS and LMTPS on host ports.
- SMTP goes to Postfix first. Postfix relays mail back through HAProxy over LMTPS to the two Director instances.
- IMAP, IMAPS and LMTPS traffic from HAProxy to the Directors uses the PROXY protocol.
- The Directors own backend selection, health handling, affinity and metrics.
- Nauthilus is intentionally lean in this stack: LDAP/cache identity, LDAP-backed `mailShard` routing facts and a small Lua environment hook only.
- The Directors authenticate against Nauthilus through the TLS-protected gRPC AuthService.
- Three Dovecot 2.4 containers provide IMAPS and LMTPS backend shards.
- OpenLDAP contains four demo users. Nauthilus uses LDAP with cache in front.

The current production Director supports IMAP and LMTP listeners. Direct SMTP-to-Director ingress is therefore not part of this demo yet; SMTP is represented by the HAProxy-to-Postfix-to-LMTPS path until SMTP listener support is added.

## Demo Users

All users use the password `demo-secret`.

| User | Shard |
| --- | --- |
| `alice@example.test` | `mailstore-a` |
| `bob@example.test` | `mailstore-b` |
| `carol@example.test` | `mailstore-c` |
| `dave@example.test` | `mailstore-a` |

## Run

```bash
cd contrib/demo-stack
cp .env.example .env
docker compose up --build -d
```

Useful host ports:

| Service | Host port |
| --- | --- |
| SMTP through HAProxy/Postfix | `2525` |
| IMAP through HAProxy/Director | `8143` |
| IMAPS through HAProxy/Director | `8993` |
| LMTPS through HAProxy/Director | `8024` |
| HAProxy stats | `8404` |
| Director A control API | `9090` |
| Director B control API | `9091` |

## Smoke Test

```bash
./scripts/send-mail.sh alice@example.test
./scripts/fetch-mail.sh alice@example.test
```

The scripts also accept the other demo users. To keep the demo simple, frontend and backend TLS certificates are self-signed and the test fetcher disables certificate verification.
The stack also generates an internal demo CA for Director-to-Nauthilus gRPC TLS in the `grpc-tls` volume.

## Runtime State Reset

The demo uses Redis schema version `1` with the development-stage runtime key layout. It is not a published production compatibility contract and this stack is not sized or tuned as a million-session load environment.

If an older demo run left incompatible runtime keys behind, stop the Directors and either let the short-lived session and reservation leases expire, or clear the isolated demo Valkey database explicitly:

```bash
docker compose stop director-a director-b
docker compose exec valkey valkey-cli FLUSHDB
docker compose up -d director-a director-b
```

`docker compose down -v` also recreates demo-only state when you want a completely clean lab. Do not use these reset commands against a Redis database that carries active production sessions.

If you change the LDAP schema or bootstrap data after the first run, recreate the demo volumes with `docker compose down -v` before starting the stack again.

## Inspect

```bash
docker compose ps
docker compose logs -f director-a director-b
docker compose exec director-a nauthilus-directorctl --address http://127.0.0.1:9090 status
```

## Stop

```bash
docker compose down -v
```
