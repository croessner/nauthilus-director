#!/usr/bin/env bash
#
# Copyright (C) 2026 Christian Rößner
#
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

python3 - <<'PY'
from __future__ import annotations

from dataclasses import dataclass
from email.message import EmailMessage
import json
import os
import poplib
import smtplib
import ssl
import time
import urllib.error
import urllib.request
import uuid


class ProofError(Exception):
    """Report a failed externally visible POP3 demo proof."""


@dataclass
class DemoConfig:
    """Hold POP3 proof settings loaded from environment variables."""

    user: str
    password: str
    mail_host: str
    smtp_port: int
    pop3_port: int
    pop3s_port: int
    control_url: str
    control_token: str
    wait_seconds: float


def int_env(name: str, default: int) -> int:
    """Read a positive integer environment override."""

    value = os.environ.get(name)
    if value is None or value == "":
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ProofError(f"{name} must be an integer") from exc
    if parsed <= 0:
        raise ProofError(f"{name} must be positive")
    return parsed


def load_control_token() -> str:
    """Load the public control API bearer token from environment or file."""

    for name in ("DEMO_CONTROL_TOKEN_FILE", "NAUTHILUS_DIRECTORCTL_BEARER_TOKEN_FILE"):
        path = os.environ.get(name, "").strip()
        if not path:
            continue
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as handle:
                return handle.read().strip()

    return os.environ.get(
        "DEMO_CONTROL_TOKEN",
        os.environ.get("DIRECTOR_CONTROL_TOKEN", "demo-control-token"),
    ).strip()


def load_config() -> DemoConfig:
    """Load the demo POP3 proof configuration."""

    return DemoConfig(
        user=os.environ.get("DEMO_USER", "alice@example.test"),
        password=os.environ.get("DEMO_PASSWORD", "demo-secret"),
        mail_host=os.environ.get("DEMO_MAIL_HOST", "127.0.0.1"),
        smtp_port=int_env("DEMO_SMTP_PORT", 2525),
        pop3_port=int_env("DEMO_POP3_PORT", 8110),
        pop3s_port=int_env("DEMO_POP3S_PORT", 8995),
        control_url=os.environ.get("DEMO_CONTROL_URL", "https://127.0.0.1:9090").rstrip("/"),
        control_token=load_control_token(),
        wait_seconds=float(os.environ.get("DEMO_WAIT_SECONDS", "20")),
    )


def tls_context() -> ssl.SSLContext:
    """Create the demo TLS context for self-signed local certificates."""

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def control_ssl_context(config: DemoConfig) -> ssl.SSLContext | None:
    """Create a TLS context for the demo control API."""

    if not config.control_url.lower().startswith("https://"):
        return None

    cafile = os.environ.get("DEMO_CONTROL_CAFILE", "").strip()
    if cafile:
        return ssl.create_default_context(cafile=cafile)

    return tls_context()


def send_probe_message(config: DemoConfig, token: str) -> None:
    """Inject one message through the public SMTP to Director LMTP path."""

    message = EmailMessage()
    message["From"] = "sender@example.test"
    message["To"] = config.user
    message["Subject"] = "Director POP3 demo proof"
    message.set_content("POP3 demo proof token: " + token)
    with smtplib.SMTP(config.mail_host, config.smtp_port, timeout=config.wait_seconds) as client:
        client.send_message(message)


def request_route(config: DemoConfig, token: str) -> dict[str, object]:
    """Run one side-effect-free POP3 route lookup through the control API."""

    payload = {
        "protocol": "pop3",
        "listener": "pop3",
        "user_key": config.user,
        "include_affinity": True,
    }
    data = json.dumps(payload).encode("utf-8")
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if config.control_token:
        headers["Authorization"] = f"Bearer {config.control_token}"

    request = urllib.request.Request(
        config.control_url + "/api/v1/route/lookup",
        data=data,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(
            request,
            timeout=config.wait_seconds,
            context=control_ssl_context(config),
        ) as response:
            route = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise ProofError(f"could not reach control API at {config.control_url}: {exc}") from exc

    rendered = json.dumps(route, sort_keys=True)
    if token in rendered:
        raise ProofError("route lookup leaked POP3 message material")
    selected = str(route.get("selected_backend") or "")
    if "-pop3" not in selected:
        raise ProofError(f"route lookup did not select a POP3 backend: {route}")
    return route


def connect_starttls(config: DemoConfig) -> poplib.POP3:
    """Open public POP3 and negotiate STLS before authentication."""

    client = poplib.POP3(config.mail_host, config.pop3_port, timeout=config.wait_seconds)
    capabilities = {name.upper() for name in client.capa()}
    if "STLS" not in capabilities:
        raise ProofError(f"POP3 CAPA did not advertise STLS: {sorted(capabilities)}")
    client.stls(context=tls_context())
    capabilities = {name.upper() for name in client.capa()}
    if "STLS" in capabilities:
        raise ProofError("POP3 CAPA still advertised STLS after TLS was active")
    if "USER" not in capabilities:
        raise ProofError(f"POP3 CAPA did not advertise USER after STLS: {sorted(capabilities)}")
    client.user(config.user)
    client.pass_(config.password)
    return client


def connect_implicit_tls(config: DemoConfig) -> poplib.POP3_SSL:
    """Open public POP3S and authenticate through implicit TLS."""

    client = poplib.POP3_SSL(
        config.mail_host,
        config.pop3s_port,
        timeout=config.wait_seconds,
        context=tls_context(),
    )
    capabilities = {name.upper() for name in client.capa()}
    if "STLS" in capabilities:
        raise ProofError("POP3S CAPA advertised STLS on an implicit-TLS listener")
    client.user(config.user)
    client.pass_(config.password)
    return client


def prove_mailbox_read(config: DemoConfig, token: str) -> None:
    """Poll POP3 until the delivered message can be read through the Director."""

    deadline = time.monotonic() + config.wait_seconds
    last_error = "message was not visible yet"
    while time.monotonic() < deadline:
        client: poplib.POP3 | None = None
        try:
            client = connect_starttls(config)
            count, _ = client.stat()
            if count < 1:
                last_error = "POP3 STAT returned an empty maildrop"
                time.sleep(1)
                continue
            _, listings, _ = client.list()
            if not listings:
                last_error = "POP3 LIST returned no messages"
                time.sleep(1)
                continue
            message_numbers: list[int] = []
            for listing in listings:
                fields = listing.decode("utf-8", errors="replace").split()
                if not fields:
                    continue
                message_numbers.append(int(fields[0]))
            if not message_numbers:
                last_error = "POP3 LIST returned no parseable message numbers"
                time.sleep(1)
                continue
            _, uidls, _ = client.uidl()
            if not uidls:
                raise ProofError("POP3 UIDL returned no entries")
            for message_number in message_numbers:
                _, lines, _ = client.retr(message_number)
                body = b"\n".join(lines).decode("utf-8", errors="replace")
                if token in body:
                    return
            last_error = "POP3 RETR did not return the delivered token"
        except (OSError, poplib.error_proto, ValueError) as exc:
            last_error = str(exc)
        finally:
            if client is not None:
                try:
                    client.quit()
                except (OSError, poplib.error_proto):
                    client.close()
        time.sleep(1)

    raise ProofError(last_error)


def prove_implicit_tls(config: DemoConfig) -> None:
    """Prove POP3S auth and a basic mailbox status command."""

    client = connect_implicit_tls(config)
    try:
        count, _ = client.stat()
        if count < 0:
            raise ProofError("POP3S STAT returned an invalid count")
    finally:
        client.quit()


def main() -> int:
    """Run the public POP3 demo proof."""

    config = load_config()
    token = "demo-pop3-" + uuid.uuid4().hex
    send_probe_message(config, token)
    request_route(config, token)
    prove_mailbox_read(config, token)
    prove_implicit_tls(config)
    print("proof ok: POP3 STLS, POP3S auth, mailbox read and route lookup crossed public demo-stack sockets")
    return 0


try:
    raise SystemExit(main())
except ProofError as exc:
    print(f"proof failed: {exc}", flush=True)
    raise SystemExit(1) from exc
PY
