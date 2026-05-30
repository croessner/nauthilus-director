#!/usr/bin/env python3
#
# Copyright (C) 2026 Christian Rößner
#
# SPDX-License-Identifier: AGPL-3.0-only

"""Prove demo-stack IMAP affinity and optional backend pinning."""

from __future__ import annotations

from dataclasses import dataclass
from email.message import EmailMessage
import imaplib
import json
import os
import smtplib
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class ProofError(Exception):
    """Report a failed externally visible demo-stack proof."""


@dataclass
class DemoConfig:
    """Hold demo proof settings loaded from environment variables."""

    mode: str
    user: str
    password: str
    expected_backend: str
    pin_backend: str
    pin_strategy: str
    keep_backend_pin: bool
    control_url: str
    imap_host: str
    imaps_port: int
    smtp_host: str
    smtp_port: int
    sender: str
    followup_count: int
    wait_seconds: float


@dataclass
class HeldSession:
    """Track one frontend IMAP session and its Director runtime record."""

    label: str
    session_id: str
    backend: str
    client: imaplib.IMAP4_SSL


def bool_env(name: str, default: bool = False) -> bool:
    """Parse a conservative boolean environment variable."""

    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def int_env(name: str, default: int) -> int:
    """Parse a positive integer environment variable."""

    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ProofError(f"{name} must be an integer") from exc
    if value < 1:
        raise ProofError(f"{name} must be greater than zero")
    return value


def load_config() -> DemoConfig:
    """Load runtime proof configuration from the shell environment."""

    mode = os.environ.get("DEMO_PROOF_MODE", "affinity").strip()
    if mode not in {"affinity", "backend-pin"}:
        raise ProofError("DEMO_PROOF_MODE must be affinity or backend-pin")

    user = os.environ.get("DEMO_USER", "alice@example.test").strip()
    if not user:
        raise ProofError("DEMO_USER must not be empty")

    pin_backend = os.environ.get("DEMO_PIN_BACKEND", "").strip()
    expected_backend = os.environ.get("DEMO_EXPECTED_BACKEND", pin_backend).strip()
    if mode == "backend-pin" and not pin_backend:
        raise ProofError("DEMO_PIN_BACKEND is required for backend-pin mode")

    return DemoConfig(
        mode=mode,
        user=user,
        password=os.environ.get("DEMO_PASSWORD", "demo-secret"),
        expected_backend=expected_backend,
        pin_backend=pin_backend,
        pin_strategy=os.environ.get("DEMO_PIN_STRATEGY", "kick_existing").strip(),
        keep_backend_pin=bool_env("DEMO_KEEP_BACKEND_PIN", False),
        control_url=os.environ.get("DEMO_CONTROL_URL", "http://127.0.0.1:9090").rstrip("/"),
        imap_host=os.environ.get("DEMO_IMAP_HOST", "127.0.0.1"),
        imaps_port=int_env("DEMO_IMAPS_PORT", 8993),
        smtp_host=os.environ.get("DEMO_SMTP_HOST", "127.0.0.1"),
        smtp_port=int_env("DEMO_SMTP_PORT", 2525),
        sender=os.environ.get("DEMO_SENDER", "sender@example.test"),
        followup_count=int_env("DEMO_FOLLOWUP_COUNT", 2),
        wait_seconds=float(os.environ.get("DEMO_WAIT_SECONDS", "20")),
    )


def user_path(config: DemoConfig, suffix: str) -> str:
    """Build a URL path for one runtime user key."""

    encoded = urllib.parse.quote(config.user, safe="")
    return f"/api/v1/users/{encoded}{suffix}"


def request_json(
    config: DemoConfig,
    method: str,
    path: str,
    payload: dict[str, object] | None = None,
    ok_statuses: set[int] | None = None,
) -> dict[str, object]:
    """Perform one JSON request against the public control API."""

    statuses = ok_statuses or {200}
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        config.control_url + path,
        data=data,
        headers=headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(request, timeout=config.wait_seconds) as response:
            body = response.read()
            if response.status not in statuses:
                raise ProofError(f"{method} {path} returned HTTP {response.status}")
            if not body:
                return {}
            return json.loads(body.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        if exc.code in statuses:
            return {"http_status": exc.code, "error": body}
        raise ProofError(f"{method} {path} returned HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise ProofError(f"could not reach control API at {config.control_url}: {exc}") from exc


def user_sessions(config: DemoConfig) -> list[dict[str, object]]:
    """Return active runtime sessions for the configured user."""

    data = request_json(config, "GET", user_path(config, "/sessions"))
    sessions = data.get("sessions") or []
    return [session for session in sessions if isinstance(session, dict)]


def imap_sessions(config: DemoConfig) -> list[dict[str, object]]:
    """Return active IMAP sessions for the configured user."""

    return [
        session
        for session in user_sessions(config)
        if session.get("protocol") == "imap"
    ]


def clear_backend_pin(config: DemoConfig, reason: str) -> None:
    """Remove any existing backend pin for a repeatable demo run."""

    request_json(
        config,
        "DELETE",
        user_path(config, "/backend-pin"),
        {"reason": reason},
        ok_statuses={202, 404},
    )


def clear_affinity(config: DemoConfig, reason: str) -> None:
    """Remove inactive affinity for a repeatable demo run."""

    request_json(
        config,
        "DELETE",
        user_path(config, "/affinity"),
        {"reason": reason},
        ok_statuses={202, 404},
    )


def ensure_no_active_imap_sessions(config: DemoConfig) -> None:
    """Refuse to disturb an already active user proof session."""

    active = imap_sessions(config)
    if active:
        session_ids = ", ".join(str(session.get("session_id")) for session in active)
        raise ProofError(
            f"{config.user} already has active IMAP sessions: {session_ids}; "
            "log them out before running this proof"
        )


def set_backend_pin(config: DemoConfig) -> None:
    """Set and verify one concrete backend pin through the control API."""

    request_json(
        config,
        "PUT",
        user_path(config, "/backend-pin"),
        {
            "backend": config.pin_backend,
            "strategy": config.pin_strategy,
            "reason": "demo backend pin proof",
        },
        ok_statuses={202},
    )
    pin = request_json(config, "GET", user_path(config, "/backend-pin"))
    if not pin.get("present") or pin.get("backend") != config.pin_backend:
        raise ProofError(f"backend pin was not visible after set: {pin}")
    print(
        "backend pin set: "
        f"user={config.user} backend={config.pin_backend} strategy={config.pin_strategy}"
    )


def open_imap_client(config: DemoConfig) -> imaplib.IMAP4_SSL:
    """Open and authenticate one public IMAPS frontend session."""

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    client = imaplib.IMAP4_SSL(
        config.imap_host,
        config.imaps_port,
        ssl_context=context,
        timeout=config.wait_seconds,
    )
    status, detail = client.login(config.user, config.password)
    if status != "OK":
        raise ProofError(f"IMAP login failed: {detail!r}")
    status, detail = client.select("INBOX")
    if status != "OK":
        raise ProofError(f"could not select INBOX: {detail!r}")
    return client


def wait_for_new_imap_session(
    config: DemoConfig,
    known_session_ids: set[str],
) -> dict[str, object]:
    """Wait until the control API exposes the newly opened IMAP session."""

    deadline = time.monotonic() + config.wait_seconds
    while time.monotonic() < deadline:
        for session in imap_sessions(config):
            session_id = str(session.get("session_id") or "")
            if session_id and session_id not in known_session_ids:
                return session
        time.sleep(0.2)
    raise ProofError("new IMAP session did not appear in runtime state")


def hold_session(
    config: DemoConfig,
    label: str,
    known_session_ids: set[str],
) -> HeldSession:
    """Open one IMAP session and bind it to its runtime backend record."""

    client = open_imap_client(config)
    try:
        record = wait_for_new_imap_session(config, known_session_ids)
        session_id = str(record.get("session_id") or "")
        backend = str(record.get("backend") or "")
        if not session_id or not backend:
            raise ProofError(f"session record is incomplete: {record}")
        known_session_ids.add(session_id)
        print(f"{label}: session={session_id} backend={backend}")
        return HeldSession(label=label, session_id=session_id, backend=backend, client=client)
    except Exception:
        client.logout()
        raise


def send_demo_mail(config: DemoConfig, token: str) -> None:
    """Inject one message through the public SMTP to LMTP delivery path."""

    message = EmailMessage()
    message["From"] = config.sender
    message["To"] = config.user
    message["Subject"] = f"Nauthilus Director affinity proof {token}"
    message.set_content(
        "This message proves SMTP to LMTPS delivery while an IMAP session "
        "keeps active affinity.\n\n"
        f"Token: {token}\n"
    )

    with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=config.wait_seconds) as client:
        client.send_message(message)


def fetch_contains_token(client: imaplib.IMAP4_SSL, token: str) -> bool:
    """Return whether the mailbox contains a recently delivered token."""

    status, _ = client.select("INBOX")
    if status != "OK":
        return False
    status, data = client.search(None, "ALL")
    if status != "OK" or not data or not data[0]:
        return False

    message_ids = data[0].split()
    for message_id in reversed(message_ids[-20:]):
        status, fetched = client.fetch(message_id, "(BODY.PEEK[])")
        if status != "OK":
            continue
        payload = b""
        for item in fetched:
            if isinstance(item, tuple):
                payload += item[1]
        if token in payload.decode("utf-8", errors="replace"):
            return True
    return False


def wait_for_delivery(config: DemoConfig, client: imaplib.IMAP4_SSL, token: str) -> None:
    """Wait until the LMTP-delivered message is visible through IMAP."""

    deadline = time.monotonic() + config.wait_seconds
    while time.monotonic() < deadline:
        if fetch_contains_token(client, token):
            print(f"delivery visible through IMAP: token={token}")
            return
        time.sleep(0.5)
    raise ProofError(f"delivered message token was not visible through IMAP: {token}")


def close_sessions(sessions: list[HeldSession]) -> None:
    """Logout held IMAP sessions without hiding the original proof failure."""

    for session in reversed(sessions):
        try:
            session.client.logout()
        except Exception as exc:  # noqa: BLE001
            print(f"warning: could not logout {session.label}: {exc}", file=sys.stderr)


def prepare_runtime(config: DemoConfig) -> None:
    """Prepare repeatable user runtime state for the requested proof mode."""

    ensure_no_active_imap_sessions(config)
    clear_backend_pin(config, "demo proof reset")
    clear_affinity(config, "demo proof reset")
    if config.mode == "backend-pin":
        set_backend_pin(config)
    else:
        print(f"backend pin cleared: user={config.user}")


def prove_flow(config: DemoConfig) -> None:
    """Run the externally visible mail affinity proof."""

    prepare_runtime(config)
    known_ids = {str(session.get("session_id")) for session in imap_sessions(config)}
    held: list[HeldSession] = []
    token = f"demo-proof-{uuid.uuid4().hex[:12]}"
    delivery_error: list[BaseException] = []

    def deliver() -> None:
        """Run SMTP delivery while IMAP sessions are active."""

        try:
            send_demo_mail(config, token)
        except BaseException as exc:  # noqa: BLE001
            delivery_error.append(exc)

    try:
        primary = hold_session(config, "primary IMAP", known_ids)
        held.append(primary)

        expected_backend = config.expected_backend or primary.backend
        if primary.backend != expected_backend:
            raise ProofError(
                f"primary session backend {primary.backend} != expected {expected_backend}"
            )

        delivery_thread = threading.Thread(target=deliver, name="demo-lmtp-delivery")
        delivery_thread.start()
        print(
            "SMTP to LMTP delivery started while primary IMAP remains active: "
            f"token={token}"
        )

        for index in range(config.followup_count):
            followup = hold_session(config, f"follow-up IMAP {index + 1}", known_ids)
            held.append(followup)
            if followup.backend != expected_backend:
                raise ProofError(
                    f"{followup.label} backend {followup.backend} != {expected_backend}"
                )

        delivery_thread.join(timeout=config.wait_seconds)
        if delivery_thread.is_alive():
            raise ProofError("SMTP to LMTP delivery did not finish in time")
        if delivery_error:
            raise ProofError(f"SMTP to LMTP delivery failed: {delivery_error[0]}")

        wait_for_delivery(config, primary.client, token)
        print(
            "proof ok: "
            f"mode={config.mode} user={config.user} backend={expected_backend} "
            f"followups={config.followup_count}"
        )
    finally:
        close_sessions(held)
        if config.mode == "backend-pin" and not config.keep_backend_pin:
            clear_backend_pin(config, "demo backend pin proof cleanup")
            print(f"backend pin cleared after proof: user={config.user}")


def main() -> int:
    """Run the command-line proof and return a process exit code."""

    try:
        prove_flow(load_config())
        return 0
    except ProofError as exc:
        print(f"proof failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
