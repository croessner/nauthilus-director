#!/usr/bin/env bash
#
# Copyright (C) 2026 Christian Rößner
#
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

python3 - <<'PY'
from __future__ import annotations

from dataclasses import dataclass
import base64
import json
import os
import select
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid


class ProofError(Exception):
    """Report a failed externally visible ManageSieve demo proof."""


@dataclass
class DemoConfig:
    """Hold ManageSieve proof settings loaded from environment variables."""

    user: str
    password: str
    sieve_host: str
    sieve_port: int
    sieves_port: int
    control_url: str
    control_token: str
    wait_seconds: float


class SieveClient:
    """Small RFC 5804 client for public demo-stack proof traffic."""

    def __init__(self, sock: socket.socket, wait_seconds: float) -> None:
        self.sock = sock
        self.wait_seconds = wait_seconds
        self.file = sock.makefile("rb")

    @classmethod
    def connect_plain(cls, host: str, port: int, wait_seconds: float) -> "SieveClient":
        """Open a cleartext ManageSieve socket."""

        sock = socket.create_connection((host, port), timeout=wait_seconds)
        sock.settimeout(wait_seconds)
        return cls(sock, wait_seconds)

    @classmethod
    def connect_tls(cls, host: str, port: int, wait_seconds: float) -> "SieveClient":
        """Open an implicit-TLS ManageSieve socket."""

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((host, port), timeout=wait_seconds)
        tls_sock = context.wrap_socket(sock, server_hostname=host)
        tls_sock.settimeout(wait_seconds)
        return cls(tls_sock, wait_seconds)

    def close(self) -> None:
        """Close the socket without hiding proof failures."""

        try:
            self.sock.close()
        except OSError:
            pass

    def send_line(self, line: str) -> None:
        """Send one CRLF-terminated ManageSieve command."""

        self.sock.sendall(line.encode("utf-8") + b"\r\n")

    def read_response(self) -> list[str]:
        """Read a ManageSieve response block through the next status line."""

        lines: list[str] = []
        deadline = time.monotonic() + self.wait_seconds
        while time.monotonic() < deadline:
            raw = self.file.readline()
            if not raw:
                raise ProofError("ManageSieve connection closed while reading response")
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            lines.append(line)
            if line.startswith(("OK", "NO", "BYE")):
                return lines
        raise ProofError("timed out waiting for ManageSieve response")

    def expect_status(self, prefix: str) -> list[str]:
        """Require a response with the expected final status prefix."""

        response = self.read_response()
        if not response[-1].startswith(prefix):
            raise ProofError(f"unexpected ManageSieve response status: {response!r}")
        return response

    def drain_optional_status(self, label: str) -> None:
        """Drain an immediate backend status emitted after proxy handoff."""

        ready, _, _ = select.select([self.sock], [], [], min(1.0, self.wait_seconds))
        if not ready:
            return
        response = self.read_response()
        if not response[-1].startswith("OK"):
            raise ProofError(f"unexpected {label} status: {response!r}")

    def starttls(self) -> None:
        """Upgrade the cleartext connection with STARTTLS."""

        self.send_line("STARTTLS")
        self.expect_status("OK")
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        tls_sock = context.wrap_socket(self.sock, server_hostname=None)
        tls_sock.settimeout(self.wait_seconds)
        self.sock = tls_sock
        self.file = tls_sock.makefile("rb")

    def authenticate_plain(self, user: str, password: str, expected_prefix: str = "OK") -> list[str]:
        """Authenticate with SASL PLAIN."""

        payload = base64.b64encode(f"\0{user}\0{password}".encode("utf-8")).decode("ascii")
        self.send_line(f'AUTHENTICATE "PLAIN" "{payload}"')
        return self.expect_status(expected_prefix)


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
    """Load runtime proof configuration from the shell environment."""

    user = os.environ.get("DEMO_USER", "alice@example.test").strip()
    if not user:
        raise ProofError("DEMO_USER must not be empty")

    return DemoConfig(
        user=user,
        password=os.environ.get("DEMO_PASSWORD", "demo-secret"),
        sieve_host=os.environ.get("DEMO_SIEVE_HOST", "127.0.0.1"),
        sieve_port=int_env("DEMO_SIEVE_PORT", 4190),
        sieves_port=int_env("DEMO_SIEVES_PORT", 8490),
        control_url=os.environ.get("DEMO_CONTROL_URL", "https://127.0.0.1:9090").rstrip("/"),
        control_token=load_control_token(),
        wait_seconds=float(os.environ.get("DEMO_WAIT_SECONDS", "20")),
    )


def control_ssl_context(config: DemoConfig) -> ssl.SSLContext | None:
    """Create a TLS context for the demo control API."""

    if not config.control_url.lower().startswith("https://"):
        return None

    cafile = os.environ.get("DEMO_CONTROL_CAFILE", "").strip()
    if cafile:
        return ssl.create_default_context(cafile=cafile)

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def require_capability(response: list[str], capability: str) -> None:
    """Verify a quoted ManageSieve capability is present."""

    wanted = f'"{capability.upper()}"'
    if not any(line.upper().startswith(wanted) for line in response):
        raise ProofError(f"ManageSieve capability {capability} missing: {response!r}")


def request_json(config: DemoConfig, path: str, payload: dict[str, object]) -> dict[str, object]:
    """Perform one JSON POST request against the public control API."""

    data = json.dumps(payload).encode("utf-8")
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if config.control_token:
        headers["Authorization"] = f"Bearer {config.control_token}"

    request = urllib.request.Request(
        config.control_url + path,
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
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise ProofError(f"could not reach control API at {config.control_url}: {exc}") from exc


def assert_safe_route(route: dict[str, object], script_name: str, script_body: str) -> None:
    """Verify route lookup returns placement metadata without script data."""

    rendered = json.dumps(route, sort_keys=True)
    if script_name in rendered or script_body in rendered:
        raise ProofError("route lookup leaked ManageSieve script material")
    if not route.get("selected_backend"):
        raise ProofError(f"route lookup did not select a Sieve backend: {route}")


def prove_starttls_flow(config: DemoConfig, script_name: str, script_body: str) -> None:
    """Prove public STARTTLS auth and script-management proxying."""

    client = SieveClient.connect_plain(config.sieve_host, config.sieve_port, config.wait_seconds)
    try:
        greeting = client.read_response()
        require_capability(greeting, "STARTTLS")
        client.authenticate_plain(config.user, config.password, "NO")
        client.starttls()
        client.send_line("CAPABILITY")
        require_capability(client.expect_status("OK"), "SASL")
        client.authenticate_plain(config.user, config.password)
        client.drain_optional_status("backend login")
        client.send_line("LISTSCRIPTS")
        client.expect_status("OK")
        client.send_line(f'PUTSCRIPT "{script_name}" "{script_body}"')
        client.expect_status("OK")
        client.send_line(f'SETACTIVE "{script_name}"')
        client.expect_status("OK")
        client.send_line("LISTSCRIPTS")
        listed = client.expect_status("OK")
        if script_name not in "\n".join(listed):
            raise ProofError("new Sieve script was not listed by the backend")
        client.send_line(f'GETSCRIPT "{script_name}"')
        fetched = client.expect_status("OK")
        if script_body not in "\n".join(fetched):
            raise ProofError("new Sieve script content was not returned by the backend")

        route = request_json(
            config,
            "/api/v1/route/lookup",
            {
                "protocol": "sieve",
                "listener": "sieve",
                "user_key": config.user,
                "include_affinity": True,
            },
        )
        assert_safe_route(route, script_name, script_body)
        print(
            "STARTTLS ManageSieve proof ok: "
            f"user={config.user} backend={route.get('selected_backend')}"
        )
    finally:
        client.close()


def prove_implicit_tls_flow(config: DemoConfig) -> None:
    """Prove public implicit-TLS ManageSieve auth."""

    client = SieveClient.connect_tls(config.sieve_host, config.sieves_port, config.wait_seconds)
    try:
        greeting = client.read_response()
        require_capability(greeting, "SASL")
        client.authenticate_plain(config.user, config.password)
        client.drain_optional_status("backend login")
        client.send_line("LISTSCRIPTS")
        client.expect_status("OK")
        print(f"implicit-TLS ManageSieve proof ok: user={config.user}")
    finally:
        client.close()


def main() -> int:
    """Run the command-line proof and return a process exit code."""

    try:
        config = load_config()
        script_name = "demo-sieve-" + uuid.uuid4().hex[:12]
        script_body = "keep;"
        prove_starttls_flow(config, script_name, script_body)
        prove_implicit_tls_flow(config)
        print("proof ok: ManageSieve auth and script-management operations crossed public demo-stack sockets")
        return 0
    except ProofError as exc:
        print(f"proof failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
PY
