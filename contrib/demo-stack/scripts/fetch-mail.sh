#!/usr/bin/env bash
#
# Copyright (C) 2026 Christian Rößner
#
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

if [[ $# -ne 1 ]]; then
  printf 'usage: %s <user>\n' "$0" >&2
  exit 64
fi

user="$1"

DEMO_IMAP_HOST="${DEMO_IMAP_HOST:-127.0.0.1}" \
DEMO_IMAPS_PORT="${DEMO_IMAPS_PORT:-8993}" \
DEMO_PASSWORD="${DEMO_PASSWORD:-demo-secret}" \
DEMO_USER="${user}" \
python3 - <<'PY'
import imaplib
import os
import ssl
import sys

host = os.environ["DEMO_IMAP_HOST"]
port = int(os.environ["DEMO_IMAPS_PORT"])
user = os.environ["DEMO_USER"]
password = os.environ["DEMO_PASSWORD"]

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

with imaplib.IMAP4_SSL(host, port, ssl_context=context) as client:
    client.login(user, password)
    status, _ = client.select("INBOX")
    if status != "OK":
        raise SystemExit("could not select INBOX")

    status, data = client.search(None, "ALL")
    if status != "OK" or not data or not data[0]:
        raise SystemExit(f"no messages found for {user}")

    message_ids = data[0].split()
    latest = message_ids[-1]
    status, fetched = client.fetch(latest, "(BODY.PEEK[])")
    if status != "OK":
        raise SystemExit(f"could not fetch message {latest.decode()}")

    payload = b""
    for item in fetched:
        if isinstance(item, tuple):
            payload += item[1]

    print(f"Fetched message {latest.decode()} for {user}:")
    for line in payload.decode("utf-8", errors="replace").splitlines()[:20]:
        print(line)

    client.logout()
PY
