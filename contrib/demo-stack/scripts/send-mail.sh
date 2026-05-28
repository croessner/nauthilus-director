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

recipient="$1"

DEMO_SMTP_HOST="${DEMO_SMTP_HOST:-127.0.0.1}" \
DEMO_SMTP_PORT="${DEMO_SMTP_PORT:-2525}" \
DEMO_SENDER="${DEMO_SENDER:-sender@example.test}" \
DEMO_RECIPIENT="${recipient}" \
python3 - <<'PY'
from email.message import EmailMessage
import os
import smtplib
import time

host = os.environ["DEMO_SMTP_HOST"]
port = int(os.environ["DEMO_SMTP_PORT"])
sender = os.environ["DEMO_SENDER"]
recipient = os.environ["DEMO_RECIPIENT"]
token = f"demo-delivery-{int(time.time())}"

message = EmailMessage()
message["From"] = sender
message["To"] = recipient
message["Subject"] = f"Nauthilus Director demo {token}"
message.set_content(
    "This message travelled through HAProxy, Postfix, LMTPS, "
    f"nauthilus-director and Dovecot.\n\nToken: {token}\n"
)

with smtplib.SMTP(host, port, timeout=20) as client:
    client.send_message(message)

print(f"Delivered demo message to {recipient} with token {token}")
PY
