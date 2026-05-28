#!/bin/sh
#
# Copyright (C) 2026 Christian Rößner
#
# SPDX-License-Identifier: AGPL-3.0-only

set -eu

relay="${DIRECTOR_LMTPS_RELAY:-haproxy:2465}"

postconf -c /etc/postfix -e "myhostname = postfix.demo.local"
postconf -c /etc/postfix -e "inet_interfaces = all"
postconf -c /etc/postfix -e "inet_protocols = ipv4"
postconf -c /etc/postfix -e "mydestination ="
postconf -c /etc/postfix -e "mynetworks = 0.0.0.0/0"
postconf -c /etc/postfix -e "smtpd_recipient_restrictions = permit_mynetworks,reject_unauth_destination"
postconf -c /etc/postfix -e "local_transport = error:local delivery disabled"
postconf -c /etc/postfix -e "relay_transport = lmtp:inet:${relay}"
postconf -c /etc/postfix -e "default_transport = lmtp:inet:${relay}"
postconf -c /etc/postfix -e "lmtp_tls_security_level = encrypt"
postconf -c /etc/postfix -e "lmtp_tls_wrappermode = yes"
postconf -c /etc/postfix -e "lmtp_tls_mandatory_protocols = >=TLSv1.2"
postconf -c /etc/postfix -e "lmtp_tls_loglevel = 1"
