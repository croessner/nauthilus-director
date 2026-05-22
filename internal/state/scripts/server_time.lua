-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Minimal M0 script used to establish script loading, SHA tracking and Redis
-- server-time conventions before the full affinity mutation scripts exist.
return redis.call("TIME")
