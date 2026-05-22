-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Minimal script used to verify script loading, SHA tracking and Redis
-- server-time conventions.
return redis.call("TIME")
