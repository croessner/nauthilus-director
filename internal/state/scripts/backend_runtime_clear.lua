-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Clears runtime-only backend overrides while preserving configured baseline
-- facts and Redis-coordinated active-session counts.

local backend_key = KEYS[1]
local backend_index_key = KEYS[2]

local backend_id = ARGV[1]
local reason = ARGV[2]
local actor = ARGV[3]

local function ambiguous(message)
	error("NDAMBIGUOUS " .. message)
end

local function now_ms()
	local now = redis.call("TIME")
	return (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
end

if backend_id == nil or backend_id == "" then
	return ambiguous("backend_id_required")
end

local now = now_ms()
local generation = redis.call("HINCRBY", backend_key, "generation", 1)
local active_count = tonumber(redis.call("HGET", backend_key, "active_session_count") or "0")
if active_count == nil or active_count < 0 then
	return ambiguous("backend_count_invalid")
end

redis.call("HDEL", backend_key,
	"in_service",
	"weight",
	"maintenance_mode",
	"drain_enabled",
	"drain_mode",
	"drain_started_at_ms")
redis.call("HSET", backend_key,
	"backend_id", backend_id,
	"active_session_count", active_count,
	"updated_at_ms", now,
	"last_clear_reason", reason or "",
	"last_clear_actor", actor or "")
redis.call("SADD", backend_index_key, backend_id)

return {
	"status", "cleared",
	"backend_id", backend_id,
	"generation", tostring(generation),
	"active_session_count", tostring(active_count),
	"marked_session_count", "0",
	"server_time_ms", tostring(now)
}
