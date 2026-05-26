-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Marks all active sessions for one affinity key for controlled shutdown.

local state_key = KEYS[1]
local sessions_key = KEYS[2]

local reason = ARGV[1]
local actor = ARGV[2]

local function now_ms()
	local now = redis.call("TIME")
	return (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
end

local now = now_ms()
redis.call("ZREMRANGEBYSCORE", sessions_key, "-inf", now)

if redis.call("EXISTS", state_key) == 0 then
	return {
		"status", "missing",
		"present", "0",
		"shard_tag", "",
		"target_shard", "",
		"strategy", "",
		"generation", "",
		"control_generation", "",
		"control_action", "none",
		"active_session_count", "0",
		"server_time_ms", tostring(now)
	}
end

local generation = redis.call("HINCRBY", state_key, "control_generation", 1)
local shard = redis.call("HGET", state_key, "shard_tag") or ""
local active_count = redis.call("ZCARD", sessions_key)

redis.call("HSET", state_key,
	"control_action", "kick",
	"kick_generation", generation,
	"kick_reason", reason or "",
	"kick_actor", actor or "",
	"updated_at_ms", now)

return {
	"status", "kicked",
	"present", "1",
	"shard_tag", shard,
	"target_shard", "",
	"strategy", "",
	"generation", tostring(generation),
	"control_generation", tostring(generation),
	"control_action", "kick",
	"active_session_count", tostring(active_count),
	"server_time_ms", tostring(now)
}
