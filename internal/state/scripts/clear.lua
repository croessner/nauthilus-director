-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Clears inactive affinity state and pending overrides without force-closing
-- active sessions.

local state_key = KEYS[1]
local sessions_key = KEYS[2]
local override_key = KEYS[3]

local allow_active_clear = ARGV[1]
local reason = ARGV[2]
local actor = ARGV[3]

local function ambiguous(message)
	error("NDAMBIGUOUS " .. message)
end

local function now_ms()
	local now = redis.call("TIME")
	return (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
end

local now = now_ms()
redis.call("ZREMRANGEBYSCORE", sessions_key, "-inf", now)

local active_count = redis.call("ZCARD", sessions_key)
if active_count > 0 and allow_active_clear ~= "1" then
	return ambiguous("active_affinity")
end

local shard = redis.call("HGET", state_key, "shard_tag") or ""
local generation = redis.call("HINCRBY", override_key, "generation", 1)
redis.call("HSET", override_key,
	"last_clear_generation", generation,
	"last_clear_reason", reason or "",
	"last_clear_actor", actor or "",
	"updated_at_ms", now)

redis.call("DEL", state_key)
redis.call("DEL", sessions_key)
redis.call("DEL", override_key)

return {
	"status", "cleared",
	"present", "0",
	"shard_tag", shard,
	"target_shard", "",
	"strategy", "",
	"generation", tostring(generation),
	"control_generation", tostring(generation),
	"control_action", "none",
	"active_session_count", "0",
	"server_time_ms", tostring(now)
}
