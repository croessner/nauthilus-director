-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Marks one indexed session for controlled shutdown through heartbeat.

local session_index_key = KEYS[1]

local session_id = ARGV[1]
local reason = ARGV[2]
local actor = ARGV[3]

local function ambiguous(message)
	error("NDAMBIGUOUS " .. message)
end

local function now_ms()
	local now = redis.call("TIME")
	return (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
end

local function require_value(value, message)
	if value == false or value == nil or value == "" then
		return ambiguous(message)
	end

	return value
end

require_value(session_id, "session_id_required")

local now = now_ms()
local session_key = require_value(redis.call("HGET", session_index_key, session_id), "session_index_missing")
if redis.call("EXISTS", session_key) == 0 then
	redis.call("HDEL", session_index_key, session_id)
	return ambiguous("session_missing")
end

local observed_generation = tonumber(redis.call("HGET", session_key, "control_generation") or "0")
if observed_generation == nil or observed_generation < 0 then
	return ambiguous("control_generation_invalid")
end

local generation = observed_generation + 1
redis.call("HSET", session_key,
	"session_control_generation", generation,
	"session_control_action", "kick",
	"kill_reason", reason or "",
	"kill_actor", actor or "",
	"updated_at_ms", now)

return {
	"status", "marked",
	"session_id", session_id,
	"control_generation", tostring(generation),
	"control_action", "kick",
	"server_time_ms", tostring(now)
}
