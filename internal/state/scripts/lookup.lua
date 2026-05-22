-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Reads affinity state without mutating leases or key TTLs.

local state_key = KEYS[1]
local sessions_key = KEYS[2]

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

local now = now_ms()
local active_count = redis.call("ZCOUNT", sessions_key, "(" .. tostring(now), "+inf")

if redis.call("EXISTS", state_key) == 0 then
	if active_count > 0 then
		return ambiguous("sessions_without_state")
	end

	return {
		"status", "missing",
		"present", "0",
		"shard_tag", "",
		"generation", "",
		"active_session_count", "0",
		"server_time_ms", tostring(now),
		"expires_at_ms", "0",
		"lease_expires_at_ms", "0"
	}
end

local shard = require_value(redis.call("HGET", state_key, "shard_tag"), "state_shard_required")
local generation = require_value(redis.call("HGET", state_key, "generation"), "state_generation_required")
local expires_at = tonumber(require_value(redis.call("HGET", state_key, "expires_at_ms"), "expires_at_required"))

if expires_at == nil or expires_at <= now then
	return ambiguous("state_expired")
end

local top = redis.call("ZREVRANGE", sessions_key, 0, 0, "WITHSCORES")
local lease_expires_at = 0
if top[2] ~= nil then
	lease_expires_at = tonumber(top[2])
	if lease_expires_at == nil then
		return ambiguous("invalid_session_score")
	end
end

return {
	"status", "found",
	"present", "1",
	"shard_tag", shard,
	"generation", tostring(generation),
	"active_session_count", tostring(active_count),
	"server_time_ms", tostring(now),
	"expires_at_ms", tostring(expires_at),
	"lease_expires_at_ms", tostring(lease_expires_at)
}
