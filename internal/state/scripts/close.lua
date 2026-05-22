-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Closes one session lease and keeps or releases the affinity state according
-- to the idle grace stored with the session.

local state_key = KEYS[1]
local sessions_key = KEYS[2]
local session_key = KEYS[3]

local session_id = ARGV[1]

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

local function max_session_expiry(default_expiry)
	local top = redis.call("ZREVRANGE", sessions_key, 0, 0, "WITHSCORES")
	if top[2] == nil then
		return default_expiry
	end

	local expiry = tonumber(top[2])
	if expiry == nil then
		return ambiguous("invalid_session_score")
	end

	if expiry > default_expiry then
		return expiry
	end

	return default_expiry
end

require_value(session_id, "session_id_required")

local now = now_ms()

if redis.call("EXISTS", state_key) == 0 then
	return ambiguous("state_missing")
end

if redis.call("EXISTS", session_key) == 0 then
	return ambiguous("session_missing")
end

local shard = require_value(redis.call("HGET", state_key, "shard_tag"), "state_shard_required")
require_value(redis.call("HGET", state_key, "generation"), "state_generation_required")

local session_shard = require_value(redis.call("HGET", session_key, "shard_tag"), "session_shard_required")
local idle_grace_ms = tonumber(require_value(redis.call("HGET", session_key, "idle_grace_ms"), "idle_grace_required"))

if idle_grace_ms == nil or idle_grace_ms < 0 then
	return ambiguous("idle_grace_invalid")
end

if session_shard ~= shard then
	return ambiguous("session_shard_conflict")
end

redis.call("ZREM", sessions_key, session_id)
redis.call("DEL", session_key)
redis.call("ZREMRANGEBYSCORE", sessions_key, "-inf", now)

local active_count = redis.call("ZCARD", sessions_key)
local generation = redis.call("HINCRBY", state_key, "generation", 1)
local state_expires_at = now
local lease_expires_at = now
local status = "released"

if active_count > 0 then
	state_expires_at = max_session_expiry(now) + idle_grace_ms
	status = "closed"
	redis.call("HSET", state_key,
		"active_session_count", active_count,
		"updated_at_ms", now,
		"expires_at_ms", state_expires_at)
	redis.call("PEXPIREAT", state_key, state_expires_at)
	redis.call("PEXPIREAT", sessions_key, state_expires_at)
elseif idle_grace_ms > 0 then
	state_expires_at = now + idle_grace_ms
	status = "idle"
	redis.call("HSET", state_key,
		"active_session_count", 0,
		"updated_at_ms", now,
		"expires_at_ms", state_expires_at)
	redis.call("PEXPIREAT", state_key, state_expires_at)
	redis.call("DEL", sessions_key)
else
	redis.call("DEL", state_key)
	redis.call("DEL", sessions_key)
end

return {
	"status", status,
	"present", "1",
	"shard_tag", shard,
	"generation", tostring(generation),
	"active_session_count", tostring(active_count),
	"server_time_ms", tostring(now),
	"expires_at_ms", tostring(state_expires_at),
	"lease_expires_at_ms", tostring(lease_expires_at)
}
