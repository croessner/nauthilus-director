-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Opens or refreshes one session lease while preserving an existing affinity
-- pin. All keys are expected to share the same Redis Cluster hash tag.

local state_key = KEYS[1]
local sessions_key = KEYS[2]
local session_key = KEYS[3]

local session_id = ARGV[1]
local protocol = ARGV[2]
local requested_shard = ARGV[3]
local lease_ms = tonumber(ARGV[4])
local idle_grace_ms = tonumber(ARGV[5])
local schema_version = ARGV[6]

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
require_value(protocol, "protocol_required")
require_value(requested_shard, "shard_required")
require_value(schema_version, "schema_version_required")

if lease_ms == nil or lease_ms <= 0 then
	return ambiguous("lease_required")
end

if idle_grace_ms == nil or idle_grace_ms < 0 then
	return ambiguous("idle_grace_invalid")
end

local now = now_ms()
local lease_expires_at = now + lease_ms

redis.call("ZREMRANGEBYSCORE", sessions_key, "-inf", now)

local state_exists = redis.call("EXISTS", state_key)
local status = "created"
local shard = requested_shard

if state_exists == 0 then
	if redis.call("ZCARD", sessions_key) > 0 then
		return ambiguous("sessions_without_state")
	end

	redis.call("HSET", state_key,
		"schema_version", schema_version,
		"shard_tag", shard,
		"generation", 0,
		"created_at_ms", now)
else
	shard = require_value(redis.call("HGET", state_key, "shard_tag"), "state_shard_required")
	require_value(redis.call("HGET", state_key, "generation"), "state_generation_required")
	status = "reused"
end

if redis.call("EXISTS", session_key) == 1 then
	local existing_protocol = require_value(redis.call("HGET", session_key, "protocol"), "session_protocol_required")
	local existing_shard = require_value(redis.call("HGET", session_key, "shard_tag"), "session_shard_required")

	if existing_protocol ~= protocol then
		return ambiguous("session_protocol_conflict")
	end

	if existing_shard ~= shard then
		return ambiguous("session_shard_conflict")
	end
end

local opened_at = redis.call("HGET", session_key, "opened_at_ms")
if opened_at == false or opened_at == nil or opened_at == "" then
	opened_at = now
end

redis.call("ZADD", sessions_key, lease_expires_at, session_id)
redis.call("HSET", session_key,
	"session_id", session_id,
	"protocol", protocol,
	"shard_tag", shard,
	"opened_at_ms", opened_at,
	"updated_at_ms", now,
	"lease_expires_at_ms", lease_expires_at,
	"idle_grace_ms", idle_grace_ms)
redis.call("PEXPIREAT", session_key, lease_expires_at)

local active_count = redis.call("ZCARD", sessions_key)
local state_expires_at = max_session_expiry(lease_expires_at) + idle_grace_ms
local generation = redis.call("HINCRBY", state_key, "generation", 1)

redis.call("HSET", state_key,
	"schema_version", schema_version,
	"shard_tag", shard,
	"active_session_count", active_count,
	"updated_at_ms", now,
	"expires_at_ms", state_expires_at)
redis.call("PEXPIREAT", state_key, state_expires_at)
redis.call("PEXPIREAT", sessions_key, state_expires_at)

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
