-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Opens or refreshes one session lease while preserving an existing affinity
-- pin. The affinity state keys share one Redis Cluster hash tag; the remaining
-- keys are repairable namespace indexes.

local state_key = KEYS[1]
local sessions_key = KEYS[2]
local session_key = KEYS[3]
local override_key = KEYS[4]
local session_index_key = KEYS[5]
local user_index_key = KEYS[6]
local user_sessions_key = KEYS[7]

local session_id = ARGV[1]
local protocol = ARGV[2]
local requested_shard = ARGV[3]
local lease_ms = tonumber(ARGV[4])
local idle_grace_ms = tonumber(ARGV[5])
local schema_version = ARGV[6]
local affinity_hash = ARGV[7]
local tenant = ARGV[8]
local account_key = ARGV[9]
local listener_name = ARGV[10]
local service_name = ARGV[11]
local director_instance_id = ARGV[12]

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
require_value(affinity_hash, "affinity_hash_required")
require_value(tenant, "tenant_required")
require_value(account_key, "account_key_required")

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
local control_generation = "0"
local prior_active_count = redis.call("ZCARD", sessions_key)
local clear_override = false

local override_target = redis.call("HGET", override_key, "target_shard")
local override_strategy = redis.call("HGET", override_key, "strategy")

if state_exists == 0 then
	if redis.call("ZCARD", sessions_key) > 0 then
		return ambiguous("sessions_without_state")
	end

	if override_target ~= false and override_target ~= nil and override_target ~= "" then
		shard = override_target
		status = "created_from_override"
		clear_override = true
	end

	redis.call("HSET", state_key,
		"schema_version", schema_version,
		"shard_tag", shard,
		"generation", 0,
		"control_generation", 0,
		"control_action", "none",
		"affinity_hash", affinity_hash,
		"tenant", tenant,
		"account_key", account_key,
		"idle_grace_ms", idle_grace_ms,
		"created_at_ms", now)
else
	shard = require_value(redis.call("HGET", state_key, "shard_tag"), "state_shard_required")
	require_value(redis.call("HGET", state_key, "generation"), "state_generation_required")
	control_generation = tostring(redis.call("HGET", state_key, "control_generation") or "0")
	status = "reused"

	if override_target ~= false and override_target ~= nil and override_target ~= "" then
		if override_strategy == "drain_existing" then
			shard = override_target
			status = "drain_override"
		elseif prior_active_count == 0 then
			shard = override_target
			status = "moved_from_override"
			clear_override = true
		end
	end
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
	"state_key", state_key,
	"sessions_key", sessions_key,
	"user_sessions_key", user_sessions_key,
	"affinity_hash", affinity_hash,
	"tenant", tenant,
	"account_key", account_key,
	"protocol", protocol,
	"listener_name", listener_name,
	"service_name", service_name,
	"shard_tag", shard,
	"selected_backend_id", "",
	"director_instance_id", director_instance_id,
	"opened_at_ms", opened_at,
	"updated_at_ms", now,
	"lease_expires_at_ms", lease_expires_at,
	"idle_grace_ms", idle_grace_ms,
	"control_generation", control_generation,
	"session_control_generation", control_generation,
	"session_control_action", "none",
	"backend_counted", "0")

local active_count = redis.call("ZCARD", sessions_key)
local state_expires_at = max_session_expiry(lease_expires_at) + idle_grace_ms
local generation = redis.call("HINCRBY", state_key, "generation", 1)
local session_retention_ms = idle_grace_ms
if session_retention_ms < lease_ms then
	session_retention_ms = lease_ms
end

redis.call("HSET", state_key,
	"schema_version", schema_version,
	"shard_tag", shard,
	"affinity_hash", affinity_hash,
	"tenant", tenant,
	"account_key", account_key,
	"idle_grace_ms", idle_grace_ms,
	"active_session_count", active_count,
	"updated_at_ms", now,
	"expires_at_ms", state_expires_at)
redis.call("PEXPIREAT", state_key, state_expires_at)
redis.call("PEXPIREAT", sessions_key, state_expires_at)
redis.call("PEXPIREAT", session_key, lease_expires_at + session_retention_ms)
redis.call("HSET", session_index_key, session_id, session_key)
redis.call("SADD", user_index_key, affinity_hash)
redis.call("SADD", user_sessions_key, session_id)

if clear_override then
	redis.call("DEL", override_key)
	redis.call("HDEL", state_key,
		"move_strategy",
		"move_target_shard",
		"move_reason",
		"move_actor")
end

return {
	"status", status,
	"present", "1",
	"shard_tag", shard,
	"generation", tostring(generation),
	"control_generation", control_generation,
	"control_action", "none",
	"backend_id", "",
	"active_session_count", tostring(active_count),
	"server_time_ms", tostring(now),
	"expires_at_ms", tostring(state_expires_at),
	"lease_expires_at_ms", tostring(lease_expires_at)
}
