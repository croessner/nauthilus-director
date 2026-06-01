-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Extends one active session lease with Redis server time. The script fails
-- closed when the session or affinity state cannot be interpreted safely.

local state_key = KEYS[1]
local sessions_key = KEYS[2]
local session_key = KEYS[3]

local session_id = ARGV[1]
local lease_ms = tonumber(ARGV[2])

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

if lease_ms == nil or lease_ms <= 0 then
	return ambiguous("lease_required")
end

local now = now_ms()
local lease_expires_at = now + lease_ms

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
local retention_ttl_ms = tonumber(redis.call("HGET", session_key, "retention_ttl_ms") or redis.call("HGET", state_key, "retention_ttl_ms") or tostring(idle_grace_ms))
local backend_node = tostring(redis.call("HGET", state_key, "backend_node") or redis.call("HGET", session_key, "backend_node") or "")
local session_backend_node = tostring(redis.call("HGET", session_key, "backend_node") or "")
local affinity_hash = require_value(redis.call("HGET", session_key, "affinity_hash"), "affinity_hash_required")
local tenant = require_value(redis.call("HGET", session_key, "tenant"), "tenant_required")
local account_key = require_value(redis.call("HGET", session_key, "account_key"), "account_key_required")
local holder_kind = require_value(redis.call("HGET", session_key, "holder_kind"), "holder_kind_required")
local protocol = require_value(redis.call("HGET", session_key, "protocol"), "protocol_required")
local listener_name = tostring(redis.call("HGET", session_key, "listener_name") or "")
local service_name = tostring(redis.call("HGET", session_key, "service_name") or "")
local move_strategy = redis.call("HGET", state_key, "move_strategy") or ""

if idle_grace_ms == nil or idle_grace_ms < 0 then
	return ambiguous("idle_grace_invalid")
end

if retention_ttl_ms == nil or retention_ttl_ms < 0 then
	return ambiguous("retention_ttl_invalid")
end

local existing_score = tonumber(require_value(redis.call("ZSCORE", sessions_key, session_id), "session_score_required"))
if existing_score == nil or existing_score <= now then
	return ambiguous("session_expired")
end

local observed_generation = tonumber(redis.call("HGET", session_key, "control_generation") or "0")
if observed_generation == nil or observed_generation < 0 then
	return ambiguous("control_generation_invalid")
end

local state_control_generation = tonumber(redis.call("HGET", state_key, "control_generation") or "0")
if state_control_generation == nil or state_control_generation < 0 then
	return ambiguous("state_control_generation_invalid")
end

local session_control_generation = tonumber(redis.call("HGET", session_key, "session_control_generation") or "0")
if session_control_generation == nil or session_control_generation < 0 then
	return ambiguous("session_control_generation_invalid")
end

local control_action = "none"
local control_generation = observed_generation
if session_control_generation > observed_generation then
	control_generation = session_control_generation
	control_action = require_value(redis.call("HGET", session_key, "session_control_action"), "session_control_action_required")
elseif state_control_generation > observed_generation then
	control_generation = state_control_generation
	control_action = require_value(redis.call("HGET", state_key, "control_action"), "state_control_action_required")
end

if session_shard ~= shard and control_action == "none" and move_strategy ~= "drain_existing" then
	return ambiguous("session_shard_conflict")
end

if backend_node ~= "" and session_backend_node ~= "" and backend_node ~= session_backend_node then
	return ambiguous("session_backend_node_conflict")
end

redis.call("ZREMRANGEBYSCORE", sessions_key, "-inf", now)
redis.call("ZADD", sessions_key, lease_expires_at, session_id)
redis.call("HSET", session_key,
	"updated_at_ms", now,
	"lease_expires_at_ms", lease_expires_at)

if control_action == "none" and control_generation > observed_generation then
	redis.call("HSET", session_key, "control_generation", control_generation)
end

local active_count = redis.call("ZCARD", sessions_key)
local state_expires_at = max_session_expiry(lease_expires_at) + retention_ttl_ms
local generation = redis.call("HINCRBY", state_key, "generation", 1)
local session_retention_ms = retention_ttl_ms
if session_retention_ms < lease_ms then
	session_retention_ms = lease_ms
end

redis.call("HSET", state_key,
	"active_session_count", active_count,
	"active_holder_count", active_count,
	"retention_expires_at_ms", 0,
	"retention_ttl_ms", retention_ttl_ms,
	"updated_at_ms", now,
	"expires_at_ms", state_expires_at)
redis.call("PEXPIREAT", state_key, state_expires_at)
redis.call("PEXPIREAT", sessions_key, state_expires_at)
redis.call("PEXPIREAT", session_key, lease_expires_at + session_retention_ms)

return {
	"status", "heartbeat",
	"present", "1",
	"shard_tag", shard,
	"backend_node", backend_node,
	"generation", tostring(generation),
	"binding_generation", tostring(redis.call("HGET", state_key, "binding_generation") or "0"),
	"binding_status", "active_binding",
	"control_generation", tostring(control_generation),
	"control_action", control_action,
	"backend_id", tostring(redis.call("HGET", session_key, "selected_backend_id") or ""),
	"backend_reservation_id", tostring(redis.call("HGET", session_key, "backend_reservation_id") or ""),
	"backend_max_connections", tostring(redis.call("HGET", session_key, "backend_max_connections") or "0"),
	"backend_counted", tostring(redis.call("HGET", session_key, "backend_counted") or "0"),
	"session_id", session_id,
	"affinity_hash", affinity_hash,
	"tenant", tenant,
	"account_key", account_key,
	"holder_kind", holder_kind,
	"protocol", protocol,
	"listener_name", listener_name,
	"service_name", service_name,
	"active_session_count", tostring(active_count),
	"active_holder_count", tostring(active_count),
	"server_time_ms", tostring(now),
	"expires_at_ms", tostring(state_expires_at),
	"retention_expires_at_ms", "0",
	"lease_expires_at_ms", tostring(lease_expires_at),
	"idle_expires_at_ms", tostring(state_expires_at)
}
