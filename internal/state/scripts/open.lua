-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Opens or refreshes one session lease while preserving an existing affinity
-- pin. All keys passed to this script share one Redis Cluster hash tag.

local state_key = KEYS[1]
local sessions_key = KEYS[2]
local session_key = KEYS[3]
local override_key = KEYS[4]

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
local holder_kind = ARGV[13]
local proposed_backend_node = ARGV[14]
local retention_ttl_ms = tonumber(ARGV[15])

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

local function binding_status(active_count, retention_expires_at, now)
	if active_count > 0 then
		return "active_binding"
	end

	if retention_expires_at ~= nil and retention_expires_at > now then
		return "retained_binding"
	end

	return "none"
end

require_value(session_id, "session_id_required")
require_value(protocol, "protocol_required")
require_value(requested_shard, "shard_required")
require_value(schema_version, "schema_version_required")
require_value(affinity_hash, "affinity_hash_required")
require_value(tenant, "tenant_required")
require_value(account_key, "account_key_required")

if holder_kind == false or holder_kind == nil or holder_kind == "" then
	holder_kind = "session"
end

if holder_kind ~= "session" and holder_kind ~= "delivery" then
	return ambiguous("holder_kind_invalid")
end

if lease_ms == nil or lease_ms <= 0 then
	return ambiguous("lease_required")
end

if idle_grace_ms == nil or idle_grace_ms < 0 then
	return ambiguous("idle_grace_invalid")
end

if retention_ttl_ms == nil or retention_ttl_ms < 0 then
	return ambiguous("retention_ttl_invalid")
end

if proposed_backend_node == false or proposed_backend_node == nil then
	proposed_backend_node = ""
end

local now = now_ms()
local lease_expires_at = now + lease_ms

redis.call("ZREMRANGEBYSCORE", sessions_key, "-inf", now)

local state_exists = redis.call("EXISTS", state_key)
local status = "created"
local shard = requested_shard
local backend_node = proposed_backend_node
local control_generation = "0"
local prior_active_count = redis.call("ZCARD", sessions_key)
local clear_override = false
local retention_expires_at = 0
local binding_generation = "1"

if state_exists == 1 and prior_active_count == 0 then
	local existing_retention = tonumber(redis.call("HGET", state_key, "retention_expires_at_ms") or redis.call("HGET", state_key, "expires_at_ms") or "0")
	if existing_retention ~= nil and existing_retention > 0 and existing_retention <= now then
		redis.call("DEL", state_key)
		redis.call("DEL", sessions_key)
		state_exists = 0
		status = "created"
	end
end

local override_target = redis.call("HGET", override_key, "target_shard")
local override_strategy = redis.call("HGET", override_key, "strategy")
local override_backend_pin = redis.call("HGET", override_key, "backend_pin")

if state_exists == 0 then
	if redis.call("ZCARD", sessions_key) > 0 then
		return ambiguous("sessions_without_state")
	end

	if override_target ~= false and override_target ~= nil and override_target ~= "" and override_backend_pin ~= "1" then
		shard = override_target
		status = "created_from_override"
		clear_override = true
	end

	redis.call("HSET", state_key,
		"schema_version", schema_version,
		"shard_tag", shard,
		"backend_node", backend_node,
		"generation", 0,
		"binding_generation", binding_generation,
		"control_generation", 0,
		"control_action", "none",
		"affinity_hash", affinity_hash,
		"tenant", tenant,
		"account_key", account_key,
		"idle_grace_ms", idle_grace_ms,
		"retention_ttl_ms", retention_ttl_ms,
		"retention_expires_at_ms", 0,
		"created_at_ms", now)
else
	shard = require_value(redis.call("HGET", state_key, "shard_tag"), "state_shard_required")
	require_value(redis.call("HGET", state_key, "generation"), "state_generation_required")
	control_generation = tostring(redis.call("HGET", state_key, "control_generation") or "0")
	backend_node = tostring(redis.call("HGET", state_key, "backend_node") or "")
	binding_generation = tostring(redis.call("HGET", state_key, "binding_generation") or "0")
	retention_expires_at = tonumber(redis.call("HGET", state_key, "retention_expires_at_ms") or "0") or 0
	status = "reused"
	if prior_active_count == 0 and retention_expires_at > now then
		status = "retained"
	end

	if backend_node == "" and proposed_backend_node ~= "" then
		backend_node = proposed_backend_node
		binding_generation = tostring(redis.call("HINCRBY", state_key, "binding_generation", 1))
	end

	if override_target ~= false and override_target ~= nil and override_target ~= "" and override_backend_pin ~= "1" then
		if override_strategy == "drain_existing" then
			shard = override_target
			status = "drain_override"
		elseif prior_active_count == 0 then
			shard = override_target
			backend_node = proposed_backend_node
			binding_generation = tostring(redis.call("HINCRBY", state_key, "binding_generation", 1))
			status = "moved_from_override"
			clear_override = true
		end
	end

	if backend_node ~= "" and proposed_backend_node ~= "" and backend_node ~= proposed_backend_node then
		return {
			"status", "backend_node_mismatch",
			"present", "1",
			"shard_tag", shard,
			"backend_node", backend_node,
			"generation", tostring(redis.call("HGET", state_key, "generation") or "0"),
			"binding_generation", binding_generation,
			"binding_status", "backend_node_mismatch",
			"control_generation", control_generation,
			"control_action", "none",
			"backend_id", "",
			"backend_counted", "0",
			"active_session_count", tostring(prior_active_count),
			"active_holder_count", tostring(prior_active_count),
			"server_time_ms", tostring(now),
			"expires_at_ms", tostring(redis.call("HGET", state_key, "expires_at_ms") or "0"),
			"retention_expires_at_ms", tostring(retention_expires_at),
			"lease_expires_at_ms", "0"
		}
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

	local existing_backend_node = tostring(redis.call("HGET", session_key, "backend_node") or "")
	if existing_backend_node ~= "" and backend_node ~= "" and existing_backend_node ~= backend_node then
		return ambiguous("session_backend_node_conflict")
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
	"affinity_hash", affinity_hash,
	"tenant", tenant,
	"account_key", account_key,
	"holder_kind", holder_kind,
	"protocol", protocol,
	"listener_name", listener_name,
	"service_name", service_name,
	"shard_tag", shard,
	"backend_node", backend_node,
	"selected_backend_id", "",
	"director_instance_id", director_instance_id,
	"opened_at_ms", opened_at,
	"updated_at_ms", now,
	"lease_expires_at_ms", lease_expires_at,
	"idle_grace_ms", idle_grace_ms,
	"retention_ttl_ms", retention_ttl_ms,
	"control_generation", control_generation,
	"session_control_generation", control_generation,
	"session_control_action", "none",
	"backend_counted", "0")

local active_count = redis.call("ZCARD", sessions_key)
local state_expires_at = max_session_expiry(lease_expires_at) + retention_ttl_ms
local generation = redis.call("HINCRBY", state_key, "generation", 1)
local session_retention_ms = retention_ttl_ms
if session_retention_ms < lease_ms then
	session_retention_ms = lease_ms
end

redis.call("HSET", state_key,
	"schema_version", schema_version,
	"shard_tag", shard,
	"backend_node", backend_node,
	"binding_generation", binding_generation,
	"affinity_hash", affinity_hash,
	"tenant", tenant,
	"account_key", account_key,
	"idle_grace_ms", idle_grace_ms,
	"retention_ttl_ms", retention_ttl_ms,
	"active_session_count", active_count,
	"active_holder_count", active_count,
	"retention_expires_at_ms", 0,
	"updated_at_ms", now,
	"expires_at_ms", state_expires_at)
redis.call("PEXPIREAT", state_key, state_expires_at)
redis.call("PEXPIREAT", sessions_key, state_expires_at)
redis.call("PEXPIREAT", session_key, lease_expires_at + session_retention_ms)

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
	"backend_node", backend_node,
	"generation", tostring(generation),
	"binding_generation", binding_generation,
	"binding_status", binding_status(active_count, 0, now),
	"control_generation", control_generation,
	"control_action", "none",
	"backend_id", "",
	"backend_counted", "0",
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
