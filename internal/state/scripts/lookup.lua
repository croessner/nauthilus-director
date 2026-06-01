-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Reads affinity state without mutating leases or key TTLs.

local state_key = KEYS[1]
local sessions_key = KEYS[2]
local override_key = KEYS[3]

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
local override_target = tostring(redis.call("HGET", override_key, "target_shard") or "")
local override_strategy = tostring(redis.call("HGET", override_key, "strategy") or "")

if redis.call("EXISTS", state_key) == 0 then
	if active_count > 0 then
		return ambiguous("sessions_without_state")
	end

	return {
		"status", "missing",
		"present", "0",
		"shard_tag", "",
		"backend_node", "",
		"generation", "",
		"binding_generation", "",
		"binding_status", "none",
		"control_generation", "",
		"control_action", "none",
		"backend_id", "",
		"target_shard", override_target,
		"strategy", override_strategy,
		"active_session_count", "0",
		"active_holder_count", "0",
		"server_time_ms", tostring(now),
		"expires_at_ms", "0",
		"retention_expires_at_ms", "0",
		"lease_expires_at_ms", "0"
	}
end

local shard = require_value(redis.call("HGET", state_key, "shard_tag"), "state_shard_required")
local generation = require_value(redis.call("HGET", state_key, "generation"), "state_generation_required")
local backend_node = tostring(redis.call("HGET", state_key, "backend_node") or "")
local binding_generation = tostring(redis.call("HGET", state_key, "binding_generation") or "0")
local retention_expires_at = tonumber(redis.call("HGET", state_key, "retention_expires_at_ms") or "0") or 0
local expires_at = tonumber(require_value(redis.call("HGET", state_key, "expires_at_ms"), "expires_at_required"))
if override_target == "" then
	override_target = tostring(redis.call("HGET", state_key, "move_target_shard") or "")
end
if override_strategy == "" then
	override_strategy = tostring(redis.call("HGET", state_key, "move_strategy") or "")
end

if expires_at == nil then
	return ambiguous("state_expired")
end

if expires_at <= now and active_count > 0 then
	return ambiguous("state_expired_with_active_sessions")
end

if active_count == 0 and ((retention_expires_at > 0 and retention_expires_at <= now) or expires_at <= now) then
	return {
		"status", "expired",
		"present", "0",
		"shard_tag", shard,
		"backend_node", backend_node,
		"generation", tostring(generation),
		"binding_generation", binding_generation,
		"binding_status", "expired_binding",
		"control_generation", tostring(redis.call("HGET", state_key, "control_generation") or "0"),
		"control_action", tostring(redis.call("HGET", state_key, "control_action") or "none"),
		"backend_id", "",
		"target_shard", override_target,
		"strategy", override_strategy,
		"active_session_count", "0",
		"active_holder_count", "0",
		"server_time_ms", tostring(now),
		"expires_at_ms", tostring(expires_at),
		"retention_expires_at_ms", tostring(retention_expires_at),
		"lease_expires_at_ms", "0"
	}
end

local top = redis.call("ZREVRANGE", sessions_key, 0, 0, "WITHSCORES")
local lease_expires_at = 0
if top[2] ~= nil then
	lease_expires_at = tonumber(top[2])
	if lease_expires_at == nil then
		return ambiguous("invalid_session_score")
	end
end

local status = "found"
local binding = "active_binding"
if active_count == 0 then
	if backend_node == "" then
		status = "idle"
		binding = "none"
	else
		status = "retained"
		binding = "retained_binding"
	end
end

return {
	"status", status,
	"present", "1",
	"shard_tag", shard,
	"backend_node", backend_node,
	"generation", tostring(generation),
	"binding_generation", binding_generation,
	"binding_status", binding,
	"control_generation", tostring(redis.call("HGET", state_key, "control_generation") or "0"),
	"control_action", tostring(redis.call("HGET", state_key, "control_action") or "none"),
	"backend_id", "",
	"target_shard", override_target,
	"strategy", override_strategy,
	"active_session_count", tostring(active_count),
	"active_holder_count", tostring(active_count),
	"server_time_ms", tostring(now),
	"expires_at_ms", tostring(expires_at),
	"retention_expires_at_ms", tostring(retention_expires_at),
	"lease_expires_at_ms", tostring(lease_expires_at)
}
