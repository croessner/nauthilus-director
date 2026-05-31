-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Stores a concrete backend pin without changing shard affinity.

local state_key = KEYS[1]
local sessions_key = KEYS[2]
local backend_pin_key = KEYS[4]

local backend_id = ARGV[1]
local protocol = ARGV[2]
local backend_pool = ARGV[3]
local shard_tag = ARGV[4]
local strategy = ARGV[5]
local reason = ARGV[6]
local actor = ARGV[7]
local schema_version = ARGV[8]
local tenant = ARGV[9]
local account_key = ARGV[10]

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

require_value(backend_id, "backend_id_required")
require_value(protocol, "protocol_required")
require_value(backend_pool, "backend_pool_required")
require_value(shard_tag, "shard_required")
require_value(strategy, "strategy_required")
require_value(reason, "reason_required")
require_value(schema_version, "schema_version_required")
require_value(tenant, "tenant_required")
require_value(account_key, "account_key_required")

if strategy ~= "new_sessions_only" and strategy ~= "kick_existing" and strategy ~= "drain_existing" then
	return ambiguous("strategy_invalid")
end

local now = now_ms()
redis.call("ZREMRANGEBYSCORE", sessions_key, "-inf", now)

local active_count = redis.call("ZCARD", sessions_key)
local generation = 0
local control_action = "none"
local control_generation = 0

if redis.call("EXISTS", state_key) == 1 then
	require_value(redis.call("HGET", state_key, "shard_tag"), "state_shard_required")
	require_value(redis.call("HGET", state_key, "generation"), "state_generation_required")
else
	if active_count > 0 then
		return ambiguous("sessions_without_state")
	end
end

generation = redis.call("HINCRBY", backend_pin_key, "generation", 1)
control_generation = generation

if redis.call("EXISTS", state_key) == 1 and strategy == "kick_existing" then
	control_generation = redis.call("HINCRBY", state_key, "control_generation", 1)
	control_action = "move_generation_changed"
	redis.call("HSET", state_key,
		"updated_at_ms", now,
		"control_action", control_action)
end

redis.call("HSET", backend_pin_key,
	"schema_version", schema_version,
	"tenant", tenant,
	"account_key", account_key,
	"backend_id", backend_id,
	"protocol", protocol,
	"backend_pool", backend_pool,
	"shard_tag", shard_tag,
	"strategy", strategy,
	"generation", generation,
	"reason", reason,
	"actor", actor or "",
	"updated_at_ms", now)

return {
	"status", "pinned",
	"present", "1",
	"tenant", tenant,
	"account_key", account_key,
	"backend_id", backend_id,
	"protocol", protocol,
	"backend_pool", backend_pool,
	"shard_tag", shard_tag,
	"strategy", strategy,
	"generation", tostring(generation),
	"control_generation", tostring(control_generation),
	"control_action", control_action,
	"active_session_count", tostring(active_count),
	"server_time_ms", tostring(now)
}
