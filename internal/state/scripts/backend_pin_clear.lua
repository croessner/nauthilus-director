-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Clears only the concrete backend pin while preserving shard affinity state.

local sessions_key = KEYS[1]
local backend_pin_key = KEYS[2]

local reason = ARGV[1]
local actor = ARGV[2]
local fallback_tenant = ARGV[3]
local fallback_account_key = ARGV[4]

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

require_value(reason, "reason_required")
require_value(fallback_tenant, "tenant_required")
require_value(fallback_account_key, "account_key_required")

local now = now_ms()
local active_count = redis.call("ZCOUNT", sessions_key, "(" .. tostring(now), "+inf")

if redis.call("EXISTS", backend_pin_key) == 0 then
	return {
		"status", "missing",
		"present", "0",
		"tenant", fallback_tenant,
		"account_key", fallback_account_key,
		"backend_id", "",
		"protocol", "",
		"backend_pool", "",
		"shard_tag", "",
		"strategy", "",
		"generation", "",
		"active_session_count", tostring(active_count),
		"server_time_ms", tostring(now)
	}
end

local tenant = require_value(redis.call("HGET", backend_pin_key, "tenant"), "tenant_required")
local account_key = require_value(redis.call("HGET", backend_pin_key, "account_key"), "account_key_required")
local backend_id = require_value(redis.call("HGET", backend_pin_key, "backend_id"), "backend_id_required")
local protocol = require_value(redis.call("HGET", backend_pin_key, "protocol"), "protocol_required")
local backend_pool = require_value(redis.call("HGET", backend_pin_key, "backend_pool"), "backend_pool_required")
local shard_tag = require_value(redis.call("HGET", backend_pin_key, "shard_tag"), "shard_required")
local strategy = require_value(redis.call("HGET", backend_pin_key, "strategy"), "strategy_required")
local generation = redis.call("HINCRBY", backend_pin_key, "generation", 1)

redis.call("HSET", backend_pin_key,
	"last_clear_reason", reason,
	"last_clear_actor", actor or "",
	"updated_at_ms", now)
redis.call("DEL", backend_pin_key)

return {
	"status", "cleared",
	"present", "0",
	"tenant", tenant,
	"account_key", account_key,
	"backend_id", backend_id,
	"protocol", protocol,
	"backend_pool", backend_pool,
	"shard_tag", shard_tag,
	"strategy", strategy,
	"generation", tostring(generation),
	"active_session_count", tostring(active_count),
	"server_time_ms", tostring(now)
}
