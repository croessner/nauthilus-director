-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Reads one concrete backend pin without mutating affinity or session leases.

local sessions_key = KEYS[1]
local backend_pin_key = KEYS[2]

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

if redis.call("EXISTS", backend_pin_key) == 0 then
	return {
		"status", "missing",
		"present", "0",
		"tenant", "",
		"account_key", "",
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
local generation = require_value(redis.call("HGET", backend_pin_key, "generation"), "generation_required")

return {
	"status", "found",
	"present", "1",
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
