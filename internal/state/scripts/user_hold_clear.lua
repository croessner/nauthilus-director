-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Clears only user placement-hold state in an affinity-owned slot.

local hold_key = KEYS[1]

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

local function require_number(value, message)
	local parsed = tonumber(require_value(value, message))
	if parsed == nil then
		return ambiguous(message)
	end

	return parsed
end

require_value(reason, "reason_required")
require_value(fallback_tenant, "tenant_required")
require_value(fallback_account_key, "account_key_required")

local now = now_ms()

if redis.call("EXISTS", hold_key) == 0 then
	return {
		"status", "missing",
		"present", "0",
		"tenant", fallback_tenant,
		"account_key", fallback_account_key,
		"generation", "",
		"created_at_ms", "0",
		"expires_at_ms", "0",
		"requested_duration_ms", "0",
		"updated_at_ms", "0",
		"server_time_ms", tostring(now)
	}
end

local tenant = require_value(redis.call("HGET", hold_key, "tenant"), "tenant_required")
local account_key = require_value(redis.call("HGET", hold_key, "account_key"), "account_key_required")
require_value(redis.call("HGET", hold_key, "generation"), "generation_required")
local created_at = require_number(redis.call("HGET", hold_key, "created_at_ms"), "created_at_required")
local expires_at = require_number(redis.call("HGET", hold_key, "expires_at_ms"), "expires_at_required")
local requested_duration = require_number(redis.call("HGET", hold_key, "requested_duration_ms"), "duration_required")
require_number(redis.call("HGET", hold_key, "updated_at_ms"), "updated_at_required")

if requested_duration <= 0 then
	return ambiguous("duration_required")
end

local status = "cleared"
if expires_at <= now then
	status = "expired"
end

local generation = redis.call("HINCRBY", hold_key, "generation", 1)

redis.call("HSET", hold_key,
	"last_clear_reason", reason,
	"last_clear_actor", actor or "",
	"updated_at_ms", now)
redis.call("DEL", hold_key)

return {
	"status", status,
	"present", "0",
	"tenant", tenant,
	"account_key", account_key,
	"generation", tostring(generation),
	"created_at_ms", tostring(created_at),
	"expires_at_ms", tostring(expires_at),
	"requested_duration_ms", tostring(requested_duration),
	"updated_at_ms", tostring(now),
	"server_time_ms", tostring(now)
}
