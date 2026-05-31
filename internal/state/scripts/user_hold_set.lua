-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Stores one bounded user placement hold in an affinity-owned slot.

local hold_key = KEYS[1]

local duration_ms = tonumber(ARGV[1])
local max_duration_ms = tonumber(ARGV[2])
local reason = ARGV[3]
local actor = ARGV[4]
local schema_version = ARGV[5]
local tenant = ARGV[6]
local account_key = ARGV[7]

local cleanup_grace_ms = 60000

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

if duration_ms == nil or duration_ms <= 0 then
	return ambiguous("duration_required")
end

if max_duration_ms == nil or max_duration_ms <= 0 then
	return ambiguous("max_duration_required")
end

if duration_ms > max_duration_ms then
	return ambiguous("duration_exceeds_maximum")
end

require_value(reason, "reason_required")
require_value(schema_version, "schema_version_required")
require_value(tenant, "tenant_required")
require_value(account_key, "account_key_required")

local now = now_ms()
local expires_at = now + duration_ms
local cleanup_expires_at = expires_at + cleanup_grace_ms
local generation = redis.call("HINCRBY", hold_key, "generation", 1)

redis.call("HSET", hold_key,
	"schema_version", schema_version,
	"tenant", tenant,
	"account_key", account_key,
	"generation", generation,
	"created_at_ms", now,
	"expires_at_ms", expires_at,
	"requested_duration_ms", duration_ms,
	"reason", reason,
	"actor", actor or "",
	"updated_at_ms", now)
redis.call("PEXPIREAT", hold_key, cleanup_expires_at)

return {
	"status", "held",
	"present", "1",
	"tenant", tenant,
	"account_key", account_key,
	"generation", tostring(generation),
	"created_at_ms", tostring(now),
	"expires_at_ms", tostring(expires_at),
	"requested_duration_ms", tostring(duration_ms),
	"updated_at_ms", tostring(now),
	"server_time_ms", tostring(now)
}
