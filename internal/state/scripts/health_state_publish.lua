-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Publishes a backend deep-health state only when the writer still owns the
-- matching health lease and fencing token.

local owner_key = KEYS[1]
local state_key = KEYS[2]

local backend_id = ARGV[1]
local instance_id = ARGV[2]
local fencing_token = tonumber(ARGV[3])
local status = ARGV[4]
local reason_class = ARGV[5]
local state_ttl_ms = tonumber(ARGV[6])

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
require_value(instance_id, "instance_id_required")

if fencing_token == nil or fencing_token <= 0 then
	return ambiguous("fencing_token_required")
end

if status ~= "healthy" and status ~= "unhealthy" and status ~= "unknown" and status ~= "stale" then
	return ambiguous("health_status_invalid")
end

if state_ttl_ms == nil or state_ttl_ms <= 0 then
	return ambiguous("state_ttl_required")
end

local owner_instance = require_value(redis.call("HGET", owner_key, "instance_id"), "owner_missing")
local owner_token = tonumber(require_value(redis.call("HGET", owner_key, "fencing_token"), "owner_token_missing"))

if owner_instance ~= instance_id or owner_token ~= fencing_token then
	return ambiguous("owner_fence_mismatch")
end

local current_token = tonumber(redis.call("HGET", state_key, "fencing_token") or "0")
if current_token ~= nil and current_token > fencing_token then
	return ambiguous("stale_fencing_token")
end

local now = now_ms()
local generation = redis.call("HINCRBY", state_key, "generation", 1)

redis.call("HSET", state_key,
	"backend_id", backend_id,
	"status", status,
	"reason_class", reason_class or "",
	"owner_instance_id", instance_id,
	"fencing_token", tostring(fencing_token),
	"generation", tostring(generation),
	"checked_at_ms", tostring(now),
	"expires_at_ms", tostring(now + state_ttl_ms))

return {
	"status", status,
	"backend_id", backend_id,
	"owner_instance_id", instance_id,
	"fencing_token", tostring(fencing_token),
	"generation", tostring(generation),
	"reason_class", reason_class or "",
	"checked_at_ms", tostring(now),
	"expires_at_ms", tostring(now + state_ttl_ms),
	"server_time_ms", tostring(now)
}
