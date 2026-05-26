-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Renews a backend deep-health owner lease only for the current fenced owner.

local instance_key = KEYS[1]
local owner_key = KEYS[2]

local instance_id = ARGV[1]
local backend_id = ARGV[2]
local fencing_token = tonumber(ARGV[3])
local lease_ttl_ms = tonumber(ARGV[4])

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

require_value(instance_id, "instance_id_required")
require_value(backend_id, "backend_id_required")

if fencing_token == nil or fencing_token <= 0 then
	return ambiguous("fencing_token_required")
end

if lease_ttl_ms == nil or lease_ttl_ms <= 0 then
	return ambiguous("lease_ttl_required")
end

if redis.call("EXISTS", instance_key) == 0 then
	return ambiguous("instance_missing")
end

local owner_instance = require_value(redis.call("HGET", owner_key, "instance_id"), "owner_missing")
local owner_token = tonumber(require_value(redis.call("HGET", owner_key, "fencing_token"), "owner_token_missing"))

if owner_instance ~= instance_id or owner_token ~= fencing_token then
	return ambiguous("owner_fence_mismatch")
end

local now = now_ms()
redis.call("HSET", owner_key,
	"backend_id", backend_id,
	"instance_id", instance_id,
	"fencing_token", tostring(fencing_token),
	"updated_at_ms", tostring(now),
	"expires_at_ms", tostring(now + lease_ttl_ms))
redis.call("PEXPIRE", owner_key, lease_ttl_ms)

return {
	"status", "renewed",
	"backend_id", backend_id,
	"owner_instance_id", instance_id,
	"instance_id", instance_id,
	"fencing_token", tostring(fencing_token),
	"server_time_ms", tostring(now),
	"expires_at_ms", tostring(now + lease_ttl_ms)
}
