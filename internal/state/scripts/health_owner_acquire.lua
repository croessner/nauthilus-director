-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Acquires or renews a backend deep-health owner lease with a fencing token
-- derived from the durable health state record.

local instance_key = KEYS[1]
local owner_key = KEYS[2]
local state_key = KEYS[3]

local instance_id = ARGV[1]
local backend_id = ARGV[2]
local lease_ttl_ms = tonumber(ARGV[3])

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

if lease_ttl_ms == nil or lease_ttl_ms <= 0 then
	return ambiguous("lease_ttl_required")
end

if redis.call("EXISTS", instance_key) == 0 then
	return ambiguous("instance_missing")
end

local now = now_ms()
local current_owner = redis.call("HGET", owner_key, "instance_id")
local token = redis.call("HGET", owner_key, "fencing_token")
local status = "held_by_other"

if current_owner == false or current_owner == nil or current_owner == "" then
	token = redis.call("HINCRBY", state_key, "fencing_token", 1)
	status = "acquired"
elseif current_owner == instance_id then
	token = tonumber(require_value(token, "fencing_token_required"))
	status = "renewed"
else
	token = tonumber(require_value(token, "fencing_token_required"))
	return {
		"status", status,
		"backend_id", backend_id,
		"owner_instance_id", current_owner,
		"instance_id", instance_id,
		"fencing_token", tostring(token),
		"server_time_ms", tostring(now),
		"expires_at_ms", tostring(now + lease_ttl_ms)
	}
end

redis.call("HSET", owner_key,
	"backend_id", backend_id,
	"instance_id", instance_id,
	"fencing_token", tostring(token),
	"updated_at_ms", tostring(now),
	"expires_at_ms", tostring(now + lease_ttl_ms))
redis.call("PEXPIRE", owner_key, lease_ttl_ms)

return {
	"status", status,
	"backend_id", backend_id,
	"owner_instance_id", instance_id,
	"instance_id", instance_id,
	"fencing_token", tostring(token),
	"server_time_ms", tostring(now),
	"expires_at_ms", tostring(now + lease_ttl_ms)
}
