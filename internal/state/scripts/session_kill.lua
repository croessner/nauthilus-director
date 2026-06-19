-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Marks one indexed session for controlled shutdown through heartbeat.

local session_index_key = KEYS[1]

local session_id = ARGV[1]
local reason = ARGV[2]
local actor = ARGV[3]

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

local function valid_unsigned_integer(value)
	if value == false or value == nil or value == "" then
		return false
	end

	return tostring(value):match("^%d+$") ~= nil
end

require_value(session_id, "session_id_required")
require_value(reason, "reason_required")

local now = now_ms()
local session_key = redis.call("HGET", session_index_key, session_id)
if session_key == false or session_key == nil then
	return {
		"status", "missing",
		"session_id", session_id,
		"control_generation", "",
		"control_action", "none",
		"server_time_ms", tostring(now)
	}
end

session_key = require_value(session_key, "session_locator_invalid")
if redis.call("EXISTS", session_key) == 0 then
	redis.call("HDEL", session_index_key, session_id)
	return {
		"status", "stale_index_repaired",
		"session_id", session_id,
		"control_generation", "",
		"control_action", "none",
		"server_time_ms", tostring(now)
	}
end

local stored_session_id = require_value(redis.call("HGET", session_key, "session_id"), "session_id_required")
if stored_session_id ~= session_id then
	return ambiguous("session_id_mismatch")
end

require_value(redis.call("HGET", session_key, "affinity_hash"), "affinity_hash_required")
require_value(redis.call("HGET", session_key, "tenant"), "tenant_required")
require_value(redis.call("HGET", session_key, "account_key"), "account_key_required")
require_value(redis.call("HGET", session_key, "protocol"), "protocol_required")
require_value(redis.call("HGET", session_key, "shard_tag"), "shard_tag_required")

local holder_kind = require_value(redis.call("HGET", session_key, "holder_kind"), "holder_kind_required")
if holder_kind ~= "session" and holder_kind ~= "delivery" then
	return ambiguous("holder_kind_invalid")
end

local lease_expires_at = require_value(redis.call("HGET", session_key, "lease_expires_at_ms"), "lease_required")
if not valid_unsigned_integer(lease_expires_at) or tonumber(lease_expires_at) <= 0 then
	return ambiguous("lease_invalid")
end

local observed_generation_value = require_value(redis.call("HGET", session_key, "control_generation"), "control_generation_required")
if not valid_unsigned_integer(observed_generation_value) then
	return ambiguous("control_generation_invalid")
end
local observed_generation = tonumber(observed_generation_value)

local generation = observed_generation + 1
redis.call("HSET", session_key,
	"session_control_generation", generation,
	"session_control_action", "kick",
	"kill_reason", reason or "",
	"kill_actor", actor or "",
	"updated_at_ms", now)

return {
	"status", "marked",
	"session_id", session_id,
	"control_generation", tostring(generation),
	"control_action", "kick",
	"server_time_ms", tostring(now)
}
