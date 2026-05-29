-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Stores backend runtime override state and marks indexed sessions when the
-- operation can affect existing proxy streams.

local backend_key = KEYS[1]
local backend_index_key = KEYS[2]

local backend_id = ARGV[1]
local in_service = ARGV[2]
local weight = ARGV[3]
local maintenance_mode = ARGV[4]
local drain_enabled = ARGV[5]
local drain_mode = ARGV[6]
local reason = ARGV[7]
local actor = ARGV[8]

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

local now = now_ms()
local generation = redis.call("HINCRBY", backend_key, "generation", 1)
local marked = 0

redis.call("HSET", backend_key,
	"backend_id", backend_id,
	"updated_at_ms", now,
	"last_reason", reason or "",
	"last_actor", actor or "")

if in_service ~= nil and in_service ~= "" then
	if in_service ~= "true" and in_service ~= "false" then
		return ambiguous("in_service_invalid")
	end
	redis.call("HSET", backend_key, "in_service", in_service)
end

if weight ~= nil and weight ~= "" then
	local parsed_weight = tonumber(weight)
	if parsed_weight == nil or parsed_weight < 0 then
		return ambiguous("weight_invalid")
	end
	redis.call("HSET", backend_key, "weight", tostring(parsed_weight))
end

if maintenance_mode ~= nil and maintenance_mode ~= "" then
	if maintenance_mode ~= "disabled" and maintenance_mode ~= "soft" and maintenance_mode ~= "hard" then
		return ambiguous("maintenance_mode_invalid")
	end
	redis.call("HSET", backend_key, "maintenance_mode", maintenance_mode)
end

if drain_enabled == "true" then
	if drain_mode == "" then
		drain_mode = "soft"
	end
	if drain_mode ~= "soft" and drain_mode ~= "hard" then
		return ambiguous("drain_mode_invalid")
	end
	redis.call("HSET", backend_key,
		"drain_enabled", "true",
		"drain_mode", drain_mode,
		"drain_started_at_ms", now)
elseif drain_enabled == "false" then
	redis.call("HSET", backend_key,
		"drain_enabled", "false",
		"drain_mode", "disabled")
end

redis.call("SADD", backend_index_key, backend_id)

local active_count = tonumber(redis.call("HGET", backend_key, "active_session_count") or "0")
if active_count == nil or active_count < 0 then
	return ambiguous("backend_count_invalid")
end

return {
	"status", "updated",
	"backend_id", backend_id,
	"generation", tostring(generation),
	"active_session_count", tostring(active_count),
	"marked_session_count", tostring(marked),
	"server_time_ms", tostring(now)
}
