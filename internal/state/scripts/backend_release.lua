-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Idempotently releases one backend-local capacity reservation.

local reservation_key = KEYS[1]
local reservation_due_key = KEYS[2]

local backend_id = ARGV[1]
local reservation_id = ARGV[2]

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
require_value(reservation_id, "reservation_id_required")

local now = now_ms()
local reservation_field = "reservation:" .. reservation_id
local active_count = tonumber(redis.call("HGET", reservation_key, "active_session_count") or "0")

if active_count == nil or active_count < 0 then
	return ambiguous("backend_count_invalid")
end

local released = 0
local existing = redis.call("HGET", reservation_key, reservation_field)
if existing ~= false and existing ~= nil and existing ~= "" then
	redis.call("HDEL", reservation_key, reservation_field)
	redis.call("ZREM", reservation_due_key, reservation_id)
	released = 1

	if active_count > 0 then
		active_count = redis.call("HINCRBY", reservation_key, "active_session_count", -1)
	else
		redis.call("HSET", reservation_key, "active_session_count", 0)
		active_count = 0
	end

	if active_count < 0 then
		redis.call("HSET", reservation_key, "active_session_count", 0)
		active_count = 0
	end
else
	redis.call("ZREM", reservation_due_key, reservation_id)
end

redis.call("HSET", reservation_key,
	"backend_id", backend_id,
	"updated_at_ms", now)

return {
	"status", "released",
	"backend_id", backend_id,
	"backend_reservation_id", reservation_id,
	"active_session_count", tostring(active_count),
	"repaired_reservations", tostring(released),
	"server_time_ms", tostring(now),
	"lease_expires_at_ms", "0"
}
