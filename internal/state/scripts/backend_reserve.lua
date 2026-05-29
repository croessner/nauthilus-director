-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Reserves one backend-local capacity slot. The reservation state and due set
-- share a Redis Cluster hash tag, so this script never touches affinity keys.

local reservation_key = KEYS[1]
local reservation_due_key = KEYS[2]

local backend_id = ARGV[1]
local reservation_id = ARGV[2]
local max_connections = tonumber(ARGV[3])
local ttl_ms = tonumber(ARGV[4])

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

if max_connections == nil or max_connections <= 0 then
	return ambiguous("max_connections_required")
end

if ttl_ms == nil or ttl_ms <= 0 then
	return ambiguous("ttl_required")
end

local now = now_ms()
local expires_at = now + ttl_ms
local reservation_field = "reservation:" .. reservation_id
local active_count = tonumber(redis.call("HGET", reservation_key, "active_session_count") or "0")

if active_count == nil or active_count < 0 then
	return ambiguous("backend_count_invalid")
end

local existing = redis.call("HGET", reservation_key, reservation_field)
if existing ~= false and existing ~= nil and existing ~= "" then
	redis.call("HSET", reservation_key,
		"backend_id", backend_id,
		reservation_field, expires_at,
		"updated_at_ms", now)
	redis.call("ZADD", reservation_due_key, expires_at, reservation_id)

	return {
		"status", "reserved",
		"backend_id", backend_id,
		"backend_reservation_id", reservation_id,
		"active_session_count", tostring(active_count),
		"repaired_reservations", "0",
		"server_time_ms", tostring(now),
		"lease_expires_at_ms", tostring(expires_at)
	}
end

if active_count >= max_connections then
	return ambiguous("backend_at_capacity")
end

local reserved_count = redis.call("HINCRBY", reservation_key, "active_session_count", 1)
if reserved_count == nil or reserved_count < 0 then
	return ambiguous("backend_count_negative")
end

redis.call("HSET", reservation_key,
	"backend_id", backend_id,
	reservation_field, expires_at,
	"updated_at_ms", now)
redis.call("ZADD", reservation_due_key, expires_at, reservation_id)

return {
	"status", "reserved",
	"backend_id", backend_id,
	"backend_reservation_id", reservation_id,
	"active_session_count", tostring(reserved_count),
	"repaired_reservations", "0",
	"server_time_ms", tostring(now),
	"lease_expires_at_ms", tostring(expires_at)
}
