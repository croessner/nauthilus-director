-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Repairs expired backend-local reservations from a bounded due set.

local reservation_key = KEYS[1]
local reservation_due_key = KEYS[2]

local backend_id = ARGV[1]
local limit = tonumber(ARGV[2])

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

if limit == nil or limit <= 0 then
	return ambiguous("limit_invalid")
end

local now = now_ms()
local due_reservations = redis.call("ZRANGEBYSCORE", reservation_due_key, "-inf", now, "LIMIT", 0, limit)
local active_count = tonumber(redis.call("HGET", reservation_key, "active_session_count") or "0")

if active_count == nil or active_count < 0 then
	return ambiguous("backend_count_invalid")
end

local repaired = 0

for _, reservation_id in ipairs(due_reservations) do
	local reservation_field = "reservation:" .. reservation_id
	local expires_at = tonumber(redis.call("HGET", reservation_key, reservation_field) or "0")

	if expires_at == nil then
		return ambiguous("reservation_expiry_invalid")
	end

	if expires_at <= 0 then
		redis.call("ZREM", reservation_due_key, reservation_id)
	elseif expires_at > now then
		redis.call("ZADD", reservation_due_key, expires_at, reservation_id)
	else
		redis.call("HDEL", reservation_key, reservation_field)
		redis.call("ZREM", reservation_due_key, reservation_id)
		repaired = repaired + 1

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
	end
end

redis.call("HSET", reservation_key,
	"backend_id", backend_id,
	"updated_at_ms", now)

return {
	"status", "reaped",
	"backend_id", backend_id,
	"backend_reservation_id", "",
	"active_session_count", tostring(active_count),
	"repaired_reservations", tostring(repaired),
	"server_time_ms", tostring(now),
	"lease_expires_at_ms", "0"
}
