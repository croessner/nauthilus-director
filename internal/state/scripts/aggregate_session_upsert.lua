-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Records one active session in a bucketed aggregate group. The marker hash and
-- its dimension counters share one Redis Cluster hash tag, so the marker and
-- every counter move together. Only dimensions whose value changed are
-- adjusted; an unchanged marker costs one read.

local marker_key = KEYS[1]
local dimension_keys = { KEYS[2], KEYS[3], KEYS[4], KEYS[5], KEYS[6] }

local session_id = ARGV[1]
local encoded = ARGV[2]
local next_values = { ARGV[3], ARGV[4], ARGV[5], ARGV[6], ARGV[7] }

local function ambiguous(message)
	error("NDAMBIGUOUS " .. message)
end

local function text(value)
	if type(value) ~= "string" or value == "" then
		return nil
	end

	return value
end

local function previous_values(raw)
	if raw == false or raw == nil then
		return nil
	end

	local ok, decoded = pcall(cjson.decode, raw)
	if not ok or type(decoded) ~= "table" then
		return nil
	end

	local values = { text(decoded.protocol), text(decoded.listener), text(decoded.service), text(decoded.shard_tag), text(decoded.backend) }
	for index = 1, 4 do
		if values[index] == nil then
			return nil
		end
	end

	return values
end

local function decrement(key, field)
	local value = redis.call("HINCRBY", key, field, -1)
	if value <= 0 then
		redis.call("HDEL", key, field)
	end
end

if text(session_id) == nil or text(encoded) == nil then
	return ambiguous("aggregate_session_required")
end

for index = 1, 4 do
	if text(next_values[index]) == nil then
		return ambiguous("aggregate_dimension_required")
	end
end

local raw = redis.call("HGET", marker_key, session_id)
if raw == encoded then
	return 0
end

redis.call("HSET", marker_key, session_id, encoded)

local previous = previous_values(raw)

for index = 1, 5 do
	local old_value = previous and previous[index] or nil
	local new_value = text(next_values[index])

	if old_value ~= new_value then
		if old_value ~= nil then
			decrement(dimension_keys[index], old_value)
		end

		if new_value ~= nil then
			redis.call("HINCRBY", dimension_keys[index], new_value, 1)
		end
	end
end

return 1
