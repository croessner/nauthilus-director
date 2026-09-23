-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Removes one active-session marker from a bucketed aggregate group and
-- decrements its dimension counters exactly once. Marker and counters share
-- one Redis Cluster hash tag. Returns 1 when a marker was removed.

local marker_key = KEYS[1]
local dimension_keys = { KEYS[2], KEYS[3], KEYS[4], KEYS[5], KEYS[6] }

local session_id = ARGV[1]

local function text(value)
	if type(value) ~= "string" or value == "" then
		return nil
	end

	return value
end

if text(session_id) == nil then
	error("NDAMBIGUOUS aggregate_session_required")
end

local raw = redis.call("HGET", marker_key, session_id)
if raw == false or raw == nil then
	return 0
end

redis.call("HDEL", marker_key, session_id)

local ok, decoded = pcall(cjson.decode, raw)
if not ok or type(decoded) ~= "table" then
	return 1
end

local values = { text(decoded.protocol), text(decoded.listener), text(decoded.service), text(decoded.shard_tag), text(decoded.backend) }
for index = 1, 4 do
	if values[index] == nil then
		return 1
	end
end

for index = 1, 5 do
	if values[index] ~= nil then
		local value = redis.call("HINCRBY", dimension_keys[index], values[index], -1)
		if value <= 0 then
			redis.call("HDEL", dimension_keys[index], values[index])
		end
	end
end

return 1
