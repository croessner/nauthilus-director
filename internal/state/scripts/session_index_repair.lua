-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Repairs one co-slotted locator/due pair only while it still describes the
-- observed registration. A later lease or replacement locator wins.
local index_key = KEYS[1]
local due_key = KEYS[2]
local session_id = ARGV[1]
local expected_key = ARGV[2]
local observed_at = tonumber(ARGV[3])
local next_due = tonumber(ARGV[4])

if session_id == nil or session_id == "" or expected_key == nil or
   observed_at == nil or observed_at < 0 or next_due == nil or next_due < 0 then
 error("NDAMBIGUOUS invalid_index_repair")
end

local current = redis.call("HGET", index_key, session_id) or ""
if current ~= expected_key then return 0 end
local score = tonumber(redis.call("ZSCORE", due_key, session_id))
if next_due > 0 then
 if current == "" or (score ~= nil and score > next_due) then return 0 end
 redis.call("ZADD", due_key, next_due, session_id)
else
 if score ~= nil and score > observed_at then return 0 end
 redis.call("HDEL", index_key, session_id)
 redis.call("ZREM", due_key, session_id)
end
return 1
