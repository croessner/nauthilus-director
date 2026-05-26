-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Records a user move strategy and generation without storing a raw username.

local state_key = KEYS[1]
local sessions_key = KEYS[2]
local override_key = KEYS[3]

local target_shard = ARGV[1]
local strategy = ARGV[2]
local reason = ARGV[3]
local actor = ARGV[4]

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

require_value(target_shard, "target_shard_required")
require_value(strategy, "strategy_required")

if strategy ~= "new_sessions_only" and strategy ~= "kick_existing" and strategy ~= "drain_existing" then
	return ambiguous("strategy_invalid")
end

local now = now_ms()
redis.call("ZREMRANGEBYSCORE", sessions_key, "-inf", now)

local active_count = redis.call("ZCARD", sessions_key)
local shard = ""
local generation = 0
local control_action = "none"

if redis.call("EXISTS", state_key) == 1 then
	shard = require_value(redis.call("HGET", state_key, "shard_tag"), "state_shard_required")
	generation = redis.call("HINCRBY", state_key, "control_generation", 1)
	redis.call("HSET", state_key,
		"move_generation", generation,
		"move_strategy", strategy,
		"move_target_shard", target_shard,
		"move_reason", reason or "",
		"move_actor", actor or "",
		"updated_at_ms", now)

	if strategy == "kick_existing" then
		shard = target_shard
		control_action = "move_generation_changed"
		redis.call("HSET", state_key,
			"shard_tag", target_shard,
			"control_action", control_action)
	elseif strategy == "drain_existing" then
		control_action = "none"
		redis.call("HSET", override_key,
			"target_shard", target_shard,
			"strategy", strategy,
			"generation", generation,
			"updated_at_ms", now)
	else
		redis.call("HSET", override_key,
			"target_shard", target_shard,
			"strategy", strategy,
			"generation", generation,
			"updated_at_ms", now)
	end
else
	generation = redis.call("HINCRBY", override_key, "generation", 1)
	redis.call("HSET", override_key,
		"target_shard", target_shard,
		"strategy", strategy,
		"reason", reason or "",
		"actor", actor or "",
		"updated_at_ms", now)
	shard = target_shard
end

return {
	"status", "moved",
	"present", "1",
	"shard_tag", shard,
	"target_shard", target_shard,
	"strategy", strategy,
	"generation", tostring(generation),
	"control_generation", tostring(generation),
	"control_action", control_action,
	"active_session_count", tostring(active_count),
	"server_time_ms", tostring(now)
}
