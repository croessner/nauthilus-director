-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Registers the selected backend for an already-open session reservation and
-- increments the backend active-session count exactly once.

local state_key = KEYS[1]
local sessions_key = KEYS[2]
local session_key = KEYS[3]
local backend_key = KEYS[4]
local session_index_key = KEYS[5]
local backend_index_key = KEYS[6]
local backend_sessions_key = KEYS[7]
local user_sessions_key = KEYS[8]
local session_due_index_key = KEYS[9]

local session_id = ARGV[1]
local backend_id = ARGV[2]
local max_connections = tonumber(ARGV[3])

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

require_value(session_id, "session_id_required")
require_value(backend_id, "backend_id_required")

if max_connections == nil or max_connections <= 0 then
	return ambiguous("max_connections_required")
end

local now = now_ms()

if redis.call("EXISTS", state_key) == 0 then
	return ambiguous("state_missing")
end

if redis.call("EXISTS", session_key) == 0 then
	return ambiguous("session_missing")
end

local lease_expires_at = tonumber(require_value(redis.call("ZSCORE", sessions_key, session_id), "session_score_required"))
if lease_expires_at == nil or lease_expires_at <= now then
	return ambiguous("session_expired")
end

local current_backend = redis.call("HGET", session_key, "selected_backend_id")
if current_backend ~= false and current_backend ~= nil and current_backend ~= "" then
	if current_backend ~= backend_id then
		return ambiguous("session_backend_conflict")
	end

	local current_count = tonumber(redis.call("HGET", backend_key, "active_session_count") or "0")
	if current_count == nil then
		return ambiguous("backend_count_invalid")
	end

	return {
		"status", "attached",
		"backend_id", backend_id,
		"backend_active_session_count", tostring(current_count),
		"server_time_ms", tostring(now),
		"lease_expires_at_ms", tostring(lease_expires_at),
		"control_generation", tostring(redis.call("HGET", session_key, "control_generation") or "0")
	}
end

local current_count = tonumber(redis.call("HGET", backend_key, "active_session_count") or "0")
if current_count == nil or current_count < 0 then
	return ambiguous("backend_count_invalid")
end

if current_count >= max_connections then
	return ambiguous("backend_at_capacity")
end

local backend_count = redis.call("HINCRBY", backend_key, "active_session_count", 1)
if backend_count < 0 then
	return ambiguous("backend_count_negative")
end

local control_generation = tostring(redis.call("HGET", state_key, "control_generation") or "0")

redis.call("HSET", backend_key,
	"backend_id", backend_id,
	"updated_at_ms", now)
redis.call("SADD", backend_index_key, backend_id)
redis.call("SADD", backend_sessions_key, session_id)
redis.call("SADD", user_sessions_key, session_id)
redis.call("ZADD", session_due_index_key, lease_expires_at, session_id)
redis.call("HSET", session_key,
	"selected_backend_id", backend_id,
	"backend_runtime_key", backend_key,
	"backend_sessions_key", backend_sessions_key,
	"user_sessions_key", user_sessions_key,
	"session_due_index_key", session_due_index_key,
	"backend_counted", "1",
	"status", "active",
	"control_generation", control_generation,
	"updated_at_ms", now)
redis.call("HSET", session_index_key, session_id, session_key)

return {
	"status", "attached",
	"backend_id", backend_id,
	"backend_active_session_count", tostring(backend_count),
	"server_time_ms", tostring(now),
	"lease_expires_at_ms", tostring(lease_expires_at),
	"control_generation", control_generation
}
