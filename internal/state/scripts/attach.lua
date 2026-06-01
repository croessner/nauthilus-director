-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Attaches a selected backend and reservation reference to an already-open
-- affinity session. All keys passed to this script share one Redis Cluster
-- affinity hash tag.

local state_key = KEYS[1]
local sessions_key = KEYS[2]
local session_key = KEYS[3]

local session_id = ARGV[1]
local backend_id = ARGV[2]
local reservation_id = ARGV[3]
local max_connections = tonumber(ARGV[4])
local backend_node = ARGV[5]

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
require_value(reservation_id, "reservation_id_required")

if max_connections == nil or max_connections <= 0 then
	return ambiguous("max_connections_required")
end

if backend_node == false or backend_node == nil then
	backend_node = ""
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

local state_backend_node = tostring(redis.call("HGET", state_key, "backend_node") or "")
local session_backend_node = tostring(redis.call("HGET", session_key, "backend_node") or "")
local binding_generation = tostring(redis.call("HGET", state_key, "binding_generation") or "0")

if state_backend_node ~= "" and backend_node ~= "" and state_backend_node ~= backend_node then
	return ambiguous("backend_node_conflict")
end

if session_backend_node ~= "" and backend_node ~= "" and session_backend_node ~= backend_node then
	return ambiguous("session_backend_node_conflict")
end

if state_backend_node == "" and backend_node ~= "" then
	state_backend_node = backend_node
	binding_generation = tostring(redis.call("HINCRBY", state_key, "binding_generation", 1))
	redis.call("HSET", state_key, "backend_node", state_backend_node)
end

if session_backend_node == "" and state_backend_node ~= "" then
	session_backend_node = state_backend_node
	redis.call("HSET", session_key, "backend_node", session_backend_node)
end

local current_backend = redis.call("HGET", session_key, "selected_backend_id")
if current_backend ~= false and current_backend ~= nil and current_backend ~= "" then
	if current_backend ~= backend_id then
		return ambiguous("session_backend_conflict")
	end

	local current_reservation = require_value(redis.call("HGET", session_key, "backend_reservation_id"), "reservation_required")
	if current_reservation ~= reservation_id then
		return ambiguous("session_reservation_conflict")
	end

	return {
		"status", "attached",
		"backend_id", backend_id,
		"backend_node", state_backend_node,
		"backend_reservation_id", reservation_id,
		"backend_max_connections", tostring(max_connections),
		"binding_generation", binding_generation,
		"backend_active_session_count", "0",
		"server_time_ms", tostring(now),
		"lease_expires_at_ms", tostring(lease_expires_at),
		"control_generation", tostring(redis.call("HGET", session_key, "control_generation") or "0")
	}
end

local control_generation = tostring(redis.call("HGET", state_key, "control_generation") or "0")

redis.call("HSET", session_key,
	"selected_backend_id", backend_id,
	"backend_node", session_backend_node,
	"backend_reservation_id", reservation_id,
	"backend_max_connections", tostring(max_connections),
	"backend_counted", "1",
	"status", "active",
	"control_generation", control_generation,
	"updated_at_ms", now)

return {
	"status", "attached",
	"backend_id", backend_id,
	"backend_node", state_backend_node,
	"backend_reservation_id", reservation_id,
	"backend_max_connections", tostring(max_connections),
	"binding_generation", binding_generation,
	"backend_active_session_count", "0",
	"server_time_ms", tostring(now),
	"lease_expires_at_ms", tostring(lease_expires_at),
	"control_generation", control_generation
}
