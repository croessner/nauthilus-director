-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Stores one or more scoped backend pins without changing shard affinity.

local state_key = KEYS[1]
local sessions_key = KEYS[2]
local backend_pin_key = KEYS[4]

local reason = ARGV[1]
local actor = ARGV[2]
local schema_version = ARGV[3]
local tenant = ARGV[4]
local account_key = ARGV[5]
local strategy = ARGV[6]
local pin_count = tonumber(ARGV[7] or "")

local scope_separator = "|"

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

local function trim(value)
	if value == nil or value == false then
		return ""
	end

	return tostring(value):match("^%s*(.-)%s*$")
end

local function scope_name(protocol, backend_pool)
	protocol = string.lower(trim(protocol))
	backend_pool = trim(backend_pool)
	require_value(protocol, "protocol_required")
	require_value(backend_pool, "backend_pool_required")
	if string.find(protocol, scope_separator, 1, true) or string.find(protocol, "\n", 1, true) or
		string.find(backend_pool, scope_separator, 1, true) or string.find(backend_pool, "\n", 1, true) then
		return ambiguous("scope_invalid")
	end

	return protocol .. scope_separator .. backend_pool
end

local function field(scope, name)
	return "pin:" .. scope .. ":" .. name
end

local function split_scopes(value)
	local scopes = {}
	value = trim(value)
	if value == "" then
		return scopes
	end

	for scope in string.gmatch(value, "[^\n]+") do
		table.insert(scopes, scope)
	end

	return scopes
end

local function join_scopes(scopes)
	table.sort(scopes)
	return table.concat(scopes, "\n")
end

local function legacy_present()
	return redis.call("HGET", backend_pin_key, "backend_id") ~= false or
		redis.call("HGET", backend_pin_key, "protocol") ~= false or
		redis.call("HGET", backend_pin_key, "backend_pool") ~= false
end

local function legacy_scope()
	local protocol = require_value(redis.call("HGET", backend_pin_key, "protocol"), "legacy_protocol_required")
	local backend_pool = require_value(redis.call("HGET", backend_pin_key, "backend_pool"), "legacy_backend_pool_required")
	return scope_name(protocol, backend_pool)
end

local function clear_legacy_fields()
	redis.call("HDEL", backend_pin_key,
		"backend_id",
		"protocol",
		"backend_pool",
		"shard_tag",
		"strategy",
		"reason",
		"actor",
		"updated_at_ms")
end

local function parse_pin_args()
	if pin_count == nil or pin_count < 1 then
		return ambiguous("pin_count_required")
	end

	local pins = {}
	local scopes = {}
	local seen = {}
	local offset = 8
	for index = 1, pin_count do
		local backend_id = require_value(trim(ARGV[offset]), "backend_id_required")
		local protocol = string.lower(require_value(trim(ARGV[offset + 1]), "protocol_required"))
		local backend_pool = require_value(trim(ARGV[offset + 2]), "backend_pool_required")
		local shard_tag = require_value(trim(ARGV[offset + 3]), "shard_required")
		local backend_node = require_value(trim(ARGV[offset + 4]), "backend_node_required")
		local scope = scope_name(protocol, backend_pool)
		if seen[scope] then
			return ambiguous("duplicate_scope")
		end

		seen[scope] = true
		table.insert(scopes, scope)
		table.insert(pins, {
			scope = scope,
			backend_id = backend_id,
			protocol = protocol,
			backend_pool = backend_pool,
			shard_tag = shard_tag,
			backend_node = backend_node,
		})
		offset = offset + 5
	end

	return pins, scopes, seen
end

local function append_pin(result, index, pin, generation, now, active_count, control_generation, control_action)
	local prefix = "pin_" .. tostring(index) .. "_"
	table.insert(result, prefix .. "backend_id")
	table.insert(result, pin.backend_id)
	table.insert(result, prefix .. "protocol")
	table.insert(result, pin.protocol)
	table.insert(result, prefix .. "backend_pool")
	table.insert(result, pin.backend_pool)
	table.insert(result, prefix .. "shard_tag")
	table.insert(result, pin.shard_tag)
	table.insert(result, prefix .. "backend_node")
	table.insert(result, pin.backend_node)
	table.insert(result, prefix .. "strategy")
	table.insert(result, strategy)
	table.insert(result, prefix .. "generation")
	table.insert(result, tostring(generation))
	table.insert(result, prefix .. "reason")
	table.insert(result, reason)
	table.insert(result, prefix .. "actor")
	table.insert(result, actor or "")
	table.insert(result, prefix .. "updated_at_ms")
	table.insert(result, tostring(now))
	table.insert(result, prefix .. "legacy")
	table.insert(result, "0")
end

local function return_pins(pins, generation, control_generation, control_action, active_count, now)
	table.sort(pins, function(left, right)
		return left.scope < right.scope
	end)

	local result = {
		"status", "pinned",
		"present", "1",
		"tenant", tenant,
		"account_key", account_key,
		"generation", tostring(generation),
		"control_generation", tostring(control_generation),
		"control_action", control_action,
		"active_session_count", tostring(active_count),
		"server_time_ms", tostring(now),
		"pin_count", tostring(#pins),
	}

	for index, pin in ipairs(pins) do
		append_pin(result, index, pin, generation, now, active_count, control_generation, control_action)
	end

	return result
end

require_value(reason, "reason_required")
require_value(schema_version, "schema_version_required")
require_value(tenant, "tenant_required")
require_value(account_key, "account_key_required")
require_value(strategy, "strategy_required")

if strategy ~= "new_sessions_only" and strategy ~= "kick_existing" and strategy ~= "drain_existing" then
	return ambiguous("strategy_invalid")
end

local pins, incoming_scopes, incoming_scope_set = parse_pin_args()
local existing_scopes = split_scopes(redis.call("HGET", backend_pin_key, "scopes"))
if legacy_present() and #existing_scopes > 0 then
	return ambiguous("legacy_scoped_mixed")
end

if legacy_present() then
	local existing_scope = legacy_scope()
	if not incoming_scope_set[existing_scope] then
		return ambiguous("legacy_scope_conflict")
	end
end

local now = now_ms()
redis.call("ZREMRANGEBYSCORE", sessions_key, "-inf", now)

local active_count = redis.call("ZCARD", sessions_key)
local generation = 0
local control_action = "none"
local control_generation = 0

if redis.call("EXISTS", state_key) == 1 then
	require_value(redis.call("HGET", state_key, "shard_tag"), "state_shard_required")
	require_value(redis.call("HGET", state_key, "generation"), "state_generation_required")
else
	if active_count > 0 then
		return ambiguous("sessions_without_state")
	end
end

generation = redis.call("HINCRBY", backend_pin_key, "generation", 1)
control_generation = generation

if redis.call("EXISTS", state_key) == 1 and strategy == "kick_existing" then
	control_generation = redis.call("HINCRBY", state_key, "control_generation", 1)
	if active_count > 0 then
		control_action = "move_generation_changed"
		redis.call("HSET", state_key,
			"updated_at_ms", now,
			"control_action", control_action)
	else
		redis.call("HINCRBY", state_key, "binding_generation", 1)
		redis.call("HSET", state_key,
			"backend_node", "",
			"retention_expires_at_ms", 0,
			"updated_at_ms", now,
			"control_action", "none")
	end
end

if legacy_present() then
	clear_legacy_fields()
end

local scope_set = {}
local merged_scopes = {}
for _, scope in ipairs(existing_scopes) do
	if not scope_set[scope] then
		scope_set[scope] = true
		table.insert(merged_scopes, scope)
	end
end
for _, scope in ipairs(incoming_scopes) do
	if not scope_set[scope] then
		scope_set[scope] = true
		table.insert(merged_scopes, scope)
	end
end

redis.call("HSET", backend_pin_key,
	"schema_version", schema_version,
	"tenant", tenant,
	"account_key", account_key,
	"generation", generation,
	"updated_at_ms", now,
	"scopes", join_scopes(merged_scopes))

for _, pin in ipairs(pins) do
	redis.call("HSET", backend_pin_key,
		field(pin.scope, "backend_id"), pin.backend_id,
		field(pin.scope, "protocol"), pin.protocol,
		field(pin.scope, "backend_pool"), pin.backend_pool,
		field(pin.scope, "shard_tag"), pin.shard_tag,
		field(pin.scope, "backend_node"), pin.backend_node,
		field(pin.scope, "strategy"), strategy,
		field(pin.scope, "generation"), generation,
		field(pin.scope, "reason"), reason,
		field(pin.scope, "actor"), actor or "",
		field(pin.scope, "updated_at_ms"), now)
end

return return_pins(pins, generation, control_generation, control_action, active_count, now)
