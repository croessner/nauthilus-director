-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Clears scoped backend pins while preserving shard affinity state.

local sessions_key = KEYS[1]
local backend_pin_key = KEYS[2]

local reason = ARGV[1]
local actor = ARGV[2]
local fallback_tenant = ARGV[3]
local fallback_account_key = ARGV[4]
local requested_protocol = ARGV[5] or ""
local requested_backend_pool = ARGV[6] or ""

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
	table.sort(scopes)

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

local function append_common(result, status, present, tenant, account_key, generation, active_count, now, pin_count)
	table.insert(result, "status")
	table.insert(result, status)
	table.insert(result, "present")
	table.insert(result, present)
	table.insert(result, "tenant")
	table.insert(result, tenant)
	table.insert(result, "account_key")
	table.insert(result, account_key)
	table.insert(result, "generation")
	table.insert(result, generation or "")
	table.insert(result, "active_session_count")
	table.insert(result, tostring(active_count))
	table.insert(result, "server_time_ms")
	table.insert(result, tostring(now))
	table.insert(result, "pin_count")
	table.insert(result, tostring(pin_count))
end

local function missing(now, active_count)
	local result = {}
	append_common(result, "missing", "0", fallback_tenant, fallback_account_key, "", active_count, now, 0)
	return result
end

local function append_pin(result, index, pin, generation, now, legacy)
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
	table.insert(result, pin.backend_node or "")
	table.insert(result, prefix .. "strategy")
	table.insert(result, pin.strategy)
	table.insert(result, prefix .. "generation")
	table.insert(result, tostring(generation))
	table.insert(result, prefix .. "reason")
	table.insert(result, pin.reason or "")
	table.insert(result, prefix .. "actor")
	table.insert(result, pin.actor or "")
	table.insert(result, prefix .. "updated_at_ms")
	table.insert(result, tostring(now))
	table.insert(result, prefix .. "legacy")
	if legacy then
		table.insert(result, "1")
	else
		table.insert(result, "0")
	end
end

local function return_cleared(tenant, account_key, generation, active_count, now, pins, legacy)
	local result = {}
	append_common(result, "cleared", "0", tenant, account_key, generation, active_count, now, #pins)
	for index, pin in ipairs(pins) do
		append_pin(result, index, pin, generation, now, legacy)
	end

	return result
end

local function legacy_pin()
	local protocol = require_value(redis.call("HGET", backend_pin_key, "protocol"), "legacy_protocol_required")
	local backend_pool = require_value(redis.call("HGET", backend_pin_key, "backend_pool"), "legacy_backend_pool_required")
	return {
		backend_id = require_value(redis.call("HGET", backend_pin_key, "backend_id"), "legacy_backend_id_required"),
		protocol = protocol,
		backend_pool = backend_pool,
		shard_tag = require_value(redis.call("HGET", backend_pin_key, "shard_tag"), "legacy_shard_required"),
		backend_node = redis.call("HGET", backend_pin_key, "backend_node") or "",
		strategy = require_value(redis.call("HGET", backend_pin_key, "strategy"), "legacy_strategy_required"),
		reason = redis.call("HGET", backend_pin_key, "reason") or "",
		actor = redis.call("HGET", backend_pin_key, "actor") or "",
		scope = scope_name(protocol, backend_pool),
	}
end

local function scoped_pin(scope)
	return {
		backend_id = require_value(redis.call("HGET", backend_pin_key, field(scope, "backend_id")), "backend_id_required"),
		protocol = require_value(redis.call("HGET", backend_pin_key, field(scope, "protocol")), "protocol_required"),
		backend_pool = require_value(redis.call("HGET", backend_pin_key, field(scope, "backend_pool")), "backend_pool_required"),
		shard_tag = require_value(redis.call("HGET", backend_pin_key, field(scope, "shard_tag")), "shard_required"),
		backend_node = require_value(redis.call("HGET", backend_pin_key, field(scope, "backend_node")), "backend_node_required"),
		strategy = require_value(redis.call("HGET", backend_pin_key, field(scope, "strategy")), "strategy_required"),
		reason = redis.call("HGET", backend_pin_key, field(scope, "reason")) or "",
		actor = redis.call("HGET", backend_pin_key, field(scope, "actor")) or "",
		scope = scope,
	}
end

local function delete_scope(scope)
	redis.call("HDEL", backend_pin_key,
		field(scope, "backend_id"),
		field(scope, "protocol"),
		field(scope, "backend_pool"),
		field(scope, "shard_tag"),
		field(scope, "backend_node"),
		field(scope, "strategy"),
		field(scope, "generation"),
		field(scope, "reason"),
		field(scope, "actor"),
		field(scope, "updated_at_ms"))
end

require_value(reason, "reason_required")
require_value(fallback_tenant, "tenant_required")
require_value(fallback_account_key, "account_key_required")

local now = now_ms()
local active_count = redis.call("ZCOUNT", sessions_key, "(" .. tostring(now), "+inf")
local scopes = split_scopes(redis.call("HGET", backend_pin_key, "scopes"))

if redis.call("EXISTS", backend_pin_key) == 0 then
	return missing(now, active_count)
end

if legacy_present() and #scopes > 0 then
	return ambiguous("legacy_scoped_mixed")
end

requested_protocol = trim(requested_protocol)
requested_backend_pool = trim(requested_backend_pool)
local requested_scope = ""
if requested_protocol ~= "" or requested_backend_pool ~= "" then
	requested_scope = scope_name(requested_protocol, requested_backend_pool)
end

if legacy_present() then
	local pin = legacy_pin()
	if requested_scope ~= "" and requested_scope ~= pin.scope then
		return missing(now, active_count)
	end

	local tenant = require_value(redis.call("HGET", backend_pin_key, "tenant"), "legacy_tenant_required")
	local account_key = require_value(redis.call("HGET", backend_pin_key, "account_key"), "legacy_account_key_required")
	local generation = redis.call("HINCRBY", backend_pin_key, "generation", 1)
	redis.call("DEL", backend_pin_key)
	return return_cleared(tenant, account_key, generation, active_count, now, {pin}, true)
end

if #scopes == 0 then
	return missing(now, active_count)
end

local tenant = require_value(redis.call("HGET", backend_pin_key, "tenant"), "tenant_required")
local account_key = require_value(redis.call("HGET", backend_pin_key, "account_key"), "account_key_required")

if requested_scope == "" then
	local pins = {}
	for _, scope in ipairs(scopes) do
		table.insert(pins, scoped_pin(scope))
	end

	local generation = redis.call("HINCRBY", backend_pin_key, "generation", 1)
	redis.call("DEL", backend_pin_key)
	return return_cleared(tenant, account_key, generation, active_count, now, pins, false)
end

local remaining = {}
local target_pin = nil
for _, scope in ipairs(scopes) do
	if scope == requested_scope then
		target_pin = scoped_pin(scope)
	else
		table.insert(remaining, scope)
	end
end

if target_pin == nil then
	return missing(now, active_count)
end

local generation = redis.call("HINCRBY", backend_pin_key, "generation", 1)
delete_scope(requested_scope)

if #remaining == 0 then
	redis.call("DEL", backend_pin_key)
else
	redis.call("HSET", backend_pin_key,
		"generation", generation,
		"updated_at_ms", now,
		"last_clear_reason", reason,
		"last_clear_actor", actor or "",
		"scopes", join_scopes(remaining))
end

return return_cleared(tenant, account_key, generation, active_count, now, {target_pin}, false)
