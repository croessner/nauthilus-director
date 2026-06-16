-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Reads scoped backend pins without mutating affinity or session leases.

local sessions_key = KEYS[1]
local backend_pin_key = KEYS[2]

local mode = ARGV[1] or "get"
local requested_protocol = ARGV[2] or ""
local requested_backend_pool = ARGV[3] or ""
local fallback_tenant = ARGV[4] or ""
local fallback_account_key = ARGV[5] or ""

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

local function missing(status, now, active_count)
	local result = {}
	append_common(result, status or "missing", "0", fallback_tenant, fallback_account_key, "", active_count, now, 0)
	return result
end

local function append_pin(result, index, pin, legacy)
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
	table.insert(result, tostring(pin.generation))
	table.insert(result, prefix .. "reason")
	table.insert(result, pin.reason or "")
	table.insert(result, prefix .. "actor")
	table.insert(result, pin.actor or "")
	table.insert(result, prefix .. "updated_at_ms")
	table.insert(result, tostring(pin.updated_at_ms or 0))
	table.insert(result, prefix .. "legacy")
	if legacy then
		table.insert(result, "1")
	else
		table.insert(result, "0")
	end
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
		generation = require_value(redis.call("HGET", backend_pin_key, "generation"), "legacy_generation_required"),
		reason = redis.call("HGET", backend_pin_key, "reason") or "",
		actor = redis.call("HGET", backend_pin_key, "actor") or "",
		updated_at_ms = redis.call("HGET", backend_pin_key, "updated_at_ms") or "0",
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
		generation = require_value(redis.call("HGET", backend_pin_key, field(scope, "generation")), "generation_required"),
		reason = redis.call("HGET", backend_pin_key, field(scope, "reason")) or "",
		actor = redis.call("HGET", backend_pin_key, field(scope, "actor")) or "",
		updated_at_ms = redis.call("HGET", backend_pin_key, field(scope, "updated_at_ms")) or "0",
		scope = scope,
	}
end

local function return_pins(status, tenant, account_key, generation, active_count, now, pins, legacy)
	local result = {}
	append_common(result, status, "1", tenant, account_key, generation, active_count, now, #pins)
	for index, pin in ipairs(pins) do
		append_pin(result, index, pin, legacy)
	end

	return result
end

local now = now_ms()
local active_count = redis.call("ZCOUNT", sessions_key, "(" .. tostring(now), "+inf")
local scopes = split_scopes(redis.call("HGET", backend_pin_key, "scopes"))

if redis.call("EXISTS", backend_pin_key) == 0 then
	return missing("missing", now, active_count)
end

if legacy_present() and #scopes > 0 then
	return ambiguous("legacy_scoped_mixed")
end

local requested_scope = ""
requested_protocol = trim(requested_protocol)
requested_backend_pool = trim(requested_backend_pool)
if requested_protocol ~= "" or requested_backend_pool ~= "" then
	requested_scope = scope_name(requested_protocol, requested_backend_pool)
end

if legacy_present() then
	local pin = legacy_pin()
	if requested_scope ~= "" and requested_scope ~= pin.scope then
		return missing("missing", now, active_count)
	end

	return return_pins(
		"found",
		require_value(redis.call("HGET", backend_pin_key, "tenant"), "legacy_tenant_required"),
		require_value(redis.call("HGET", backend_pin_key, "account_key"), "legacy_account_key_required"),
		pin.generation,
		active_count,
		now,
		{pin},
		true)
end

if #scopes == 0 then
	return missing("missing", now, active_count)
end

local tenant = require_value(redis.call("HGET", backend_pin_key, "tenant"), "tenant_required")
local account_key = require_value(redis.call("HGET", backend_pin_key, "account_key"), "account_key_required")
local generation = require_value(redis.call("HGET", backend_pin_key, "generation"), "generation_required")

if mode == "list" then
	local pins = {}
	for _, scope in ipairs(scopes) do
		table.insert(pins, scoped_pin(scope))
	end

	return return_pins("found", tenant, account_key, generation, active_count, now, pins, false)
end

if requested_scope == "" then
	if #scopes ~= 1 then
		return ambiguous("scope_required")
	end
	requested_scope = scopes[1]
end

local found = false
for _, scope in ipairs(scopes) do
	if scope == requested_scope then
		found = true
		break
	end
end

if not found then
	return missing("missing", now, active_count)
end

return return_pins("found", tenant, account_key, generation, active_count, now, {scoped_pin(requested_scope)}, false)
