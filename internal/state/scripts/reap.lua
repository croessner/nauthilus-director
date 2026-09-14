-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Rechecks and expires one session inside its affinity slot. Secondary index
-- repairs and idempotent backend releases are returned to the caller.

local state_key = KEYS[1]
local sessions_key = KEYS[2]
local session_key = KEYS[3]
local session_id = ARGV[1]

-- ambiguous rejects malformed authority state before applying a mutation.
local function ambiguous(message)
 error("NDAMBIGUOUS " .. message)
end

-- now_ms reads the clock of the authority slot owner.
local function now_ms()
 local now = redis.call("TIME")
 return (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
end

if session_id == nil or session_id == "" then return ambiguous("session_id_required") end
local now = now_ms()
local scanned = 1
local expired = 0
local repaired_backends = 0
local stale_index_entries = 0
local next_due = 0
local backend_sessions_key = ""
local user_sessions_key = ""
local reservation_releases = {}
local aggregate_removals = {}
local idle_affinities = {}

if redis.call("EXISTS", session_key) == 0 then
 stale_index_entries = 1
else
 if redis.call("HGET", session_key, "session_id") ~= session_id then return ambiguous("session_id_mismatch") end
	local lease_expires_at = tonumber(redis.call("HGET", session_key, "lease_expires_at_ms") or "0")
	if lease_expires_at == nil then
		return ambiguous("lease_invalid")
	end

	if lease_expires_at > now then
		next_due = lease_expires_at
	else
		local stored_sessions_key = redis.call("HGET", session_key, "sessions_key")
		local stored_state_key = redis.call("HGET", session_key, "state_key")
		if stored_sessions_key ~= sessions_key then
			return ambiguous("sessions_key_required")
		end
		if stored_state_key ~= state_key then
			return ambiguous("state_key_required")
		end

		local idle_grace_ms = tonumber(redis.call("HGET", state_key, "idle_grace_ms") or redis.call("HGET", session_key, "idle_grace_ms") or "0")
		if idle_grace_ms == nil or idle_grace_ms < 0 then
			idle_grace_ms = 0
		end
		local retention_ttl_ms = tonumber(redis.call("HGET", session_key, "retention_ttl_ms") or redis.call("HGET", state_key, "retention_ttl_ms") or tostring(idle_grace_ms))
		if retention_ttl_ms == nil or retention_ttl_ms < 0 then
			retention_ttl_ms = 0
		end

		local holder_kind = tostring(redis.call("HGET", session_key, "holder_kind") or "session")
		local affinity_hash = redis.call("HGET", session_key, "affinity_hash")
		local counted = redis.call("HGET", session_key, "backend_counted")
		local backend_id = redis.call("HGET", session_key, "selected_backend_id")
		local reservation_id = redis.call("HGET", session_key, "backend_reservation_id")
		if counted == "1" and backend_id ~= false and backend_id ~= nil and backend_id ~= "" and reservation_id ~= false and reservation_id ~= nil and reservation_id ~= "" then
			repaired_backends = repaired_backends + 1
			table.insert(reservation_releases, backend_id .. "\t" .. reservation_id)
		end

		if holder_kind == "session" then
			table.insert(aggregate_removals, session_id)
		end

		backend_sessions_key = redis.call("HGET", session_key, "backend_sessions_key")

		user_sessions_key = redis.call("HGET", session_key, "user_sessions_key")

		redis.call("ZREM", sessions_key, session_id)
		redis.call("DEL", session_key)

		local active_count = redis.call("ZCARD", sessions_key)
		if redis.call("EXISTS", state_key) == 1 then
			if active_count == 0 and retention_ttl_ms == 0 then
				redis.call("DEL", state_key)
				redis.call("DEL", sessions_key)
			else
				local expires_at = now + retention_ttl_ms
				local retention_expires_at = expires_at
				if active_count > 0 then
					local top = redis.call("ZREVRANGE", sessions_key, 0, 0, "WITHSCORES")
					expires_at = tonumber(top[2]) or now
					expires_at = expires_at + retention_ttl_ms
					retention_expires_at = 0
				elseif affinity_hash ~= false and affinity_hash ~= nil and affinity_hash ~= "" and retention_ttl_ms > 0 then
					table.insert(idle_affinities, affinity_hash .. "\t" .. tostring(expires_at))
				end
				redis.call("HSET", state_key,
					"active_session_count", active_count,
					"active_holder_count", active_count,
					"retention_ttl_ms", retention_ttl_ms,
					"retention_expires_at_ms", retention_expires_at,
					"updated_at_ms", now,
					"expires_at_ms", expires_at)
				redis.call("PEXPIREAT", state_key, expires_at)
				redis.call("PEXPIREAT", sessions_key, expires_at)
			end
		end

		expired = expired + 1
	end
end

return {
	"status", "reaped",
	"scanned_sessions", tostring(scanned),
	"expired_sessions", tostring(expired),
	"stale_index_entries", tostring(stale_index_entries),
	"repaired_backends", tostring(repaired_backends),
	"reservation_releases", table.concat(reservation_releases, "\n"),
	"aggregate_removals", table.concat(aggregate_removals, "\n"),
	"idle_affinities", table.concat(idle_affinities, "\n"),
	"next_due_ms", tostring(next_due),
	"backend_sessions_key", backend_sessions_key or "",
	"user_sessions_key", user_sessions_key or "",
	"server_time_ms", tostring(now)
}
