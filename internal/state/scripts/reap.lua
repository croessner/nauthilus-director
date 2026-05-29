-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only
--
-- Repairs due session leases, active affinity counts, backend counts and
-- repairable listing indexes using Redis server time.

local session_index_key = KEYS[1]
local session_due_index_key = KEYS[2]

local limit = tonumber(ARGV[1])

local function ambiguous(message)
	error("NDAMBIGUOUS " .. message)
end

local function now_ms()
	local now = redis.call("TIME")
	return (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
end

local function decrement_backend(session_key)
	local counted = redis.call("HGET", session_key, "backend_counted")
	if counted ~= "1" then
		return 0
	end

	local backend_key = redis.call("HGET", session_key, "backend_runtime_key")
	if backend_key == false or backend_key == nil or backend_key == "" then
		return ambiguous("backend_key_required")
	end

	local current = tonumber(redis.call("HGET", backend_key, "active_session_count") or "0")
	if current == nil or current < 0 then
		return ambiguous("backend_count_invalid")
	end

	if current > 0 then
		redis.call("HINCRBY", backend_key, "active_session_count", -1)
	else
		redis.call("HSET", backend_key, "active_session_count", 0)
	end

	return 1
end

if limit == nil or limit <= 0 then
	return ambiguous("limit_invalid")
end

local now = now_ms()
local due_sessions = redis.call("ZRANGEBYSCORE", session_due_index_key, "-inf", now, "LIMIT", 0, limit)
local scanned = 0
local expired = 0
local repaired_backends = 0

for _, session_id in ipairs(due_sessions) do
	scanned = scanned + 1

	local session_key = redis.call("HGET", session_index_key, session_id)
	if session_key == false or session_key == nil or session_key == "" then
		redis.call("ZREM", session_due_index_key, session_id)
		redis.call("HDEL", session_index_key, session_id)
	elseif redis.call("EXISTS", session_key) == 0 then
		redis.call("ZREM", session_due_index_key, session_id)
		redis.call("HDEL", session_index_key, session_id)
	else
		local lease_expires_at = tonumber(redis.call("HGET", session_key, "lease_expires_at_ms") or "0")
		if lease_expires_at == nil then
			return ambiguous("lease_invalid")
		end

		if lease_expires_at > now then
			redis.call("ZADD", session_due_index_key, lease_expires_at, session_id)
		else
			local sessions_key = redis.call("HGET", session_key, "sessions_key")
			local state_key = redis.call("HGET", session_key, "state_key")
			if sessions_key == false or sessions_key == nil or sessions_key == "" then
				return ambiguous("sessions_key_required")
			end
			if state_key == false or state_key == nil or state_key == "" then
				return ambiguous("state_key_required")
			end

			local idle_grace_ms = tonumber(redis.call("HGET", state_key, "idle_grace_ms") or redis.call("HGET", session_key, "idle_grace_ms") or "0")
			if idle_grace_ms == nil or idle_grace_ms < 0 then
				idle_grace_ms = 0
			end

			repaired_backends = repaired_backends + decrement_backend(session_key)

			local backend_sessions_key = redis.call("HGET", session_key, "backend_sessions_key")
			if backend_sessions_key ~= false and backend_sessions_key ~= nil and backend_sessions_key ~= "" then
				redis.call("SREM", backend_sessions_key, session_id)
			end

			local user_sessions_key = redis.call("HGET", session_key, "user_sessions_key")
			if user_sessions_key ~= false and user_sessions_key ~= nil and user_sessions_key ~= "" then
				redis.call("SREM", user_sessions_key, session_id)
			end

			redis.call("ZREM", sessions_key, session_id)
			redis.call("ZREM", session_due_index_key, session_id)
			redis.call("HDEL", session_index_key, session_id)
			redis.call("DEL", session_key)

			local active_count = redis.call("ZCARD", sessions_key)
			if redis.call("EXISTS", state_key) == 1 then
				if active_count == 0 and idle_grace_ms == 0 then
					redis.call("DEL", state_key)
					redis.call("DEL", sessions_key)
				else
					local expires_at = now + idle_grace_ms
					if active_count > 0 then
						local top = redis.call("ZREVRANGE", sessions_key, 0, 0, "WITHSCORES")
						expires_at = tonumber(top[2]) or now
					end
					redis.call("HSET", state_key,
						"active_session_count", active_count,
						"updated_at_ms", now,
						"expires_at_ms", expires_at)
					redis.call("PEXPIREAT", state_key, expires_at)
					redis.call("PEXPIREAT", sessions_key, expires_at)
				end
			end

			expired = expired + 1
		end
	end
end

return {
	"status", "reaped",
	"scanned_sessions", tostring(scanned),
	"expired_sessions", tostring(expired),
	"repaired_backends", tostring(repaired_backends),
	"server_time_ms", tostring(now)
}
