-- Copyright (C) 2026 Christian Rößner
--
-- SPDX-License-Identifier: AGPL-3.0-only

local nauthilus_context = require("nauthilus_context")

local shard_by_user = {
    ["alice@example.test"] = "mailstore-a",
    ["bob@example.test"] = "mailstore-b",
    ["carol@example.test"] = "mailstore-c",
    ["dave@example.test"] = "mailstore-a",
    ["erin@example.test"] = "stalwart",
    ["frank@example.test"] = "stalwart",
    ["healthcheck@example.test"] = "mailstore-a",
}

local function normalize(value)
    return string.lower(tostring(value or ""))
end

local function first_present(...)
    for index = 1, select("#", ...) do
        local normalized = normalize(select(index, ...))
        if normalized ~= "" then
            return normalized
        end
    end

    return ""
end

local function shard_for(username)
    return shard_by_user[normalize(username)] or "mailstore-a"
end

function nauthilus_call_environment(request)
    local account = first_present(request.account, request.username)
    local shard = shard_for(account)

    nauthilus_context.context_set("director.account", account)
    nauthilus_context.context_set("director.tenant", "default")
    nauthilus_context.context_set("director.mailShard", shard)

    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
