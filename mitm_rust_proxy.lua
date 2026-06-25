local mp = require 'mp'
local options = require 'mp.options'
local utils = require 'mp.utils'

local opts = {
    use_proxies = false,
    proxy_rotation_enabled = false,
    auto_restart_on_failure = false,
    cooldown_hours = 16,
    fallback_to_direct = false,
    direct_cdn = false,
    ytdl_extractor_profile = "android_vr",
    bypass_chunk_modification = false,
    verify_tls = false,
    disable_pooling = true,
    enable_proxy_auth = true,
    max_resolution = 2160,
    debug = false
}
options.read_options(opts, "mitm_rust_proxy")

local function dprint(...)
    if opts.debug then
        print(...)
    end
end

local function dump_table(t)
    local parts = {}
    for k, v in pairs(t) do
        local kstr = type(k) == "string" and k or tostring(k)
        local vstr = type(v) == "string" and ('"' .. v .. '"') or tostring(v)
        parts[#parts + 1] = kstr .. "=" .. vstr
    end
    return "{" .. table.concat(parts, ", ") .. "}"
end

local function generate_random_string(len)
    local charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    local result = {}
    for i = 1, len do
        local idx = math.random(1, #charset)
        result[i] = charset:sub(idx, idx)
    end
    return table.concat(result)
end

local function escape_shell_single_quote(s)
    -- Per POSIX, to include a literal single quote in a single-quoted string,
    -- end the string, insert an escaped quote, then resume.
    return s:gsub("'", "'\\''")
end

local function is_path_shell_safe(path)
    -- Reject null bytes and newlines silently; they break shell command construction.
    if path:find("%z") or path:find("\n") or path:find("\r") then
        return false
    end
    return true
end

-- Detect the host OS: package.config:sub(1,1) is '/' on Unix, '\\' on Windows.
local is_windows = package.config:sub(1, 1) == "\\"
local path_sep = is_windows and "\\" or "/"

local mitm_job = nil
local proxy_port = nil
local proxy_ready = false
local proxy_starting = false
local proxy_generation = 0
local proxy_auth_user = nil
local proxy_auth_pass = nil
local script_dir = mp.get_script_directory() or "."
local proxy_binary = is_windows and "mpv-mitm-proxy.exe" or "mpv-mitm-proxy"

local function join_path(...)
    local parts = {...}
    return table.concat(parts, path_sep)
end

local proxies = {}
local current_proxy_index = 0
local blocked_proxies = {}
local proxy_file = join_path(script_dir, "proxies.txt")
local cooldown_file = join_path(script_dir, "proxy_cooldowns.json")
local status_file_path = join_path(script_dir, ".proxy_status")

local function load_proxies()
    proxies = {}
    local f = io.open(proxy_file, "r")
    if f then
        for line in f:lines() do
            line = line:gsub("%s+", "")
            if line ~= "" and not line:find("^#") then
                table.insert(proxies, line)
            end
        end
        f:close()
    end
end

local function load_cooldowns()
    local f = io.open(cooldown_file, "r")
    if f then
        local content = f:read("*all")
        f:close()
        local data = utils.parse_json(content)
        if data then
            local now = os.time()
            local cooldown_sec = opts.cooldown_hours * 3600
            for url, timestamp in pairs(data) do
                if now - timestamp < cooldown_sec then
                    blocked_proxies[url] = timestamp
                end
            end
        end
    end
end

local function save_cooldowns()
    local f = io.open(cooldown_file, "w")
    if f then
        local success, json = pcall(utils.format_json, blocked_proxies)
        if success then f:write(json) end
        f:close()
    end
end

local function get_next_proxy()
    if #proxies == 0 then return nil end
    local now = os.time()
    local cooldown_sec = opts.cooldown_hours * 3600
    for i = 1, #proxies do
        current_proxy_index = (current_proxy_index % #proxies) + 1
        local url = proxies[current_proxy_index]
        if not blocked_proxies[url] or (now - blocked_proxies[url] >= cooldown_sec) then
            blocked_proxies[url] = nil
            return url
        end
    end
    return nil
end

local function count_proxies_left()
    if #proxies == 0 then return 0 end
    local now = os.time()
    local cooldown_sec = opts.cooldown_hours * 3600
    local count = 0
    for _, url in ipairs(proxies) do
        if not blocked_proxies[url] or (now - blocked_proxies[url] >= cooldown_sec) then
            count = count + 1
        end
    end
    return count
end

local function proxy_label(url)
    if not url then return "direct" end
    for i, u in ipairs(proxies) do
        if u == url then return "proxy " .. i end
    end
    return "unknown"
end

local function cleanup()
    if mitm_job then
        mp.abort_async_command(mitm_job)
        mitm_job = nil
    end
    proxy_ready = false
    proxy_starting = false
    proxy_port = nil
    os.remove(status_file_path)
end

local function find_binary()
    local paths = {
        proxy_binary,
        join_path(script_dir, "..", "proxy", proxy_binary),
        join_path(script_dir, proxy_binary),
        join_path(script_dir, "mpv-mitm-proxy.exe"),
        join_path(script_dir, "mpv-mitm-proxy")
    }
    dprint("searching for binary in paths: " .. dump_table(paths))

    for _, path in ipairs(paths) do
        dprint("trying path: " .. path)
        local f = io.open(path, "rb")
        if f then
            f:close()
            if is_windows then
                dprint("binary found at: " .. path)
                return path
            else
                if not is_path_shell_safe(path) then
                    mp.msg.warn("Skipping unsafe path: " .. path)
                else
                    local safe_path = escape_shell_single_quote(path)
                    local check_cmd = "test -x '" .. safe_path .. "' 2>/dev/null && test -f '" .. safe_path .. "' 2>/dev/null && echo 'ok'"
                    local handle = io.popen(check_cmd)
                    local result = ""
                    if handle then
                        result = handle:read("*l") or ""
                        handle:close()
                    end
                    if result == "ok" then
                        dprint("binary found at: " .. path)
                        return path
                    end
                end
            end
        end
    end

    local path_cmd = is_windows and "where" or "which"
    local res = mp.command_native({
        name = "subprocess",
        args = {path_cmd, proxy_binary},
        capture_stdout = not opts.debug,
        capture_stderr = not opts.debug,
        playback_only = false
    })
    if res and res.status == 0 then
        local found = (res.stdout or ""):match("^%S+")
        if found and found ~= "" then
            dprint("binary found via " .. path_cmd .. ": " .. found)
            return found
        end
    end

    if is_windows then
        local res2 = mp.command_native({
            name = "subprocess",
            args = {"where", "mpv-mitm-proxy.exe"},
            capture_stdout = true,
            capture_stderr = true,
            playback_only = false
        })
        if res2 and res2.status == 0 then
            local found = (res2.stdout or ""):match("^%S+")
            if found and found ~= "" then
                dprint("binary found via where: " .. found)
                return found
            end
        end
    end

    dprint("binary not found in any search path")
    mp.msg.error("No proxy binary found")
    return nil
end

local function check_status_file(custom_path)
    local spath = custom_path or status_file_path
    dprint("checking status file at: " .. spath)
    local f = io.open(spath, "r")
    if not f then
        dprint("status file not found or empty")
        return nil, nil
    end
    local content = f:read("*all")
    f:close()
    dprint("status file content: " .. content)
    local port = content:match("READY:(%d+)")
    local err = content:match("ERROR:(.+)")
    return port and tonumber(port), err
end

local function apply_proxy_settings()
    if not proxy_port then
        mp.set_property("file-local-options/http-proxy", "")
        mp.set_property("file-local-options/ytdl-raw-options", "")
        return
    end
    local px
    if proxy_auth_user and proxy_auth_pass then
        px = "http://" .. proxy_auth_user .. ":" .. proxy_auth_pass .. "@127.0.0.1:" .. proxy_port
    else
        px = "http://127.0.0.1:" .. proxy_port
    end
    mp.set_property("file-local-options/http-proxy", px)

    local ytdl_opts
    if opts.ytdl_extractor_profile == "ios_m3u8" then
        -- iOS player client with m3u8_native format selection and resolution cap.
        ytdl_opts = 'proxy=' .. px .. ',force-ipv4=,no-check-certificates=,extractor-args="youtube:player_client=ios,formats=missing_pot",format="bv[protocol=m3u8_native][height<=' .. opts.max_resolution .. ']+ba/b"'
    elseif opts.ytdl_extractor_profile == "android_vr" then
        -- Android VR player client (default profile).
        ytdl_opts = 'proxy=' .. px .. ',force-ipv4=,no-check-certificates=,extractor-args="youtube:player_client=android_vr,-android_sdkless"'
    else
        -- Minimal yt-dlp options for the "basic" extractor profile.
        ytdl_opts = "proxy=" .. px .. ",force-ipv4=,no-check-certificates=,"
    end

    mp.set_property("file-local-options/ytdl-raw-options", ytdl_opts)
end

local function is_ytdl_applicable()
    local path = mp.get_property("path")
    if not path then return false end
    if not (path:find("://") or path:find("^[a-zA-Z0-9.-]+:[0-9]+")) then
        return false
    end
    if mp.get_property_native("ytdl") == false then
        return false
    end

    local lower_path = path:lower()
    local is_youtube = lower_path:find("youtube%.com") or
                      lower_path:find("youtu%.be") or
                      lower_path:find("googlevideo%.com") or
                      lower_path:find("ytimg%.com")

    if not is_youtube then
        return false
    end

    local non_ytdl_protos = {"rtsp://", "rtmp://", "mms://", "dvb://"}
    for _, proto in ipairs(non_ytdl_protos) do
        if lower_path:find(proto, 1, true) == 1 then
            return false
        end
    end
    return true
end

--------------------------------------------------------------------------------
-- Async proxy startup
--
-- All proxy startup is fully asynchronous. Status-file polling is driven by
-- mp.add_timeout(), which yields back to mpv between checks. This keeps the
-- UI responsive and lets the subprocess-exit callback fire promptly if the
-- binary dies during startup.
--------------------------------------------------------------------------------

-- Launch a single proxy instance and poll its status file asynchronously.
-- Calls on_ready(ready_port) on success or on_failed(err) on failure/timeout.
local function try_start_single_proxy_async(bin, upstream, on_ready, on_failed)
    math.randomseed(os.time() + math.random(1, 1000))
    local port_attempt = math.random(15000, 25000)

    local args = {bin, "--port", tostring(port_attempt)}
    if upstream then
        table.insert(args, "--upstream")
        table.insert(args, upstream)
    end
    if opts.direct_cdn then
        table.insert(args, "--direct-cdn")
    end
    if opts.bypass_chunk_modification then
        table.insert(args, "--bypass-chunk-modification")
    end
    if opts.verify_tls then
        table.insert(args, "--verify-tls")
    end
    if opts.disable_pooling then
        table.insert(args, "--disable-pooling")
    end
    if proxy_auth_user and proxy_auth_pass then
        table.insert(args, "--proxy-auth-user")
        table.insert(args, proxy_auth_user)
        table.insert(args, "--proxy-auth-pass")
        table.insert(args, proxy_auth_pass)
    end
    if opts.debug then
        table.insert(args, "--verbose")
    end

    os.remove(status_file_path)
    local unique_status_file = status_file_path .. "." .. tostring(port_attempt)
    os.remove(unique_status_file)
    table.insert(args, "--status-file")
    table.insert(args, unique_status_file)
    table.insert(args, "--auto-port")
    dprint("async CLI arguments: " .. dump_table(args))

    proxy_generation = proxy_generation + 1
    local my_generation = proxy_generation
    local completed = false

    mitm_job = mp.command_native_async({
        name = "subprocess",
        args = args,
        capture_stdout = not opts.debug,
        capture_stderr = not opts.debug,
        playback_only = false
    }, function(success, result, error)
        if my_generation ~= proxy_generation then return end
        if completed then return end
        -- Fail fast if the process exits during startup rather than waiting
        -- for the full poll timeout.
        if proxy_starting then
            mp.msg.error("Proxy subprocess exited unexpectedly during async startup")
            completed = true
            on_failed("Proxy subprocess exited unexpectedly during async startup")
        end
    end)

    local poll_count = 0
    local max_polls = 100  -- ~5s at 50ms intervals

    local function poll()
        if completed then return end
        if my_generation ~= proxy_generation then return end

        poll_count = poll_count + 1
        local ready_port, status_err = check_status_file(unique_status_file)

        if status_err then
            os.remove(unique_status_file)
            if mitm_job then mp.abort_async_command(mitm_job); mitm_job = nil end
            completed = true
            on_failed(status_err)
            return
        end

        if ready_port then
            os.remove(unique_status_file)
            completed = true
            on_ready(ready_port)
            return
        end

        if poll_count >= max_polls then
            os.remove(unique_status_file)
            if mitm_job then mp.abort_async_command(mitm_job); mitm_job = nil end
            completed = true
            on_failed("Timeout waiting for proxy to start")
            return
        end

        mp.add_timeout(0.05, poll)
    end

    mp.add_timeout(0.1, poll)
end

-- Start the proxy, optionally rotating across upstreams, and invoke
-- on_complete(true) on success or on_complete(false) on failure.
local function start_proxy_async(on_complete)
    dprint("start_proxy_async() called")
    if proxy_starting then
        dprint("Proxy startup already in progress, skipping")
        on_complete(false)
        return
    end
    if mitm_job then cleanup() end

    local bin = find_binary()
    if not bin then
        dprint("find_binary() returned nil in async path")
        on_complete(false)
        return
    end

    proxy_starting = true

    -- One-shot health check: run the binary with "init" to verify it exists
    -- and is executable before committing to a full startup.
    local test_res = mp.command_native({
        name = "subprocess",
        args = {bin, "init"},
        capture_stdout = not opts.debug,
        capture_stderr = not opts.debug,
        playback_only = false
    })
    if not test_res or test_res.status ~= 0 then
        local err = (test_res and test_res.error) or "unknown error"
        local status = (test_res and test_res.status) or "N/A"
        mp.msg.error(string.format("[mpv_mitm_proxy] Subprocess failed: init (error: %s, status: %s)", err, status))
        proxy_starting = false
        on_complete(false)
        return
    end

    -- Generate per-session proxy authentication credentials.
    proxy_auth_user = nil
    proxy_auth_pass = nil
    if opts.enable_proxy_auth then
        proxy_auth_user = generate_random_string(16)
        proxy_auth_pass = generate_random_string(32)
        dprint("Generated proxy auth credentials")
    end

    local upstream_list_mode = opts.use_proxies and opts.proxy_rotation_enabled
    local max_retries = 1
    if upstream_list_mode then
        max_retries = opts.fallback_to_direct and (#proxies + 1) or #proxies
        if max_retries <= 0 then max_retries = 1 end
    end

    local attempt_num = 0

    local function try_next()
        if not proxy_starting then
            dprint("Proxy startup cancelled before attempt")
            on_complete(false)
            return
        end

        attempt_num = attempt_num + 1
        if attempt_num > max_retries then
            mp.msg.error("All proxy attempts exhausted")
            proxy_starting = false
            cleanup()
            on_complete(false)
            return
        end

        local upstream = nil
        if opts.use_proxies then
            upstream = get_next_proxy()
            if not upstream and not opts.fallback_to_direct then
                mp.osd_message("All proxies are blocked!", 5)
                proxy_starting = false
                on_complete(false)
                return
            end
        end

        if upstream then
            dprint("async attempt " .. attempt_num .. "/" .. max_retries .. ", upstream: " .. proxy_label(upstream))
        else
            dprint("async attempt " .. attempt_num .. "/" .. max_retries .. ", direct (no upstream proxy)")
        end

        try_start_single_proxy_async(bin, upstream, function(ready_port)
            proxy_port = ready_port
            proxy_ready = true
            proxy_starting = false
            mp.msg.info("Proxy ready on port " .. ready_port .. (upstream and " via " .. proxy_label(upstream) or " (direct)"))
            apply_proxy_settings()
            on_complete(true)
        end, function(err)
            mp.msg.warn("Proxy startup failed for " .. (upstream and proxy_label(upstream) or "direct") .. ": " .. err)
            cleanup()
            -- Retry with the next available upstream after a brief delay.
            mp.add_timeout(0.5, try_next)
        end)
    end

    try_next()
end

--------------------------------------------------------------------------------
-- mpv hook integration
--
-- mpv hooks run synchronously: we must return quickly. When the proxy is not
-- ready yet we initiate an async startup and return immediately. The file
-- then loads once (without the proxy); when the proxy comes up we reload the
-- file so yt-dlp re-runs with the proxy applied. The reload's on_load sees
-- proxy_ready == true and only applies settings (no further reload), so there
-- is no loop.
--------------------------------------------------------------------------------

-- Monotonic token to keep track of which load cycle requested a startup, so a
-- stale callback never reloads an unrelated file.
local load_token = 0

local function reload_current_file()
    local path = mp.get_property("path")
    if path then
        mp.commandv("loadfile", path, "replace")
    end
end

-- Called from the load hooks. Starts the proxy if needed and applies settings
-- when ready. Never blocks.
local function ensure_proxy_started()
    dprint("ensure_proxy_started() called, proxy_ready=" .. tostring(proxy_ready) .. ", proxy_starting=" .. tostring(proxy_starting))
    if not is_ytdl_applicable() then
        return
    end

    if proxy_ready then
        -- Proxy already running: apply settings for the current file and return.
        apply_proxy_settings()
        return
    end

    if proxy_starting then
        -- A startup is already in progress; the pending callback will reload
        -- when it completes.
        return
    end

    load_token = load_token + 1
    local token = load_token
    dprint("kickoff async proxy startup, token=" .. tostring(token))

    start_proxy_async(function(success)
        if success and proxy_ready and token == load_token then
            -- Reload so yt-dlp runs with the newly applied proxy settings.
            dprint("proxy became ready, reloading file to apply proxy (token=" .. tostring(token) .. ")")
            reload_current_file()
        end
    end)
end

local function on_load_hook()
    dprint("on_load_hook triggered")
    ensure_proxy_started()
end

local function on_start_file()
    dprint("on_start_file triggered")
    ensure_proxy_started()
end

-- Mark the current upstream as blocked, tear down the running proxy, and
-- reload the current file. The reload triggers ensure_proxy_started(), which
-- starts a fresh proxy with the next available upstream and re-reloads once
-- ready. Reloading immediately (rather than waiting for the new proxy)
-- prevents mpv from holding open a connection that can no longer succeed.
local function rotate_proxy()
    local blocked_url = proxies[current_proxy_index]
    dprint("rotating proxy, current: " .. tostring(blocked_url or "none") .. ", blocked count: " .. tostring(#blocked_proxies))
    if blocked_url then
        blocked_proxies[blocked_url] = os.time()
        save_cooldowns()
        mp.osd_message("Proxy blocked, rotating...", 3)
        mp.msg.warn("Proxy " .. proxy_label(blocked_url) .. " blocked, rotating...")
    end
    cleanup()

    local path = mp.get_property("path")
    if path then
        mp.commandv("loadfile", path, "replace")
    end
end

mp.add_hook("on_load", -1, on_load_hook)
mp.register_event("start-file", on_start_file)
mp.register_event("shutdown", cleanup)

if opts.proxy_rotation_enabled and opts.use_proxies then
    mp.enable_messages("info")
else
    mp.enable_messages("warn")
end

local recent_load_attempts = 0

mp.register_event("log-message", function(e)
    if not opts.use_proxies or not opts.proxy_rotation_enabled then return end
    if e.prefix == "ytdl_hook" then
        local msg = e.text:lower()
        if msg:find("sign in") and msg:find("bot") then
            -- During proxy startup the file loads without a proxy, which can
            -- trigger bot detection. Ignore it; the file will be reloaded with
            -- the new proxy once startup completes.
            if proxy_starting then
                dprint("Ignoring bot detection while proxy is starting")
                return
            end

            local blocked_url = proxies[current_proxy_index]
            if blocked_url then
                blocked_proxies[blocked_url] = os.time()
                save_cooldowns()
                mp.msg.warn("Blocking " .. proxy_label(blocked_url))
            end

            if opts.auto_restart_on_failure then
                if recent_load_attempts >= 5 then
                    mp.msg.warn("Too many rotation attempts, giving up")
                    mp.osd_message("All proxies blocked!", 5)
                    return
                end
                recent_load_attempts = recent_load_attempts + 1
                mp.msg.warn("Bot detection detected, auto-rotating (attempt " .. tostring(recent_load_attempts) .. "/5)")
                rotate_proxy()
            else
                mp.osd_message("Proxy blocked! Reload to rotate.", 5)
                mp.msg.warn("Bot detection detected, proxy marked as blocked. Reload to use a different proxy.")
            end
        end
    end
end)

mp.register_event("file-loaded", function()
    recent_load_attempts = 0
end)


local function show_status()
    local status = (proxy_ready and "🟢" or "🔴")
    if not opts.use_proxies then status = "⚪ (direct)" end
    local upstream = proxies[current_proxy_index] or "direct"
    if not proxy_port then upstream = "none" end
    local msg = status .. " Port: " .. (proxy_port or "N/A") .. "\nUpstream: " .. upstream
    if not opts.verify_tls then
        msg = msg .. "\n⚠️ TLS verification disabled"
    end
    if opts.enable_proxy_auth and proxy_auth_user then
        msg = msg .. "\n🔒 Proxy auth enabled"
    end
    if not opts.auto_restart_on_failure then
        msg = msg .. "\n⛔ Auto-rotate disabled"
    end
    mp.osd_message(msg)
end

mp.add_key_binding("P", "proxy-status", show_status)

load_proxies()
load_cooldowns()
save_cooldowns()
