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

local mitm_job = nil
local proxy_port = nil
local proxy_ready = false
local proxy_starting = false
local proxy_generation = 0
local proxy_auth_user = nil
local proxy_auth_pass = nil
local script_dir = mp.get_script_directory() or "."
local proxy_binary = is_windows and "mpv-mitm-proxy.exe" or "mpv-mitm-proxy"

-- OS detection: package.config:sub(1,1) is '/' on Unix, '\\' on Windows
local is_windows = package.config:sub(1, 1) == "\\"
local path_sep = is_windows and "\\" or "/"

local function join_path(...)
    local parts = {...}
    return table.concat(parts, path_sep)
end

local proxies = {}
local current_proxy_index = 0
local blocked_proxies = {}
local rotating = false
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

local function cross_platform_delay(ms)
    if is_windows then
        mp.command_native({
            name = "subprocess",
            args = {"ping", "-n", "1", "-w", tostring(ms), "127.0.0.1"},
            capture_stdout = true,
            capture_stderr = true,
            playback_only = false
        })
    else
        mp.command_native({
            name = "subprocess",
            args = {"sleep", tostring(ms / 1000)},
            capture_stdout = true,
            capture_stderr = true,
            playback_only = false
        })
    end
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
        -- iOS client with m3u8_native format selection
        ytdl_opts = 'proxy=' .. px .. ',force-ipv4=,no-check-certificates=,extractor-args="youtube:player_client=ios,formats=missing_pot",format="bv[protocol=m3u8_native][height<=' .. opts.max_resolution .. ']+ba/b"'
    elseif opts.ytdl_extractor_profile == "android_vr" then
        -- android_vr client
        ytdl_opts = 'proxy=' .. px .. ',force-ipv4=,no-check-certificates=,extractor-args="youtube:player_client=android_vr,-android_sdkless"'
    else
        -- "basic" or any other value: minimal options only
        ytdl_opts = "proxy=" .. px .. ",force-ipv4=,no-check-certificates=,"
    end

    mp.set_property("file-local-options/ytdl-raw-options", ytdl_opts)
end

local start_proxy_background

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

local function on_load_hook()
    dprint("on_load_hook triggered")
    if not is_ytdl_applicable() then
        return
    end
    if not proxy_port and not proxy_starting then
        if proxy_ready then
            apply_proxy_settings()
        else
            start_proxy_background()
            if proxy_ready then
                apply_proxy_settings()
            end
        end
    end
end

local function on_start_file()
    dprint("on_start_file triggered")
    if not is_ytdl_applicable() then
        return
    end

    if not proxy_port and not proxy_starting then
        start_proxy_background()
    end

    if proxy_ready then
        apply_proxy_settings()
    end
end

-- Launch a single proxy instance and wait for its READY status.
local function try_start_single_proxy(bin, upstream)
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
    dprint("CLI arguments: " .. dump_table(args))

    proxy_generation = proxy_generation + 1
    local my_generation = proxy_generation

    mitm_job = mp.command_native_async({
        name = "subprocess",
        args = args,
        capture_stdout = not opts.debug,
        capture_stderr = not opts.debug,
        playback_only = false
    }, function(success, result, error)
        if my_generation ~= proxy_generation then return end
        if not success or (result and result.status ~= 0) then
            local err_msg = "Proxy subprocess failed"
            if error then err_msg = err_msg .. ": " .. error end
            if result and result.status then err_msg = err_msg .. " (status: " .. result.status .. ")" end
            dprint("Proxy process exited (output was not captured, check terminal)")
            mp.msg.error(err_msg)
        end
        proxy_ready = false
        proxy_starting = false
        proxy_port = nil
        mitm_job = nil
    end)
    dprint("subprocess launched, pid via job handle")

    local check_count = 0
    local max_wait = 100
    dprint("starting status file poll, path=" .. unique_status_file .. ", timeout=~5s")

    while check_count < max_wait do
        check_count = check_count + 1
        if check_count % 10 == 0 then
            dprint("poll iteration " .. check_count .. "/" .. max_wait .. ", still waiting...")
        end
        dprint("poll iteration " .. check_count .. "/" .. max_wait .. ", checking status file")
        local ready_port, status_err = check_status_file(unique_status_file)
        if status_err then
            os.remove(unique_status_file)
            cleanup()
            return nil, status_err
        end
        if ready_port then
            os.remove(unique_status_file)
            return ready_port, nil
        end

        if mitm_job == nil and my_generation == proxy_generation then
            mp.msg.error("Proxy subprocess exited unexpectedly during startup")
            os.remove(unique_status_file)
            cleanup()
            return nil, "Proxy subprocess exited unexpectedly during startup"
        end

        cross_platform_delay(50)
    end

    os.remove(unique_status_file)
    cleanup()
    return nil, "Timeout waiting for proxy to start"
end

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
        if proxy_starting then
            mp.msg.error("Proxy subprocess exited unexpectedly during async startup")
            completed = true
            on_failed("Proxy subprocess exited unexpectedly during async startup")
        end
    end)

    local poll_count = 0
    local max_polls = 100

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
            mp.add_timeout(0.5, try_next)
        end)
    end

    try_next()
end

start_proxy_background = function()
    dprint("start_proxy_background() called")
    -- Guard against concurrent startup attempts
    if proxy_starting then
        dprint("Proxy startup already in progress, skipping duplicate request")
        return
    end
    if mitm_job then cleanup() end

    dprint("passed concurrency guard, starting binary search")
    local bin = find_binary()
    if not bin then
        dprint("find_binary() returned nil")
        return
    end
    dprint("find_binary() returned: " .. tostring(bin))

    proxy_starting = true
    dprint("Starting proxy...")

    -- Check if binary is executable and works
    dprint("running init health check on binary")
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
        local stderr = (test_res and test_res.stderr) or ""
        local stdout = (test_res and test_res.stdout) or ""
        dprint("init health check failed: error=" .. tostring(err) .. ", status=" .. tostring(status))
        mp.msg.error(string.format("[mpv_mitm_proxy] Subprocess failed: init (error: %s, status: %s)", err, status))
        if stdout ~= "" then mp.msg.error("Stdout: " .. stdout) end
        if stderr ~= "" then mp.msg.error("Stderr: " .. stderr) end
        proxy_starting = false
        return
    end
    dprint("init health check passed")

    -- Generate per-session proxy auth credentials if enabled
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
        max_retries = 0
        if opts.fallback_to_direct then
            -- proxies + direct fallback
            max_retries = #proxies + 1
        else
            max_retries = #proxies
        end
        if max_retries <= 0 then max_retries = 1 end
    end

    local attempt_num = 0
    while attempt_num < max_retries do
        attempt_num = attempt_num + 1
        local should_retry = false

        local upstream = nil
        if opts.use_proxies then
            upstream = get_next_proxy()
            if not upstream and not opts.fallback_to_direct then
                mp.osd_message("All proxies are blocked!", 5)
                proxy_starting = false
                return
            end
        end

        if upstream then
            dprint("startup attempt " .. attempt_num .. "/" .. max_retries .. ", upstream: " .. proxy_label(upstream))
        else
            dprint("startup attempt " .. attempt_num .. "/" .. max_retries .. ", direct (no upstream proxy)")
        end

        local ready_port, status_err = try_start_single_proxy(bin, upstream)
        if not ready_port then
            mp.msg.warn("Proxy startup failed for " .. (upstream and proxy_label(upstream) or "direct") .. ": " .. status_err)
            should_retry = true
        end

        if not should_retry then
            proxy_port = ready_port
            proxy_ready = true
            proxy_starting = false
            mp.msg.info("Proxy ready on port " .. ready_port .. (upstream and " via " .. proxy_label(upstream) or " (direct)"))
            apply_proxy_settings()
            return
        end

        cross_platform_delay(500)
    end

    mp.msg.error("All proxy attempts exhausted")
    proxy_starting = false
    cleanup()
end

local function rotate_proxy()
    if rotating then
        dprint("Rotation already in progress, ignoring duplicate request")
        return
    end
    rotating = true

    local blocked_url = proxies[current_proxy_index]
    dprint("rotating proxy, current: " .. tostring(blocked_url or "none") .. ", blocked count: " .. tostring(#blocked_proxies))
    if blocked_url then
        blocked_proxies[blocked_url] = os.time()
        save_cooldowns()
        mp.osd_message("Proxy blocked, rotating...", 3)
        mp.msg.warn("Proxy " .. proxy_label(blocked_url) .. " blocked, rotating...")
    end
    cleanup()

    start_proxy_async(true, function(success)
        rotating = false
        if success and proxy_ready then
            local path = mp.get_property("path")
            if path then
                mp.commandv("loadfile", path, "replace")
            end
        else
            mp.msg.warn("Rotation failed, all proxies exhausted")
            mp.osd_message("All proxies blocked!", 5)
        end
    end)
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
                cleanup()
                local path = mp.get_property("path")
                if path then
                    mp.osd_message("Proxy blocked, rotating...", 3)
                    mp.commandv("loadfile", path, "replace")
                end
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
