local mp = require 'mp'
local options = require 'mp.options'
local utils = require 'mp.utils'

local opts = {
    use_proxies = true,
    proxy_rotation_enabled = true,
    cooldown_hours = 16,
    fallback_to_direct = false,
    direct_cdn = false
}
options.read_options(opts, "mitm_rust_proxy")

local mitm_job = nil
local proxy_port = nil
local proxy_ready = false
local script_dir = mp.get_script_directory() or "."
local proxy_binary = "mpv-mitm-proxy"

local proxies = {}
local current_proxy_index = 0
local blocked_proxies = {}
local proxy_file = script_dir .. "/proxies.txt"
local cooldown_file = script_dir .. "/proxy_cooldowns.json"

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

local function cleanup()
    if mitm_job then
        mp.abort_async_command(mitm_job)
        mitm_job = nil
    end
    proxy_ready = false
    proxy_port = nil
end

local function find_binary()
    local paths = {
        proxy_binary,
        script_dir .. "/../proxy/" .. proxy_binary,
        script_dir .. "/" .. proxy_binary,
        script_dir .. "/mpv-mitm-proxy.exe",
        script_dir .. "/mpv-mitm-proxy"
    }
    for _, path in ipairs(paths) do
        local f = io.open(path, "r")
        if f then
            f:close()
            return path
        end
    end
    mp.msg.error("No proxy binary found")
    return nil
end

local function check_port_open(port)
    local res = mp.command_native({
        name = "subprocess",
        args = {
            "curl", "-s", "-o", "/dev/null",
            "--max-time", "0.05",
            "--connect-timeout", "0.05",
            "http://127.0.0.1:" .. port .. "/"
        },
        capture_stdout = false,
        capture_stderr = false,
        playback_only = false
    })
    return res and (res.status == 0)
end

local function apply_proxy_settings()
    if not proxy_port then
        mp.set_property("file-local-options/http-proxy", "")
        mp.set_property("file-local-options/ytdl-raw-options", "")
        return
    end
    local px = "http://127.0.0.1:" .. proxy_port
    mp.set_property("file-local-options/http-proxy", px)
    mp.set_property("file-local-options/tls-verify", "no")
    mp.set_property("file-local-options/ytdl-raw-options",
        "proxy=" .. px .. "," ..
        "force-ipv4=," ..
        "no-check-certificates=,")
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
    if not is_ytdl_applicable() then
        return
    end
    if not proxy_port then
        start_proxy_background()
    end
end

local function on_start_file()
    if not is_ytdl_applicable() then
        return
    end
    if not proxy_port then
        start_proxy_background()
    end
    if proxy_port then
        apply_proxy_settings()
    end
    if proxy_ready or not proxy_port then
        return
    end
    mp.add_timeout(0.5, function()
        if proxy_ready then return end
        if proxy_port and check_port_open(proxy_port) then
            proxy_ready = true
            mp.msg.info("Proxy ready on port " .. proxy_port)
        end
    end)
end

start_proxy_background = function()
    if mitm_job then cleanup() end
    local bin = find_binary()
    if not bin then return end
    local upstream = nil
    if opts.use_proxies then
        upstream = get_next_proxy()
        if not upstream then
            if #proxies > 0 then
                mp.osd_message("All proxies are blocked!", 5)
            end
            if not opts.fallback_to_direct then
                return
            end
        end
    end
    math.randomseed(os.time())
    local port_attempt = math.random(15000, 25000)
    local args = {bin, "--port", tostring(port_attempt)}
    if upstream then
        table.insert(args, "--upstream")
        table.insert(args, upstream)
    end

    if opts.direct_cdn then
        table.insert(args, "--direct-cdn")
    end
    mitm_job = mp.command_native_async({
        name = "subprocess",
        args = args,
        capture_stdout = true,
        capture_stderr = true,
        playback_only = false
    }, function(success, result, error)
        proxy_ready = false
        mitm_job = nil
    end)
    proxy_port = port_attempt
    mp.add_timeout(0.5, function()
        if proxy_ready then return end
        if proxy_port and check_port_open(port_attempt) then
            proxy_ready = true
            mp.msg.info("Proxy ready on port " .. proxy_port)
        end
    end)
end

local function rotate_proxy()
    local blocked_url = proxies[current_proxy_index]
    if blocked_url then
        blocked_proxies[blocked_url] = os.time()
        save_cooldowns()
        mp.osd_message("Proxy blocked, rotating...", 3)
        mp.msg.warn("Proxy " .. blocked_url .. " blocked, rotating...")
    end
    cleanup()
    mp.add_timeout(0.2, function()
        start_proxy_background()
        local check_count = 0
        local function wait_and_reload()
            if proxy_ready then
                apply_proxy_settings()
                local path = mp.get_property("path")
                if path then
                    mp.commandv("loadfile", path, "replace")
                end
            elseif check_count < 10 then
                check_count = check_count + 1
                mp.add_timeout(0.2, wait_and_reload)
            end
        end
        wait_and_reload()
    end)
end

mp.add_hook("on_load", -1, on_load_hook)
mp.register_event("start-file", on_start_file)
mp.register_event("shutdown", cleanup)

mp.enable_messages("warn")
mp.register_event("log-message", function(e)
    if not opts.use_proxies or not opts.proxy_rotation_enabled then return end
    if e.prefix == "ytdl_hook" then
        local msg = e.text:lower()
        if msg:find("sign in to confirm you") and msg:find("not a bot") then
            mp.msg.warn("Bot detection detected in log, rotating proxy...")
            rotate_proxy()
        end
    end
end)

mp.add_hook("on_load_fail", 50, function()
end)

local function show_status()
    local status = (proxy_ready and "🟢" or "🔴")
    if not opts.use_proxies then status = "⚪ (direct)" end
    local upstream = proxies[current_proxy_index] or "direct"
    if not proxy_port then upstream = "none" end
    mp.osd_message(status .. " Port: " .. (proxy_port or "N/A") .. "\nUpstream: " .. upstream)
end

mp.add_key_binding("P", "proxy-status", show_status)

load_proxies()
load_cooldowns()
save_cooldowns()
