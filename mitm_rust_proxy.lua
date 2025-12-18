-- Set to empty string "" to use NO upstream proxy
-- Example: local upstream_socks5_url = "socks5://127.0.0.1:1080"
local upstream_socks5_url = ""
local mp = require 'mp'
local options = require 'mp.options'

local opts = {
}
options.read_options(opts, "mitm_rust_proxy")

local mitm_job = nil
local proxy_port = nil
local proxy_ready = false
local script_dir = mp.get_script_directory() or "."
local proxy_binary = "mpv-mitm-proxy"

mp.add_key_binding("P", "proxy-status", function()
    mp.osd_message((proxy_ready and "🟢" or "🔴") .. " " .. (proxy_port or "none"))
end)

local function cleanup()
    if mitm_job then
        mp.abort_async_command(mitm_job)
        mitm_job = nil
    end
    proxy_ready = false
    proxy_port = nil
end

local function find_binary()
    local paths = {proxy_binary, script_dir .. "/../proxy/mpv-mitm-proxy", script_dir .. "/mpv-mitm-proxy"}
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
    local px = "http://127.0.0.1:" .. proxy_port
    mp.set_property("file-local-options/http-proxy", px)
    mp.set_property("file-local-options/tls-verify", "no")
    
    mp.set_property("file-local-options/ytdl-raw-options",
        "proxy=" .. px .. "," ..
        "force-ipv4=," ..
        "no-check-certificates=,")
    
    mp.msg.info("Using proxy on port " .. proxy_port)
end

local start_proxy_background

local function on_load_hook()
    local url = mp.get_property("path")
    if not (url and (url:find("youtu") or url:find("piped") or url:find("yewtu"))) then
        return
    end

    if not proxy_port then
        start_proxy_background()
    end
end

local function on_start_file()
    local url = mp.get_property("path")
    if not (url and (url:find("youtu") or url:find("piped") or url:find("yewtu"))) then
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

    mp.add_timeout(1, function()
        if proxy_ready then
            return
        end

        if check_port_open(proxy_port) then
            proxy_ready = true
            mp.msg.info("Proxy ready on port " .. proxy_port)
        end
    end)
end

start_proxy_background = function()
    if proxy_ready and proxy_port and mitm_job then return end
    if mitm_job then return end
    
    local bin = find_binary()
    if not bin then return end
    
    math.randomseed(os.time())
    local port_attempt = math.random(15000, 25000)
    
    mp.msg.info("Starting proxy on port " .. port_attempt .. "...")
    local start_time = mp.get_time()
    
    local args = {bin, "--port", tostring(port_attempt)}
    if upstream_socks5_url and upstream_socks5_url ~= "" then
        table.insert(args, "--upstream")
        table.insert(args, upstream_socks5_url)
    end

    mitm_job = mp.command_native_async({
        name = "subprocess",
        args = args,
        capture_stdout = true,
        capture_stderr = true,
        playback_only = false
    }, function(success, result, error)
        mp.msg.info("Proxy process ended")
        if result and result.stderr and result.stderr ~= "" then
            mp.msg.error("Proxy stderr: " .. result.stderr)
        end
        proxy_ready = false
        mitm_job = nil
    end)
    
    proxy_port = port_attempt
    
    mp.add_timeout(1, function()
        if proxy_ready then
            return
        end

        if check_port_open(port_attempt) then
            proxy_ready = true
            mp.msg.info("Proxy ready on port " .. proxy_port)
        end
    end)
end

mp.add_hook("on_load", -1, on_load_hook)
mp.register_event("start-file", on_start_file)
mp.register_event("shutdown", cleanup)

start_proxy_background()
