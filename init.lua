-- vim: set ts=2 sw=2 et:

local function show_version_task()
	local version = vpp.get_version()
	print("VPP version is: ", version)
	coroutine.yield()

	local output, err = vpp.cli.run("show version")
	if err then
		error("vpp.cli.run failed: " .. err)
	end
	print("Show version via CLI:")
	print(output)
	coroutine.yield()
end

local function interface_task()
	local iface = vpp.interface("local0")
	local _, set_err = iface.set_state("up")
	if set_err then
		error("vpp.interface.set_state failed: " .. set_err)
	end

	local state, get_err = iface.get_state()
	if get_err then
		error("vpp.interface.get_state failed: " .. get_err)
	end

	print("interface local0 state:", state)
	coroutine.yield()
end

local function periodic_log_task(logger, interval, message)
	local period = interval or 1
	while true do
		logger.warn(message)
		vpp.sleep(period)
	end
end

-- Run the basic tests once during init.
show_version_task()
interface_task()

do
	local log = vpp.log.class("test", "lua")
	log.warn("lua log self-test warning")
	log.err("lua log self-test error")

	local log_default = vpp.log.class("lua_init_default")
	log_default.debug("lua log self-test debug")

	local cfg = log.get_config()
	cfg.syslog_level = "debug"
	log.set_config(cfg)
	log.notice(string.format("log cfg: level=%s syslog=%s rate=%d", cfg.level, cfg.syslog_level, cfg.rate_limit))

	if vpp.log.clear then
		vpp.log.clear()
	end
	vpp.log.clear()
	vpp.sleep(0.1)
	coroutine.yield()
end

-- Spawn two periodic loggers that run in parallel with explicit classes.
local foo_logger = vpp.log.class("foo", "lua")
local bar_logger = vpp.log.class("bar", "lua")

local foo_cfg = foo_logger.get_config()
foo_cfg.level = "warning"
foo_cfg.syslog_level = "warning"
foo_cfg.rate_limit = 100000
foo_logger.set_config(foo_cfg)

local bar_cfg = bar_logger.get_config()
bar_cfg.level = "warning"
bar_cfg.syslog_level = "warning"
bar_cfg.rate_limit = 100000
bar_logger.set_config(bar_cfg)

foo_logger.warn("foo logger initialized")
bar_logger.warn("bar logger initialized")

coroutine.create(function()
	periodic_log_task(foo_logger, 1, "foo heartbeat")
end)
coroutine.create(function()
	periodic_log_task(bar_logger, 2, "bar heartbeat")
end)
