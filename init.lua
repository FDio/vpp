-- vim: set ts=2 sw=2 et:
do
	local version = vpp.get_version()
	print("VPP version is: ", version)
end
do
	local output, err = vpp.cli.run("show version")
	if err then
		error("vpp.cli.run failed: " .. err)
	end
	print("Show version via CLI:")
	print(output)
end
do
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
end
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
	vpp.yield()
end
