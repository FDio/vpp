do
  local version = vpp.get_version()
  print('VPP version is :', version)
end
do
  local output, err = vpp.cli.run('show version')
  if err then error('vpp.cli.run failed: ' .. err) end
  print('Show version via CLI:')
  print(output)
end
do
  local iface = vpp.interface('local0')
  local _, set_err = iface.set_state('up')
  if set_err then error('vpp.interface.set_state failed: ' .. set_err) end
  local state, get_err = iface.get_state()
  if get_err then error('vpp.interface.get_state failed: ' .. get_err) end
  print('interface local0 state:', state)
end
