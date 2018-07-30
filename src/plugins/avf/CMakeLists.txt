
##############################################################################
# plugin .so file
##############################################################################

add_vpp_plugin(avf_plugin
  cli.c
  device.c
  format.c
  input.c
  output.c
  plugin.c
  avf_api.c
  avf.api
)

