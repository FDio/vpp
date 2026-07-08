#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <pipe/pipe.h>

static subint_config_t *
pipe_subint_config (vnet_main_t *vm, u32 sw_if_index, u32 *flags)
{
  pipe_t *pipe = pipe_get (sw_if_index);
  if (!pipe)
    return NULL;

  *flags = SUBINT_CONFIG_P2P;

  return &pipe->subint;
}

static clib_error_t *
pipe_plugin_init (vlib_main_t *vm)
{
  ethernet_register_subint_config_fn (VNET_SW_INTERFACE_TYPE_PIPE, pipe_subint_config);
  return NULL;
}

VLIB_INIT_FUNCTION (pipe_plugin_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Pipe plugin",
};
