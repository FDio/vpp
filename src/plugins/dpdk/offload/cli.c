#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <dpdk/device/dpdk.h>

static clib_error_t *
offload_flow_command_fn (vlib_main_t * vm,
                        unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  dpdk_main_t * dm = &dpdk_main;
  vnet_main_t * vnm = dm->vnet_main;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  u32 rx_sw_if_index = ~0;
  u32 hw_if_index = ~0;
  int is_add = 1;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "hw %U", unformat_vnet_hw_interface, vnm, &hw_if_index))
        continue;
      if (unformat (line_input, "rx %U", unformat_vnet_sw_interface, vnm, &rx_sw_if_index))
        continue;
      if (unformat (line_input, "del"))
      {
        is_add = 0;
        continue;
      }
      return clib_error_return (0, "unknown input `%U'", format_unformat_error, line_input);
    }

  if (rx_sw_if_index == ~0)
    return clib_error_return (0, "missing rx interface");
  if (hw_if_index == ~0)
    return clib_error_return (0, "missing hw interface");

  clib_error_t * dpdk_enable_disable_vxlan_flow (u32 hw_if_index, u32 sw_if_index, int is_add);

  return dpdk_enable_disable_vxlan_flow (hw_if_index, rx_sw_if_index, is_add);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (offload_dpdk_command, static) = {
    .path = "offload dpdk",
    .short_help =
    "offload dpdk hw <device> rx <sw_interface> [del]",
    .function = offload_flow_command_fn,
};
/* *INDENT-ON* */

