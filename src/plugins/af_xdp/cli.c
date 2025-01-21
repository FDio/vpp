/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <af_xdp/af_xdp.h>

static clib_error_t *
af_xdp_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
			  vlib_cli_command_t * cmd)
{
  af_xdp_create_if_args_t args;

  if (!unformat_user (input, unformat_af_xdp_create_if_args, &args))
    return clib_error_return (0, "unknown input `%U'",
			      format_unformat_error, input);

  af_xdp_create_if (vm, &args);

  vec_free (args.linux_ifname);
  vec_free (args.name);
  vec_free (args.prog);
  vec_free (args.netns);

  return args.error;
}

VLIB_CLI_COMMAND (af_xdp_create_command, static) = {
  .path = "create interface af_xdp",
  .short_help =
    "create interface af_xdp <host-if linux-ifname> [name ifname] "
    "[rx-queue-size size] [tx-queue-size size] [num-rx-queues <num|all>] "
    "[prog pathname] [netns ns] [zero-copy|no-zero-copy] [no-syscall-lock] "
    "[csum-enabled] [multi-buffer]",
  .function = af_xdp_create_command_fn,
};

static clib_error_t *
af_xdp_delete_command_fn (vlib_main_t * vm, unformat_input_t * input,
			  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hw;
  af_xdp_main_t *am = &af_xdp_main;
  af_xdp_device_t *ad;
  vnet_main_t *vnm = vnet_get_main ();

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (line_input, "%U", unformat_vnet_sw_interface,
			 vnm, &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (sw_if_index == ~0)
    return clib_error_return (0,
			      "please specify interface name or sw_if_index");

  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (hw == NULL || af_xdp_device_class.index != hw->dev_class_index)
    return clib_error_return (0, "not an AVF interface");

  ad = pool_elt_at_index (am->devices, hw->dev_instance);

  af_xdp_delete_if (vm, ad);

  return 0;
}

VLIB_CLI_COMMAND (af_xdp_delete_command, static) = {
  .path = "delete interface af_xdp",
  .short_help = "delete interface af_xdp "
    "{<interface> | sw_if_index <sw_idx>}",
  .function = af_xdp_delete_command_fn,
};

static clib_error_t *
af_xdp_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  int show_stats = 0;
  u32 hw_if_index, *hw_if_indices = 0;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = 0;
  clib_error_t *error = 0;
  af_xdp_main_t *am = &af_xdp_main;
  af_xdp_device_t *ad;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_hw_interface, vnm,
		    &hw_if_index))
	{
	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	  if (af_xdp_device_class.index != hi->dev_class_index)
	    {
	      error = clib_error_return (0, "unknown input `%U'",
					 format_unformat_error, input);
	      goto done;
	    }
	  vec_add1 (hw_if_indices, hw_if_index);
	}
      else if (unformat (input, "stats"))
	show_stats = 1;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (vec_len (hw_if_indices) == 0)
    {
      pool_foreach (ad, am->devices)
	vec_add1 (hw_if_indices, ad->hw_if_index);
    }

  if (show_stats)
    {
      vlib_cli_output (vm, "%-20s  %11s  %16s  %12s  %18s  %16s  %19s", "Name",
		       "RX droppped", "RX invalid descs", "RX ring full",
		       "RX fill ring empty", "TX invalid descs",
		       "TX ring empty descs");
      for (int i = 0; i < vec_len (hw_if_indices); i++)
	{
	  struct xdp_statistics stats;
	  socklen_t optlen;
	  int err, fd;
	  struct xsk_socket *xsk;

	  hi = vnet_get_hw_interface (vnm, hw_if_indices[i]);
	  ad = vec_elt_at_index (am->devices, hi->dev_instance);
	  xsk = *ad->xsk;
	  fd = xsk_socket__fd (xsk);
	  err = getsockopt (fd, SOL_XDP, XDP_STATISTICS, &stats, &optlen);
	  if (err)
	    {
	      error = clib_error_return (
		0, "error %d returned from getsockopt'", err);
	      goto done;
	    }
	  if (optlen == sizeof (struct xdp_statistics))
	    vlib_cli_output (
	      vm, "%-20v  %11ld  %16ld  %12ld  %18ld  %16ld  %19ld", hi->name,
	      stats.rx_dropped, stats.rx_invalid_descs, stats.rx_ring_full,
	      stats.rx_fill_ring_empty_descs, stats.tx_invalid_descs,
	      stats.tx_ring_empty_descs);
	}
    }
done:
  vec_free (hw_if_indices);
  return error;
}

VLIB_CLI_COMMAND (af_xdp_show_command, static) = {
  .path = "show af_xdp",
  .short_help = "show af_xdp [<interace>] [stats]",
  .function = af_xdp_show_command_fn,
  .is_mp_safe = 1,
};

clib_error_t *
af_xdp_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (af_xdp_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
