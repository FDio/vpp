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
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/devices/virtio/virtio.h>
#include <vnet/devices/virtio/pci.h>

static clib_error_t *
virtio_pci_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  virtio_pci_create_if_args_t args;
  u32 tmp;
  u64 feature_mask = (u64) ~ (0ULL);

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  memset (&args, 0, sizeof (args));
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vlib_pci_addr, &args.addr))
	;
      else if (unformat (line_input, "feature-mask 0x%llx", &feature_mask))
	args.features = feature_mask;
      else if (unformat (line_input, "rx-queue-size %u", &tmp))
	args.rxq_size = tmp;
      else if (unformat (line_input, "tx-queue-size %u", &tmp))
	args.txq_size = tmp;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  virtio_pci_create_if (vm, &args);

  return args.error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (virtio_pci_create_command, static) = {
  .path = "create interface virtio",
  .short_help = "create interface virtio <pci-address>"
                "[feature-mask <hex-mask>] [rx-queue-size <size>] [tx-queue-size <size>]",
  .function = virtio_pci_create_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
virtio_pci_delete_command_fn (vlib_main_t * vm, unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hw;
  virtio_main_t *vmxm = &virtio_main;
  virtio_if_t *vif;
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
  if (hw == NULL || virtio_device_class.index != hw->dev_class_index)
    return clib_error_return (0, "not a virtio interface");

  vif = pool_elt_at_index (vmxm->interfaces, hw->dev_instance);

  if (virtio_pci_delete_if (vm, vif) < 0)
    return clib_error_return (0, "not a virtio pci interface");

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (virtio_pci_delete_command, static) = {
  .path = "delete interface virtio",
  .short_help = "delete interface virtio"
    "{<interface> | sw_if_index <sw_idx>}",
  .function = virtio_pci_delete_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_virtio_pci_fn (vlib_main_t * vm, unformat_input_t * input,
		    vlib_cli_command_t * cmd)
{
  virtio_main_t *vmxm = &virtio_main;
  vnet_main_t *vnm = &vnet_main;
  virtio_if_t *vif;
  clib_error_t *error = 0;
  u32 hw_if_index, *hw_if_indices = 0;
  vnet_hw_interface_t *hi;
  u8 show_descr = 0, show_device_config = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index))
	{
	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	  if (virtio_device_class.index != hi->dev_class_index)
	    {
	      error = clib_error_return (0, "unknown input `%U'",
					 format_unformat_error, input);
	      goto done;
	    }
	  vec_add1 (hw_if_indices, hw_if_index);
	}
      else if (unformat (input, "descriptors") || unformat (input, "desc"))
	show_descr = 1;
      else if (unformat (input, "debug-device"))
	show_device_config = 1;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (vec_len (hw_if_indices) == 0)
    {
      pool_foreach (vif, vmxm->interfaces,
		    vec_add1 (hw_if_indices, vif->hw_if_index);
	);
    }
  else if (show_device_config)
    {
      vif = pool_elt_at_index (vmxm->interfaces, hi->dev_instance);
      if (vif->type == VIRTIO_IF_TYPE_PCI)
	debug_device_config_space (vm, vif);
    }

  virtio_show (vm, hw_if_indices, show_descr, VIRTIO_IF_TYPE_PCI);

done:
  vec_free (hw_if_indices);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_virtio_pci_command, static) = {
  .path = "show virtio pci",
  .short_help = "show virtio pci [<interface>] [descriptors | desc] [debug-device]",
  .function = show_virtio_pci_fn,
};
/* *INDENT-ON* */

clib_error_t *
virtio_pci_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (virtio_pci_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
