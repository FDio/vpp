/*
 * l2_bvi.c : layer 2 Bridged Virtual Interface
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/l2/l2_fwd.h>
#include <vnet/l2/l2_flood.h>
#include <vnet/l2/l2_bvi.h>

/* Allocated BVI instances */
static uword *l2_bvi_instances;

/* Call the L2 nodes that need the ethertype mapping */
void
l2bvi_register_input_type (vlib_main_t * vm,
			   ethernet_type_t type, u32 node_index)
{
  l2fwd_register_input_type (vm, type, node_index);
  l2flood_register_input_type (vm, type, node_index);
}

static u8 *
format_bvi_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "bvi%d", dev_instance);
}

static clib_error_t *
bvi_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
    VNET_HW_INTERFACE_FLAG_LINK_UP : 0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);
  return 0;
}

static clib_error_t *
bvi_mac_change (vnet_hw_interface_t * hi,
		const u8 * old_address, const u8 * mac_address)
{
  l2input_interface_mac_change (hi->sw_if_index, old_address, mac_address);

  return (NULL);
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (bvi_device_class) = {
  .name = "BVI",
  .format_device_name = format_bvi_name,
  .admin_up_down_function = bvi_admin_up_down,
  .mac_addr_change_function = bvi_mac_change,
};
/* *INDENT-ON* */

/*
 * Maintain a bitmap of allocated bvi instance numbers.
 */
#define BVI_MAX_INSTANCE		(16 * 1024)

static u32
bvi_instance_alloc (u32 want)
{
  /*
   * Check for dynamically allocaetd instance number.
   */
  if (~0 == want)
    {
      u32 bit;

      bit = clib_bitmap_first_clear (l2_bvi_instances);
      if (bit >= BVI_MAX_INSTANCE)
	{
	  return ~0;
	}
      l2_bvi_instances = clib_bitmap_set (l2_bvi_instances, bit, 1);
      return bit;
    }

  /*
   * In range?
   */
  if (want >= BVI_MAX_INSTANCE)
    {
      return ~0;
    }

  /*
   * Already in use?
   */
  if (clib_bitmap_get (l2_bvi_instances, want))
    {
      return ~0;
    }

  /*
   * Grant allocation request.
   */
  l2_bvi_instances = clib_bitmap_set (l2_bvi_instances, want, 1);

  return want;
}

static int
bvi_instance_free (u32 instance)
{
  if (instance >= BVI_MAX_INSTANCE)
    {
      return -1;
    }

  if (clib_bitmap_get (l2_bvi_instances, instance) == 0)
    {
      return -1;
    }

  l2_bvi_instances = clib_bitmap_set (l2_bvi_instances, instance, 0);
  return 0;
}

int
l2_bvi_create (u32 user_instance,
	       const mac_address_t * mac_in, u32 * sw_if_indexp)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  u32 instance, hw_if_index, slot;
  vnet_hw_interface_t *hw_if;
  clib_error_t *error;
  mac_address_t mac;

  int rv = 0;

  ASSERT (sw_if_indexp);

  *sw_if_indexp = (u32) ~ 0;

  /*
   * Allocate a bvi instance.  Either select on dynamically
   * or try to use the desired user_instance number.
   */
  instance = bvi_instance_alloc (user_instance);
  if (instance == ~0)
    {
      return VNET_API_ERROR_INVALID_REGISTRATION;
    }

  /*
   * Default MAC address (b0b0:0000:0000 + instance) is allocated
   * if zero mac_address is configured. Otherwise, user-configurable MAC
   * address is programmed on the bvi interface.
   */
  if (mac_address_is_zero (mac_in))
    {
      u8 bytes[6] = {
	[0] = 0xb0,
	[1] = 0xb0,
	[5] = instance,
      };
      mac_address_from_bytes (&mac, bytes);
    }
  else
    {
      mac_address_copy (&mac, mac_in);
    }

  error = ethernet_register_interface (vnm,
				       bvi_device_class.index,
				       instance, mac.bytes, &hw_if_index,
				       /* flag change */ 0);

  if (error)
    {
      rv = VNET_API_ERROR_INVALID_REGISTRATION;
      clib_error_report (error);
      return rv;
    }

  hw_if = vnet_get_hw_interface (vnm, hw_if_index);

  slot = vlib_node_add_named_next_with_slot (vm, hw_if->tx_node_index,
					     "l2-input", 0);
  ASSERT (slot == 0);

  {
    vnet_sw_interface_t *si = vnet_get_hw_sw_interface (vnm, hw_if_index);
    *sw_if_indexp = si->sw_if_index;

    si->flood_class = VNET_FLOOD_CLASS_BVI;
  }

  return 0;
}

int
l2_bvi_delete (u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();

  if (pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (hw == 0 || hw->dev_class_index != bvi_device_class.index)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (bvi_instance_free (hw->dev_instance) < 0)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  ethernet_delete_interface (vnm, hw->hw_if_index);

  return 0;
}

static clib_error_t *
l2_bvi_create_cli (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 instance, sw_if_index;
  clib_error_t *error;
  mac_address_t mac;
  int rv;

  error = NULL;
  instance = sw_if_index = ~0;
  mac_address_set_zero (&mac);

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "mac %U", unformat_mac_address_t, &mac))
	    ;
	  else if (unformat (line_input, "instance %d", &instance))
	    ;
	  else
	    {
	      error = clib_error_return (0, "unknown input: %U",
					 format_unformat_error, line_input);
	      break;
	    }
	}

      unformat_free (line_input);

      if (error)
	return error;
    }

  rv = l2_bvi_create (instance, &mac, &sw_if_index);

  if (rv)
    return clib_error_return (0, "BVI create failed");

  vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main (),
		   sw_if_index);
  return 0;
}

/*?
 * Create a BVI interface. Optionally, a MAC Address can be
 * provided. If not provided, 0b:0b::00:00:00:<instance> will be used.
 *
 * @cliexpar
 * The following two command syntaxes are equivalent:
 * @cliexcmd{bvi create [mac <mac-addr>] [instance <instance>]}
 * Example of how to create a bvi interface:
 * @cliexcmd{bvi create}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l2_bvi_create_command, static) = {
  .path = "bvi create",
  .short_help = "bvi create [mac <mac-addr>] [instance <instance>]",
  .function = l2_bvi_create_cli,
};
/* *INDENT-ON* */

static clib_error_t *
l2_bvi_delete_cli (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm;
  u32 sw_if_index;
  int rv;

  vnm = vnet_get_main ();
  sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	break;
    }

  if (~0 != sw_if_index)
    {
      rv = l2_bvi_delete (sw_if_index);

      if (rv)
	return clib_error_return (0, "BVI delete failed");
    }
  else
    return clib_error_return (0, "no such interface: %U",
			      format_unformat_error, input);

  return 0;
}

/*?
 * Delete a BVI interface.
 *
 * @cliexpar
 * The following two command syntaxes are equivalent:
 * @cliexcmd{bvi delete <interace>}
 * Example of how to create a bvi interface:
 * @cliexcmd{bvi delete bvi0}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l2_bvi_delete_command, static) = {
  .path = "bvi delete",
  .short_help = "bvi delete <interface>",
  .function = l2_bvi_delete_cli,
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
