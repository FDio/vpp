/*
 *------------------------------------------------------------------
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/format.h>
#include <linux/virtio_net.h>
#include <linux/vhost.h>
#include <vnet/devices/virtio/virtio.h>
#include <vnet/devices/tap/tap.h>

static clib_error_t *
tap_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  tap_create_if_args_t args = { 0 };
  int ip_addr_set = 0;

  args.id = ~0;
  args.tap_flags = 0;

  /* Get a line of input. */
  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "id %u", &args.id))
	    ;
	  else
	    if (unformat (line_input, "host-if-name %s", &args.host_if_name))
	    ;
	  else if (unformat (line_input, "host-ns %s", &args.host_namespace))
	    ;
	  else if (unformat (line_input, "host-mac-addr %U",
			     unformat_ethernet_address, args.host_mac_addr))
	    ;
	  else if (unformat (line_input, "host-bridge %s", &args.host_bridge))
	    ;
	  else if (unformat (line_input, "host-ip4-addr %U/%d",
			     unformat_ip4_address, &args.host_ip4_addr,
			     &args.host_ip4_prefix_len))
	    ip_addr_set = 1;
	  else if (unformat (line_input, "host-ip4-gw %U",
			     unformat_ip4_address, &args.host_ip4_gw))
	    args.host_ip4_gw_set = 1;
	  else if (unformat (line_input, "host-ip6-addr %U/%d",
			     unformat_ip6_address, &args.host_ip6_addr,
			     &args.host_ip6_prefix_len))
	    ip_addr_set = 1;
	  else if (unformat (line_input, "host-ip6-gw %U",
			     unformat_ip6_address, &args.host_ip6_gw))
	    args.host_ip6_gw_set = 1;
	  else if (unformat (line_input, "rx-ring-size %d", &args.rx_ring_sz))
	    ;
	  else if (unformat (line_input, "tx-ring-size %d", &args.tx_ring_sz))
	    ;
	  else if (unformat (line_input, "no-gso"))
	    args.tap_flags &= ~TAP_FLAG_GSO;
	  else if (unformat (line_input, "gso"))
	    args.tap_flags |= TAP_FLAG_GSO;
	  else if (unformat (line_input, "hw-addr %U",
			     unformat_ethernet_address, args.mac_addr))
	    args.mac_addr_set = 1;
	  else
	    {
	      unformat_free (line_input);
	      return clib_error_return (0, "unknown input `%U'",
					format_unformat_error, input);
	    }
	}
      unformat_free (line_input);
    }

  if (ip_addr_set && args.host_bridge)
    return clib_error_return (0, "Please specify either host ip address or "
			      "host bridge");

  tap_create_if (vm, &args);

  vec_free (args.host_if_name);
  vec_free (args.host_namespace);
  vec_free (args.host_bridge);

  return args.error;

}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tap_create_command, static) = {
  .path = "create tap",
  .short_help = "create tap {id <if-id>} [hw-addr <mac-address>] "
    "[rx-ring-size <size>] [tx-ring-size <size>] [host-ns <netns>] "
    "[host-bridge <bridge-name>] [host-ip4-addr <ip4addr/mask>] "
    "[host-ip6-addr <ip6-addr>] [host-ip4-gw <ip4-addr>] "
    "[host-ip6-gw <ip6-addr>] [host-if-name <name>] [no-gso|gso]",
  .function = tap_create_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
tap_delete_command_fn (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  vnet_main_t *vnm = vnet_get_main ();
  int rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "Missing <interface>");

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

  rv = tap_delete_if (vm, sw_if_index);
  if (rv == VNET_API_ERROR_INVALID_SW_IF_INDEX)
    return clib_error_return (0, "not a tap interface");
  else if (rv != 0)
    return clib_error_return (0, "error on deleting tap interface");

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tap_delete__command, static) =
{
  .path = "delete tap",
  .short_help = "delete tap {<interface> | sw_if_index <sw_idx>}",
  .function = tap_delete_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
tap_gso_command_fn (vlib_main_t * vm, unformat_input_t * input,
		    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  vnet_main_t *vnm = vnet_get_main ();
  int enable = 1;
  int rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "Missing <interface>");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (line_input, "%U", unformat_vnet_sw_interface,
			 vnm, &sw_if_index))
	;
      else if (unformat (line_input, "enable"))
	enable = 1;
      else if (unformat (line_input, "disable"))
	enable = 0;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (sw_if_index == ~0)
    return clib_error_return (0,
			      "please specify interface name or sw_if_index");

  rv = tap_gso_enable_disable (vm, sw_if_index, enable);
  if (rv == VNET_API_ERROR_INVALID_SW_IF_INDEX)
    return clib_error_return (0, "not a tap interface");
  else if (rv != 0)
    return clib_error_return (0, "error on configuring GSO on tap interface");

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tap_gso__command, static) =
{
  .path = "set tap gso",
  .short_help = "set tap gso {<interface> | sw_if_index <sw_idx>} <enable|disable>",
  .function = tap_gso_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
tap_show_command_fn (vlib_main_t * vm, unformat_input_t * input,
		     vlib_cli_command_t * cmd)
{
  virtio_main_t *mm = &virtio_main;
  virtio_if_t *vif;
  vnet_main_t *vnm = vnet_get_main ();
  int show_descr = 0;
  clib_error_t *error = 0;
  u32 hw_if_index, *hw_if_indices = 0;
  virtio_vring_t *vring;
  int i, j;
  struct feat_struct
  {
    u8 bit;
    char *str;
  };
  struct feat_struct *feat_entry;

  static struct feat_struct feat_array[] = {
#define _(s,b) { .str = #s, .bit = b, },
    foreach_virtio_net_features
#undef _
    {.str = NULL}
  };

  struct feat_struct *flag_entry;
  static struct feat_struct flags_array[] = {
#define _(b,e,s) { .bit = b, .str = s, },
    foreach_virtio_if_flag
#undef _
    {.str = NULL}
  };

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index))
	vec_add1 (hw_if_indices, hw_if_index);
      else if (unformat (input, "descriptors"))
	show_descr = 1;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (vec_len (hw_if_indices) == 0)
    {
      /* *INDENT-OFF* */
      pool_foreach (vif, mm->interfaces,
	  vec_add1 (hw_if_indices, vif->hw_if_index);
      );
      /* *INDENT-ON* */
    }

  for (hw_if_index = 0; hw_if_index < vec_len (hw_if_indices); hw_if_index++)
    {
      vnet_hw_interface_t *hi =
	vnet_get_hw_interface (vnm, hw_if_indices[hw_if_index]);
      vif = pool_elt_at_index (mm->interfaces, hi->dev_instance);
      vlib_cli_output (vm, "interface %U", format_vnet_sw_if_index_name,
		       vnm, vif->sw_if_index);
      if (vif->host_if_name)
	vlib_cli_output (vm, "  name \"%s\"", vif->host_if_name);
      if (vif->net_ns)
	vlib_cli_output (vm, "  host-ns \"%s\"", vif->net_ns);
      vlib_cli_output (vm, "  flags 0x%x", vif->flags);
      flag_entry = (struct feat_struct *) &flags_array;
      while (flag_entry->str)
	{
	  if (vif->flags & (1ULL << flag_entry->bit))
	    vlib_cli_output (vm, "    %s (%d)", flag_entry->str,
			     flag_entry->bit);
	  flag_entry++;
	}
      vlib_cli_output (vm, "  fd %d", vif->fd);
      vlib_cli_output (vm, "  tap-fd %d", vif->tap_fd);
      vlib_cli_output (vm, "  features 0x%lx", vif->features);
      vlib_cli_output (vm, "  gso enabled %d", vif->gso_enabled);
      feat_entry = (struct feat_struct *) &feat_array;
      while (feat_entry->str)
	{
	  if (vif->features & (1ULL << feat_entry->bit))
	    vlib_cli_output (vm, "    %s (%d)", feat_entry->str,
			     feat_entry->bit);
	  feat_entry++;
	}
      vlib_cli_output (vm, "  remote-features 0x%lx", vif->remote_features);
      feat_entry = (struct feat_struct *) &feat_array;
      while (feat_entry->str)
	{
	  if (vif->remote_features & (1ULL << feat_entry->bit))
	    vlib_cli_output (vm, "    %s (%d)", feat_entry->str,
			     feat_entry->bit);
	  feat_entry++;
	}
      vec_foreach_index (i, vif->vrings)
      {
	// RX = 0, TX = 1
	vring = vec_elt_at_index (vif->vrings, i);
	vlib_cli_output (vm, "  Virtqueue (%s)", (i & 1) ? "TX" : "RX");
	vlib_cli_output (vm,
			 "    qsz %d, last_used_idx %d, desc_next %d, desc_in_use %d",
			 vring->size, vring->last_used_idx, vring->desc_next,
			 vring->desc_in_use);
	vlib_cli_output (vm,
			 "    avail.flags 0x%x avail.idx %d used.flags 0x%x used.idx %d",
			 vring->avail->flags, vring->avail->idx,
			 vring->used->flags, vring->used->idx);
	vlib_cli_output (vm, "    kickfd %d, callfd %d", vring->kick_fd,
			 vring->call_fd);
	if (show_descr)
	  {
	    vlib_cli_output (vm, "\n  descriptor table:\n");
	    vlib_cli_output (vm,
			     "   id          addr         len  flags  next      user_addr\n");
	    vlib_cli_output (vm,
			     "  ===== ================== ===== ====== ===== ==================\n");
	    vring = vif->vrings;
	    for (j = 0; j < vring->size; j++)
	      {
		struct vring_desc *desc = &vring->desc[j];
		vlib_cli_output (vm,
				 "  %-5d 0x%016lx %-5d 0x%04x %-5d 0x%016lx\n",
				 j, desc->addr,
				 desc->len,
				 desc->flags, desc->next, desc->addr);
	      }
	  }
      }
    }
  vlib_cli_output (vm, "Total GSO-enabled interfaces: %d",
		   vnm->interface_main.gso_interface_count);
done:
  vec_free (hw_if_indices);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tap_show_command, static) = {
  .path = "show tap",
  .short_help = "show tap {<interface>] [descriptors]",
  .function = tap_show_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
tap_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (tap_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
