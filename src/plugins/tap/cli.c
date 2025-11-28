/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016-2025 Cisco and/or its affiliates.
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
#include <tap/internal.h>

static void
tap_show (vlib_main_t *vm, u32 *hw_if_indices, u8 show_descr, int is_tun)
{
  u32 i, j, hw_if_index;
  tap_if_t *tif;
  vnet_main_t *vnm = &vnet_main;
  tap_main_t *tm = &tap_main;
  tap_txq_t *txq;
  tap_rxq_t *rxq;

  if (!hw_if_indices)
    return;

  for (hw_if_index = 0; hw_if_index < vec_len (hw_if_indices); hw_if_index++)
    {
      vnet_hw_interface_t *hi =
	vnet_get_hw_interface (vnm, hw_if_indices[hw_if_index]);
      tif = pool_elt_at_index (tm->interfaces, hi->dev_instance);
      vlib_cli_output (vm, "Interface: %U (ifindex %d)",
		       format_vnet_hw_if_index_name, vnm,
		       hw_if_indices[hw_if_index], tif->hw_if_index);
      u8 *str = 0;
      if (tif->host_if_name)
	vlib_cli_output (vm, "  name \"%s\"", tif->host_if_name);
      if (tif->net_ns)
	vlib_cli_output (vm, "  host-ns \"%s\"", tif->net_ns);
      if (tif->host_mtu_size)
	vlib_cli_output (vm, "  host-mtu-size \"%d\"", tif->host_mtu_size);
      if (!is_tun)
	vlib_cli_output (vm, "  host-mac-addr: %U", format_ethernet_address,
			 tif->host_mac_addr);
      vlib_cli_output (vm, "  host-carrier-up: %u", tif->host_carrier_up);

      vec_foreach_index (i, tif->vhost_fds)
	str = format (str, " %d", tif->vhost_fds[i]);
      vlib_cli_output (vm, "  vhost-fds%v", str);
      vec_free (str);
      vec_foreach_index (i, tif->tap_fds)
	str = format (str, " %d", tif->tap_fds[i]);
      vlib_cli_output (vm, "  tap-fds%v", str);
      vec_free (str);

      vlib_cli_output (vm, "  gso-enabled %d", tif->gso_enabled);
      vlib_cli_output (vm, "  csum-enabled %d", tif->csum_offload_enabled);
      vlib_cli_output (vm, "  packet-coalesce %d", tif->packet_coalesce);
      if (!is_tun)
	vlib_cli_output (vm, "  mac Address: %U", format_ethernet_address,
			 tif->mac_addr);
      vlib_cli_output (vm, "  device instance: %u", tif->dev_instance);
      vlib_cli_output (vm, "  admin state: %s", tif->admin_up ? "up" : "down");
      vlib_cli_output (vm, "  features 0x%lx\n     %U", tif->features,
		       format_virtio_features, tif->features);
      vlib_cli_output (vm, "  remote-features 0x%lx\n    %U",
		       tif->remote_features, format_virtio_features,
		       tif->remote_features);
      vlib_cli_output (vm, "  Number of RX Virtqueue  %u",
		       vec_len (tif->rx_queues));
      vlib_cli_output (vm, "  Number of TX Virtqueue  %u",
		       vec_len (tif->tx_queues));
      vec_foreach_index (i, tif->rx_queues)
	{
	  rxq = tap_get_rx_queue (tif, i);
	  vlib_cli_output (vm, "  Virtqueue (RX) %d", rxq->queue_id);
	  vlib_cli_output (
	    vm, "    qsz %d, last_used_idx %d, desc_next %d, desc_in_use %d",
	    rxq->queue_size, rxq->last_used_idx, rxq->desc_next,
	    rxq->desc_in_use);
	  vlib_cli_output (
	    vm,
	    "    avail.flags 0x%x avail.idx %d used.flags 0x%x used.idx %d",
	    rxq->avail->flags, rxq->avail->idx, rxq->used->flags,
	    rxq->used->idx);
	  vlib_cli_output (vm, "    kickfd %d, callfd %d", rxq->kick_fd,
			   rxq->call_fd);
	  if (show_descr)
	    {
	      vlib_cli_output (vm, "\n  descriptor table:\n");
	      vlib_cli_output (vm, "   id          addr         len  flags  "
				   "next/id      user_addr\n");
	      vlib_cli_output (vm, "  ===== ================== ===== ====== "
				   "======= ==================\n");
	      for (j = 0; j < rxq->queue_size; j++)
		{
		  vnet_virtio_vring_desc_t *desc = &rxq->desc[j];
		  vlib_cli_output (
		    vm, "  %-5d 0x%016lx %-5d 0x%04x %-8d 0x%016lx\n", j,
		    desc->addr, desc->len, desc->flags, desc->next,
		    desc->addr);
		}
	    }
	}
      vec_foreach_index (i, tif->tx_queues)
	{
	  txq = tap_get_tx_queue (tif, i);
	  vlib_cli_output (vm, "  Virtqueue (TX) %d", txq->queue_id);
	  vlib_cli_output (
	    vm, "    qsz %d, last_used_idx %d, desc_next %d, desc_in_use %d",
	    txq->queue_size, txq->last_used_idx, txq->desc_next,
	    txq->desc_in_use);
	  vlib_cli_output (
	    vm,
	    "    avail.flags 0x%x avail.idx %d used.flags 0x%x used.idx %d",
	    txq->avail->flags, txq->avail->idx, txq->used->flags,
	    txq->used->idx);
	  vlib_cli_output (vm, "    kickfd %d", txq->kick_fd);
	  if (txq->flow_table)
	    {
	      vlib_cli_output (vm, "    %U", gro_flow_table_format,
			       txq->flow_table);
	    }
	  if (show_descr)
	    {
	      vlib_cli_output (vm, "\n  descriptor table:\n");
	      vlib_cli_output (vm, "   id          addr         len  flags  "
				   "next/id      user_addr\n");
	      vlib_cli_output (vm, "  ===== ================== ===== ====== "
				   "======== ==================\n");
	      for (j = 0; j < txq->queue_size; j++)
		{
		  vnet_virtio_vring_desc_t *desc = &txq->desc[j];
		  vlib_cli_output (
		    vm, "  %-5d 0x%016lx %-5d 0x%04x %-8d 0x%016lx\n", j,
		    desc->addr, desc->len, desc->flags, desc->next,
		    desc->addr);
		}
	    }
	}
    }
}
static clib_error_t *
tap_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  tap_create_if_args_t args = { 0 };
  int ip_addr_set = 0;
  u32 tmp;

  args.id = ~0;
  args.tap_flags = 0;
  args.rv = -1;
  args.num_rx_queues = 1;
  args.num_tx_queues = 1;

  /* Get a line of input. */
  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "id %u", &args.id))
	    ;
	  else if (unformat (line_input, "if-name %s", &args.if_name))
	    ;
	  else if (unformat (line_input, "host-if-name %s",
			     &args.host_if_name))
	    ;
	  else if (unformat (line_input, "host-ns %s", &args.host_namespace))
	    ;
	  else if (unformat (line_input, "host-mac-addr %U",
			     unformat_ethernet_address,
			     args.host_mac_addr.bytes))
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
	  else if (unformat (line_input, "num-rx-queues %d", &tmp))
	    args.num_rx_queues = tmp;
	  else if (unformat (line_input, "num-tx-queues %d", &tmp))
	    args.num_tx_queues = tmp;
	  else if (unformat (line_input, "rx-ring-size %d", &tmp))
	    args.rx_ring_sz = tmp;
	  else if (unformat (line_input, "tx-ring-size %d", &tmp))
	    args.tx_ring_sz = tmp;
	  else if (unformat (line_input, "host-mtu-size %d",
			     &args.host_mtu_size))
	    args.host_mtu_set = 1;
	  else if (unformat (line_input, "no-gso"))
	    args.tap_flags &= ~TAP_FLAG_GSO;
	  else if (unformat (line_input, "gso"))
	    args.tap_flags |= TAP_FLAG_GSO;
	  else if (unformat (line_input, "gro-coalesce"))
	    args.tap_flags |= TAP_FLAG_GRO_COALESCE;
	  else if (unformat (line_input, "csum-offload"))
	    args.tap_flags |= TAP_FLAG_CSUM_OFFLOAD;
	  else if (unformat (line_input, "persist"))
	    args.tap_flags |= TAP_FLAG_PERSIST;
	  else if (unformat (line_input, "attach"))
	    args.tap_flags |= TAP_FLAG_ATTACH;
	  else if (unformat (line_input, "tun"))
	    args.tap_flags |= TAP_FLAG_TUN;
	  else if (unformat (line_input, "packed"))
	    args.tap_flags |= TAP_FLAG_PACKED;
	  else if (unformat (line_input, "in-order"))
	    args.tap_flags |= TAP_FLAG_IN_ORDER;
	  else if (unformat (line_input, "consistent-qp"))
	    args.tap_flags |= TAP_FLAG_CONSISTENT_QP;
	  else if (unformat (line_input, "hw-addr %U",
			     unformat_ethernet_address, args.mac_addr.bytes))
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

  if (!args.rv)
    vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name,
		     vnet_get_main (), args.sw_if_index);

  vec_free (args.if_name);
  vec_free (args.host_if_name);
  vec_free (args.host_namespace);
  vec_free (args.host_bridge);

  return args.error;
}

VLIB_CLI_COMMAND (tap_create_command, static) = {
  .path = "create tap",
  .short_help =
    "create tap {id <if-id>} [hw-addr <mac-address>] [if-name <if-name>] "
    "[num-rx-queues <n>] [num-tx-queues <n>] [rx-ring-size <size>] "
    "[tx-ring-size <size>] [host-ns <netns>] [host-bridge <bridge-name>] "
    "[host-ip4-addr <ip4addr/mask>] [host-ip6-addr <ip6-addr>] "
    "[host-ip4-gw <ip4-addr>] [host-ip6-gw <ip6-addr>] "
    "[host-mac-addr <host-mac-address>] [host-if-name <name>] "
    "[host-mtu-size <size>] [no-gso|gso [gro-coalesce]|csum-offload] "
    "[persist] [attach] [tun] [packed] [in-order]",
  .function = tap_create_command_fn,
};

static clib_error_t *
tap_delete_command_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
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
      else if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
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

VLIB_CLI_COMMAND (tap_delete__command, static) = {
  .path = "delete tap",
  .short_help = "delete tap {<interface> | sw_if_index <sw_idx>}",
  .function = tap_delete_command_fn,
};

static clib_error_t *
tap_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  tap_main_t *tm = &tap_main;
  tap_if_t *tif;
  vnet_main_t *vnm = vnet_get_main ();
  int show_descr = 0;
  clib_error_t *error = 0;
  u32 hw_if_index, *hw_if_indices = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_hw_interface, vnm,
		    &hw_if_index))
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
      pool_foreach (tif, tm->interfaces)
	vec_add1 (hw_if_indices, tif->hw_if_index);
    }

  tap_show (vm, hw_if_indices, show_descr, 0);

done:
  vec_free (hw_if_indices);
  return error;
}

VLIB_CLI_COMMAND (tap_show_command, static) = {
  .path = "show tap",
  .short_help = "show tap {<interface>] [descriptors]",
  .function = tap_show_command_fn,
};

static clib_error_t *
tun_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  tap_main_t *tm = &tap_main;
  tap_if_t *tif;
  vnet_main_t *vnm = vnet_get_main ();
  int show_descr = 0;
  clib_error_t *error = 0;
  u32 hw_if_index, *hw_if_indices = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_hw_interface, vnm,
		    &hw_if_index))
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
      pool_foreach (tif, tm->interfaces)
	vec_add1 (hw_if_indices, tif->hw_if_index);
    }

  tap_show (vm, hw_if_indices, show_descr, 1);

done:
  vec_free (hw_if_indices);
  return error;
}

VLIB_CLI_COMMAND (tun_show_command, static) = {
  .path = "show tun",
  .short_help = "show tun {<interface>] [descriptors]",
  .function = tun_show_command_fn,
};

static clib_error_t *
tap_cli_init (vlib_main_t *vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (tap_cli_init);
