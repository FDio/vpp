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
#include <vnet/interface/cli_types.h>
#include <vnet/ip/cli_types.h>
#include <vnet/ethernet/cli_types.h>
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
      /* Display vhost worker fork mode if available.
       * We only check the first vhost_fd since all fds for this interface
       * share the same fork mode (configured at interface creation). */
      if (vec_len (tif->vhost_fds) > 0)
	{
	  u8 fork_mode = 0;
	  if (ioctl (tif->vhost_fds[0], VHOST_GET_FORK_FROM_OWNER,
		     &fork_mode) == 0)
	    {
	      if (fork_mode == VHOST_FORK_OWNER_KTHREAD)
		vlib_cli_output (vm, "  vhost-worker-mode: kthread");
	      else if (fork_mode == VHOST_FORK_OWNER_TASK)
		vlib_cli_output (vm, "  vhost-worker-mode: task");
	      else
		vlib_cli_output (vm, "  vhost-worker-mode: unknown (%d)",
				 fork_mode);
	    }
	  else
	    {
	      vlib_cli_output (vm, "  vhost-worker-mode: not supported");
	    }
	}
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
static u8 *
tap_cli_string (cli_ctx_t *ctx, const char *name)
{
  cli_value_t *v = cli_get (ctx, name);
  u8 *s;

  if (!v)
    return 0;

  s = vec_dup (v->str);
  vec_add1 (s, 0);
  return s;
}

static clib_error_t *
tap_cli_host_addr (cli_ctx_t *ctx, const char *name, int is_ip6, void *addr, u8 *len, int *is_set)
{
  cli_value_t *v = cli_get (ctx, name);

  if (!v)
    return 0;

  if (v->prefix.is_ip6 != is_ip6)
    return clib_error_return (0, "'%s' needs an IPv%u address", name, is_ip6 ? 6 : 4);

  clib_memcpy (addr, v->prefix.addr, is_ip6 ? 16 : 4);
  *len = v->prefix.len;
  *is_set = 1;
  return 0;
}

static clib_error_t *
tap_cli_gw (cli_ctx_t *ctx, const char *name, int is_ip6, void *addr, u8 *is_set)
{
  cli_value_t *v = cli_get (ctx, name);

  if (!v)
    return 0;

  if (v->prefix.is_ip6 != is_ip6)
    return clib_error_return (0, "'%s' needs an IPv%u address", name, is_ip6 ? 6 : 4);

  clib_memcpy (addr, v->prefix.addr, is_ip6 ? 16 : 4);
  *is_set = 1;
  return 0;
}

static clib_error_t *
tap_create_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  tap_create_if_args_t args = {
    .id = cli_u64 (ctx, "id", ~0),
    .rv = -1,
    .num_rx_queues = cli_u64 (ctx, "num-rx-queues", 1),
    .num_tx_queues = cli_u64 (ctx, "num-tx-queues", 1),
    .rx_ring_sz = cli_u64 (ctx, "rx-ring-size", 0),
    .tx_ring_sz = cli_u64 (ctx, "tx-ring-size", 0),
  };
  clib_error_t *err = 0;
  cli_value_t *v;
  int ip_addr_set = 0;

  args.if_name = tap_cli_string (ctx, "if-name");
  args.host_if_name = tap_cli_string (ctx, "host-if-name");
  args.host_namespace = tap_cli_string (ctx, "host-ns");
  args.host_bridge = tap_cli_string (ctx, "host-bridge");

  if ((v = cli_get (ctx, "host-mac-addr")))
    clib_memcpy (args.host_mac_addr.bytes, v->prefix.addr, 6);
  if ((v = cli_get (ctx, "hw-addr")))
    {
      clib_memcpy (args.mac_addr.bytes, v->prefix.addr, 6);
      args.mac_addr_set = 1;
    }
  if ((v = cli_get (ctx, "host-mtu-size")))
    {
      args.host_mtu_size = v->u64;
      args.host_mtu_set = 1;
    }

  err = tap_cli_host_addr (ctx, "host-ip4-addr", 0, &args.host_ip4_addr, &args.host_ip4_prefix_len,
			   &ip_addr_set);
  if (!err)
    err = tap_cli_host_addr (ctx, "host-ip6-addr", 1, &args.host_ip6_addr,
			     &args.host_ip6_prefix_len, &ip_addr_set);
  if (!err)
    err = tap_cli_gw (ctx, "host-ip4-gw", 0, &args.host_ip4_gw, &args.host_ip4_gw_set);
  if (!err)
    err = tap_cli_gw (ctx, "host-ip6-gw", 1, &args.host_ip6_gw, &args.host_ip6_gw_set);
  if (err)
    goto done;

  if (cli_flag (ctx, "gso"))
    args.tap_flags |= TAP_FLAG_GSO;
  if (cli_flag (ctx, "gro-coalesce"))
    args.tap_flags |= TAP_FLAG_GRO_COALESCE;
  if (cli_flag (ctx, "csum-offload"))
    args.tap_flags |= TAP_FLAG_CSUM_OFFLOAD;
  if (cli_flag (ctx, "persist"))
    args.tap_flags |= TAP_FLAG_PERSIST;
  if (cli_flag (ctx, "attach"))
    args.tap_flags |= TAP_FLAG_ATTACH;
  if (cli_flag (ctx, "tun"))
    args.tap_flags |= TAP_FLAG_TUN;
  if (cli_flag (ctx, "packed"))
    args.tap_flags |= TAP_FLAG_PACKED;
  if (cli_flag (ctx, "in-order"))
    args.tap_flags |= TAP_FLAG_IN_ORDER;
  if (cli_flag (ctx, "consistent-qp"))
    args.tap_flags |= TAP_FLAG_CONSISTENT_QP;

  if (ip_addr_set && args.host_bridge)
    {
      err = clib_error_return (0, "Please specify either host ip address or host bridge");
      goto done;
    }

  tap_create_if (vm, &args);

  if (!args.rv)
    vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main (), args.sw_if_index);
  err = args.error;

done:
  vec_free (args.if_name);
  vec_free (args.host_if_name);
  vec_free (args.host_namespace);
  vec_free (args.host_bridge);

  return err;
}

VLIB_CLI_COMMAND (tap_create_command, static) = {
  .path = "create tap",
  .short_help = "Create a tap interface",
  .args = CLI_ARGS (
    CLI_OPT_KEYWORD ("id", cli_type_u32, .max = CLIB_U32_MAX - 1, .help = "interface id"),
    CLI_OPT_KEYWORD ("hw-addr", cli_type_mac_address, .help = "MAC address of the interface"),
    CLI_OPT_KEYWORD ("if-name", cli_type_string, .help = "name of the interface"),
    CLI_OPT_KEYWORD ("num-rx-queues", cli_type_u32, .min = 1, .max = CLIB_U16_MAX),
    CLI_OPT_KEYWORD ("num-tx-queues", cli_type_u32, .min = 1, .max = CLIB_U16_MAX),
    CLI_OPT_KEYWORD ("rx-ring-size", cli_type_u32, .min = 1, .max = CLIB_U16_MAX),
    CLI_OPT_KEYWORD ("tx-ring-size", cli_type_u32, .min = 1, .max = CLIB_U16_MAX),
    CLI_OPT_KEYWORD ("host-ns", cli_type_string, .help = "network namespace of the host side"),
    CLI_OPT_KEYWORD ("host-bridge", cli_type_string, .excludes = "host-ip4-addr,host-ip6-addr",
		     .help = "host bridge to attach the host side to"),
    CLI_OPT_KEYWORD ("host-ip4-addr", cli_type_ip_prefix, .help = "host IPv4 address/length"),
    CLI_OPT_KEYWORD ("host-ip6-addr", cli_type_ip_prefix, .help = "host IPv6 address/length"),
    CLI_OPT_KEYWORD ("host-ip4-gw", cli_type_ip_address, .help = "host IPv4 gateway"),
    CLI_OPT_KEYWORD ("host-ip6-gw", cli_type_ip_address, .help = "host IPv6 gateway"),
    CLI_OPT_KEYWORD ("host-mac-addr", cli_type_mac_address, .help = "MAC address of the host side"),
    CLI_OPT_KEYWORD ("host-if-name", cli_type_string, .help = "name of the host side interface"),
    CLI_OPT_KEYWORD ("host-mtu-size", cli_type_u32, .min = 64, .help = "MTU of the host side"),
    CLI_FLAG ("no-gso", .excludes = "gso", .help = "no GSO, the default"),
    CLI_FLAG ("gso", .help = "enable GSO"),
    CLI_FLAG ("gro-coalesce", .help = "coalesce received packets"),
    CLI_FLAG ("csum-offload", .help = "enable checksum offload"),
    CLI_FLAG ("persist", .help = "keep the host interface after deletion"),
    CLI_FLAG ("attach", .help = "attach to an existing host interface"),
    CLI_FLAG ("tun", .help = "create a tun interface"), CLI_FLAG ("packed", .help = "packed rings"),
    CLI_FLAG ("in-order", .help = "in-order descriptor use"),
    CLI_FLAG ("consistent-qp", .help = "consistent queue pair to thread mapping")),
  .handler = tap_create_command_fn,
};

static clib_error_t *
tap_delete_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  int rv = tap_delete_if (vm, cli_index (ctx, "interface"));

  if (rv == VNET_API_ERROR_INVALID_SW_IF_INDEX)
    return clib_error_return (0, "not a tap interface");
  else if (rv != 0)
    return clib_error_return (0, "error on deleting tap interface");

  return 0;
}

VLIB_CLI_COMMAND (tap_delete__command, static) = {
  .path = "delete tap",
  .short_help = "Delete a tap interface",
  .args = CLI_ARGS (CLI_VALUE ("interface", cli_type_sw_interface)),
  .handler = tap_delete_command_fn,
};

static clib_error_t *
tap_show_common (vlib_main_t *vm, cli_ctx_t *ctx, int is_tun)
{
  tap_main_t *tm = &tap_main;
  tap_if_t *tif;
  cli_value_t *v;
  u32 *hw_if_indices = 0;

  cli_foreach (v, ctx, "interface") vec_add1 (hw_if_indices, v->index);

  if (vec_len (hw_if_indices) == 0)
    {
      pool_foreach (tif, tm->interfaces)
	vec_add1 (hw_if_indices, tif->hw_if_index);
    }

  tap_show (vm, hw_if_indices, cli_flag (ctx, "descriptors"), is_tun);

  vec_free (hw_if_indices);
  return 0;
}

static clib_error_t *
tap_show_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return tap_show_common (vm, ctx, 0);
}

VLIB_CLI_COMMAND (tap_show_command, static) = {
  .path = "show tap",
  .short_help = "Show tap interfaces",
  .args = CLI_ARGS (CLI_VALUE ("interface", cli_type_hw_interface,
			       .flags = CLI_F_OPTIONAL | CLI_F_REPEAT),
		    CLI_FLAG ("descriptors", .help = "show the descriptor tables")),
  .handler = tap_show_command_fn,
};

static clib_error_t *
tun_show_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return tap_show_common (vm, ctx, 1);
}

VLIB_CLI_COMMAND (tun_show_command, static) = {
  .path = "show tun",
  .short_help = "Show tun interfaces",
  .args = CLI_ARGS (CLI_VALUE ("interface", cli_type_hw_interface,
			       .flags = CLI_F_OPTIONAL | CLI_F_REPEAT),
		    CLI_FLAG ("descriptors", .help = "show the descriptor tables")),
  .handler = tun_show_command_fn,
};

static clib_error_t *
tap_cli_init (vlib_main_t *vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (tap_cli_init);
