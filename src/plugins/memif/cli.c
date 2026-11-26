/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/cli_types.h>
#include <vnet/interface/cli_types.h>

#include <memif/memif.h>
#include <memif/private.h>

static clib_error_t *
memif_socket_filename_create_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  u32 socket_id = cli_u64 (ctx, "id", ~0);
  u8 *socket_filename = cli_get (ctx, "filename")->str;

  if (socket_id == 0 || socket_id == ~0)
    return clib_error_return (0, "Invalid socket id");

  return memif_socket_filename_add_del (1, socket_id, (char *) socket_filename);
}

VLIB_CLI_COMMAND (memif_socket_filename_create_command, static) = {
  .path = "create memif socket",
  .short_help = "Create a memif socket",
  .args = CLI_ARGS (
    CLI_KEYWORD ("id", cli_type_u32, .help = "id of the socket"),
    CLI_KEYWORD ("filename", cli_type_string,
		 .help = "path of the socket file, 'abstract:<name>' for an abstract socket")),
  .handler = memif_socket_filename_create_command_fn,
};

static clib_error_t *
memif_socket_filename_delete_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  u32 socket_id = cli_u64 (ctx, "id", ~0);

  if (socket_id == 0 || socket_id == ~0)
    return clib_error_return (0, "Invalid socket id");

  return memif_socket_filename_add_del (0, socket_id, 0);
}

VLIB_CLI_COMMAND (memif_socket_filename_delete_command, static) = {
  .path = "delete memif socket",
  .short_help = "Delete a memif socket",
  .args = CLI_ARGS (CLI_KEYWORD ("id", cli_type_u32, .help = "id of the socket")),
  .handler = memif_socket_filename_delete_command_fn,
};

static const cli_choice_t memif_mode_choices[] = {
  { "ip", "carry IP packets instead of Ethernet frames", MEMIF_INTERFACE_MODE_IP },
  {},
};

static clib_error_t *
memif_create_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  u32 ring_size = cli_u64 (ctx, "ring-size", MEMIF_DEFAULT_RING_SIZE);
  u32 rx_queues = cli_u64 (ctx, "rx-queues", MEMIF_DEFAULT_RX_QUEUES);
  u32 tx_queues = cli_u64 (ctx, "tx-queues", MEMIF_DEFAULT_TX_QUEUES);
  memif_create_if_args_t args = {
    .id = cli_u64 (ctx, "id", 0),
    .socket_id = cli_u64 (ctx, "socket-id", 0),
    .buffer_size = cli_u64 (ctx, "buffer-size", MEMIF_DEFAULT_BUFFER_SIZE),
    .is_master = cli_flag (ctx, "master"),
    .is_zero_copy = !cli_flag (ctx, "no-zero-copy"),
    .use_dma = cli_flag (ctx, "use-dma"),
  };
  cli_value_t *v;
  clib_error_t *err;

  if (cli_flag (ctx, "mode"))
    args.mode = cli_index (ctx, "mode");

  if ((v = cli_get (ctx, "hw-addr")))
    {
      clib_memcpy (args.hw_addr, v->prefix.addr, 6);
      args.hw_addr_set = 1;
    }

  if (!is_pow2 (ring_size))
    return clib_error_return (0, "ring size must be power of 2");

  if (ring_size > 32768)
    return clib_error_return (0, "maximum ring size is 32768");

  args.log2_ring_size = min_log2 (ring_size);

  if (rx_queues > 255 || rx_queues < 1)
    return clib_error_return (0, "rx queue must be between 1 - 255");
  if (tx_queues > 255 || tx_queues < 1)
    return clib_error_return (0, "tx queue must be between 1 - 255");

  args.rx_queues = rx_queues;
  args.tx_queues = tx_queues;

  if ((v = cli_get (ctx, "secret")))
    args.secret = vec_dup (v->str);

  err = memif_create_if (vm, &args);

  vec_free (args.secret);

  return err;
}

VLIB_CLI_COMMAND (memif_create_command, static) = {
  .path = "create interface memif",
  .short_help = "Create a memif interface",
  .args = CLI_ARGS (
    CLI_OPT_KEYWORD ("id", cli_type_u32, .help = "id of the interface on the socket, default 0"),
    CLI_OPT_KEYWORD ("socket-id", cli_type_u32, .help = "id of the socket, default 0"),
    CLI_FLAG ("master", .excludes = "slave", .help = "listen on the socket"),
    CLI_FLAG ("slave", .help = "connect to the socket, default"),
    CLI_OPT_KEYWORD ("ring-size", cli_type_u32, .help = "power of 2, up to 32768"),
    CLI_OPT_KEYWORD ("buffer-size", cli_type_u32, .max = 0xffff, .help = "size of a buffer"),
    CLI_OPT_KEYWORD ("rx-queues", cli_type_u32, .help = "1 - 255"),
    CLI_OPT_KEYWORD ("tx-queues", cli_type_u32, .help = "1 - 255"),
    CLI_OPT_KEYWORD ("hw-addr", cli_type_mac_address, .help = "MAC address"),
    CLI_OPT_KEYWORD ("mode", cli_type_enum, .choices = memif_mode_choices),
    CLI_OPT_KEYWORD ("secret", cli_type_string, .help = "shared secret"),
    CLI_FLAG ("no-zero-copy", .help = "copy packet data"),
    CLI_FLAG ("use-dma", .help = "copy with a DMA engine")),
  .handler = memif_create_command_fn,
};

static clib_error_t *
memif_delete_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  u32 sw_if_index = cli_index (ctx, "interface");
  vnet_hw_interface_t *hw;
  memif_main_t *mm = &memif_main;
  memif_if_t *mif;
  vnet_main_t *vnm = vnet_get_main ();

  hw = vnet_get_sup_hw_interface_api_visible_or_null (vnm, sw_if_index);
  if (hw == NULL || memif_device_class.index != hw->dev_class_index)
    return clib_error_return (0, "not a memif interface");

  mif = pool_elt_at_index (mm->interfaces, hw->dev_instance);
  memif_delete_if (vm, mif);

  return 0;
}

VLIB_CLI_COMMAND (memif_delete_command, static) = {
  .path = "delete interface memif",
  .short_help = "Delete a memif interface",
  .args = CLI_ARGS (CLI_VALUE ("interface", cli_type_sw_interface, .alt_keyword = "sw_if_index")),
  .handler = memif_delete_command_fn,
};

static u8 *
format_memif_if_flags (u8 * s, va_list * args)
{
  u32 flags = va_arg (*args, u32);
#define _(a,b,c) if ( flags & (1 << a)) s = format (s, " %s", c);
  foreach_memif_if_flag
#undef _
    return s;
}

static u8 *
format_memif_if_mode (u8 * s, va_list * args)
{
  memif_if_t *mif = va_arg (*args, memif_if_t *);
  if (mif->mode == MEMIF_INTERFACE_MODE_ETHERNET)
    return format (s, "ethernet");
  if (mif->mode == MEMIF_INTERFACE_MODE_IP)
    return format (s, "ip");
  if (mif->mode == MEMIF_INTERFACE_MODE_PUNT_INJECT)
    return format (s, "punt-inject");
  return format (s, "unknown mode (%u)", mif->mode);;
}

static u8 *
format_memif_queue (u8 * s, va_list * args)
{
  memif_queue_t *mq = va_arg (*args, memif_queue_t *);
  uword i = va_arg (*args, uword);
  u32 indent = format_get_indent (s);

  s = format (s, "%U%s ring %u:\n",
	      format_white_space, indent,
	      (mq->type == MEMIF_RING_S2M) ?
	      "slave-to-master" : "master-to-slave", i);
  s = format (s, "%Uregion %u offset %u ring-size %u int-fd %d\n",
	      format_white_space, indent + 4,
	      mq->region, mq->offset, (1 << mq->log2_ring_size), mq->int_fd);

  if (mq->ring)
    s = format (s, "%Uhead %u tail %u flags 0x%04x interrupts %u\n",
		format_white_space, indent + 4,
		mq->ring->head, mq->ring->tail, mq->ring->flags,
		mq->int_count);

  return s;
}

static u8 *
format_memif_descriptor (u8 * s, va_list * args)
{
  memif_if_t *mif = va_arg (*args, memif_if_t *);
  memif_queue_t *mq = va_arg (*args, memif_queue_t *);
  u32 indent = format_get_indent (s);
  memif_ring_t *ring;
  u16 ring_size;
  u16 slot;

  ring_size = 1 << mq->log2_ring_size;
  ring = mq->ring;
  if (ring)
    {
      s = format (s, "%Udescriptor table:\n", format_white_space, indent);
      s = format (s,
		  "%Uid    flags region len         address         offset    "
		  "    user address\n",
		  format_white_space, indent);
      s = format (s,
		  "%U===== ===== ====== ======== ================== "
		  "========== ==================\n",
		  format_white_space, indent);
      for (slot = 0; slot < ring_size; slot++)
	{
	  s = format (s, "%U%-5d %-5d %-6d %-7d  0x%016lx %-10d 0x%016lx\n",
		      format_white_space, indent, slot, ring->desc[slot].flags,
		      ring->desc[slot].region, ring->desc[slot].length,
		      mif->regions[ring->desc[slot].region].shm,
		      ring->desc[slot].offset,
		      memif_get_buffer (mif, ring, slot));
	}
      s = format (s, "\n");
    }

  return s;
}

static clib_error_t *
memif_show_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  memif_main_t *mm = &memif_main;
  memif_if_t *mif;
  vnet_main_t *vnm = vnet_get_main ();
  memif_region_t *mr;
  memif_queue_t *mq;
  uword i;
  int show_descr = cli_flag (ctx, "descriptors");
  clib_error_t *error = 0;
  u32 hw_if_index, *hw_if_indices = 0;
  u32 sock_id;
  u32 msf_idx;
  cli_value_t *v;
  u8 *s = 0;

  cli_foreach (v, ctx, "interface")
  {
    if (vnet_get_hw_interface (vnm, v->index)->dev_class_index != memif_device_class.index)
      {
	error = clib_error_return (0, "not a memif interface");
	goto done;
      }
    vec_add1 (hw_if_indices, v->index);
  }

  vlib_cli_output (vm, "sockets\n");
  vlib_cli_output (vm, "  %-3s %-11s %s\n", "id", "listener", "filename");

  hash_foreach (sock_id, msf_idx, mm->socket_file_index_by_sock_id,
    ({
      memif_socket_file_t *msf;
      u8 *filename;

      msf = pool_elt_at_index(mm->socket_files, msf_idx);
      filename = msf->filename;
      if (msf->is_listener)
        s = format (s, "yes (%u)", msf->ref_cnt);
      else
        s = format (s, "no");

      vlib_cli_output(vm, "  %-3u %-11v %s\n", sock_id, s, filename);
      vec_reset_length (s);
    }));
  vec_free (s);

  vlib_cli_output (vm, "\n");

  if (vec_len (hw_if_indices) == 0)
    {
      pool_foreach (mif, mm->interfaces)
	  vec_add1 (hw_if_indices, mif->hw_if_index);
    }

  for (hw_if_index = 0; hw_if_index < vec_len (hw_if_indices); hw_if_index++)
    {
      vnet_hw_interface_t *hi =
	vnet_get_hw_interface (vnm, hw_if_indices[hw_if_index]);
      mif = pool_elt_at_index (mm->interfaces, hi->dev_instance);
      memif_socket_file_t *msf = vec_elt_at_index (mm->socket_files,
						   mif->socket_file_index);
      vlib_cli_output (vm, "interface %U", format_vnet_sw_if_index_name,
		       vnm, mif->sw_if_index);
      if (mif->remote_name)
	vlib_cli_output (vm, "  remote-name \"%s\"", mif->remote_name);
      if (mif->remote_if_name)
	vlib_cli_output (vm, "  remote-interface \"%s\"",
			 mif->remote_if_name);
      vlib_cli_output (vm, "  socket-id %u id %u mode %U", msf->socket_id,
		       mif->id, format_memif_if_mode, mif);
      vlib_cli_output (vm, "  flags%U", format_memif_if_flags, mif->flags);
      vlib_cli_output (vm, "  listener-fd %d conn-fd %d",
		       msf->sock ? msf->sock->fd : 0,
		       mif->sock ? mif->sock->fd : 0);
      vlib_cli_output (vm, "  num-s2m-rings %u num-m2s-rings %u "
		       "buffer-size %u num-regions %u",
		       mif->run.num_s2m_rings, mif->run.num_m2s_rings,
		       mif->run.buffer_size, vec_len (mif->regions));

      if (mif->local_disc_string)
	vlib_cli_output (vm, "  local-disc-reason \"%s\"",
			 mif->local_disc_string);
      if (mif->remote_disc_string)
	vlib_cli_output (vm, "  remote-disc-reason \"%s\"",
			 mif->remote_disc_string);

      vec_foreach_index (i, mif->regions)
	{
	  mr = vec_elt_at_index (mif->regions, i);
	  vlib_cli_output (vm, "  region %u size %u fd %d", i,
			   mr->region_size, mr->fd);
	}
      vec_foreach_index (i, mif->tx_queues)
	{
	  mq = vec_elt_at_index (mif->tx_queues, i);
	  vlib_cli_output (vm, "  %U", format_memif_queue, mq, i);
	  if (show_descr)
	    vlib_cli_output (vm, "  %U", format_memif_descriptor, mif, mq);
	}
      vec_foreach_index (i, mif->rx_queues)
	{
	  mq = vec_elt_at_index (mif->rx_queues, i);
	  vlib_cli_output (vm, "  %U", format_memif_queue, mq, i);
	  if (show_descr)
	    vlib_cli_output (vm, "  %U", format_memif_descriptor, mif, mq);
	}
    }
done:
  vec_free (hw_if_indices);
  return error;
}

VLIB_CLI_COMMAND (memif_show_command, static) = {
  .path = "show memif",
  .short_help = "Show memif sockets and interfaces",
  .args = CLI_ARGS (CLI_VALUE ("interface", cli_type_hw_interface,
			       .flags = CLI_F_OPTIONAL | CLI_F_REPEAT),
		    CLI_FLAG ("descriptors", .help = "show the descriptor tables")),
  .handler = memif_show_command_fn,
};

clib_error_t *
memif_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (memif_cli_init);
