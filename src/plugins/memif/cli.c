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

#include <memif/memif.h>
#include <memif/private.h>

static clib_error_t *
memif_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  int r;
  u32 ring_size = MEMIF_DEFAULT_RING_SIZE;
  memif_create_if_args_t args = { 0 };
  args.buffer_size = MEMIF_DEFAULT_BUFFER_SIZE;
  u32 rx_queues = MEMIF_DEFAULT_RX_QUEUES;
  u32 tx_queues = MEMIF_DEFAULT_TX_QUEUES;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "id %u", &args.id))
	;
      else if (unformat (line_input, "socket %s", &args.socket_filename))
	;
      else if (unformat (line_input, "secret %s", &args.secret))
	;
      else if (unformat (line_input, "ring-size %u", &ring_size))
	;
      else if (unformat (line_input, "rx-queues %u", &rx_queues))
	;
      else if (unformat (line_input, "tx-queues %u", &tx_queues))
	;
      else if (unformat (line_input, "buffer-size %u", &args.buffer_size))
	;
      else if (unformat (line_input, "master"))
	args.is_master = 1;
      else if (unformat (line_input, "slave"))
	args.is_master = 0;
      else if (unformat (line_input, "mode ip"))
	args.mode = MEMIF_INTERFACE_MODE_IP;
      else if (unformat (line_input, "hw-addr %U",
			 unformat_ethernet_address, args.hw_addr))
	args.hw_addr_set = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (!is_pow2 (ring_size))
    return clib_error_return (0, "ring size must be power of 2");

  args.log2_ring_size = min_log2 (ring_size);

  if (rx_queues > 255 || rx_queues < 1)
    return clib_error_return (0, "rx queue must be between 1 - 255");
  if (tx_queues > 255 || tx_queues < 1)
    return clib_error_return (0, "tx queue must be between 1 - 255");

  args.rx_queues = rx_queues;
  args.tx_queues = tx_queues;

  r = memif_create_if (vm, &args);

  vec_free (args.socket_filename);
  vec_free (args.secret);

  if (r <= VNET_API_ERROR_SYSCALL_ERROR_1
      && r >= VNET_API_ERROR_SYSCALL_ERROR_10)
    return clib_error_return (0, "%s (errno %d)", strerror (errno), errno);

  if (r == VNET_API_ERROR_INVALID_INTERFACE)
    return clib_error_return (0, "Invalid interface name");

  if (r == VNET_API_ERROR_SUBIF_ALREADY_EXISTS)
    return clib_error_return (0, "Interface with same id already exists");

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (memif_create_command, static) = {
  .path = "create memif",
  .short_help = "create memif [id <id>] [socket <path>] "
                "[ring-size <size>] [buffer-size <size>] [hw-addr <mac-address>] "
		"<master|slave> [rx-queues <number>] [tx-queues <number>] "
		"[mode ip] [secret <string>]",
  .function = memif_create_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
memif_delete_command_fn (vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hw;
  memif_main_t *mm = &memif_main;
  memif_if_t *mif;
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
  if (hw == NULL || memif_device_class.index != hw->dev_class_index)
    return clib_error_return (0, "not a memif interface");

  mif = pool_elt_at_index (mm->interfaces, hw->dev_instance);
  memif_delete_if (vm, mif);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (memif_delete_command, static) = {
  .path = "delete memif",
  .short_help = "delete memif {<interface> | sw_if_index <sw_idx>}",
  .function = memif_delete_command_fn,
};
/* *INDENT-ON* */

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
  memif_if_t *mif = va_arg (*args, memif_if_t *);
  memif_queue_t *mq = va_arg (*args, memif_queue_t *);
  uword i = va_arg (*args, uword);
  uword indent = format_get_indent (s);

  s = format (s, "%U%s ring %u:\n",
	      format_white_space, indent,
	      (mif->flags & MEMIF_IF_FLAG_IS_SLAVE) ?
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
  uword indent = format_get_indent (s);
  memif_ring_t *ring;
  u16 ring_size;
  u16 slot;

  ring_size = 1 << mq->log2_ring_size;
  ring = mq->ring;
  if (ring)
    {
      s = format (s, "%Udescriptor table:\n", format_white_space, indent);
      s =
	format (s,
		"%Uid    flags buf len desc len      address       offset    user address\n",
		format_white_space, indent);
      s =
	format (s,
		"%U===== ===== ======= ======== ================== ====== ==================\n",
		format_white_space, indent);
      for (slot = 0; slot < ring_size; slot++)
	{
	  s = format (s, "%U%-5d %-5d %-7d %-7d  0x%016lx %-6d 0x%016lx\n",
		      format_white_space, indent, slot,
		      ring->desc[slot].flags, ring->desc[slot].buffer_length,
		      ring->desc[slot].length,
		      mif->regions[ring->desc[slot].region].shm,
		      ring->desc[slot].offset, memif_get_buffer (mif, ring,
								 slot));
	}
      s = format (s, "\n");
    }

  return s;
}

static clib_error_t *
memif_show_command_fn (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  memif_main_t *mm = &memif_main;
  memif_if_t *mif;
  vnet_main_t *vnm = vnet_get_main ();
  memif_queue_t *mq;
  uword i;
  int show_descr = 0;
  clib_error_t *error = 0;
  u32 hw_if_index, *hw_if_indices = 0;

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
      pool_foreach (mif, mm->interfaces,
	  vec_add1 (hw_if_indices, mif->hw_if_index);
      );
      /* *INDENT-ON* */
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
      vlib_cli_output (vm, "  id %d mode %U file %s", mif->id,
		       format_memif_if_mode, mif, msf->filename);
      vlib_cli_output (vm, "  flags%U", format_memif_if_flags, mif->flags);
      vlib_cli_output (vm, "  listener-fd %d conn-fd %d",
		       msf->sock ? msf->sock->fd : 0,
		       mif->sock ? mif->sock->fd : 0);
      vlib_cli_output (vm,
		       "  num-s2m-rings %u num-m2s-rings %u buffer-size %u",
		       mif->run.num_s2m_rings, mif->run.num_m2s_rings,
		       mif->run.buffer_size);

      if (mif->local_disc_string)
	vlib_cli_output (vm, "  local-disc-reason \"%s\"",
			 mif->local_disc_string);
      if (mif->remote_disc_string)
	vlib_cli_output (vm, "  remote-disc-reason \"%s\"",
			 mif->remote_disc_string);

      vec_foreach_index (i, mif->tx_queues)
      {
	mq = vec_elt_at_index (mif->tx_queues, i);
	vlib_cli_output (vm, "  %U", format_memif_queue, mif, mq, i);
	if (show_descr)
	  vlib_cli_output (vm, "  %U", format_memif_descriptor, mif, mq);
      }
      vec_foreach_index (i, mif->rx_queues)
      {
	mq = vec_elt_at_index (mif->rx_queues, i);
	vlib_cli_output (vm, "  %U", format_memif_queue, mif, mq, i);
	if (show_descr)
	  vlib_cli_output (vm, "  %U", format_memif_descriptor, mif, mq);
      }
    }
done:
  vec_free (hw_if_indices);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (memif_show_command, static) = {
  .path = "show memif",
  .short_help = "show memif {<interface>] [descriptors]",
  .function = memif_show_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
memif_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (memif_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
