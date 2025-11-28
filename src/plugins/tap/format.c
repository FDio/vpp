/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018-2025 Cisco and/or its affiliates.
 */
#include <vlib/vlib.h>
#include <tap/internal.h>

u8 *
format_tx_node_name (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  tap_virtio_main_t *mm = &tap_virtio_main;
  tap_virtio_if_t *vif = pool_elt_at_index (mm->interfaces, dev_instance);

  if (vif->initial_if_name)
    return format (s, "%s", vif->initial_if_name);

  if (vif->type == VIRTIO_IF_TYPE_TAP)
    s = format (s, "tap%u", vif->id);
  else if (vif->type == VIRTIO_IF_TYPE_TUN)
    s = format (s, "tun%u", vif->id);
  else
    s = format (s, "tap-virtio-%lu", vif->dev_instance);

  return s;
}

u8 *
format_tap_virtio_log_name (u8 *s, va_list *args)
{
  tap_virtio_if_t *vif = va_arg (*args, tap_virtio_if_t *);

  if (vif->type == VIRTIO_IF_TYPE_TAP)
    s = format (s, "tap%u", vif->id);
  else if (vif->type == VIRTIO_IF_TYPE_TUN)
    s = format (s, "tun%u", vif->id);
  else
    s = format (s, "tap-virtio-%lu", vif->dev_instance);

  return s;
}

u8 *
format_tap_virtio_tx_trace (u8 *s, va_list *va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  tap_virtio_tx_trace_t *t = va_arg (*va, tap_virtio_tx_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "%Ubuffer 0x%x: %U\n", format_white_space, indent,
	      t->buffer_index, format_vnet_buffer_no_chain, &t->buffer);
  s = format (s, "%U%U\n", format_white_space, indent,
	      format_generic_header_offset, &t->gho);
  s = format (s, "%U%U", format_white_space, indent,
	      format_ethernet_header_with_length, t->buffer.pre_data,
	      sizeof (t->buffer.pre_data));
  return s;
}

u8 *
format_tap_virtio_device (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  int verbose = va_arg (*args, int);
  u32 indent = format_get_indent (s);
  tap_virtio_main_t *vim = &tap_virtio_main;
  tap_virtio_if_t *vif = vec_elt_at_index (vim->interfaces, dev_instance);
  vnet_virtio_vring_t *vring = 0;

  s = format (s, "VIRTIO interface");
  if (verbose)
    {
      s = format (s, "\n%U instance %u", format_white_space, indent + 2,
		  dev_instance);
      s = format (s, "\n%U RX QUEUE : Total Packets", format_white_space,
		  indent + 4);
      vec_foreach (vring, vif->rxq_vrings)
	{
	  s = format (s, "\n%U %8u : %llu", format_white_space, indent + 4,
		      RX_QUEUE_ACCESS (vring->queue_id), vring->total_packets);
	}
      s = format (s, "\n%U TX QUEUE : Total Packets", format_white_space,
		  indent + 4);
      vec_foreach (vring, vif->txq_vrings)
	{
	  s = format (s, "\n%U %8u : %llu", format_white_space, indent + 4,
		      TX_QUEUE_ACCESS (vring->queue_id), vring->total_packets);
	}
    }

  return s;
}

u8 *
format_tap_virtio_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  tap_virtio_input_trace_t *t = va_arg (*args, tap_virtio_input_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "virtio: hw_if_index %d next-index %d vring %u len %u",
	      t->hw_if_index, t->next_index, t->ring, t->len);
  s = format (s,
	      "\n%Uhdr: flags 0x%02x gso_type 0x%02x hdr_len %u "
	      "gso_size %u csum_start %u csum_offset %u num_buffers %u",
	      format_white_space, indent + 2, t->hdr.flags, t->hdr.gso_type,
	      t->hdr.hdr_len, t->hdr.gso_size, t->hdr.csum_start,
	      t->hdr.csum_offset, t->hdr.num_buffers);
  return s;
}
