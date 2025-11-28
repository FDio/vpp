/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018-2025 Cisco and/or its affiliates.
 */
#include <vlib/vlib.h>
#include <tap/internal.h>
#include <tap/if_tun.h>

u8 *
format_tx_node_name (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  tap_main_t *tm = &tap_main;
  tap_if_t *tif = pool_elt_at_index (tm->interfaces, dev_instance);

  if (tif->name)
    return format (s, "%s", tif->name);

  s =
    tif->is_tun ? format (s, "tun%u", tif->id) : format (s, "tap%u", tif->id);

  return s;
}

u8 *
format_tap_log_name (u8 *s, va_list *args)
{
  tap_if_t *tif = va_arg (*args, tap_if_t *);

  s =
    tif->is_tun ? format (s, "tun%u", tif->id) : format (s, "tap%u", tif->id);

  return s;
}

u8 *
format_tap_tx_trace (u8 *s, va_list *va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  tap_tx_trace_t *t = va_arg (*va, tap_tx_trace_t *);
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
format_tap_device (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  int verbose = va_arg (*args, int);
  u32 indent = format_get_indent (s);
  tap_main_t *tm = &tap_main;
  tap_if_t *tif = vec_elt_at_index (tm->interfaces, dev_instance);
  tap_rxq_t *rxq = 0;
  tap_txq_t *txq = 0;

  s = format (s, "VIRTIO interface");
  if (verbose)
    {
      s = format (s, "\n%U instance %u", format_white_space, indent + 2,
		  dev_instance);
      s = format (s, "\n%U RX QUEUE : Total Packets", format_white_space,
		  indent + 4);
      vec_foreach (rxq, tif->rx_queues)
	{
	  s = format (s, "\n%U %8u : %llu", format_white_space, indent + 4,
		      rxq->queue_id, rxq->total_packets);
	}
      s = format (s, "\n%U TX QUEUE : Total Packets", format_white_space,
		  indent + 4);
      vec_foreach (txq, tif->tx_queues)
	{
	  s = format (s, "\n%U %8u : %llu", format_white_space, indent + 4,
		      txq->queue_id, txq->total_packets);
	}
    }

  return s;
}

u8 *
format_virtio_features (u8 *s, va_list *args)
{
  u64 feats = va_arg (*args, u64);
  u32 i, first = 1;
  u32 indent = format_get_indent (s);
  const char *names[64] = {
#define _(n, bit) [bit] = "VIRTIO_NET_F_" #n,
    foreach_virtio_net_features
#undef _
#define _(n, bit) [bit] = "VIRTIO_F_" #n,
      foreach_virtio_config_features
#undef _
#define _(n, bit) [bit] = "VIRTIO_RING_F_" #n,
	foreach_virtio_ring_features
#undef _
#define _(n, bit) [bit] = "VHOST_F_" #n,
	  foreach_vhost_features
#undef _
  };

  foreach_set_bit_index (i, feats)
    {
      if (first)
	first = 0;
      else
	s = format (s, "\n%U", format_white_space, indent);

      if (i >= ARRAY_LEN (names) || names[i] == 0)
	s = format (s, "unknown(%u)", i);
      else
	s = format (s, "%s(%u)", names[i], i);
    }

  return s;
}

u8 *
format_if_tun_features (u8 *s, va_list *args)
{
  u32 feats = va_arg (*args, u32);
  u32 i, first = 0;
  const char *names[] = {
#define _(bit, n) [bit] = #n,
    foreach_tun_feature
#undef _
  };

  foreach_set_bit_index (i, feats)
    {
      if (i >= ARRAY_LEN (names) || names[i] == 0)
	s = format (s, "%sunknown(%u)", first++ ? " " : "", i);
      else
	s = format (s, "%s%s(%u)", first++ ? " " : "", names[i], i);
    }

  return s;
}

u8 *
format_if_tun_offloads (u8 *s, va_list *args)
{
  u32 feats = va_arg (*args, u32);
  u32 i, first = 0;
  const char *names[] = {
#define _(bit, n) [bit] = "TUN_F_" #n,
    foreach_tun_offload
#undef _
  };

  foreach_set_bit_index (i, feats)
    {
      if (i >= ARRAY_LEN (names) || names[i] == 0)
	s = format (s, "%sunknown(%u)", first++ ? "" : " ", i);
      else
	s = format (s, "%s%s(%u)", first++ ? "" : " ", names[i], i);
    }

  return s;
}

u8 *
format_tap_input_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm __clib_unused = va_arg (*args, vlib_main_t *);
  vlib_node_t *node __clib_unused = va_arg (*args, vlib_node_t *);
  tap_rx_trace_t *t = va_arg (*args, tap_rx_trace_t *);
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
