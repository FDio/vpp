/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ip/ip.h>
#include <vnet/udp/udp_packet.h>
#include <vppinfra/error.h>
#include <udp-echo/udp_echo.h>

vlib_node_registration_t udp_echo_node;
#define foreach_udp_echo_error                                                                     \
  _ (PROCESSED, "UDP echo packets processed")                                                      \
  _ (CLONE_FAIL, "UDP echo clone failures")

typedef enum
{
#define _(sym, str) UDP_ECHO_ERROR_##sym,
  foreach_udp_echo_error
#undef _
    UDP_ECHO_N_ERROR,
} udp_echo_error_t;

static char *udp_echo_error_strings[] = {
#define _(sym, string) string,
  foreach_udp_echo_error
#undef _
};

typedef enum
{
  UDP_ECHO_NEXT_IP4_LOOKUP,
  UDP_ECHO_N_NEXT,
} udp_echo_next_t;

VLIB_NODE_FN (udp_echo_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  udp_echo_main_t *uem = &udp_echo_main;
  u32 n_left_from = frame->n_vectors;
  u32 *from = vlib_frame_vector_args (frame);
  u8 n_clones = uem->n_clones;
  u8 linearize = uem->linearize;
  u8 regen_udp_cksum = uem->regen_udp_cksum;
  u8 regen_ip_cksum = uem->regen_ip_cksum;
  vnet_buffer_oflags_t cksum_oflags = 0;
  u32 n_clone_fail = 0;
  u32 n_to_next = frame->n_vectors;
  u32 *to_next = from;
  u32 node_index = udp_echo_node.index;
  u32 to[VLIB_FRAME_SIZE * 5];
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE * 5 + 4], **b;

  if (regen_ip_cksum)
    cksum_oflags |= VNET_BUFFER_OFFLOAD_F_IP_CKSUM;
  if (regen_udp_cksum)
    cksum_oflags |= VNET_BUFFER_OFFLOAD_F_UDP_CKSUM;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  for (u32 i = 0; i < 4; i++)
    bufs[n_left_from + i] = bufs[n_left_from - 1];
  b = bufs;

  for (; n_left_from >= 4; n_left_from -= 4, b += 4)
    {
      i16 ip_off0 = vnet_buffer (b[0])->l3_hdr_offset;
      i16 ip_off1 = vnet_buffer (b[1])->l3_hdr_offset;
      i16 ip_off2 = vnet_buffer (b[2])->l3_hdr_offset;
      i16 ip_off3 = vnet_buffer (b[3])->l3_hdr_offset;
      ip4_header_t *ip0 = (ip4_header_t *) (b[0]->data + ip_off0);
      ip4_header_t *ip1 = (ip4_header_t *) (b[1]->data + ip_off1);
      ip4_header_t *ip2 = (ip4_header_t *) (b[2]->data + ip_off2);
      ip4_header_t *ip3 = (ip4_header_t *) (b[3]->data + ip_off3);

      udp_header_t *udp0 = ip4_next_header (ip0);
      udp_header_t *udp1 = ip4_next_header (ip1);
      udp_header_t *udp2 = ip4_next_header (ip2);
      udp_header_t *udp3 = ip4_next_header (ip3);

      vlib_prefetch_buffer_header (b[4], LOAD);
      vlib_prefetch_buffer_header (b[5], LOAD);
      vlib_prefetch_buffer_header (b[6], LOAD);
      vlib_prefetch_buffer_header (b[7], LOAD);

      CLIB_PREFETCH (b[4]->data, CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH (b[5]->data, CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH (b[6]->data, CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH (b[7]->data, CLIB_CACHE_LINE_BYTES, LOAD);

      CLIB_SWAP (ip0->src_address.as_u32, ip0->dst_address.as_u32);
      CLIB_SWAP (udp0->src_port, udp0->dst_port);
      vlib_buffer_advance (b[0], ip_off0 - b[0]->current_data);

      CLIB_SWAP (ip1->src_address.as_u32, ip1->dst_address.as_u32);
      CLIB_SWAP (udp1->src_port, udp1->dst_port);
      vlib_buffer_advance (b[1], ip_off1 - b[1]->current_data);

      CLIB_SWAP (ip2->src_address.as_u32, ip2->dst_address.as_u32);
      CLIB_SWAP (udp2->src_port, udp2->dst_port);
      vlib_buffer_advance (b[2], ip_off2 - b[2]->current_data);

      CLIB_SWAP (ip3->src_address.as_u32, ip3->dst_address.as_u32);
      CLIB_SWAP (udp3->src_port, udp3->dst_port);
      vlib_buffer_advance (b[3], ip_off3 - b[3]->current_data);

      if (cksum_oflags)
	{
	  u32 cksum_bflags = VNET_BUFFER_F_L3_HDR_OFFSET_VALID | VNET_BUFFER_F_L4_HDR_OFFSET_VALID |
			     VNET_BUFFER_F_IS_IP4;

	  if (regen_ip_cksum)
	    ip0->checksum = ip1->checksum = ip2->checksum = ip3->checksum = 0;
	  if (regen_udp_cksum)
	    udp0->checksum = udp1->checksum = udp2->checksum = udp3->checksum = 0;

	  vnet_buffer (b[0])->l4_hdr_offset = (u8 *) udp0 - b[0]->data;
	  vnet_buffer (b[1])->l4_hdr_offset = (u8 *) udp1 - b[1]->data;
	  vnet_buffer (b[2])->l4_hdr_offset = (u8 *) udp2 - b[2]->data;
	  vnet_buffer (b[3])->l4_hdr_offset = (u8 *) udp3 - b[3]->data;
	  b[0]->flags |= cksum_bflags;
	  b[1]->flags |= cksum_bflags;
	  b[2]->flags |= cksum_bflags;
	  b[3]->flags |= cksum_bflags;
	  vnet_buffer_offload_flags_set (b[0], cksum_oflags);
	  vnet_buffer_offload_flags_set (b[1], cksum_oflags);
	  vnet_buffer_offload_flags_set (b[2], cksum_oflags);
	  vnet_buffer_offload_flags_set (b[3], cksum_oflags);
	}
    }

  for (; n_left_from > 0; n_left_from -= 1, b += 1)
    {
      i16 ip_off0 = vnet_buffer (b[0])->l3_hdr_offset;
      ip4_header_t *ip0 = (ip4_header_t *) (b[0]->data + ip_off0);
      udp_header_t *udp0 = ip4_next_header (ip0);

      CLIB_SWAP (ip0->src_address.as_u32, ip0->dst_address.as_u32);
      CLIB_SWAP (udp0->src_port, udp0->dst_port);
      if (cksum_oflags)
	{
	  if (regen_ip_cksum)
	    ip0->checksum = 0;
	  if (regen_udp_cksum)
	    udp0->checksum = 0;
	  vnet_buffer (b[0])->l4_hdr_offset = (u8 *) udp0 - b[0]->data;
	  b[0]->flags |= VNET_BUFFER_F_L3_HDR_OFFSET_VALID | VNET_BUFFER_F_L4_HDR_OFFSET_VALID |
			 VNET_BUFFER_F_IS_IP4;
	  vnet_buffer_offload_flags_set (b[0], cksum_oflags);
	}
      vlib_buffer_advance (b[0], ip_off0 - b[0]->current_data);
    }

  if (n_clones > 0)
    {
      u16 n_req = n_clones + 1;
      n_to_next = 0;

      for (u32 i = 0; i < frame->n_vectors; i++)
	{
	  vlib_buffer_t *sb = vlib_get_buffer (vm, from[i]);
	  u16 n_got;

	  n_got = vlib_buffer_clone_at_offset (vm, from[i], to + n_to_next, n_req,
					       clib_min (32, sb->current_length), 0);
	  if (PREDICT_FALSE (n_got != n_req))
	    {
	      if (n_got == 0)
		to[n_to_next++] = from[i];
	      else
		n_to_next += n_got;

	      n_clone_fail += n_req - n_got;
	    }
	  else
	    n_to_next += n_req;
	}

      to_next = to;
    }

  if (linearize)
    {
      vlib_get_buffers (vm, to_next, bufs, n_to_next);
      for (u32 i = 0; i < n_to_next; i++)
	vlib_buffer_chain_linearize (vm, bufs[i]);
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      if (!linearize)
	vlib_get_buffers (vm, to_next, bufs, n_to_next);
      for (u32 i = 0; i < n_to_next; i++)
	{
	  if (bufs[i]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      ip4_header_t *ip = vlib_buffer_get_current (bufs[i]);
	      udp_header_t *udp = ip4_next_header (ip);
	      udp_echo_trace_t *t = vlib_add_trace (vm, node, bufs[i], sizeof (*t));
	      t->src = ip->src_address;
	      t->dst = ip->dst_address;
	      t->src_port = udp->src_port;
	      t->dst_port = udp->dst_port;
	    }
	}
    }

  vlib_buffer_enqueue_to_single_next (vm, node, to_next, UDP_ECHO_NEXT_IP4_LOOKUP, n_to_next);
  vlib_node_increment_counter (vm, node_index, UDP_ECHO_ERROR_PROCESSED, n_to_next);
  vlib_node_increment_counter (vm, node_index, UDP_ECHO_ERROR_CLONE_FAIL, n_clone_fail);

  return n_to_next;
}

VLIB_REGISTER_NODE (udp_echo_node) = {
  .name = "udp-echo",
  .vector_size = sizeof (u32),
  .format_trace = format_udp_echo_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (udp_echo_error_strings),
  .error_strings = udp_echo_error_strings,

  .next_nodes = {
        [UDP_ECHO_NEXT_IP4_LOOKUP] = "ip4-lookup",
  },
  .n_next_nodes = UDP_ECHO_N_NEXT,
};
