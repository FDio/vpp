/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/feature/feature.h>
#include <ip_validate/ip_validate.h>

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u32 src_addr;
  u32 dst_addr;
} ip4_validate_trace_t;

static u8 *
format_ip4_validate_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip4_validate_trace_t *t = va_arg (*args, ip4_validate_trace_t *);

  s = format (s, "IP4-VALIDATE: sw_if_index %d next %d src %U dst %U", t->sw_if_index,
	      t->next_index, format_ip4_address, &t->src_addr, format_ip4_address, &t->dst_addr);
  return s;
}

#define foreach_ip4_validate_error                                                                 \
  _ (VALID, "valid packets")                                                                       \
  _ (SRC_LOOPBACK, "source address is loopback")                                                   \
  _ (SRC_MULTICAST, "source address is multicast")                                                 \
  _ (SRC_CLASS_E, "source address is class E")                                                     \
  _ (SRC_UNSPECIFIED, "source address is unspecified")                                             \
  _ (SRC_LINK_LOCAL, "source address is link-local")                                               \
  _ (DST_LOOPBACK, "destination address is loopback")                                              \
  _ (DST_LINK_LOCAL, "destination address is link-local")                                          \
  _ (L2_MCAST_BCAST, "unicast IP with multicast~broadcast L2 destination")

typedef enum
{
#define _(sym, str) IP4_VALIDATE_ERROR_##sym,
  foreach_ip4_validate_error
#undef _
    IP4_VALIDATE_N_ERROR,
} ip4_validate_error_t;

static char *ip4_validate_error_strings[] = {
#define _(sym, string) string,
  foreach_ip4_validate_error
#undef _
};

typedef enum
{
  IP4_VALIDATE_NEXT_DROP,
  IP4_VALIDATE_NEXT_FEATURE,
  IP4_VALIDATE_N_NEXT,
} ip4_validate_next_t;

/*
 * Validate a single IPv4 packet. Returns the error code and sets *next
 * to the appropriate next-node index (feature-arc next on success,
 * IP4_VALIDATE_NEXT_DROP on failure).
 */
static_always_inline ip4_validate_error_t
ip4_validate_x1 (vlib_buffer_t *b, u16 *next)
{
  ip4_header_t *ip = vlib_buffer_get_current (b);
  u32 feat_next;
  u32 src, dst;

  vnet_feature_next (&feat_next, b);

  /*
   * L2 check: unicast IP but multicast/broadcast ETH dst.
   * Use ethernet_buffer_get_header() which correctly handles VLAN-tagged
   * frames via l2_hdr_offset set by ethernet-input.
   */
  {
    ethernet_header_t *eth = ethernet_buffer_get_header (b);
    if (PREDICT_FALSE (eth->dst_address[0] & 0x01))
      {
	*next = IP4_VALIDATE_NEXT_DROP;
	return IP4_VALIDATE_ERROR_L2_MCAST_BCAST;
      }
  }

  src = clib_net_to_host_u32 (ip->src_address.as_u32);
  dst = clib_net_to_host_u32 (ip->dst_address.as_u32);

  /* SRC checks */

  /* Drop packets with source in 127.0.0.0/8 (loopback range) */
  if (PREDICT_FALSE ((src >> 24) == 127))
    {
      *next = IP4_VALIDATE_NEXT_DROP;
      return IP4_VALIDATE_ERROR_SRC_LOOPBACK;
    }
  /* Drop packets with source in 224.0.0.0/4 (multicast range) */
  if (PREDICT_FALSE ((src >> 28) == 0xE))
    {
      *next = IP4_VALIDATE_NEXT_DROP;
      return IP4_VALIDATE_ERROR_SRC_MULTICAST;
    }
  /* Drop packets with source in 240.0.0.0/4 (class E reserved range) */
  if (PREDICT_FALSE ((src >> 28) == 0xF))
    {
      *next = IP4_VALIDATE_NEXT_DROP;
      return IP4_VALIDATE_ERROR_SRC_CLASS_E;
    }
  /* Drop packets with source 0.0.0.0 (unspecified address) */
  if (PREDICT_FALSE (src == 0))
    {
      *next = IP4_VALIDATE_NEXT_DROP;
      return IP4_VALIDATE_ERROR_SRC_UNSPECIFIED;
    }
  /* Drop packets with source in 169.254.0.0/16 (link-local range) */
  if (PREDICT_FALSE ((src >> 16) == 0xA9FE))
    {
      *next = IP4_VALIDATE_NEXT_DROP;
      return IP4_VALIDATE_ERROR_SRC_LINK_LOCAL;
    }

  /* DST checks */

  /* Drop packets with destination in 127.0.0.0/8 (loopback range) */
  if (PREDICT_FALSE ((dst >> 24) == 127))
    {
      *next = IP4_VALIDATE_NEXT_DROP;
      return IP4_VALIDATE_ERROR_DST_LOOPBACK;
    }
  /* Drop packets with destination in 169.254.0.0/16 (link-local range) */
  if (PREDICT_FALSE ((dst >> 16) == 0xA9FE))
    {
      *next = IP4_VALIDATE_NEXT_DROP;
      return IP4_VALIDATE_ERROR_DST_LINK_LOCAL;
    }

  /* Valid packet - continue on feature arc */
  *next = (u16) feat_next;
  return IP4_VALIDATE_ERROR_VALID;
}

static_always_inline void
ip4_validate_trace_one (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 next)
{
  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
    {
      ip4_header_t *ip = vlib_buffer_get_current (b);
      ip4_validate_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
      t->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
      t->next_index = next;
      t->src_addr = ip->src_address.as_u32;
      t->dst_addr = ip->dst_address.as_u32;
    }
}

VLIB_NODE_FN (ip4_validate_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 error_counts[IP4_VALIDATE_N_ERROR] = { 0 };

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

#if (CLIB_N_PREFETCHES >= 8)
  while (n_left_from >= 4)
    {
      if (n_left_from >= 12)
	{
	  vlib_prefetch_buffer_header (b[8], LOAD);
	  vlib_prefetch_buffer_header (b[9], LOAD);
	  vlib_prefetch_buffer_header (b[10], LOAD);
	  vlib_prefetch_buffer_header (b[11], LOAD);

	  vlib_prefetch_buffer_data (b[4], LOAD);
	  vlib_prefetch_buffer_data (b[5], LOAD);
	  vlib_prefetch_buffer_data (b[6], LOAD);
	  vlib_prefetch_buffer_data (b[7], LOAD);
	}

      error_counts[ip4_validate_x1 (b[0], &next[0])]++;
      error_counts[ip4_validate_x1 (b[1], &next[1])]++;
      error_counts[ip4_validate_x1 (b[2], &next[2])]++;
      error_counts[ip4_validate_x1 (b[3], &next[3])]++;

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	{
	  ip4_validate_trace_one (vm, node, b[0], next[0]);
	  ip4_validate_trace_one (vm, node, b[1], next[1]);
	  ip4_validate_trace_one (vm, node, b[2], next[2]);
	  ip4_validate_trace_one (vm, node, b[3], next[3]);
	}

      b += 4;
      next += 4;
      n_left_from -= 4;
    }
#endif

  while (n_left_from)
    {
      error_counts[ip4_validate_x1 (b[0], &next[0])]++;

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  ip4_header_t *ip = vlib_buffer_get_current (b[0]);
	  ip4_validate_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	  t->next_index = next[0];
	  t->src_addr = ip->src_address.as_u32;
	  t->dst_addr = ip->dst_address.as_u32;
	}

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  for (int i = 0; i < IP4_VALIDATE_N_ERROR; i++)
    {
      if (error_counts[i])
	vlib_node_increment_counter (vm, ip4_validate_node.index, i, error_counts[i]);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ip4_validate_node) = {
  .name = "ip4-validate",
  .vector_size = sizeof (u32),
  .format_trace = format_ip4_validate_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (ip4_validate_error_strings),
  .error_strings = ip4_validate_error_strings,
  .n_next_nodes = IP4_VALIDATE_N_NEXT,
  .next_nodes = {
    [IP4_VALIDATE_NEXT_DROP] = "error-drop",
    [IP4_VALIDATE_NEXT_FEATURE] = "ip4-lookup",
  },
};

VNET_FEATURE_INIT (ip4_validate_feat, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "ip4-validate",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};
