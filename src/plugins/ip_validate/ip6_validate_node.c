/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/feature/feature.h>
#include <ip_validate/ip_validate.h>

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  ip6_address_t src_addr;
  ip6_address_t dst_addr;
} ip6_validate_trace_t;

static u8 *
format_ip6_validate_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_validate_trace_t *t = va_arg (*args, ip6_validate_trace_t *);

  s = format (s, "IP6-VALIDATE: sw_if_index %d next %d src %U dst %U", t->sw_if_index,
	      t->next_index, format_ip6_address, &t->src_addr, format_ip6_address, &t->dst_addr);
  return s;
}

#define foreach_ip6_validate_error                                                                 \
  _ (VALID, "valid packets")                                                                       \
  _ (SRC_MULTICAST, "source address is multicast")                                                 \
  _ (SRC_UNSPECIFIED, "source address is unspecified")                                             \
  _ (SRC_LOOPBACK, "source address is loopback")                                                   \
  _ (DST_UNSPECIFIED, "destination address is unspecified")                                        \
  _ (DST_LOOPBACK, "destination address is loopback")                                              \
  _ (L2_MCAST_BCAST, "unicast IP with multicast~broadcast L2 destination")

typedef enum
{
#define _(sym, str) IP6_VALIDATE_ERROR_##sym,
  foreach_ip6_validate_error
#undef _
    IP6_VALIDATE_N_ERROR,
} ip6_validate_error_t;

static char *ip6_validate_error_strings[] = {
#define _(sym, string) string,
  foreach_ip6_validate_error
#undef _
};

typedef enum
{
  IP6_VALIDATE_NEXT_DROP,
  IP6_VALIDATE_NEXT_FEATURE,
  IP6_VALIDATE_N_NEXT,
} ip6_validate_next_t;

static_always_inline int
ip6_validate_address_is_zero (const ip6_address_t *a)
{
  return (a->as_u64[0] == 0 && a->as_u64[1] == 0);
}

static_always_inline int
ip6_validate_address_is_loopback (const ip6_address_t *a)
{
  return (a->as_u64[0] == 0 && a->as_u64[1] == clib_host_to_net_u64 (1));
}

/*
 * Validate a single IPv6 packet. Returns the error code and sets *next
 * to the appropriate next-node index (feature-arc next on success,
 * IP6_VALIDATE_NEXT_DROP on failure).
 */
static_always_inline ip6_validate_error_t
ip6_validate_x1 (vlib_buffer_t *b, u16 *next)
{
  ip6_header_t *ip = vlib_buffer_get_current (b);
  u32 feat_next;

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
	*next = IP6_VALIDATE_NEXT_DROP;
	return IP6_VALIDATE_ERROR_L2_MCAST_BCAST;
      }
  }

  /* SRC checks */

  /* Drop packets with source in ff00::/8 (multicast range) */
  if (PREDICT_FALSE (ip->src_address.as_u8[0] == 0xFF))
    {
      *next = IP6_VALIDATE_NEXT_DROP;
      return IP6_VALIDATE_ERROR_SRC_MULTICAST;
    }
  /* Drop packets with source :: (unspecified address) */
  if (PREDICT_FALSE (ip6_validate_address_is_zero (&ip->src_address)))
    {
      *next = IP6_VALIDATE_NEXT_DROP;
      return IP6_VALIDATE_ERROR_SRC_UNSPECIFIED;
    }
  /* Drop packets with source ::1 (loopback address) */
  if (PREDICT_FALSE (ip6_validate_address_is_loopback (&ip->src_address)))
    {
      *next = IP6_VALIDATE_NEXT_DROP;
      return IP6_VALIDATE_ERROR_SRC_LOOPBACK;
    }

  /* DST checks */

  /* Drop packets with destination :: (unspecified address) */
  if (PREDICT_FALSE (ip6_validate_address_is_zero (&ip->dst_address)))
    {
      *next = IP6_VALIDATE_NEXT_DROP;
      return IP6_VALIDATE_ERROR_DST_UNSPECIFIED;
    }
  /* Drop packets with destination ::1 (loopback address) */
  if (PREDICT_FALSE (ip6_validate_address_is_loopback (&ip->dst_address)))
    {
      *next = IP6_VALIDATE_NEXT_DROP;
      return IP6_VALIDATE_ERROR_DST_LOOPBACK;
    }

  /* Valid packet - continue on feature arc */
  *next = (u16) feat_next;
  return IP6_VALIDATE_ERROR_VALID;
}

static_always_inline void
ip6_validate_trace_one (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b, u16 next)
{
  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
    {
      ip6_header_t *ip = vlib_buffer_get_current (b);
      ip6_validate_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
      t->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
      t->next_index = next;
      clib_memcpy_fast (&t->src_addr, &ip->src_address, sizeof (ip6_address_t));
      clib_memcpy_fast (&t->dst_addr, &ip->dst_address, sizeof (ip6_address_t));
    }
}

VLIB_NODE_FN (ip6_validate_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 error_counts[IP6_VALIDATE_N_ERROR] = { 0 };

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

      error_counts[ip6_validate_x1 (b[0], &next[0])]++;
      error_counts[ip6_validate_x1 (b[1], &next[1])]++;
      error_counts[ip6_validate_x1 (b[2], &next[2])]++;
      error_counts[ip6_validate_x1 (b[3], &next[3])]++;

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	{
	  ip6_validate_trace_one (vm, node, b[0], next[0]);
	  ip6_validate_trace_one (vm, node, b[1], next[1]);
	  ip6_validate_trace_one (vm, node, b[2], next[2]);
	  ip6_validate_trace_one (vm, node, b[3], next[3]);
	}

      b += 4;
      next += 4;
      n_left_from -= 4;
    }
#endif

  while (n_left_from)
    {
      error_counts[ip6_validate_x1 (b[0], &next[0])]++;

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  ip6_header_t *ip = vlib_buffer_get_current (b[0]);
	  ip6_validate_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	  t->next_index = next[0];
	  clib_memcpy_fast (&t->src_addr, &ip->src_address, sizeof (ip6_address_t));
	  clib_memcpy_fast (&t->dst_addr, &ip->dst_address, sizeof (ip6_address_t));
	}

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  for (int i = 0; i < IP6_VALIDATE_N_ERROR; i++)
    {
      if (error_counts[i])
	vlib_node_increment_counter (vm, ip6_validate_node.index, i, error_counts[i]);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ip6_validate_node) = {
  .name = "ip6-validate",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_validate_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (ip6_validate_error_strings),
  .error_strings = ip6_validate_error_strings,
  .n_next_nodes = IP6_VALIDATE_N_NEXT,
  .next_nodes = {
    [IP6_VALIDATE_NEXT_DROP] = "error-drop",
    [IP6_VALIDATE_NEXT_FEATURE] = "ip6-lookup",
  },
};

VNET_FEATURE_INIT (ip6_validate_feat, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "ip6-validate",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};
