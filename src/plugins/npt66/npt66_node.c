// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2023 Cisco Systems, Inc.

// This file contains the implementation of the NPT66 node.
// RFC6296: IPv6-to-IPv6 Network Prefix Translation (NPTv6)

#include <vnet/ip/ip.h>
#include <vnet/ip/ip6.h>
#include <vnet/ip/ip6_packet.h>

#include <npt66/npt66.h>

typedef struct
{
  u32 pool_index;
  ip6_address_t internal;
  ip6_address_t external;
} npt66_trace_t;

static inline u8 *
format_npt66_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  npt66_trace_t *t = va_arg (*args, npt66_trace_t *);

  if (t->pool_index != ~0)
    s = format (s, "npt66: index %d internal: %U external: %U\n",
		t->pool_index, format_ip6_address, &t->internal,
		format_ip6_address, &t->external);
  else
    s = format (s, "npt66: index %d (binding not found)\n", t->pool_index);
  return s;
}

/* NPT66 next-nodes */
typedef enum
{
  NPT66_NEXT_DROP,
  NPT66_N_NEXT
} npt66_next_t;

static ip6_address_t
ip6_prefix_copy (ip6_address_t dest, ip6_address_t src, int plen)
{
  int bytes_to_copy = plen / 8;
  int residual_bits = plen % 8;

  // Copy full bytes
  for (int i = 0; i < bytes_to_copy; i++)
    {
      dest.as_u8[i] = src.as_u8[i];
    }

  // Handle the residual bits, if any
  if (residual_bits)
    {
      uint8_t mask = 0xFF << (8 - residual_bits);
      dest.as_u8[bytes_to_copy] = (dest.as_u8[bytes_to_copy] & ~mask) |
				  (src.as_u8[bytes_to_copy] & mask);
    }
  return dest;
}
static int
ip6_prefix_cmp (ip6_address_t a, ip6_address_t b, int plen)
{
  int bytes_to_compare = plen / 8;
  int residual_bits = plen % 8;

  // Compare full bytes
  for (int i = 0; i < bytes_to_compare; i++)
    {
      if (a.as_u8[i] != b.as_u8[i])
	{
	  return 0; // prefixes are not identical
	}
    }

  // Compare the residual bits, if any
  if (residual_bits)
    {
      uint8_t mask = 0xFF << (8 - residual_bits);
      if ((a.as_u8[bytes_to_compare] & mask) !=
	  (b.as_u8[bytes_to_compare] & mask))
	{
	  return 0; // prefixes are not identical
	}
    }
  return 1; // prefixes are identical
}

static int
npt66_adjust_checksum (int plen, bool add, ip_csum_t delta,
		       ip6_address_t *address)
{
  if (plen <= 48)
    {
      // TODO: Check for 0xFFFF
      if (address->as_u16[3] == 0xffff)
	return -1;
      address->as_u16[3] = add ? ip_csum_add_even (address->as_u16[3], delta) :
				       ip_csum_sub_even (address->as_u16[3], delta);
    }
  else
    {
      /* For prefixes longer than 48 find a 16-bit word in the interface id */
      for (int i = 4; i < 8; i++)
	{
	  if (address->as_u16[i] == 0xffff)
	    continue;
	  address->as_u16[i] = add ?
				       ip_csum_add_even (address->as_u16[i], delta) :
				       ip_csum_sub_even (address->as_u16[i], delta);
	  break;
	}
    }
  return 0;
}

static int
npt66_translate (ip6_header_t *ip, npt66_binding_t *binding, int dir)
{
  int rv = 0;
  if (dir == VLIB_TX)
    {
      if (!ip6_prefix_cmp (ip->src_address, binding->internal,
			   binding->internal_plen))
	{
	  clib_warning (
	    "npt66_translate: src address is not internal (%U -> %U)",
	    format_ip6_address, &ip->src_address, format_ip6_address,
	    &ip->dst_address);
	  goto done;
	}
      ip->src_address = ip6_prefix_copy (ip->src_address, binding->external,
					 binding->external_plen);
      /* Checksum neutrality */
      rv = npt66_adjust_checksum (binding->internal_plen, false,
				  binding->delta, &ip->src_address);
    }
  else
    {
      if (!ip6_prefix_cmp (ip->dst_address, binding->external,
			   binding->external_plen))
	{
	  clib_warning (
	    "npt66_translate: dst address is not external (%U -> %U)",
	    format_ip6_address, &ip->src_address, format_ip6_address,
	    &ip->dst_address);
	  goto done;
	}
      ip->dst_address = ip6_prefix_copy (ip->dst_address, binding->internal,
					 binding->internal_plen);
      rv = npt66_adjust_checksum (binding->internal_plen, true, binding->delta,
				  &ip->dst_address);
    }
done:
  return rv;
}

/*
 * Lookup the packet tuple in the flow cache, given the lookup mask.
 * If a binding is found, rewrite the packet according to instructions,
 * otherwise follow configured default action (forward, punt or drop)
 */
// TODO: Make use of SVR configurable
static_always_inline uword
npt66_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		   vlib_frame_t *frame, int dir)
{
  npt66_main_t *nm = &npt66_main;
  u32 n_left_from, *from;
  u16 nexts[VLIB_FRAME_SIZE] = { 0 }, *next = nexts;
  u32 pool_indicies[VLIB_FRAME_SIZE], *pi = pool_indicies;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  ip6_header_t *ip;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, b, n_left_from);
  npt66_binding_t *binding;

  /* Stage 1: build vector of flow hash (based on lookup mask) */
  while (n_left_from > 0)
    {
      u32 sw_if_index = vnet_buffer (b[0])->sw_if_index[dir];
      u32 iph_offset =
	dir == VLIB_TX ? vnet_buffer (b[0])->ip.save_rewrite_length : 0;
      ip = (ip6_header_t *) (vlib_buffer_get_current (b[0]) + iph_offset);
      binding = npt66_interface_by_sw_if_index (sw_if_index);
      ASSERT (binding);
      *pi = binding - nm->bindings;

      /* By default pass packet to next node in the feature chain */
      vnet_feature_next_u16 (next, b[0]);

      int rv = npt66_translate (ip, binding, dir);
      if (rv < 0)
	{
	  clib_warning ("npt66_translate failed");
	  *next = NPT66_NEXT_DROP;
	}

      /*next: */
      next += 1;
      n_left_from -= 1;
      b += 1;
      pi += 1;
    }

  /* Packet trace */
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      u32 i;
      b = bufs;
      pi = pool_indicies;

      for (i = 0; i < frame->n_vectors; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      npt66_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	      if (*pi != ~0)
		{
		  if (!pool_is_free_index (nm->bindings, *pi))
		    {
		      npt66_binding_t *tr =
			pool_elt_at_index (nm->bindings, *pi);
		      t->internal = tr->internal;
		      t->external = tr->external;
		    }
		}
	      t->pool_index = *pi;

	      b += 1;
	      pi += 1;
	    }
	  else
	    break;
	}
    }
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (npt66_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return npt66_node_inline (vm, node, frame, VLIB_RX);
}
VLIB_NODE_FN (npt66_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return npt66_node_inline (vm, node, frame, VLIB_TX);
}

VLIB_REGISTER_NODE(npt66_input_node) = {
    .name = "npt66-input",
    .vector_size = sizeof(u32),
    .format_trace = format_npt66_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    // .n_errors = NPT66_N_ERROR,
    // .error_counters = npt66_error_counters,
    .n_next_nodes = NPT66_N_NEXT,
    .next_nodes =
        {
            [NPT66_NEXT_DROP] = "error-drop",
        },
};

VLIB_REGISTER_NODE (npt66_output_node) = {
  .name = "npt66-output",
  .vector_size = sizeof (u32),
  .format_trace = format_npt66_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  // .n_errors = npt66_N_ERROR,
  // .error_counters = npt66_error_counters,
  .sibling_of = "npt66-input",
};

/* Hook up features */
VNET_FEATURE_INIT (npt66_input, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "npt66-input",
};
VNET_FEATURE_INIT (npt66_output, static) = {
  .arc_name = "ip6-output",
  .node_name = "npt66-output",
};
