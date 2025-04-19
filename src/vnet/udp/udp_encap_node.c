/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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
 */

#include <vnet/udp/udp_encap.h>
#include <vnet/udp/udp.h>

typedef struct udp4_encap_trace_t_
{
  udp_header_t udp;
  ip4_header_t ip;
  u32 flow_hash;
  udp_encap_fixup_flags_t flags;
} udp4_encap_trace_t;

typedef struct udp6_encap_trace_t_
{
  udp_header_t udp;
  ip6_header_t ip;
  u32 flow_hash;
  udp_encap_fixup_flags_t flags;
} udp6_encap_trace_t;

extern vlib_combined_counter_main_t udp_encap_counters;

static u8 *
format_udp4_encap_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  u32 indent = format_get_indent (s);
  udp4_encap_trace_t *t;

  t = va_arg (*args, udp4_encap_trace_t *);

  s = format (s, "flags: %U, flow hash: 0x%08x\n%U%U\n%U%U",
	      format_udp_encap_fixup_flags, t->flags, t->flow_hash,
	      format_white_space, indent, format_ip4_header, &t->ip,
	      sizeof (t->ip), format_white_space, indent, format_udp_header,
	      &t->udp, sizeof (t->udp));
  return (s);
}

static u8 *
format_udp6_encap_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  u32 indent = format_get_indent (s);
  udp6_encap_trace_t *t;

  t = va_arg (*args, udp6_encap_trace_t *);

  s = format (s, "flags: %U, flow hash: 0x%08x\n%U%U\n%U%U",
	      format_udp_encap_fixup_flags, t->flags, t->flow_hash,
	      format_white_space, indent, format_ip6_header, &t->ip,
	      sizeof (t->ip), format_white_space, indent, format_udp_header,
	      &t->udp, sizeof (t->udp));
  return (s);
}

always_inline uword
udp_encap_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		  vlib_frame_t *frame, ip_address_family_t encap_family,
		  ip_address_family_t payload_family)
{
  vlib_combined_counter_main_t *cm = &udp_encap_counters;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from, n_left_to_next, *to_next, next_index;
  clib_thread_index_t thread_index = vm->thread_index;

  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t *b0, *b1;
	  udp_encap_t *ue0, *ue1;
	  u32 bi0, next0, uei0;
	  u32 bi1, next1, uei1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, STORE);
	    vlib_prefetch_buffer_header (p3, STORE);
	  }

	  bi0 = to_next[0] = from[0];
	  bi1 = to_next[1] = from[1];

	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  uei0 = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
	  uei1 = vnet_buffer (b1)->ip.adj_index[VLIB_TX];

	  vlib_increment_combined_counter (cm, thread_index, uei0, 1,
					   vlib_buffer_length_in_chain (vm,
									b0));
	  vlib_increment_combined_counter (cm, thread_index, uei1, 1,
					   vlib_buffer_length_in_chain (vm,
									b1));

	  /* Rewrite packet header and updates lengths. */
	  ue0 = udp_encap_get (uei0);
	  ue1 = udp_encap_get (uei1);

	  /* Paint */
	  if (encap_family == AF_IP6)
	    {
	      const u8 n_bytes =
		sizeof (udp_header_t) + sizeof (ip6_header_t);
	      ip_udp_encap_two (vm, b0, b1, (u8 *) &ue0->ue_hdrs,
				(u8 *) &ue1->ue_hdrs, n_bytes, encap_family,
				payload_family, ue0->ue_flags, ue1->ue_flags);

	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  udp6_encap_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));
		  tr->udp = ue0->ue_hdrs.ip6.ue_udp;
		  tr->ip = ue0->ue_hdrs.ip6.ue_ip6;
		  tr->flags = ue0->ue_flags;
		  tr->flow_hash = vnet_buffer (b0)->ip.flow_hash;
		}
	      if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
		{
		  udp6_encap_trace_t *tr =
		    vlib_add_trace (vm, node, b1, sizeof (*tr));
		  tr->udp = ue1->ue_hdrs.ip6.ue_udp;
		  tr->ip = ue1->ue_hdrs.ip6.ue_ip6;
		  tr->flags = ue1->ue_flags;
		  tr->flow_hash = vnet_buffer (b1)->ip.flow_hash;
		}
	    }
	  else
	    {
	      const u8 n_bytes =
		sizeof (udp_header_t) + sizeof (ip4_header_t);

	      ip_udp_encap_two (vm, b0, b1, (u8 *) &ue0->ue_hdrs,
				(u8 *) &ue1->ue_hdrs, n_bytes, encap_family,
				payload_family, ue0->ue_flags, ue1->ue_flags);

	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  udp4_encap_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));
		  tr->udp = ue0->ue_hdrs.ip4.ue_udp;
		  tr->ip = ue0->ue_hdrs.ip4.ue_ip4;
		  tr->flags = ue0->ue_flags;
		  tr->flow_hash = vnet_buffer (b0)->ip.flow_hash;
		}
	      if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
		{
		  udp4_encap_trace_t *tr =
		    vlib_add_trace (vm, node, b1, sizeof (*tr));
		  tr->udp = ue1->ue_hdrs.ip4.ue_udp;
		  tr->ip = ue1->ue_hdrs.ip4.ue_ip4;
		  tr->flags = ue1->ue_flags;
		  tr->flow_hash = vnet_buffer (b1)->ip.flow_hash;
		}
	    }

	  next0 = ue0->ue_dpo.dpoi_next_node;
	  next1 = ue1->ue_dpo.dpoi_next_node;
	  vnet_buffer (b0)->ip.adj_index[VLIB_TX] = ue0->ue_dpo.dpoi_index;
	  vnet_buffer (b1)->ip.adj_index[VLIB_TX] = ue1->ue_dpo.dpoi_index;

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0, uei0;
	  vlib_buffer_t *b0;
	  udp_encap_t *ue0;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  uei0 = vnet_buffer (b0)->ip.adj_index[VLIB_TX];

	  /* Rewrite packet header and updates lengths. */
	  ue0 = udp_encap_get (uei0);

	  vlib_increment_combined_counter (cm, thread_index, uei0, 1,
					   vlib_buffer_length_in_chain (vm,
									b0));

	  /* Paint */
	  if (encap_family == AF_IP6)
	    {
	      const u8 n_bytes =
		sizeof (udp_header_t) + sizeof (ip6_header_t);
	      ip_udp_encap_one (vm, b0, (u8 *) &ue0->ue_hdrs.ip6, n_bytes,
				encap_family, payload_family, ue0->ue_flags);

	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  udp6_encap_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));
		  tr->udp = ue0->ue_hdrs.ip6.ue_udp;
		  tr->ip = ue0->ue_hdrs.ip6.ue_ip6;
		  tr->flags = ue0->ue_flags;
		  tr->flow_hash = vnet_buffer (b0)->ip.flow_hash;
		}
	    }
	  else
	    {
	      const u8 n_bytes =
		sizeof (udp_header_t) + sizeof (ip4_header_t);

	      ip_udp_encap_one (vm, b0, (u8 *) &ue0->ue_hdrs.ip4, n_bytes,
				encap_family, payload_family, ue0->ue_flags);

	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  udp4_encap_trace_t *tr =
		    vlib_add_trace (vm, node, b0, sizeof (*tr));
		  tr->udp = ue0->ue_hdrs.ip4.ue_udp;
		  tr->ip = ue0->ue_hdrs.ip4.ue_ip4;
		  tr->flags = ue0->ue_flags;
		  tr->flow_hash = vnet_buffer (b0)->ip.flow_hash;
		}
	    }

	  next0 = ue0->ue_dpo.dpoi_next_node;
	  vnet_buffer (b0)->ip.adj_index[VLIB_TX] = ue0->ue_dpo.dpoi_index;

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (udp4o4_encap_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return udp_encap_inline (vm, node, frame, AF_IP4, AF_IP4);
}

VLIB_NODE_FN (udp6o4_encap_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return udp_encap_inline (vm, node, frame, AF_IP4, AF_IP6);
}

VLIB_NODE_FN (udp4_encap_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return udp_encap_inline (vm, node, frame, AF_IP4, N_AF);
}

VLIB_NODE_FN (udp6o6_encap_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return udp_encap_inline (vm, node, frame, AF_IP6, AF_IP6);
}

VLIB_NODE_FN (udp4o6_encap_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return udp_encap_inline (vm, node, frame, AF_IP6, AF_IP4);
}

VLIB_NODE_FN (udp6_encap_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return udp_encap_inline (vm, node, frame, AF_IP6, N_AF);
}

VLIB_REGISTER_NODE (udp4o4_encap_node) = {
  .name = "udp4o4-encap",
  .vector_size = sizeof (u32),
  .format_trace = format_udp4_encap_trace,
  .n_next_nodes = 0,
};

VLIB_REGISTER_NODE (udp6o4_encap_node) = {
  .name = "udp6o4-encap",
  .vector_size = sizeof (u32),
  .format_trace = format_udp4_encap_trace,
  .n_next_nodes = 0,
  .sibling_of = "udp4o4-encap",
};

VLIB_REGISTER_NODE (udp4_encap_node) = {
  .name = "udp4-encap",
  .vector_size = sizeof (u32),
  .format_trace = format_udp4_encap_trace,
  .n_next_nodes = 0,
  .sibling_of = "udp4o4-encap",
};

VLIB_REGISTER_NODE (udp6o6_encap_node) = {
  .name = "udp6o6-encap",
  .vector_size = sizeof (u32),
  .format_trace = format_udp6_encap_trace,
  .n_next_nodes = 0,
};

VLIB_REGISTER_NODE (udp4o6_encap_node) = {
  .name = "udp4o6-encap",
  .vector_size = sizeof (u32),
  .format_trace = format_udp6_encap_trace,
  .n_next_nodes = 0,
  .sibling_of = "udp6o6-encap",
};

VLIB_REGISTER_NODE (udp6_encap_node) = {
  .name = "udp6-encap",
  .vector_size = sizeof (u32),
  .format_trace = format_udp6_encap_trace,
  .n_next_nodes = 0,
  .sibling_of = "udp6o6-encap",
};


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
