/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief Classify for one armed NAT44 (in+out interface)
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/fib/ip4_fib.h>
#include <nat/nat.h>
#include <nat/nat_inlines.h>

#define foreach_nat44_classify_error                      \
_(NEXT_IN2OUT, "next in2out")                             \
_(NEXT_OUT2IN, "next out2in")                             \
_(FRAG_CACHED, "fragment cached")

typedef enum
{
#define _(sym,str) NAT44_CLASSIFY_ERROR_##sym,
  foreach_nat44_classify_error
#undef _
    NAT44_CLASSIFY_N_ERROR,
} nat44_classify_error_t;

static char *nat44_classify_error_strings[] = {
#define _(sym,string) string,
  foreach_nat44_classify_error
#undef _
};

typedef enum
{
  NAT44_CLASSIFY_NEXT_IN2OUT,
  NAT44_CLASSIFY_NEXT_OUT2IN,
  NAT44_CLASSIFY_NEXT_DROP,
  NAT44_CLASSIFY_N_NEXT,
} nat44_classify_next_t;

typedef struct
{
  u8 next_in2out;
  u8 cached;
} nat44_classify_trace_t;

static u8 *
format_nat44_classify_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nat44_classify_trace_t *t = va_arg (*args, nat44_classify_trace_t *);
  char *next;

  if (t->cached)
    s = format (s, "nat44-classify: fragment cached");
  else
    {
      next = t->next_in2out ? "nat44-in2out" : "nat44-out2in";
      s = format (s, "nat44-classify: next %s", next);
    }

  return s;
}

static inline uword
nat44_classify_node_fn_inline (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  nat44_classify_next_t next_index;
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m;
  u32 *fragments_to_drop = 0;
  u32 next_in2out = 0, next_out2in = 0, frag_cached = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = NAT44_CLASSIFY_NEXT_IN2OUT;
	  ip4_header_t *ip0;
	  snat_address_t *ap;
	  snat_session_key_t m_key0;
	  clib_bihash_kv_8_8_t kv0, value0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (b0);

          /* *INDENT-OFF* */
          vec_foreach (ap, sm->addresses)
            {
              if (ip0->dst_address.as_u32 == ap->addr.as_u32)
                {
                  next0 = NAT44_CLASSIFY_NEXT_OUT2IN;
                  goto enqueue0;
                }
            }
          /* *INDENT-ON* */

	  if (PREDICT_FALSE (pool_elts (sm->static_mappings)))
	    {
	      m_key0.addr = ip0->dst_address;
	      m_key0.port = 0;
	      m_key0.protocol = 0;
	      m_key0.fib_index = 0;
	      kv0.key = m_key0.as_u64;
	      /* try to classify the fragment based on IP header alone */
	      if (!clib_bihash_search_8_8 (&sm->static_mapping_by_external,
					   &kv0, &value0))
		{
		  m = pool_elt_at_index (sm->static_mappings, value0.value);
		  if (m->local_addr.as_u32 != m->external_addr.as_u32)
		    next0 = NAT44_CLASSIFY_NEXT_OUT2IN;
		  goto enqueue0;
		}
	      m_key0.port =
		clib_net_to_host_u16 (vnet_buffer (b0)->ip.reass.l4_dst_port);
	      m_key0.protocol = ip_proto_to_snat_proto (ip0->protocol);
	      kv0.key = m_key0.as_u64;
	      if (!clib_bihash_search_8_8
		  (&sm->static_mapping_by_external, &kv0, &value0))
		{
		  m = pool_elt_at_index (sm->static_mappings, value0.value);
		  if (m->local_addr.as_u32 != m->external_addr.as_u32)
		    next0 = NAT44_CLASSIFY_NEXT_OUT2IN;
		}
	    }

	enqueue0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      nat44_classify_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->cached = 0;
	      t->next_in2out = next0 == NAT44_CLASSIFY_NEXT_IN2OUT ? 1 : 0;
	    }

	  next_in2out += next0 == NAT44_CLASSIFY_NEXT_IN2OUT;
	  next_out2in += next0 == NAT44_CLASSIFY_NEXT_OUT2IN;

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  nat_send_all_to_node (vm, fragments_to_drop, node, 0,
			NAT44_CLASSIFY_NEXT_DROP);

  vec_free (fragments_to_drop);

  vlib_node_increment_counter (vm, node->node_index,
			       NAT44_CLASSIFY_ERROR_NEXT_IN2OUT, next_in2out);
  vlib_node_increment_counter (vm, node->node_index,
			       NAT44_CLASSIFY_ERROR_NEXT_OUT2IN, next_out2in);
  vlib_node_increment_counter (vm, node->node_index,
			       NAT44_CLASSIFY_ERROR_FRAG_CACHED, frag_cached);

  return frame->n_vectors;
}

static inline uword
nat44_ed_classify_node_fn_inline (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  nat44_classify_next_t next_index;
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m;
  u32 thread_index = vm->thread_index;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  u32 *fragments_to_drop = 0;
  u32 next_in2out = 0, next_out2in = 0, frag_cached = 0;
  u8 in_loopback = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 =
	    NAT_NEXT_IN2OUT_ED_FAST_PATH, sw_if_index0, rx_fib_index0;
	  ip4_header_t *ip0;
	  snat_address_t *ap;
	  snat_session_key_t m_key0;
	  clib_bihash_kv_8_8_t kv0, value0;
	  clib_bihash_kv_16_8_t ed_kv0, ed_value0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (b0);

	  if (!in_loopback)
	    {
	      u32 arc_next = 0;

	      vnet_feature_next (&arc_next, b0);
	      nat_buffer_opaque (b0)->arc_next = arc_next;
	    }

	  if (ip0->protocol != IP_PROTOCOL_ICMP)
	    {
	      /* process leading fragment/whole packet (with L4 header) */
	      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      rx_fib_index0 =
		fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
						     sw_if_index0);
	      make_ed_kv (&ed_kv0, &ip0->src_address,
			  &ip0->dst_address, ip0->protocol,
			  rx_fib_index0,
			  vnet_buffer (b0)->ip.reass.l4_src_port,
			  vnet_buffer (b0)->ip.reass.l4_dst_port);
	      /* process whole packet */
	      if (!clib_bihash_search_16_8
		  (&tsm->in2out_ed, &ed_kv0, &ed_value0))
		goto enqueue0;
	      /* session doesn't exist so continue in code */
	    }

          /* *INDENT-OFF* */
          vec_foreach (ap, sm->addresses)
            {
              if (ip0->dst_address.as_u32 == ap->addr.as_u32)
                {
                  next0 = NAT_NEXT_OUT2IN_ED_FAST_PATH;
                  goto enqueue0;
                }
            }
          /* *INDENT-ON* */

	  if (PREDICT_FALSE (pool_elts (sm->static_mappings)))
	    {
	      m_key0.addr = ip0->dst_address;
	      m_key0.port = 0;
	      m_key0.protocol = 0;
	      m_key0.fib_index = 0;
	      kv0.key = m_key0.as_u64;
	      /* try to classify the fragment based on IP header alone */
	      if (!clib_bihash_search_8_8 (&sm->static_mapping_by_external,
					   &kv0, &value0))
		{
		  m = pool_elt_at_index (sm->static_mappings, value0.value);
		  if (m->local_addr.as_u32 != m->external_addr.as_u32)
		    next0 = NAT_NEXT_OUT2IN_ED_FAST_PATH;
		  goto enqueue0;
		}
	      m_key0.port =
		clib_net_to_host_u16 (vnet_buffer (b0)->ip.reass.l4_dst_port);
	      m_key0.protocol = ip_proto_to_snat_proto (ip0->protocol);
	      kv0.key = m_key0.as_u64;
	      if (!clib_bihash_search_8_8
		  (&sm->static_mapping_by_external, &kv0, &value0))
		{
		  m = pool_elt_at_index (sm->static_mappings, value0.value);
		  if (m->local_addr.as_u32 != m->external_addr.as_u32)
		    next0 = NAT_NEXT_OUT2IN_ED_FAST_PATH;
		}
	    }

	enqueue0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      nat44_classify_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->cached = 0;
	      t->next_in2out = next0 == NAT_NEXT_IN2OUT_ED_FAST_PATH ? 1 : 0;
	    }

	  next_in2out += next0 == NAT_NEXT_IN2OUT_ED_FAST_PATH;
	  next_out2in += next0 == NAT_NEXT_OUT2IN_ED_FAST_PATH;

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  nat_send_all_to_node (vm, fragments_to_drop, node, 0,
			NAT44_CLASSIFY_NEXT_DROP);

  vec_free (fragments_to_drop);

  vlib_node_increment_counter (vm, node->node_index,
			       NAT44_CLASSIFY_ERROR_NEXT_IN2OUT, next_in2out);
  vlib_node_increment_counter (vm, node->node_index,
			       NAT44_CLASSIFY_ERROR_NEXT_OUT2IN, next_out2in);
  vlib_node_increment_counter (vm, node->node_index,
			       NAT44_CLASSIFY_ERROR_FRAG_CACHED, frag_cached);

  return frame->n_vectors;
}

VLIB_NODE_FN (nat44_classify_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return nat44_classify_node_fn_inline (vm, node, frame);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_classify_node) = {
  .name = "nat44-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_nat44_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(nat44_classify_error_strings),
  .error_strings = nat44_classify_error_strings,
  .n_next_nodes = NAT44_CLASSIFY_N_NEXT,
  .next_nodes = {
    [NAT44_CLASSIFY_NEXT_IN2OUT] = "nat44-in2out",
    [NAT44_CLASSIFY_NEXT_OUT2IN] = "nat44-out2in",
    [NAT44_CLASSIFY_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FN (nat44_ed_classify_node) (vlib_main_t * vm,
				       vlib_node_runtime_t * node,
				       vlib_frame_t * frame)
{
  return nat44_ed_classify_node_fn_inline (vm, node, frame);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_ed_classify_node) = {
  .name = "nat44-ed-classify",
  .vector_size = sizeof (u32),
  .sibling_of = "nat-default",
  .format_trace = format_nat44_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
};
/* *INDENT-ON* */

VLIB_NODE_FN (nat44_det_classify_node) (vlib_main_t * vm,
					vlib_node_runtime_t * node,
					vlib_frame_t * frame)
{
  return nat44_classify_node_fn_inline (vm, node, frame);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_det_classify_node) = {
  .name = "nat44-det-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_nat44_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = NAT44_CLASSIFY_N_NEXT,
  .next_nodes = {
    [NAT44_CLASSIFY_NEXT_IN2OUT] = "nat44-det-in2out",
    [NAT44_CLASSIFY_NEXT_OUT2IN] = "nat44-det-out2in",
    [NAT44_CLASSIFY_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FN (nat44_handoff_classify_node) (vlib_main_t * vm,
					    vlib_node_runtime_t * node,
					    vlib_frame_t * frame)
{
  return nat44_classify_node_fn_inline (vm, node, frame);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_handoff_classify_node) = {
  .name = "nat44-handoff-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_nat44_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = NAT44_CLASSIFY_N_NEXT,
  .next_nodes = {
    [NAT44_CLASSIFY_NEXT_IN2OUT] = "nat44-in2out-worker-handoff",
    [NAT44_CLASSIFY_NEXT_OUT2IN] = "nat44-out2in-worker-handoff",
    [NAT44_CLASSIFY_NEXT_DROP] = "error-drop",
  },
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
