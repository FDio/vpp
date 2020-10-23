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
#include <nat/nat44/ed_inlines.h>

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
  u32 next_in2out = 0, next_out2in = 0;

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
	      init_nat_k (&kv0, ip0->dst_address, 0, 0, 0);
	      /* try to classify the fragment based on IP header alone */
	      if (!clib_bihash_search_8_8 (&sm->static_mapping_by_external,
					   &kv0, &value0))
		{
		  m = pool_elt_at_index (sm->static_mappings, value0.value);
		  if (m->local_addr.as_u32 != m->external_addr.as_u32)
		    next0 = NAT44_CLASSIFY_NEXT_OUT2IN;
		  goto enqueue0;
		}
	      init_nat_k (&kv0, ip0->dst_address,
			  vnet_buffer (b0)->ip.reass.l4_dst_port, 0,
			  ip_proto_to_nat_proto (ip0->protocol));
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

  vlib_node_increment_counter (vm, node->node_index,
			       NAT44_CLASSIFY_ERROR_NEXT_IN2OUT, next_in2out);
  vlib_node_increment_counter (vm, node->node_index,
			       NAT44_CLASSIFY_ERROR_NEXT_OUT2IN, next_out2in);
  return frame->n_vectors;
}

static inline uword
nat44_handoff_classify_node_fn_inline (vlib_main_t * vm,
				       vlib_node_runtime_t * node,
				       vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  nat44_classify_next_t next_index;
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m;
  u32 next_in2out = 0, next_out2in = 0;

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
	  u32 next0 = NAT_NEXT_IN2OUT_CLASSIFY;
	  ip4_header_t *ip0;
	  snat_address_t *ap;
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
                  next0 = NAT_NEXT_OUT2IN_CLASSIFY;
                  goto enqueue0;
                }
            }
          /* *INDENT-ON* */

	  if (PREDICT_FALSE (pool_elts (sm->static_mappings)))
	    {
	      init_nat_k (&kv0, ip0->dst_address, 0, 0, 0);
	      /* try to classify the fragment based on IP header alone */
	      if (!clib_bihash_search_8_8 (&sm->static_mapping_by_external,
					   &kv0, &value0))
		{
		  m = pool_elt_at_index (sm->static_mappings, value0.value);
		  if (m->local_addr.as_u32 != m->external_addr.as_u32)
		    next0 = NAT_NEXT_OUT2IN_CLASSIFY;
		  goto enqueue0;
		}
	      init_nat_k (&kv0, ip0->dst_address,
			  vnet_buffer (b0)->ip.reass.l4_dst_port, 0,
			  ip_proto_to_nat_proto (ip0->protocol));
	      if (!clib_bihash_search_8_8
		  (&sm->static_mapping_by_external, &kv0, &value0))
		{
		  m = pool_elt_at_index (sm->static_mappings, value0.value);
		  if (m->local_addr.as_u32 != m->external_addr.as_u32)
		    next0 = NAT_NEXT_OUT2IN_CLASSIFY;
		}
	    }

	enqueue0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      nat44_classify_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->cached = 0;
	      t->next_in2out = next0 == NAT_NEXT_IN2OUT_CLASSIFY ? 1 : 0;
	    }

	  next_in2out += next0 == NAT_NEXT_IN2OUT_CLASSIFY;
	  next_out2in += next0 == NAT_NEXT_OUT2IN_CLASSIFY;

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       NAT44_CLASSIFY_ERROR_NEXT_IN2OUT, next_in2out);
  vlib_node_increment_counter (vm, node->node_index,
			       NAT44_CLASSIFY_ERROR_NEXT_OUT2IN, next_out2in);
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
  u32 next_in2out = 0, next_out2in = 0;

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
	  u32 next0 = NAT_NEXT_IN2OUT_ED_FAST_PATH;
	  u32 sw_if_index0, rx_fib_index0;
	  ip4_header_t *ip0;
	  snat_address_t *ap;
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

	  u32 arc_next;
	  vnet_feature_next (&arc_next, b0);
	  vnet_buffer2 (b0)->nat.arc_next = arc_next;

	  if (ip0->protocol != IP_PROTOCOL_ICMP)
	    {
	      /* process leading fragment/whole packet (with L4 header) */
	      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      rx_fib_index0 =
		fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
						     sw_if_index0);
	      init_ed_k (&ed_kv0, ip0->src_address,
			 vnet_buffer (b0)->ip.reass.l4_src_port,
			 ip0->dst_address,
			 vnet_buffer (b0)->ip.reass.l4_dst_port,
			 rx_fib_index0, ip0->protocol);
	      /* process whole packet */
	      if (!clib_bihash_search_16_8
		  (&sm->flow_hash, &ed_kv0, &ed_value0))
		{
		  ASSERT (vm->thread_index ==
			  ed_value_get_thread_index (&ed_value0));
		  snat_main_per_thread_data_t *tsm =
		    &sm->per_thread_data[vm->thread_index];
		  snat_session_t *s = pool_elt_at_index (tsm->sessions,
							 ed_value_get_session_index
							 (&ed_value0));
		  clib_bihash_kv_16_8_t i2o_kv;
		  nat_6t_flow_to_ed_k (&i2o_kv, &s->i2o);
		  vnet_buffer2 (b0)->nat.cached_session_index =
		    ed_value_get_session_index (&ed_value0);
		  if (i2o_kv.key[0] == ed_kv0.key[0]
		      && i2o_kv.key[1] == ed_kv0.key[1])
		    {
		      next0 = NAT_NEXT_IN2OUT_ED_FAST_PATH;
		    }
		  else
		    {
		      next0 = NAT_NEXT_OUT2IN_ED_FAST_PATH;
		    }

		  goto enqueue0;
		}
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
	      init_nat_k (&kv0, ip0->dst_address, 0, 0, 0);
	      /* try to classify the fragment based on IP header alone */
	      if (!clib_bihash_search_8_8 (&sm->static_mapping_by_external,
					   &kv0, &value0))
		{
		  m = pool_elt_at_index (sm->static_mappings, value0.value);
		  if (m->local_addr.as_u32 != m->external_addr.as_u32)
		    next0 = NAT_NEXT_OUT2IN_ED_FAST_PATH;
		  goto enqueue0;
		}
	      init_nat_k (&kv0, ip0->dst_address,
			  vnet_buffer (b0)->ip.reass.l4_dst_port, 0,
			  ip_proto_to_nat_proto (ip0->protocol));
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

  vlib_node_increment_counter (vm, node->node_index,
			       NAT44_CLASSIFY_ERROR_NEXT_IN2OUT, next_in2out);
  vlib_node_increment_counter (vm, node->node_index,
			       NAT44_CLASSIFY_ERROR_NEXT_OUT2IN, next_out2in);
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

VLIB_NODE_FN (nat44_handoff_classify_node) (vlib_main_t * vm,
					    vlib_node_runtime_t * node,
					    vlib_frame_t * frame)
{
  return nat44_handoff_classify_node_fn_inline (vm, node, frame);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_handoff_classify_node) = {
  .name = "nat44-handoff-classify",
  .vector_size = sizeof (u32),
  .sibling_of = "nat-default",
  .format_trace = format_nat44_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
