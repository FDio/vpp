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
#include <nat/nat_reass.h>
#include <nat/nat_inlines.h>

vlib_node_registration_t nat44_classify_node;
vlib_node_registration_t nat44_ed_classify_node;
vlib_node_registration_t nat44_det_classify_node;
vlib_node_registration_t nat44_handoff_classify_node;

#define foreach_nat44_classify_error                      \
_(MAX_REASS, "Maximum reassemblies exceeded")             \
_(MAX_FRAG, "Maximum fragments per reassembly exceeded")

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
			       vlib_frame_t * frame, int is_ed)
{
  u32 n_left_from, *from, *to_next;
  nat44_classify_next_t next_index;
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m;
  u32 thread_index = vm->thread_index;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  u32 *fragments_to_drop = 0;
  u32 *fragments_to_loopback = 0;

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
	  u32 next0 = NAT44_CLASSIFY_NEXT_IN2OUT, sw_if_index0, rx_fib_index0;
	  ip4_header_t *ip0;
	  snat_address_t *ap;
	  snat_session_key_t m_key0;
	  clib_bihash_kv_8_8_t kv0, value0;
	  clib_bihash_kv_16_8_t ed_kv0, ed_value0;
	  udp_header_t *udp0;
	  nat_reass_ip4_t *reass0;
	  u8 cached0 = 0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (b0);
	  udp0 = ip4_next_header (ip0);

	  if (is_ed && ip0->protocol != IP_PROTOCOL_ICMP)
	    {
	      if (!ip4_is_fragment (ip0) || ip4_is_first_fragment (ip0))
		{
		  /* process leading fragment/whole packet (with L4 header) */
		  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
		  rx_fib_index0 =
		    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
							 sw_if_index0);
		  make_ed_kv (&ed_kv0, &ip0->src_address, &ip0->dst_address,
			      ip0->protocol, rx_fib_index0, udp0->src_port,
			      udp0->dst_port);
		  if (ip4_is_fragment (ip0))
		    {
		      reass0 = nat_ip4_reass_find_or_create (ip0->src_address,
							     ip0->dst_address,
							     ip0->fragment_id,
							     ip0->protocol,
							     1,
							     &fragments_to_drop);
		      if (PREDICT_FALSE (!reass0))
			{
			  next0 = NAT44_CLASSIFY_NEXT_DROP;
			  b0->error =
			    node->errors[NAT44_CLASSIFY_ERROR_MAX_REASS];
			  nat_log_notice ("maximum reassemblies exceeded");
			  goto enqueue0;
			}
		      if (!clib_bihash_search_16_8 (&tsm->in2out_ed, &ed_kv0,
						    &ed_value0))
			{
			  /* session exists so classify as IN2OUT,
			   * save this information for future fragments and set
			   * past fragments to be looped over and reprocessed */
			  reass0->sess_index = ed_value0.value;
			  reass0->classify_next =
			    NAT_REASS_IP4_CLASSIFY_NEXT_IN2OUT;
			  nat_ip4_reass_get_frags (reass0,
						   &fragments_to_loopback);
			  goto enqueue0;
			}
		      else
			{
			  /* session doesn't exist so continue in the code,
			   * save this information for future fragments and set
			   * past fragments to be looped over and reprocessed */
			  reass0->flags |=
			    NAT_REASS_FLAG_CLASSIFY_ED_CONTINUE;
			  nat_ip4_reass_get_frags (reass0,
						   &fragments_to_loopback);
			}
		    }
		  else
		    {
		      /* process whole packet */
		      if (!clib_bihash_search_16_8 (&tsm->in2out_ed, &ed_kv0,
						    &ed_value0))
			goto enqueue0;
		      /* session doesn't exist so continue in code */
		    }
		}
	      else
		{
		  /* process non-first fragment */
		  reass0 = nat_ip4_reass_find_or_create (ip0->src_address,
							 ip0->dst_address,
							 ip0->fragment_id,
							 ip0->protocol,
							 1,
							 &fragments_to_drop);
		  if (PREDICT_FALSE (!reass0))
		    {
		      next0 = NAT44_CLASSIFY_NEXT_DROP;
		      b0->error =
			node->errors[NAT44_CLASSIFY_ERROR_MAX_REASS];
		      nat_log_notice ("maximum reassemblies exceeded");
		      goto enqueue0;
		    }
		  /* check if first fragment has arrived */
		  if (reass0->classify_next == NAT_REASS_IP4_CLASSIFY_NONE &&
		      !(reass0->flags & NAT_REASS_FLAG_CLASSIFY_ED_CONTINUE))
		    {
		      /* first fragment still hasn't arrived, cache this fragment */
		      if (nat_ip4_reass_add_fragment (reass0, bi0,
						      &fragments_to_drop))
			{
			  b0->error =
			    node->errors[NAT44_CLASSIFY_ERROR_MAX_FRAG];
			  nat_log_notice
			    ("maximum fragments per reassembly exceeded");
			  next0 = NAT44_CLASSIFY_NEXT_DROP;
			  goto enqueue0;
			}
		      cached0 = 1;
		      goto enqueue0;
		    }
		  if (reass0->classify_next ==
		      NAT_REASS_IP4_CLASSIFY_NEXT_IN2OUT)
		    goto enqueue0;
		  /* flag NAT_REASS_FLAG_CLASSIFY_ED_CONTINUE is set
		   * so keep the default next0 and continue in code to
		   * potentially find other classification for this packet */
		}
	    }

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
	      if (!ip4_is_fragment (ip0) || ip4_is_first_fragment (ip0))
		{
		  /* process leading fragment/whole packet (with L4 header) */
		  m_key0.port = clib_net_to_host_u16 (udp0->dst_port);
		  m_key0.protocol = ip_proto_to_snat_proto (ip0->protocol);
		  kv0.key = m_key0.as_u64;
		  if (!clib_bihash_search_8_8
		      (&sm->static_mapping_by_external, &kv0, &value0))
		    {
		      m =
			pool_elt_at_index (sm->static_mappings, value0.value);
		      if (m->local_addr.as_u32 != m->external_addr.as_u32)
			next0 = NAT44_CLASSIFY_NEXT_OUT2IN;
		    }
		  if (ip4_is_fragment (ip0))
		    {
		      reass0 = nat_ip4_reass_find_or_create (ip0->src_address,
							     ip0->dst_address,
							     ip0->fragment_id,
							     ip0->protocol,
							     1,
							     &fragments_to_drop);
		      if (PREDICT_FALSE (!reass0))
			{
			  next0 = NAT44_CLASSIFY_NEXT_DROP;
			  b0->error =
			    node->errors[NAT44_CLASSIFY_ERROR_MAX_REASS];
			  nat_log_notice ("maximum reassemblies exceeded");
			  goto enqueue0;
			}
		      /* save classification for future fragments and set past
		       * fragments to be looped over and reprocessed */
		      if (next0 == NAT44_CLASSIFY_NEXT_OUT2IN)
			reass0->classify_next =
			  NAT_REASS_IP4_CLASSIFY_NEXT_OUT2IN;
		      else
			reass0->classify_next =
			  NAT_REASS_IP4_CLASSIFY_NEXT_IN2OUT;
		      nat_ip4_reass_get_frags (reass0,
					       &fragments_to_loopback);
		    }
		}
	      else
		{
		  /* process non-first fragment */
		  reass0 = nat_ip4_reass_find_or_create (ip0->src_address,
							 ip0->dst_address,
							 ip0->fragment_id,
							 ip0->protocol,
							 1,
							 &fragments_to_drop);
		  if (PREDICT_FALSE (!reass0))
		    {
		      next0 = NAT44_CLASSIFY_NEXT_DROP;
		      b0->error =
			node->errors[NAT44_CLASSIFY_ERROR_MAX_REASS];
		      nat_log_notice ("maximum reassemblies exceeded");
		      goto enqueue0;
		    }
		  if (reass0->classify_next == NAT_REASS_IP4_CLASSIFY_NONE)
		    /* first fragment still hasn't arrived */
		    {
		      if (nat_ip4_reass_add_fragment (reass0, bi0,
						      &fragments_to_drop))
			{
			  b0->error =
			    node->errors[NAT44_CLASSIFY_ERROR_MAX_FRAG];
			  nat_log_notice
			    ("maximum fragments per reassembly exceeded");
			  next0 = NAT44_CLASSIFY_NEXT_DROP;
			  goto enqueue0;
			}
		      cached0 = 1;
		      goto enqueue0;
		    }
		  else if (reass0->classify_next ==
			   NAT_REASS_IP4_CLASSIFY_NEXT_OUT2IN)
		    next0 = NAT44_CLASSIFY_NEXT_OUT2IN;
		  else if (reass0->classify_next ==
			   NAT_REASS_IP4_CLASSIFY_NEXT_IN2OUT)
		    next0 = NAT44_CLASSIFY_NEXT_IN2OUT;
		}
	    }

	enqueue0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      nat44_classify_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->cached = cached0;
	      if (!cached0)
		t->next_in2out = next0 == NAT44_CLASSIFY_NEXT_IN2OUT ? 1 : 0;
	    }

	  if (cached0)
	    {
	      n_left_to_next++;
	      to_next--;
	    }
	  else
	    /* verify speculative enqueue, maybe switch current next frame */
	    vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					     to_next, n_left_to_next,
					     bi0, next0);

	  if (n_left_from == 0 && vec_len (fragments_to_loopback))
	    {
	      from = vlib_frame_vector_args (frame);
	      u32 len = vec_len (fragments_to_loopback);
	      if (len <= VLIB_FRAME_SIZE)
		{
		  clib_memcpy_fast (from, fragments_to_loopback,
				    sizeof (u32) * len);
		  n_left_from = len;
		  vec_reset_length (fragments_to_loopback);
		}
	      else
		{
		  clib_memcpy_fast (from, fragments_to_loopback +
				    (len - VLIB_FRAME_SIZE),
				    sizeof (u32) * VLIB_FRAME_SIZE);
		  n_left_from = VLIB_FRAME_SIZE;
		  _vec_len (fragments_to_loopback) = len - VLIB_FRAME_SIZE;
		}
	    }
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  nat_send_all_to_node (vm, fragments_to_drop, node, 0,
			NAT44_CLASSIFY_NEXT_DROP);

  vec_free (fragments_to_drop);

  return frame->n_vectors;
}

static uword
nat44_classify_node_fn (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return nat44_classify_node_fn_inline (vm, node, frame, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_classify_node) = {
  .function = nat44_classify_node_fn,
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

VLIB_NODE_FUNCTION_MULTIARCH (nat44_classify_node, nat44_classify_node_fn);
static uword
nat44_ed_classify_node_fn (vlib_main_t * vm,
			   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return nat44_classify_node_fn_inline (vm, node, frame, 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_ed_classify_node) = {
  .function = nat44_ed_classify_node_fn,
  .name = "nat44-ed-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_nat44_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = NAT44_CLASSIFY_N_NEXT,
  .next_nodes = {
    [NAT44_CLASSIFY_NEXT_IN2OUT] = "nat44-ed-in2out",
    [NAT44_CLASSIFY_NEXT_OUT2IN] = "nat44-ed-out2in",
    [NAT44_CLASSIFY_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (nat44_ed_classify_node,
			      nat44_ed_classify_node_fn);

static uword
nat44_det_classify_node_fn (vlib_main_t * vm,
			    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return nat44_classify_node_fn_inline (vm, node, frame, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_det_classify_node) = {
  .function = nat44_det_classify_node_fn,
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

VLIB_NODE_FUNCTION_MULTIARCH (nat44_det_classify_node,
			      nat44_det_classify_node_fn);

static uword
nat44_handoff_classify_node_fn (vlib_main_t * vm,
				vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  return nat44_classify_node_fn_inline (vm, node, frame, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat44_handoff_classify_node) = {
  .function = nat44_handoff_classify_node_fn,
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

VLIB_NODE_FUNCTION_MULTIARCH (nat44_handoff_classify_node,
                              nat44_handoff_classify_node_fn);
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
