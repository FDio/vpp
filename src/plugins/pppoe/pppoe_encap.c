/*
 * Copyright (c) 2017 Intel and/or its affiliates.
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
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <pppoe/pppoe.h>

/* Statistics (not all errors) */
#define foreach_pppoe_encap_error    \
_(ENCAPSULATED, "good packets encapsulated")

static char * pppoe_encap_error_strings[] = {
#define _(sym,string) string,
  foreach_pppoe_encap_error
#undef _
};

typedef enum {
#define _(sym,str) PPPOE_ENCAP_ERROR_##sym,
    foreach_pppoe_encap_error
#undef _
    PPPOE_ENCAP_N_ERROR,
} pppoe_encap_error_t;

#define foreach_pppoe_encap_next       \
_(DROP, "error-drop")                  \
_(INTERFACE, "interface-output" )      \

typedef enum
{
#define _(s,n) PPPOE_ENCAP_NEXT_##s,
  foreach_pppoe_encap_next
#undef _
    PPPOE_ENCAP_N_NEXT,
} pppoe_encap_next_t;

typedef struct {
  u32 session_index;
  u32 session_id;
} pppoe_encap_trace_t;

u8 * format_pppoe_encap_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pppoe_encap_trace_t * t
      = va_arg (*args, pppoe_encap_trace_t *);

  s = format (s, "PPPOE encap to pppoe_session%d session_id %d",
	      t->session_index, t->session_id);
  return s;
}


#define foreach_fixed_header2_offset            \
        _(0) _(1)


static uword
pppoe_encap (vlib_main_t * vm,
	      vlib_node_runtime_t * node,
	      vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  pppoe_main_t * pem = &pppoe_main;
  vnet_main_t * vnm = pem->vnet_main;
  vnet_interface_main_t * im = &vnm->interface_main;
  u32 pkts_encapsulated = 0;
  u32 thread_index = vlib_get_thread_index();
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;
  u32 sw_if_index0 = 0, sw_if_index1 = 0;
  u32 next0 = 0, next1 = 0;
  pppoe_session_t * t0 = NULL, * t1 = NULL;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;
  stats_sw_if_index = node->runtime_data[0];
  stats_n_packets = stats_n_bytes = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
          u32 bi0, bi1;
	  vlib_buffer_t * b0, * b1;
	  u32 len0, len1;
	  ethernet_header_t * eth0, * eth1;
          pppoe_header_t * pppoe0, * pppoe1;
          u64 * copy_src0, * copy_dst0;
          u64 * copy_src1, * copy_dst1;
          u16 * copy_src_last0, * copy_dst_last0;
          u16 * copy_src_last1, * copy_dst_last1;
          u16 new_l0, new_l1;
          u32 session_id0, session_id1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (p3->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
	  }

	  bi0 = from[0];
	  bi1 = from[1];
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  /* Get next node index and if-index from session */
	  sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_TX];
	  session_id0 = pem->session_index_by_sw_if_index[sw_if_index0];
	  t0 = pool_elt_at_index(pem->sessions, session_id0);
	  next0 = PPPOE_ENCAP_NEXT_INTERFACE;
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = t0->encap_if_index;

          /* Get next node index and if-index from session */
	  sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_TX];
	  session_id1 = pem->session_index_by_sw_if_index[sw_if_index1];
	  t1 = pool_elt_at_index(pem->sessions, session_id1);
	  next1 = PPPOE_ENCAP_NEXT_INTERFACE;
          vnet_buffer(b1)->sw_if_index[VLIB_TX] = t1->encap_if_index;

          /* Apply the rewrite string. $$$$ vnet_rewrite? */
          vlib_buffer_advance (b0, -(word)_vec_len(t0->rewrite));
          vlib_buffer_advance (b1, -(word)_vec_len(t1->rewrite));

          eth0 = (ethernet_header_t *)(vlib_buffer_get_current(b0));
          eth1 = (ethernet_header_t *)(vlib_buffer_get_current(b1));

	  /* Copy the fixed header */
	  copy_dst0 = (u64 *) eth0;
	  copy_src0 = (u64 *) t0->rewrite;
	  copy_dst1 = (u64 *) eth1;
	  copy_src1 = (u64 *) t1->rewrite;
	  /* Copy first 8-bytes at a time */
#define _(offs) copy_dst0[offs] = copy_src0[offs];
	  foreach_fixed_header2_offset;
#undef _
	  /* Last 6 octets. Hopefully gcc will be our friend */
          copy_dst_last0 = (u16 *)(&copy_dst0[2]);
          copy_src_last0 = (u16 *)(&copy_src0[2]);
          copy_dst_last0[0] = copy_src_last0[0];
          copy_dst_last0[1] = copy_src_last0[1];
          copy_dst_last0[2] = copy_src_last0[2];

#define _(offs) copy_dst1[offs] = copy_src1[offs];
	  foreach_fixed_header2_offset;
#undef _
	  /* Last 6 octets. Hopefully gcc will be our friend */
          copy_dst_last1 = (u16 *)(&copy_dst1[2]);
          copy_src_last1 = (u16 *)(&copy_src1[2]);
          copy_dst_last1[0] = copy_src_last1[0];
          copy_dst_last1[1] = copy_src_last1[1];
          copy_dst_last1[2] = copy_src_last1[2];

          /* Fix PPPoE length */
	  new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain(vm, b0)
					 - sizeof (*pppoe0) - sizeof(*eth0));
	  pppoe0 = (pppoe_header_t *)(eth0 + 1);
	  pppoe0->length = new_l0;

	  new_l1 = clib_host_to_net_u16 (vlib_buffer_length_in_chain(vm, b1)
					 - sizeof (*pppoe1) - sizeof(*eth1));
	  pppoe1 = (pppoe_header_t *)(eth1 + 1);
	  pppoe1->length = new_l1;

          pkts_encapsulated += 2;
 	  len0 = vlib_buffer_length_in_chain (vm, b0);
 	  len1 = vlib_buffer_length_in_chain (vm, b1);
	  stats_n_packets += 2;
	  stats_n_bytes += len0 + len1;

	  /* Batch stats increment on the same pppoe session so counter is not
	     incremented per packet. Note stats are still incremented for deleted
	     and admin-down session where packets are dropped. It is not worthwhile
	     to check for this rare case and affect normal path performance. */
	  if (PREDICT_FALSE ((sw_if_index0 != stats_sw_if_index) ||
			     (sw_if_index1 != stats_sw_if_index)))
	    {
	      stats_n_packets -= 2;
	      stats_n_bytes -= len0 + len1;
	      if (sw_if_index0 == sw_if_index1)
	        {
		  if (stats_n_packets)
		    vlib_increment_combined_counter
		      (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
		       thread_index, stats_sw_if_index,
		       stats_n_packets, stats_n_bytes);
		  stats_sw_if_index = sw_if_index0;
		  stats_n_packets = 2;
		  stats_n_bytes = len0 + len1;
	        }
	      else
	        {
		  vlib_increment_combined_counter
		      (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
		       thread_index, sw_if_index0, 1, len0);
		  vlib_increment_combined_counter
		      (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
		       thread_index, sw_if_index1, 1, len1);
		}
	    }

	  if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              pppoe_encap_trace_t *tr =
                vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->session_index = t0 - pem->sessions;
              tr->session_id = t0->session_id;
           }

          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
            {
              pppoe_encap_trace_t *tr =
                vlib_add_trace (vm, node, b1, sizeof (*tr));
              tr->session_index = t1 - pem->sessions;
              tr->session_id = t1->session_id;
            }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t * b0;
	  ethernet_header_t * eth0;
          pppoe_header_t * pppoe0;
          u64 * copy_src0, * copy_dst0;
          u16 * copy_src_last0, * copy_dst_last0;
          u16 new_l0;
          u32 len0;
          u32 session_id0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* Get next node index and if-index from session */
	  sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_TX];
	  session_id0 = pem->session_index_by_sw_if_index[sw_if_index0];
	  t0 = pool_elt_at_index(pem->sessions, session_id0);
	  next0 = PPPOE_ENCAP_NEXT_INTERFACE;
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = t0->encap_if_index;

          /* Apply the rewrite string. $$$$ vnet_rewrite? */
          vlib_buffer_advance (b0, -(word)_vec_len(t0->rewrite));

          eth0 = (ethernet_header_t *)(vlib_buffer_get_current(b0));
	  /* Copy the fixed header */
	  copy_dst0 = (u64 *) eth0;
	  copy_src0 = (u64 *) t0->rewrite;

	  /* Copy first 8-bytes at a time */
#define _(offs) copy_dst0[offs] = copy_src0[offs];
	  foreach_fixed_header2_offset;
#undef _
	  /* Last 6 octets. Hopefully gcc will be our friend */
          copy_dst_last0 = (u16 *)(&copy_dst0[2]);
          copy_src_last0 = (u16 *)(&copy_src0[2]);
          copy_dst_last0[0] = copy_src_last0[0];
          copy_dst_last0[1] = copy_src_last0[1];
          copy_dst_last0[2] = copy_src_last0[2];

          /* Fix PPPoE length */
	  new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain(vm, b0)
					 - sizeof (*pppoe0) - sizeof(*eth0));
	  pppoe0 = (pppoe_header_t *)(eth0 + 1);
	  pppoe0->length = new_l0;

          pkts_encapsulated ++;
	  len0 = vlib_buffer_length_in_chain (vm, b0);
	  stats_n_packets += 1;
	  stats_n_bytes += len0;

	  /* Batch stats increment on the same pppoe session so counter is not
	     incremented per packet. Note stats are still incremented for deleted
	     and admin-down session where packets are dropped. It is not worthwhile
	     to check for this rare case and affect normal path performance. */
	  if (PREDICT_FALSE (sw_if_index0 != stats_sw_if_index))
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len0;
	      if (stats_n_packets)
		vlib_increment_combined_counter
		  (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
		   thread_index, stats_sw_if_index,
		   stats_n_packets, stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len0;
	      stats_sw_if_index = sw_if_index0;
	    }

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              pppoe_encap_trace_t *tr =
                vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->session_index = t0 - pem->sessions;
              tr->session_id = t0->session_id;
            }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Do we still need this now that session tx stats is kept? */
  vlib_node_increment_counter (vm, node->node_index,
                               PPPOE_ENCAP_ERROR_ENCAPSULATED,
                               pkts_encapsulated);

  /* Increment any remaining batch stats */
  if (stats_n_packets)
    {
      vlib_increment_combined_counter
	(im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
	 thread_index, stats_sw_if_index, stats_n_packets, stats_n_bytes);
      node->runtime_data[0] = stats_sw_if_index;
    }

  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (pppoe_encap_node) = {
  .function = pppoe_encap,
  .name = "pppoe-encap",
  .vector_size = sizeof (u32),
  .format_trace = format_pppoe_encap_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(pppoe_encap_error_strings),
  .error_strings = pppoe_encap_error_strings,
  .n_next_nodes = PPPOE_ENCAP_N_NEXT,
  .next_nodes = {
#define _(s,n) [PPPOE_ENCAP_NEXT_##s] = n,
    foreach_pppoe_encap_next
#undef _
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (pppoe_encap_node, pppoe_encap)

