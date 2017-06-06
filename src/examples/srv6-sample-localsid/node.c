/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <srv6-localsid/srv6_localsid_sample.h>

typedef struct {
  u32 localsid_index;
} srv6_localsid_sample_trace_t;

/* packet trace format function */
static u8 * format_srv6_localsid_sample_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  srv6_localsid_sample_trace_t * t = va_arg (*args, srv6_localsid_sample_trace_t *);
  s = format (s, "SRv6-sample-localsid: localsid_index %d\n",
              t->localsid_index);
  return s;
}

vlib_node_registration_t srv6_localsid_sample_node;

#define foreach_srv6_localsid_counter \
_(PROCESSED, "srv6-sample-localsid processed packets") \
_(NO_SRH, "(Error) No SRH.")

typedef enum {
#define _(sym,str) SRV6_LOCALSID_COUNTER_##sym,
  foreach_srv6_localsid_counter
#undef _
  SRV6_LOCALSID_N_COUNTERS,
} srv6_localsid_sample_counters;

static char * srv6_localsid_counter_strings[] = {
#define _(sym,string) string,
  foreach_srv6_localsid_counter
#undef _
};

typedef enum {
  SRV6_SAMPLE_LOCALSID_NEXT_ERROR,
  SRV6_SAMPLE_LOCALSID_NEXT_IP6LOOKUP,
  SRV6_SAMPLE_LOCALSID_N_NEXT,
} srv6_localsid_sample_next_t;

/**
 * @brief Function doing End processing.
 */
static_always_inline void
end_srh_processing (vlib_node_runtime_t * node,
        vlib_buffer_t * b0,
        ip6_header_t * ip0,
        ip6_sr_header_t * sr0,
        ip6_sr_localsid_t * ls0,
        u32 * next0,
        u8 psp,
        ip6_ext_header_t * prev0)
{
  ip6_address_t *new_dst0;

  if (PREDICT_TRUE (sr0->type == ROUTING_HEADER_TYPE_SR))
  {
    if (sr0->segments_left == 1 && psp)
    {
      u32 new_l0, sr_len;
      u64 *copy_dst0, *copy_src0;
      u32 copy_len_u64s0 = 0;

      ip0->dst_address.as_u64[0] = sr0->segments->as_u64[0];
      ip0->dst_address.as_u64[1] = sr0->segments->as_u64[1];

      /* Remove the SRH taking care of the rest of IPv6 ext header */
      if (prev0)
        prev0->next_hdr = sr0->protocol;
      else
        ip0->protocol = sr0->protocol;

      sr_len = ip6_ext_header_len (sr0);
      vlib_buffer_advance (b0, sr_len);
      new_l0 = clib_net_to_host_u16 (ip0->payload_length) - sr_len;
      ip0->payload_length = clib_host_to_net_u16 (new_l0);
      copy_src0 = (u64 *) ip0;
      copy_dst0 = copy_src0 + (sr0->length + 1);
      /* number of 8 octet units to copy
       * By default in absence of extension headers it is equal to length of ip6 header
       * With extension headers it number of 8 octet units of ext headers preceding
       * SR header
       */
      copy_len_u64s0 =
        (((u8 *) sr0 - (u8 *) ip0) - sizeof (ip6_header_t)) >> 3;
      copy_dst0[4 + copy_len_u64s0] = copy_src0[4 + copy_len_u64s0];
      copy_dst0[3 + copy_len_u64s0] = copy_src0[3 + copy_len_u64s0];
      copy_dst0[2 + copy_len_u64s0] = copy_src0[2 + copy_len_u64s0];
      copy_dst0[1 + copy_len_u64s0] = copy_src0[1 + copy_len_u64s0];
      copy_dst0[0 + copy_len_u64s0] = copy_src0[0 + copy_len_u64s0];

      int i;
      for (i = copy_len_u64s0 - 1; i >= 0; i--)
      {
        copy_dst0[i] = copy_src0[i];
      }

      if (ls0->behavior == SR_BEHAVIOR_X)
      {
        vnet_buffer (b0)->ip.adj_index[VLIB_TX] = ls0->nh_adj;
        *next0 = SR_LOCALSID_NEXT_IP6_REWRITE;
      }
      else if(ls0->behavior == SR_BEHAVIOR_T)
      {
        vnet_buffer (b0)->sw_if_index[VLIB_TX] = ls0->vrf_index;
      }
    } 
    else if (PREDICT_TRUE(sr0->segments_left > 0))
    {
      sr0->segments_left -= 1;
      new_dst0 = (ip6_address_t *) (sr0->segments);
      new_dst0 += sr0->segments_left;
      ip0->dst_address.as_u64[0] = new_dst0->as_u64[0];
      ip0->dst_address.as_u64[1] = new_dst0->as_u64[1];

      if (ls0->behavior == SR_BEHAVIOR_X)
      {
        vnet_buffer (b0)->ip.adj_index[VLIB_TX] = ls0->nh_adj;
        *next0 = SR_LOCALSID_NEXT_IP6_REWRITE;
      }
      else if(ls0->behavior == SR_BEHAVIOR_T)
      {
        vnet_buffer (b0)->sw_if_index[VLIB_TX] = ls0->vrf_index;
      }
    }
    else
    {
      *next0 = SR_LOCALSID_NEXT_ERROR;
      b0->error = node->errors[SR_LOCALSID_ERROR_NO_MORE_SEGMENTS];
    }
  }
  else
  {
    /* Error. Routing header of type != SR */
    *next0 = SR_LOCALSID_NEXT_ERROR;
    b0->error = node->errors[SR_LOCALSID_ERROR_NO_SRH];
  }
}

/*
 * @brief SRv6 Sample Localsid graph node
 * WARNING: YOU MUST DO THE DUAL LOOP
 */
static uword
srv6_localsid_sample_fn (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  u32 next_index;
  u32 pkts_swapped = 0;
  
  ip6_sr_main_t * sm = &sr_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  u32 thread_index = vlib_get_thread_index ();

  while (n_left_from > 0)
  {
    u32 n_left_to_next;

    vlib_get_next_frame (vm, node, next_index,
		   to_next, n_left_to_next);

    while (n_left_from > 0 && n_left_to_next > 0)
    {
      u32 bi0;
      vlib_buffer_t * b0;
      ip6_header_t * ip0 = 0;
      ip6_sr_header_t * sr0;
      ip6_ext_header_t *prev0
      u32 next0 = SRV6_SAMPLE_LOCALSID_NEXT_IP6LOOKUP;
      ip6_sr_localsid_t *ls0;
      srv6_localsid_sample_per_sid_memory_t *ls0_mem;

      bi0 = from[0];
      to_next[0] = bi0;
      from += 1;
      to_next += 1;
      n_left_from -= 1;
      n_left_to_next -= 1;

      b0 = vlib_get_buffer (vm, bi0);
      ip0 = vlib_buffer_get_current (b0);
      sr0 = (ip6_sr_header_t *)(ip0+1);

      /* Lookup the SR End behavior based on IP DA (adj) */
      ls0 = pool_elt_at_index (sm->localsids, vnet_buffer(b0)->ip.adj_index[VLIB_TX]);
      ls0_mem = ls0->plugin_mem;

      /* SRH processing */
      ip6_ext_header_find_t (ip0, prev0, sr0, IP_PROTOCOL_IPV6_ROUTE);
      end_decaps_srh_processing (node, b0, ip0, sr0, ls0, &next0);

      /* ==================================================================== */
      /* INSERT CODE HERE */
      /* Example starts here */
      //In this example we are changing the next VRF table by the one in CLI
      vnet_buffer(b0)->sw_if_index[VLIB_TX] = ls0_mem->fib_table;
      /* Example finishes here */
      /* ==================================================================== */

      if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
      {
        srv6_localsid_sample_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
        tr->localsid_index = ls0 - sm->localsids;
      }

      /* This increments the SRv6 per LocalSID counters.*/
      vlib_increment_combined_counter
        (((next0 == SRV6_SAMPLE_LOCALSID_NEXT_ERROR) ? &(sm->sr_ls_invalid_counters) : &(sm->sr_ls_valid_counters)),
        thread_index,
        ls0 - sm->localsids,
        1, vlib_buffer_length_in_chain (vm, b0));

      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, 
        n_left_to_next, bi0, next0);

      pkts_swapped ++;
    }
    vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (srv6_localsid_sample_node) = {
  .function = srv6_localsid_sample_fn,
  .name = "srv6-localsid-sample",
  .vector_size = sizeof (u32),
  .format_trace = format_srv6_localsid_sample_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = SRV6_LOCALSID_N_COUNTERS,
  .error_strings = srv6_localsid_counter_strings,
  .n_next_nodes = SRV6_SAMPLE_LOCALSID_N_NEXT,
  .next_nodes = {
        [SRV6_SAMPLE_LOCALSID_NEXT_IP6LOOKUP] = "ip6-lookup",
        [SRV6_SAMPLE_LOCALSID_NEXT_ERROR] = "error-drop",
    },
};
