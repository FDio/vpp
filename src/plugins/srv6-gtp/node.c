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
#include <vppinfra/error.h>
#include <srv6-gtp/srv6_gtp.h>

typedef struct {
  u32 localsid_index;
} srv6_gtp_trace_t;

/* packet trace format function */
static u8 * format_srv6_gtp_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  srv6_gtp_trace_t * t = va_arg (*args, srv6_gtp_trace_t *);
  s = format (s, "SRv6-gtp: localsid_index %d\n",
              t->localsid_index);
  return s;
}

vlib_node_registration_t srv6_gtp_node;

#define foreach_srv6_localsid_counter \
_(PROCESSED, "srv6-gtp processed packets") \
_(NO_SRH, "(Error) No SRH.")

typedef enum {
#define _(sym,str) SRV6_LOCALSID_COUNTER_##sym,
  foreach_srv6_localsid_counter
#undef _
  SRV6_LOCALSID_N_COUNTERS,
} srv6_gtp_counters;

static char * srv6_localsid_counter_strings[] = {
#define _(sym,string) string,
  foreach_srv6_localsid_counter
#undef _
};

typedef enum {
  SRV6_GTP_NEXT_ERROR,
  SRV6_GTP_NEXT_IP4LOOKUP,
  SRV6_GTP_N_NEXT,
} srv6_gtp_next_t;

/*
 * @brief Function doing SRH processing for D* variants
 */
static_always_inline void
end_decaps_srh_processing (vlib_node_runtime_t * node,
         vlib_buffer_t * b0,
         ip6_header_t * ip0,
         ip6_sr_header_t * sr0,
         ip6_sr_localsid_t * ls0, u32 * next0)
{
  /* Compute the size of the IPv6 header with all Ext. headers */
  u8 next_proto;
  ip6_ext_header_t *next_ext_header;
  u16 total_size = 0;

  next_proto = ip0->protocol;
  next_ext_header = (void *) (ip0 + 1);
  total_size = sizeof (ip6_header_t);
  while (ip6_ext_hdr (next_proto))
  {
    total_size += ip6_ext_header_len (next_ext_header);
    next_proto = next_ext_header->next_hdr;
    next_ext_header = ip6_ext_next_header (next_ext_header);
  }
  vlib_buffer_advance (b0, total_size);
  return;
}

/*
 * @brief SRv6 Sample Localsid graph node
 * WARNING: YOU MUST DO THE DUAL LOOP
 */
static uword
srv6_gtp_fn (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  u32 next_index;
  
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
      ip4_header_t *ip4 = 0;
      ip6_sr_header_t * sr0;
      ip6_ext_header_t *prev0;
      u32 next0 = SRV6_GTP_NEXT_IP4LOOKUP;
      ip6_sr_localsid_t *ls0;
      srv6_gtp_per_sid_memory_t *ls0_mem;
      u32 teid = 0;
      u32 sum0 = 0;
      u32 new_l0 = 0;

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
      ip0 = vlib_buffer_get_current (b0);

      /* Push GTP header */
      ASSERT (b0->current_data + VLIB_BUFFER_PRE_DATA_SIZE >= vec_len (ls0_mem->rewrite));
      clib_memcpy (((u8 *) ip0) - vec_len (ls0_mem->rewrite), ls0_mem->rewrite, vec_len (ls0_mem->rewrite));
      vlib_buffer_advance (b0, -(word) vec_len (ls0_mem->rewrite));

      ip4_gtpu_header_t *hdr = vlib_buffer_get_current (b0);
      ip4 = &hdr->ip4;
      udp_header_t *udp = &hdr->udp;
      gtpu_header_t *gtpu = &hdr->gtpu;
      gtpu->teid = teid;

      u16 old_l0 = 0;
      sum0 = ip4->checksum;
      new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
      sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t, length);
      ip4->checksum = ip_csum_fold (sum0);
      ip4->length = new_l0;

      new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain(vm, b0) - sizeof (*ip4));
      udp->length = new_l0;
      new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain(vm, b0) - sizeof (*ip4) - sizeof(*udp));
      gtpu->length = new_l0;

      /* Set Next frame to IP4 lookup */
      next0 = SRV6_GTP_NEXT_IP4LOOKUP;

      if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
      {
        srv6_gtp_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
        tr->localsid_index = ls0 - sm->localsids;
      }

      /* This increments the SRv6 per LocalSID counters.*/
      vlib_increment_combined_counter
        (((next0 == SRV6_GTP_NEXT_ERROR) ? &(sm->sr_ls_invalid_counters) : &(sm->sr_ls_valid_counters)),
        thread_index,
        ls0 - sm->localsids,
        1, vlib_buffer_length_in_chain (vm, b0));

      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, 
        n_left_to_next, bi0, next0);
    }
    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (srv6_gtp_node) = {
  .function = srv6_gtp_fn,
  .name = "srv6-gtp",
  .vector_size = sizeof (u32),
  .format_trace = format_srv6_gtp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = SRV6_LOCALSID_N_COUNTERS,
  .error_strings = srv6_localsid_counter_strings,
  .n_next_nodes = 2,
  .next_nodes = {
        [SRV6_GTP_NEXT_IP4LOOKUP] = "ip4-lookup",
        [SRV6_GTP_NEXT_ERROR] = "error-drop",
    },
};
