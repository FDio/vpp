/*
 * sr_replicate.c: ipv6 segment routing replicator for multicast
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <vnet/sr/sr.h>
#include <vnet/devices/dpdk/dpdk.h>
#include <vnet/ip/ip.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

typedef struct {
  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} sr_replicate_main_t;

sr_replicate_main_t sr_replicate_main;

vlib_node_registration_t sr_replicate_node;


typedef struct {
  ip6_address_t src, dst;
  u16 length;
  u32 next_index;
  u32 tunnel_index;
  u8 sr[256];
} sr_replicate_trace_t;

/* packet trace format function */
static u8 * format_sr_replicate_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  sr_replicate_trace_t * t = va_arg (*args, sr_replicate_trace_t *);
  ip6_main_t * im = &ip6_main;
  ip6_sr_main_t * sm = &sr_main;
  ip6_sr_tunnel_t *tun = pool_elt_at_index (sm->tunnels, t->tunnel_index);
  ip6_fib_t * rx_fib, * tx_fib;
  
  rx_fib = find_ip6_fib_by_table_index_or_id (im, tun->rx_fib_index, 
                                              IP6_ROUTE_FLAG_FIB_INDEX);

  tx_fib = find_ip6_fib_by_table_index_or_id (im, tun->tx_fib_index, 
                                              IP6_ROUTE_FLAG_FIB_INDEX);

  s = format 
    (s, "SR-REPLICATE: next %s ip6 src %U dst %U len %u\n" 
     "           rx-fib-id %d tx-fib-id %d\n%U", 
     "ip6-lookup",
     format_ip6_address, &t->src, 
     format_ip6_address, &t->dst, t->length, 
     rx_fib->table_id, tx_fib->table_id, 
     format_ip6_sr_header, t->sr, 0 /* print_hmac */);
  return s;

}

vlib_node_registration_t sr_replicate_node;

#define foreach_sr_replicate_error \
_(REPLICATED, "sr packets replicated") \
_(NO_BUFFER_DROPS, "sr no buffer drops")

typedef enum {
#define _(sym,str) SR_REPLICATE_ERROR_##sym,
  foreach_sr_replicate_error
#undef _
  SR_REPLICATE_N_ERROR,
} sr_replicate_error_t;

static char * sr_replicate_error_strings[] = {
#define _(sym,string) string,
  foreach_sr_replicate_error
#undef _
};

typedef enum {
  SR_REPLICATE_NEXT_IP6_LOOKUP,
  SR_REPLICATE_N_NEXT,
} sr_replicate_next_t;

static uword
sr_replicate_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  sr_replicate_next_t next_index;
  int pkts_replicated = 0;
  ip6_sr_main_t * sm = &sr_main;
  int no_buffer_drops = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
          u32 bi0, orig_bi0;
	  vlib_buffer_t * b0, * orig_b0;
          u32 next0 = SR_REPLICATE_NEXT_IP6_LOOKUP;
          // alagalah TODO fix the trace --> u32 sw_if_index0;
	  ip6_sr_policy_t * pol0;
	  ip6_sr_tunnel_t * t0;
	  int i;
	  struct rte_mbuf * mb0; 
	  u64 * copy_src0, * copy_dst0;
	  u16 new_l0;
	  ip6_sr_header_t * sr0 = 0;
	  ip6_header_t * ip0;

	  bi0 = from[0];

	  b0 = vlib_get_buffer (vm, bi0);
	  orig_b0 = b0;
	  orig_bi0 = bi0;
	  
	  // alagalah TODO - shouldn't abuse save_protocol like this in buffer.h

	  pol0 = pool_elt_at_index (sm->policies, vnet_buffer(b0)->ip.save_protocol);
	  for (i=0; i < vec_len (pol0->tunnel_indices); i++)
	    {
	      
	      if (i< vec_len (pol0->tunnel_indices) - 1)
		{
		  mb0 = rte_mbuf_from_vlib_buffer(b0);
		  i16 delta0 = vlib_buffer_length_in_chain (vm, b0) - (i16) mb0->pkt_len;
		  
		  u16 new_data_len0 = (u16)((i16) mb0->data_len + delta0);
		  u16 new_pkt_len0 = (u16)((i16) mb0->pkt_len + delta0);
      
		  mb0->data_len = new_data_len0;
		  mb0->pkt_len = new_pkt_len0;
		  mb0->data_off = (u16)(RTE_PKTMBUF_HEADROOM + b0->current_data);

		  mb0 = dpdk_replicate_packet_mb (orig_b0);
		  if (!mb0)
		    {
		      no_buffer_drops++;
		      continue;
		    }
		  b0 = vlib_buffer_from_rte_mbuf (mb0);
		  bi0 = vlib_get_buffer_index (vm, b0);
		  b0->current_data = orig_b0->current_data;
		  b0->current_length = orig_b0->current_length;
		  /*		  vnet_buffer(b0)->sw_if_index[VLIB_RX] = vnet_buffer(orig_b0)->sw_if_index[VLIB_RX]; 
				  vnet_buffer(b0)->sw_if_index[VLIB_TX] = vnet_buffer(orig_b0)->sw_if_index[VLIB_TX]; */
		  memcpy (b0->opaque, orig_b0->opaque, sizeof(b0->opaque));
		  b0->flags = orig_b0->flags;
		  
		} 
	      else 
		{
		  b0 = orig_b0;
		  bi0 = orig_bi0;
		}
	      
	      t0 = vec_elt_at_index (sm->tunnels, pol0->tunnel_indices[i]);
	      
	      ip0 = vlib_buffer_get_current (b0);

	      copy_dst0 = (u64 *)(((u8 *)ip0) - vec_len (t0->rewrite));
	      copy_src0 = (u64 *) ip0;

              /* 
               * Copy data before the punch-in point left by the 
               * required amount. Assume (for the moment) that only 
               * the main packet header needs to be copied.
               */
              copy_dst0 [0] = copy_src0 [0];
              copy_dst0 [1] = copy_src0 [1];
              copy_dst0 [2] = copy_src0 [2];
              copy_dst0 [3] = copy_src0 [3];
              copy_dst0 [4] = copy_src0 [4];
              vlib_buffer_advance (b0, - (word) vec_len(t0->rewrite));
              ip0 = vlib_buffer_get_current (b0);
              sr0 = (ip6_sr_header_t *) (ip0+1);
              /* $$$ tune */
              memcpy (sr0, t0->rewrite, vec_len (t0->rewrite));
              /* Fix the next header chain */
              sr0->protocol = ip0->protocol;
              ip0->protocol = 43; /* routing extension header */
              new_l0 = clib_net_to_host_u16(ip0->payload_length) +
                vec_len (t0->rewrite);
              ip0->payload_length = clib_host_to_net_u16(new_l0);
              /* Rewrite the ip6 dst address */
              ip0->dst_address.as_u64[0] = t0->first_hop.as_u64[0];
              ip0->dst_address.as_u64[1] = t0->first_hop.as_u64[1];

              sr_fix_hmac (sm, ip0, sr0);

	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;

	      if (n_left_to_next == 0)
		{
		  vlib_put_next_frame (vm, node, next_index, n_left_to_next);
		  vlib_get_next_frame (vm, node, next_index,
				       to_next, n_left_to_next);

		}
	      pkts_replicated++;
	    }

	  from += 1;
	  n_left_from -= 1;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
            {
              sr_replicate_trace_t *tr = vlib_add_trace (vm, node, 
                                                       b0, sizeof (*tr));
              tr->tunnel_index = t0 - sm->tunnels;
              memcpy (tr->src.as_u8, ip0->src_address.as_u8,
                      sizeof (tr->src.as_u8));
              memcpy (tr->dst.as_u8, ip0->dst_address.as_u8,
                      sizeof (tr->dst.as_u8));
              tr->length = new_l0;
              tr->next_index = next0;
              memcpy (tr->sr, sr0, sizeof (tr->sr));
            }
          
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, sr_replicate_node.index, 
                               SR_REPLICATE_ERROR_REPLICATED, pkts_replicated);

  vlib_node_increment_counter (vm, sr_replicate_node.index, 
                               SR_REPLICATE_ERROR_NO_BUFFER_DROPS, no_buffer_drops);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (sr_replicate_node) = {
  .function = sr_replicate_node_fn,
  .name = "sr-replicate",
  .vector_size = sizeof (u32),
  .format_trace = format_sr_replicate_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(sr_replicate_error_strings),
  .error_strings = sr_replicate_error_strings,

  .n_next_nodes = SR_REPLICATE_N_NEXT,

  .next_nodes = {
        [SR_REPLICATE_NEXT_IP6_LOOKUP] = "ip6-lookup",
  },
};

clib_error_t *sr_replicate_init (vlib_main_t *vm)
{
  sr_replicate_main_t *msm = &sr_replicate_main;
    
  msm->vlib_main = vm;
  msm->vnet_main = vnet_get_main();

  return 0;
}

VLIB_INIT_FUNCTION(sr_replicate_init);
