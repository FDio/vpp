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
/**
 *  @file
 *  @brief Functions for replicating packets across SR tunnels.
 *
 *  Leverages rte_pktmbuf_clone() so there is no memcpy for
 *  invariant parts of the packet.
 *
 *  @note Currently requires DPDK
*/

#if DPDK > 0			/* Cannot run replicate without DPDK */
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/sr/sr.h>
#include <vnet/devices/dpdk/dpdk.h>
#include <vnet/dpdk_replication.h>
#include <vnet/ip/ip.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

/**
 *   @brief sr_replicate state.
 *
*/
typedef struct
{
  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} sr_replicate_main_t;

sr_replicate_main_t sr_replicate_main;

/**
 *    @brief Information to display in packet trace.
 *
*/
typedef struct
{
  ip6_address_t src, dst;
  u16 length;
  u32 next_index;
  u32 tunnel_index;
  u8 sr[256];
} sr_replicate_trace_t;

/**
 *  @brief packet trace format function.
 *
 *  @param *s u8 used for string output
 *  @param *args va_list  structured input to va_arg to output @ref sr_replicate_trace_t
 *  @return *s u8 - formatted trace output
*/
static u8 *
format_sr_replicate_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  sr_replicate_trace_t *t = va_arg (*args, sr_replicate_trace_t *);
  ip6_main_t *im = &ip6_main;
  ip6_sr_main_t *sm = &sr_main;
  ip6_sr_tunnel_t *tun = pool_elt_at_index (sm->tunnels, t->tunnel_index);
  ip6_fib_t *rx_fib, *tx_fib;

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
     format_ip6_sr_header, t->sr, 0 /* print_hmac */ );
  return s;

}

#define foreach_sr_replicate_error \
_(REPLICATED, "sr packets replicated") \
_(NO_BUFFERS, "error allocating buffers for replicas") \
_(NO_REPLICAS, "no replicas were needed") \
_(NO_BUFFER_DROPS, "sr no buffer drops")

typedef enum
{
#define _(sym,str) SR_REPLICATE_ERROR_##sym,
  foreach_sr_replicate_error
#undef _
    SR_REPLICATE_N_ERROR,
} sr_replicate_error_t;

static char *sr_replicate_error_strings[] = {
#define _(sym,string) string,
  foreach_sr_replicate_error
#undef _
};

/**
 * @brief Defines next-nodes for packet processing.
 *
*/
typedef enum
{
  SR_REPLICATE_NEXT_IP6_LOOKUP,
  SR_REPLICATE_N_NEXT,
} sr_replicate_next_t;

/**
 *   @brief Single loop packet replicator.
 *
 *   @node sr-replicate
 *   @param vm vlib_main_t
 *   @return frame->n_vectors uword
*/
static uword
sr_replicate_node_fn (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  sr_replicate_next_t next_index;
  int pkts_replicated = 0;
  ip6_sr_main_t *sm = &sr_main;
  int no_buffer_drops = 0;
  vlib_buffer_free_list_t *fl;
  unsigned socket_id = rte_socket_id ();
  vlib_buffer_main_t *bm = vm->buffer_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  fl = vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, hdr_bi0;
	  vlib_buffer_t *b0, *orig_b0;
	  struct rte_mbuf *orig_mb0 = 0, *hdr_mb0 = 0, *clone0 = 0;
	  struct rte_mbuf **hdr_vec = 0, **rte_mbuf_vec = 0;
	  ip6_sr_policy_t *pol0 = 0;
	  ip6_sr_tunnel_t *t0 = 0;
	  ip6_sr_header_t *hdr_sr0 = 0;
	  ip6_header_t *ip0 = 0, *hdr_ip0 = 0;
	  int num_replicas = 0;
	  int i;

	  bi0 = from[0];

	  b0 = vlib_get_buffer (vm, bi0);
	  orig_b0 = b0;

	  pol0 = pool_elt_at_index (sm->policies,
				    vnet_buffer (b0)->ip.save_protocol);

	  ip0 = vlib_buffer_get_current (b0);
	  /* Skip forward to the punch-in point */
	  vlib_buffer_advance (b0, sizeof (*ip0));

	  orig_mb0 = rte_mbuf_from_vlib_buffer (b0);

	  i16 delta0 = vlib_buffer_length_in_chain (vm, orig_b0)
	    - (i16) orig_mb0->pkt_len;

	  u16 new_data_len0 = (u16) ((i16) orig_mb0->data_len + delta0);
	  u16 new_pkt_len0 = (u16) ((i16) orig_mb0->pkt_len + delta0);

	  orig_mb0->data_len = new_data_len0;
	  orig_mb0->pkt_len = new_pkt_len0;
	  orig_mb0->data_off =
	    (u16) (RTE_PKTMBUF_HEADROOM + b0->current_data);

	  /*
	     Before entering loop determine if we can allocate:
	     - all the new HEADER RTE_MBUFs and assign them to a vector
	     - all the clones

	     if successful, then iterate over vectors of resources

	   */
	  num_replicas = vec_len (pol0->tunnel_indices);

	  if (PREDICT_FALSE (num_replicas == 0))
	    {
	      b0->error = node->errors[SR_REPLICATE_ERROR_NO_REPLICAS];
	      goto do_trace0;
	    }

	  vec_reset_length (hdr_vec);
	  vec_reset_length (rte_mbuf_vec);

	  for (i = 0; i < num_replicas; i++)
	    {
	      hdr_mb0 = rte_pktmbuf_alloc (bm->pktmbuf_pools[socket_id]);

	      if (i < (num_replicas - 1))
		/* Not the last tunnel to process */
		clone0 = rte_pktmbuf_clone
		  (orig_mb0, bm->pktmbuf_pools[socket_id]);
	      else
		/* Last tunnel to process, use original MB */
		clone0 = orig_mb0;


	      if (PREDICT_FALSE (!clone0 || !hdr_mb0))
		{
		  b0->error = node->errors[SR_REPLICATE_ERROR_NO_BUFFERS];

		  vec_foreach_index (i, rte_mbuf_vec)
		  {
		    rte_pktmbuf_free (rte_mbuf_vec[i]);
		  }
		  vec_free (rte_mbuf_vec);

		  vec_foreach_index (i, hdr_vec)
		  {
		    rte_pktmbuf_free (hdr_vec[i]);
		  }
		  vec_free (hdr_vec);

		  goto do_trace0;
		}

	      vec_add1 (hdr_vec, hdr_mb0);
	      vec_add1 (rte_mbuf_vec, clone0);

	    }

	  for (i = 0; i < num_replicas; i++)
	    {
	      vlib_buffer_t *hdr_b0;

	      t0 = vec_elt_at_index (sm->tunnels, pol0->tunnel_indices[i]);

	      /* Our replicas */
	      hdr_mb0 = hdr_vec[i];
	      clone0 = rte_mbuf_vec[i];

	      hdr_mb0->data_len = sizeof (*ip0) + vec_len (t0->rewrite);
	      hdr_mb0->pkt_len = hdr_mb0->data_len +
		vlib_buffer_length_in_chain (vm, orig_b0);

	      hdr_b0 = vlib_buffer_from_rte_mbuf (hdr_mb0);

	      vlib_buffer_init_for_free_list (hdr_b0, fl);

	      memcpy (hdr_b0->data, ip0, sizeof (*ip0));
	      memcpy (hdr_b0->data + sizeof (*ip0), t0->rewrite,
		      vec_len (t0->rewrite));

	      hdr_b0->current_data = 0;
	      hdr_b0->current_length = sizeof (*ip0) + vec_len (t0->rewrite);
	      hdr_b0->flags = orig_b0->flags | VLIB_BUFFER_NEXT_PRESENT;


	      hdr_b0->total_length_not_including_first_buffer =
		hdr_mb0->pkt_len - hdr_b0->current_length;

	      hdr_ip0 = (ip6_header_t *) hdr_b0->data;
	      hdr_ip0->payload_length =
		clib_host_to_net_u16 (hdr_mb0->data_len);
	      hdr_sr0 = (ip6_sr_header_t *) (hdr_ip0 + 1);
	      hdr_sr0->protocol = hdr_ip0->protocol;
	      hdr_ip0->protocol = 43;

	      /* Rewrite the ip6 dst address */
	      hdr_ip0->dst_address.as_u64[0] = t0->first_hop.as_u64[0];
	      hdr_ip0->dst_address.as_u64[1] = t0->first_hop.as_u64[1];

	      sr_fix_hmac (sm, hdr_ip0, hdr_sr0);

	      /* prepend new header to invariant piece */
	      hdr_mb0->next = clone0;
	      hdr_b0->next_buffer =
		vlib_get_buffer_index (vm,
				       vlib_buffer_from_rte_mbuf (clone0));

	      /* update header's fields */
	      hdr_mb0->pkt_len =
		(uint16_t) (hdr_mb0->data_len + clone0->pkt_len);
	      hdr_mb0->nb_segs = (uint8_t) (clone0->nb_segs + 1);

	      /* copy metadata from source packet */
	      hdr_mb0->port = clone0->port;
	      hdr_mb0->vlan_tci = clone0->vlan_tci;
	      hdr_mb0->vlan_tci_outer = clone0->vlan_tci_outer;
	      hdr_mb0->tx_offload = clone0->tx_offload;
	      hdr_mb0->hash = clone0->hash;

	      hdr_mb0->ol_flags = clone0->ol_flags;

	      __rte_mbuf_sanity_check (hdr_mb0, 1);

	      hdr_bi0 = vlib_get_buffer_index (vm, hdr_b0);

	      to_next[0] = hdr_bi0;
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

	do_trace0:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      sr_replicate_trace_t *tr = vlib_add_trace (vm, node,
							 b0, sizeof (*tr));
	      tr->tunnel_index = t0 - sm->tunnels;
	      tr->length = 0;
	      if (hdr_ip0)
		{
		  memcpy (tr->src.as_u8, hdr_ip0->src_address.as_u8,
			  sizeof (tr->src.as_u8));
		  memcpy (tr->dst.as_u8, hdr_ip0->dst_address.as_u8,
			  sizeof (tr->dst.as_u8));
		  if (hdr_ip0->payload_length)
		    tr->length = clib_net_to_host_u16
		      (hdr_ip0->payload_length);
		}
	      tr->next_index = next_index;
              if (hdr_sr0)
                memcpy (tr->sr, hdr_sr0, sizeof (tr->sr));
	    }

	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, sr_replicate_node.index,
			       SR_REPLICATE_ERROR_REPLICATED,
			       pkts_replicated);

  vlib_node_increment_counter (vm, sr_replicate_node.index,
			       SR_REPLICATE_ERROR_NO_BUFFER_DROPS,
			       no_buffer_drops);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
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
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (sr_replicate_node, sr_replicate_node_fn)
     clib_error_t *sr_replicate_init (vlib_main_t * vm)
{
  sr_replicate_main_t *msm = &sr_replicate_main;

  msm->vlib_main = vm;
  msm->vnet_main = vnet_get_main ();

  return 0;
}

VLIB_INIT_FUNCTION (sr_replicate_init);

#endif /* DPDK */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
