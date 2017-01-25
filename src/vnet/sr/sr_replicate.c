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
 *  Leverages vlib_buffer_clone() so there is no memcpy for
 *  invariant parts of the packet.
*/

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/sr/sr.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/ip6_fib.h>

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
  ip6_sr_main_t *sm = &sr_main;
  ip6_sr_tunnel_t *tun = pool_elt_at_index (sm->tunnels, t->tunnel_index);
  ip6_fib_t *rx_fib, *tx_fib;

  rx_fib = ip6_fib_get (tun->rx_fib_index);
  tx_fib = ip6_fib_get (tun->tx_fib_index);

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

/**
 * @brief Struct for SR replicate errors
 */
typedef enum
{
#define _(sym,str) SR_REPLICATE_ERROR_##sym,
  foreach_sr_replicate_error
#undef _
    SR_REPLICATE_N_ERROR,
} sr_replicate_error_t;

/**
 * @brief Error strings for SR replicate
 */
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
  u32 *clones = 0;

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
	  ip6_sr_policy_t *pol0 = 0;
	  ip6_sr_tunnel_t *t0 = 0;
	  ip6_sr_header_t *hdr_sr0 = 0;
	  ip6_header_t *ip0 = 0, *hdr_ip0 = 0;
	  int num_replicas = 0;
	  int i;
	  u32 len_bytes = sizeof (ip6_header_t);
	  u8 next_hdr, ip_next_hdr = IPPROTO_IPV6_ROUTE;

	  bi0 = from[0];

	  b0 = vlib_get_buffer (vm, bi0);

	  pol0 = pool_elt_at_index (sm->policies,
				    vnet_buffer (b0)->ip.save_protocol);

	  ip0 = vlib_buffer_get_current (b0);
	  /* Skip forward to the punch-in point */
	  vlib_buffer_advance (b0, sizeof (*ip0));
	  next_hdr = ip0->protocol;

	  /* HBH must immediately follow ipv6 header */
	  if (PREDICT_FALSE
	      (ip0->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS))
	    {
	      ip6_hop_by_hop_ext_t *ext_hdr =
		(ip6_hop_by_hop_ext_t *) ip6_next_header (ip0);
	      u32 ext_hdr_len = 0;
	      ext_hdr_len = ip6_ext_header_len ((ip6_ext_header_t *) ext_hdr);
	      len_bytes += ext_hdr_len;
	      next_hdr = ext_hdr->next_hdr;
	      ext_hdr->next_hdr = IPPROTO_IPV6_ROUTE;
	      ip_next_hdr = IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS;
	      /* Skip forward to the punch-in point */
	      vlib_buffer_advance (b0, ext_hdr_len);

	    }

	  num_replicas = vec_len (pol0->tunnel_indices);

	  if (PREDICT_FALSE (num_replicas == 0))
	    {
	      b0->error = node->errors[SR_REPLICATE_ERROR_NO_REPLICAS];
	      goto do_trace0;
	    }

	  vec_validate_aligned (clones, num_replicas - 1,
				CLIB_CACHE_LINE_BYTES);
	  u32 num_cloned = vlib_buffer_clone (vm, bi0, clones, num_replicas,
					      CLIB_CACHE_LINE_BYTES * 2);

	  if (PREDICT_FALSE (num_replicas != num_cloned))
	    {
	      vlib_buffer_free (vm, clones, num_cloned);
	      b0->error = node->errors[SR_REPLICATE_ERROR_NO_BUFFERS];
	      goto do_trace0;
	    }

	  for (i = 0; i < num_replicas; i++)
	    {
	      vlib_buffer_t *hdr_b0 = vlib_get_buffer (vm, clones[i]);;
	      u16 new_l0 = 0;
	      t0 = vec_elt_at_index (sm->tunnels, pol0->tunnel_indices[i]);

	      hdr_b0->current_data -= len_bytes + vec_len (t0->rewrite);
	      hdr_b0->current_length += len_bytes + vec_len (t0->rewrite);
	      memcpy (vlib_buffer_get_current (hdr_b0), ip0, len_bytes);

	      vnet_buffer (hdr_b0)->l2_classify.opaque_index = 0;
	      vnet_buffer (hdr_b0)->sw_if_index[VLIB_TX] = t0->tx_fib_index;

	      hdr_ip0 = (ip6_header_t *) vlib_buffer_get_current (hdr_b0);
	      new_l0 = clib_net_to_host_u16 (ip0->payload_length) +
		vec_len (t0->rewrite);
	      hdr_ip0->payload_length = clib_host_to_net_u16 (new_l0);
	      hdr_sr0 = (ip6_sr_header_t *) ((u8 *) hdr_ip0 + len_bytes);
	      /* $$$ tune */
	      clib_memcpy (hdr_sr0, t0->rewrite, vec_len (t0->rewrite));
	      hdr_sr0->protocol = next_hdr;
	      hdr_ip0->protocol = ip_next_hdr;

	      /* Copy dst address into the DA slot in the segment list */
	      clib_memcpy (hdr_sr0->segments, &hdr_ip0->dst_address,
			   sizeof (ip6_address_t));

	      /* Rewrite the ip6 dst address */
	      hdr_ip0->dst_address.as_u64[0] = t0->first_hop.as_u64[0];
	      hdr_ip0->dst_address.as_u64[1] = t0->first_hop.as_u64[1];

	      sr_fix_hmac (sm, hdr_ip0, hdr_sr0);

	      to_next[0] = clones[i];
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


	do_trace0:
	  from += 1;
	  n_left_from -= 1;
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

VLIB_NODE_FUNCTION_MULTIARCH (sr_replicate_node, sr_replicate_node_fn)
/* *INDENT-ON* */

clib_error_t *
sr_replicate_init (vlib_main_t * vm)
{
  sr_replicate_main_t *msm = &sr_replicate_main;

  msm->vlib_main = vm;
  msm->vnet_main = vnet_get_main ();

  return 0;
}

VLIB_INIT_FUNCTION (sr_replicate_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
