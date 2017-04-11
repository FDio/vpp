/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
/*
 * This file implements caching of ioam header and reattaching
 * it in response message by performing request-response matching.
 *  Works for TCP SYN/SYN-ACK.
 * This feature is used for anycast server selection.
 * ioam data thus cached is used to measure and get complete round trip
 * network path to help in server selection.
 * There are 2 graph nodes defined to :
 * 1. process packets that contain iOAM header and cache it
 * 2. process TCP SYN-ACKs and reattach ioam header from the
 *    cache corresponding to TCP-SYN
 * These graph nodes are attached to the vnet graph based on
 * ioam cache and classifier configs.
 * e.g.
 * If db06::06 is the anycast service IP6 address:
 *
 * set ioam ip6 cache
 *
 * Apply this classifier on interface where requests for anycast service are received:
 * classify session acl-hit-next ip6-node ip6-lookup table-index 0 match l3 ip6 dst db06::06
 *    ioam-decap anycast <<< ioam-decap is hooked to cache when set ioam ip6 cache is enabled
 *
 * Apply this classifier on interface where responses from anycast service are received:
 * classify session acl-hit-next ip6-node ip6-add-from-cache-hop-by-hop table-index 0 match l3
 *    ip6 src db06::06 ioam-encap anycast-response
 *
 */
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/ip/ip.h>
#include <ioam/ip6/ioam_cache.h>
#include <vnet/ip/ip6_hop_by_hop.h>
#include <vnet/ip/ip6_hop_by_hop_packet.h>

typedef struct
{
  u32 next_index;
  u32 flow_label;
} cache_trace_t;

/* packet trace format function */
static u8 *
format_cache_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cache_trace_t *t = va_arg (*args, cache_trace_t *);

  s = format (s, "CACHE: flow_label %d, next index %d",
	      t->flow_label, t->next_index);
  return s;
}

#define foreach_cache_error \
_(RECORDED, "ip6 iOAM headers cached")

typedef enum
{
#define _(sym,str) CACHE_ERROR_##sym,
  foreach_cache_error
#undef _
    CACHE_N_ERROR,
} cache_error_t;

static char *cache_error_strings[] = {
#define _(sym,string) string,
  foreach_cache_error
#undef _
};

typedef enum
{
  IOAM_CACHE_NEXT_POP_HBYH,
  IOAM_CACHE_N_NEXT,
} cache_next_t;

static uword
ip6_ioam_cache_node_fn (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  cache_next_t next_index;
  u32 recorded = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      // TODO: Dual loop
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *p0;
	  u32 next0 = IOAM_CACHE_NEXT_POP_HBYH;
	  ip6_header_t *ip0;
	  ip6_hop_by_hop_header_t *hbh0;
	  tcp_header_t *tcp0;
	  u32 tcp_offset0;

	  /* speculatively enqueue p0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (p0);
	  if (IP_PROTOCOL_TCP ==
	      ip6_locate_header (p0, ip0, IP_PROTOCOL_TCP, &tcp_offset0))
	    {
	      tcp0 = (tcp_header_t *) ((u8 *) ip0 + tcp_offset0);
	      if ((tcp0->flags & TCP_FLAG_SYN) == TCP_FLAG_SYN &&
		  (tcp0->flags & TCP_FLAG_ACK) == 0)
		{
		  /* Cache the ioam hbh header */
		  hbh0 = (ip6_hop_by_hop_header_t *) (ip0 + 1);
		  if (0 == ioam_cache_add (p0,
					   ip0,
					   clib_net_to_host_u16
					   (tcp0->src_port),
					   clib_net_to_host_u16
					   (tcp0->dst_port), hbh0,
					   clib_net_to_host_u32
					   (tcp0->seq_number) + 1))
		    {
		      recorded++;
		    }
		}
	    }
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (p0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  cache_trace_t *t =
		    vlib_add_trace (vm, node, p0, sizeof (*t));
		  t->flow_label =
		    clib_net_to_host_u32
		    (ip0->ip_version_traffic_class_and_flow_label);
		  t->next_index = next0;
		}
	    }
	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, ioam_cache_node.index,
			       CACHE_ERROR_RECORDED, recorded);
  return frame->n_vectors;
}

/*
 * Node for IP6 iOAM header cache
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ioam_cache_node) =
{
  .function = ip6_ioam_cache_node_fn,
  .name = "ip6-ioam-cache",
  .vector_size = sizeof (u32),
  .format_trace = format_cache_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (cache_error_strings),
  .error_strings = cache_error_strings,
  .n_next_nodes = IOAM_CACHE_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes =
  {
    [IOAM_CACHE_NEXT_POP_HBYH] = "ip6-pop-hop-by-hop"
  },
};
/* *INDENT-ON* */

typedef struct
{
  u32 next_index;
} ip6_add_from_cache_hbh_trace_t;

/* packet trace format function */
static u8 *
format_ip6_add_from_cache_hbh_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_add_from_cache_hbh_trace_t *t = va_arg (*args,
					      ip6_add_from_cache_hbh_trace_t
					      *);

  s = format (s, "IP6_ADD_FROM_CACHE_HBH: next index %d", t->next_index);
  return s;
}

vlib_node_registration_t ip6_add_from_cache_hbh_node;

#define foreach_ip6_add_from_cache_hbh_error \
_(PROCESSED, "Pkts w/ added ip6 hop-by-hop options")

typedef enum
{
#define _(sym,str) IP6_ADD_FROM_CACHE_HBH_ERROR_##sym,
  foreach_ip6_add_from_cache_hbh_error
#undef _
    IP6_ADD_FROM_CACHE_HBH_N_ERROR,
} ip6_add_from_cache_hbh_error_t;

static char *ip6_add_from_cache_hbh_error_strings[] = {
#define _(sym,string) string,
  foreach_ip6_add_from_cache_hbh_error
#undef _
};

#define foreach_ip6_ioam_cache_input_next        \
  _(IP6_LOOKUP, "ip6-lookup")                   \
  _(DROP, "error-drop")

typedef enum
{
#define _(s,n) IP6_IOAM_CACHE_INPUT_NEXT_##s,
  foreach_ip6_ioam_cache_input_next
#undef _
    IP6_IOAM_CACHE_INPUT_N_NEXT,
} ip6_ioam_cache_input_next_t;


static uword
ip6_add_from_cache_hbh_node_fn (vlib_main_t * vm,
				vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  ioam_cache_main_t *cm = &ioam_cache_main;
  u32 n_left_from, *from, *to_next;
  ip_lookup_next_t next_index;
  u32 processed = 0;
  u8 *rewrite = 0;
  u32 rewrite_len = 0;
  u32 sr_rewrite_len = vec_len (cm->sr_rewrite_template);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      // TODO: Dual loop
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  ip6_header_t *ip0;
	  ip6_hop_by_hop_header_t *hbh0;
	  ip6_sr_header_t *srh0 = 0;
	  u64 *copy_src0, *copy_dst0;
	  u16 new_l0;
	  tcp_header_t *tcp0;
	  u32 tcp_offset0;
	  ioam_cache_entry_t *entry = 0;

	  next0 = IP6_IOAM_CACHE_INPUT_NEXT_IP6_LOOKUP;
	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  ip0 = vlib_buffer_get_current (b0);
	  if (IP_PROTOCOL_TCP !=
	      ip6_locate_header (b0, ip0, IP_PROTOCOL_TCP, &tcp_offset0))
	    {
	      goto TRACE0;
	    }
	  tcp0 = (tcp_header_t *) ((u8 *) ip0 + tcp_offset0);
	  if (((tcp0->flags & TCP_FLAG_SYN) == TCP_FLAG_SYN &&
	       (tcp0->flags & TCP_FLAG_ACK) == TCP_FLAG_ACK) ||
	      (tcp0->flags & TCP_FLAG_RST) == TCP_FLAG_RST)
	    {
	      if (0 != (entry = ioam_cache_lookup (ip0,
						   clib_net_to_host_u16
						   (tcp0->src_port),
						   clib_net_to_host_u16
						   (tcp0->dst_port),
						   clib_net_to_host_u32
						   (tcp0->ack_number))))
		{
		  rewrite = entry->ioam_rewrite_string;
		  rewrite_len = vec_len (rewrite);
		}
	      else
		{
		  next0 = IP6_IOAM_CACHE_INPUT_NEXT_DROP;
		  goto TRACE0;
		}
	    }
	  else
	    goto TRACE0;


	  /* Copy the ip header left by the required amount */
	  copy_dst0 = (u64 *) (((u8 *) ip0) - (rewrite_len + sr_rewrite_len));
	  copy_src0 = (u64 *) ip0;

	  copy_dst0[0] = copy_src0[0];
	  copy_dst0[1] = copy_src0[1];
	  copy_dst0[2] = copy_src0[2];
	  copy_dst0[3] = copy_src0[3];
	  copy_dst0[4] = copy_src0[4];
	  vlib_buffer_advance (b0, -(word) (rewrite_len + sr_rewrite_len));
	  ip0 = vlib_buffer_get_current (b0);

	  hbh0 = (ip6_hop_by_hop_header_t *) (ip0 + 1);
	  srh0 = (ip6_sr_header_t *) ((u8 *) hbh0 + rewrite_len);
	  /* $$$ tune, rewrite_len is a multiple of 8 */
	  clib_memcpy (hbh0, rewrite, rewrite_len);
	  clib_memcpy (srh0, cm->sr_rewrite_template, sr_rewrite_len);
	  /* Copy dst address into the DA slot in the segment list */
	  clib_memcpy (srh0->segments, ip0->dst_address.as_u64,
		       sizeof (ip6_address_t));
	  /* Rewrite the ip6 dst address with the first hop */
	  clib_memcpy (ip0->dst_address.as_u64, entry->next_hop.as_u64,
		       sizeof (ip6_address_t));
	  clib_memcpy (&srh0->segments[1],
		       (u8 *) hbh0 + entry->my_address_offset,
		       sizeof (ip6_address_t));
	  ioam_cache_entry_free (entry);

	  /* Patch the protocol chain, insert the h-b-h (type 0) header */
	  srh0->protocol = ip0->protocol;
	  hbh0->protocol = IPPROTO_IPV6_ROUTE;
	  ip0->protocol = 0;
	  new_l0 =
	    clib_net_to_host_u16 (ip0->payload_length) + rewrite_len +
	    sr_rewrite_len;
	  ip0->payload_length = clib_host_to_net_u16 (new_l0);
	  processed++;
	TRACE0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      ip6_add_from_cache_hbh_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->next_index = next0;
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, ip6_add_from_cache_hbh_node.index,
			       IP6_ADD_FROM_CACHE_HBH_ERROR_PROCESSED,
			       processed);
  return frame->n_vectors;
}
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_add_from_cache_hbh_node) =
{
  .function = ip6_add_from_cache_hbh_node_fn,
  .name = "ip6-add-from-cache-hop-by-hop",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_add_from_cache_hbh_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (ip6_add_from_cache_hbh_error_strings),
  .error_strings =  ip6_add_from_cache_hbh_error_strings,
  /* See ip/lookup.h */
  .n_next_nodes = IP6_IOAM_CACHE_INPUT_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [IP6_IOAM_CACHE_INPUT_NEXT_##s] = n,
    foreach_ip6_ioam_cache_input_next
#undef _
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (ip6_add_from_cache_hbh_node,
			      ip6_add_from_cache_hbh_node_fn)
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
