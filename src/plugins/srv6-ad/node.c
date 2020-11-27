/*
 * node.c
 *
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
#include <srv6-ad/ad.h>


/******************************* Packet tracing *******************************/

typedef struct
{
  u32 localsid_index;
} srv6_ad_localsid_trace_t;

typedef struct
{
  u8 error;
  ip6_address_t src, dst;
} srv6_ad_rewrite_trace_t;

static u8 *
format_srv6_ad_localsid_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  srv6_ad_localsid_trace_t *t = va_arg (*args, srv6_ad_localsid_trace_t *);

  return format (s, "SRv6-AD-localsid: localsid_index %d", t->localsid_index);
}

static u8 *
format_srv6_ad_rewrite_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  srv6_ad_rewrite_trace_t *t = va_arg (*args, srv6_ad_rewrite_trace_t *);

  if (PREDICT_FALSE (t->error != 0))
    {
      return format (s, "SRv6-AD-rewrite: cache is empty");
    }

  return format (s, "SRv6-AD-rewrite: src %U dst %U",
		 format_ip6_address, &t->src, format_ip6_address, &t->dst);
}


/***************************** Nodes registration *****************************/

vlib_node_registration_t srv6_ad4_rewrite_node;
vlib_node_registration_t srv6_ad6_rewrite_node;


/****************************** Packet counters *******************************/

#define foreach_srv6_ad_rewrite_counter \
_(PROCESSED, "srv6-ad rewritten packets") \
_(NO_RW, "(Error) No header for rewriting.")

typedef enum
{
#define _(sym,str) SRV6_AD_REWRITE_COUNTER_##sym,
  foreach_srv6_ad_rewrite_counter
#undef _
    SRV6_AD_REWRITE_N_COUNTERS,
} srv6_ad_rewrite_counters;

static char *srv6_ad_rewrite_counter_strings[] = {
#define _(sym,string) string,
  foreach_srv6_ad_rewrite_counter
#undef _
};


/********************************* Next nodes *********************************/

typedef enum
{
  SRV6_AD_LOCALSID_NEXT_ERROR,
  SRV6_AD_LOCALSID_NEXT_REWRITE4,
  SRV6_AD_LOCALSID_NEXT_REWRITE6,
  SRV6_AD_LOCALSID_NEXT_INTERFACE,
  SRV6_AD_LOCALSID_N_NEXT,
} srv6_ad_localsid_next_t;

typedef enum
{
  SRV6_AD_REWRITE_NEXT_ERROR,
  SRV6_AD_REWRITE_NEXT_LOOKUP,
  SRV6_AD_REWRITE_N_NEXT,
} srv6_ad_rewrite_next_t;


/******************************* Local SID node *******************************/

/**
 * @brief Function doing SRH processing for AD behavior
 */
static_always_inline void
end_ad_processing (vlib_buffer_t * b0,
		   ip6_header_t * ip0,
		   ip6_sr_header_t * sr0,
		   ip6_sr_localsid_t * ls0, u32 * next0)
{
  ip6_address_t *new_dst0;
  u16 total_size;
  ip6_ext_header_t *next_ext_header;
  u8 next_hdr;
  srv6_ad_localsid_t *ls0_mem;

  if (PREDICT_FALSE (ip0->protocol != IP_PROTOCOL_IPV6_ROUTE ||
		     sr0->type != ROUTING_HEADER_TYPE_SR))
    {
      return;
    }

  if (PREDICT_FALSE (sr0->segments_left == 0))
    {
      return;
    }

  /* Decrement Segments Left and update Destination Address */
  sr0->segments_left -= 1;
  new_dst0 = (ip6_address_t *) (sr0->segments) + sr0->segments_left;
  ip0->dst_address.as_u64[0] = new_dst0->as_u64[0];
  ip0->dst_address.as_u64[1] = new_dst0->as_u64[1];

  /* Compute the total size of the IPv6 header and extensions */
  total_size = sizeof (ip6_header_t);
  next_ext_header = (ip6_ext_header_t *) (ip0 + 1);
  next_hdr = ip0->protocol;

  while (ip6_ext_hdr (next_hdr))
    {
      total_size += ip6_ext_header_len (next_ext_header);
      next_hdr = next_ext_header->next_hdr;
      next_ext_header = ip6_ext_next_header (next_ext_header);
    }

  /* Make sure next header is valid */
  if (PREDICT_FALSE (next_hdr != IP_PROTOCOL_IPV6 &&
		     next_hdr != IP_PROTOCOL_IP_IN_IP &&
		     next_hdr != IP_PROTOCOL_IP6_ETHERNET))
    {
      return;
    }

  /* Retrieve SID memory */
  ls0_mem = ls0->plugin_mem;

  /* Cache IP header and extensions */
  if (PREDICT_FALSE (total_size > ls0_mem->rw_len))
    {
      vec_validate (ls0_mem->rewrite, total_size - 1);
    }
  clib_memcpy_fast (ls0_mem->rewrite, ip0, total_size);
  ls0_mem->rw_len = total_size;

  /* Remove IP header and extensions */
  vlib_buffer_advance (b0, total_size);

  if (next_hdr == IP_PROTOCOL_IP6_ETHERNET)
    {
      /* Set output interface */
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = ls0_mem->sw_if_index_out;

      /* Set next node to interface-output */
      *next0 = SRV6_AD_LOCALSID_NEXT_INTERFACE;
    }
  else
    {
      /* Set Xconnect adjacency to VNF */
      vnet_buffer (b0)->ip.adj_index = ls0_mem->nh_adj;

      /* Set next node to ip-rewrite */
      *next0 = (next_hdr == IP_PROTOCOL_IPV6) ?
	SRV6_AD_LOCALSID_NEXT_REWRITE6 : SRV6_AD_LOCALSID_NEXT_REWRITE4;
    }
}

/**
 * @brief SRv6 AD Localsid graph node
 */
static uword
srv6_ad_localsid_fn (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  ip6_sr_main_t *sm = &sr_main;
  u32 n_left_from, next_index, *from, *to_next;
  u32 cnt_packets = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* TODO: Dual/quad loop */

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0 = 0;
	  ip6_sr_header_t *sr0;
	  ip6_sr_localsid_t *ls0;
	  u32 next0 = SRV6_AD_LOCALSID_NEXT_ERROR;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (b0);
	  sr0 = (ip6_sr_header_t *) (ip0 + 1);

	  /* Lookup the SR End behavior based on IP DA (adj) */
	  ls0 = pool_elt_at_index (sm->localsids,
				   vnet_buffer (b0)->ip.adj_index);

	  /* SRH processing */
	  end_ad_processing (b0, ip0, sr0, ls0, &next0);

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      srv6_ad_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof *tr);
	      tr->localsid_index = ls0 - sm->localsids;
	    }

	  /* This increments the SRv6 per LocalSID counters. */
	  vlib_increment_combined_counter (((next0 ==
					     SRV6_AD_LOCALSID_NEXT_ERROR) ?
					    &(sm->sr_ls_invalid_counters) :
					    &(sm->sr_ls_valid_counters)),
					   vm->thread_index,
					   ls0 - sm->localsids, 1,
					   vlib_buffer_length_in_chain (vm,
									b0));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	  cnt_packets++;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (srv6_ad_localsid_node) = {
  .function = srv6_ad_localsid_fn,
  .name = "srv6-ad-localsid",
  .vector_size = sizeof (u32),
  .format_trace = format_srv6_ad_localsid_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = SRV6_AD_LOCALSID_N_NEXT,
  .next_nodes = {
    [SRV6_AD_LOCALSID_NEXT_REWRITE4] = "ip4-rewrite",
    [SRV6_AD_LOCALSID_NEXT_REWRITE6] = "ip6-rewrite",
    [SRV6_AD_LOCALSID_NEXT_INTERFACE] = "interface-output",
    [SRV6_AD_LOCALSID_NEXT_ERROR] = "error-drop",
  },
};
/* *INDENT-ON* */


/******************************* Rewriting node *******************************/

/**
 * @brief Graph node for applying a SR policy into an IPv6 packet. Encapsulation
 */
static uword
srv6_ad2_rewrite_fn (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  ip6_sr_main_t *srm = &sr_main;
  srv6_ad_main_t *sm = &srv6_ad_main;
  u32 n_left_from, next_index, *from, *to_next;
  u32 cnt_packets = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* TODO: Dual/quad loop */

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ethernet_header_t *en0;
	  ip6_header_t *ip0 = 0;
	  ip6_sr_localsid_t *ls0;
	  srv6_ad_localsid_t *ls0_mem;
	  u32 next0 = SRV6_AD_REWRITE_NEXT_LOOKUP;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  en0 = vlib_buffer_get_current (b0);
	  ls0 = pool_elt_at_index (srm->localsids,
				   sm->sw_iface_localsid2[vnet_buffer
							  (b0)->sw_if_index
							  [VLIB_RX]]);
	  ls0_mem = ls0->plugin_mem;

	  if (PREDICT_FALSE (ls0_mem == NULL || ls0_mem->rewrite == NULL))
	    {
	      next0 = SRV6_AD_REWRITE_NEXT_ERROR;
	      b0->error = node->errors[SRV6_AD_REWRITE_COUNTER_NO_RW];
	    }
	  else
	    {
	      ASSERT (VLIB_BUFFER_PRE_DATA_SIZE >=
		      (ls0_mem->rw_len + b0->current_data));

	      clib_memcpy_fast (((u8 *) en0) - ls0_mem->rw_len,
				ls0_mem->rewrite, ls0_mem->rw_len);
	      vlib_buffer_advance (b0, -(word) ls0_mem->rw_len);

	      ip0 = vlib_buffer_get_current (b0);

	      ip0->payload_length =
		clib_host_to_net_u16 (b0->current_length -
				      sizeof (ip6_header_t));
	    }

	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	      PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      srv6_ad_rewrite_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof *tr);
	      tr->error = 0;

	      if (next0 == SRV6_AD_REWRITE_NEXT_ERROR)
		{
		  tr->error = 1;
		}
	      else
		{
		  clib_memcpy_fast (tr->src.as_u8, ip0->src_address.as_u8,
				    sizeof tr->src.as_u8);
		  clib_memcpy_fast (tr->dst.as_u8, ip0->dst_address.as_u8,
				    sizeof tr->dst.as_u8);
		}
	    }

	  /* Increment per-SID AD rewrite counters */
	  vlib_increment_combined_counter (((next0 ==
					     SRV6_AD_LOCALSID_NEXT_ERROR) ?
					    &(sm->invalid_counters) :
					    &(sm->valid_counters)),
					   vm->thread_index, ls0_mem->index,
					   1, vlib_buffer_length_in_chain (vm,
									   b0));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	  cnt_packets++;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Update counters */
  vlib_node_increment_counter (vm, srv6_ad4_rewrite_node.index,
			       SRV6_AD_REWRITE_COUNTER_PROCESSED,
			       cnt_packets);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (srv6_ad2_rewrite_node) = {
  .function = srv6_ad2_rewrite_fn,
  .name = "srv6-ad2-rewrite",
  .vector_size = sizeof (u32),
  .format_trace = format_srv6_ad_rewrite_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = SRV6_AD_REWRITE_N_COUNTERS,
  .error_strings = srv6_ad_rewrite_counter_strings,
  .n_next_nodes = SRV6_AD_REWRITE_N_NEXT,
  .next_nodes = {
    [SRV6_AD_REWRITE_NEXT_LOOKUP] = "ip6-lookup",
    [SRV6_AD_REWRITE_NEXT_ERROR] = "error-drop",
  },
};
/* *INDENT-ON* */


/**
 * @brief Graph node for applying a SR policy into an IPv6 packet. Encapsulation
 */
static uword
srv6_ad4_rewrite_fn (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  ip6_sr_main_t *srm = &sr_main;
  srv6_ad_main_t *sm = &srv6_ad_main;
  u32 n_left_from, next_index, *from, *to_next;
  u32 cnt_packets = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* TODO: Dual/quad loop */

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ip4_header_t *ip0_encap = 0;
	  ip6_header_t *ip0 = 0;
	  ip6_sr_localsid_t *ls0;
	  srv6_ad_localsid_t *ls0_mem;
	  u32 next0 = SRV6_AD_REWRITE_NEXT_LOOKUP;
	  u16 new_l0 = 0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip0_encap = vlib_buffer_get_current (b0);
	  ls0 = pool_elt_at_index (srm->localsids,
				   sm->sw_iface_localsid4[vnet_buffer
							  (b0)->sw_if_index
							  [VLIB_RX]]);
	  ls0_mem = ls0->plugin_mem;

	  if (PREDICT_FALSE (ls0_mem == NULL || ls0_mem->rewrite == NULL))
	    {
	      next0 = SRV6_AD_REWRITE_NEXT_ERROR;
	      b0->error = node->errors[SRV6_AD_REWRITE_COUNTER_NO_RW];
	    }
	  else
	    {
	      ASSERT (VLIB_BUFFER_PRE_DATA_SIZE >=
		      (ls0_mem->rw_len + b0->current_data));

	      clib_memcpy_fast (((u8 *) ip0_encap) - ls0_mem->rw_len,
				ls0_mem->rewrite, ls0_mem->rw_len);
	      vlib_buffer_advance (b0, -(word) ls0_mem->rw_len);

	      ip0 = vlib_buffer_get_current (b0);

	      /* Update inner IPv4 TTL and checksum */
	      u32 checksum0;
	      ip0_encap->ttl -= 1;
	      checksum0 = ip0_encap->checksum + clib_host_to_net_u16 (0x0100);
	      checksum0 += checksum0 >= 0xffff;
	      ip0_encap->checksum = checksum0;

	      /* Update outer IPv6 length (in case it has changed) */
	      new_l0 = ls0_mem->rw_len - sizeof (ip6_header_t) +
		clib_net_to_host_u16 (ip0_encap->length);
	      ip0->payload_length = clib_host_to_net_u16 (new_l0);
	    }

	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	      PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      srv6_ad_rewrite_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof *tr);
	      tr->error = 0;

	      if (next0 == SRV6_AD_REWRITE_NEXT_ERROR)
		{
		  tr->error = 1;
		}
	      else
		{
		  clib_memcpy_fast (tr->src.as_u8, ip0->src_address.as_u8,
				    sizeof tr->src.as_u8);
		  clib_memcpy_fast (tr->dst.as_u8, ip0->dst_address.as_u8,
				    sizeof tr->dst.as_u8);
		}
	    }

	  /* Increment per-SID AD rewrite counters */
	  vlib_increment_combined_counter (((next0 ==
					     SRV6_AD_LOCALSID_NEXT_ERROR) ?
					    &(sm->invalid_counters) :
					    &(sm->valid_counters)),
					   vm->thread_index, ls0_mem->index,
					   1, vlib_buffer_length_in_chain (vm,
									   b0));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	  cnt_packets++;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Update counters */
  vlib_node_increment_counter (vm, srv6_ad4_rewrite_node.index,
			       SRV6_AD_REWRITE_COUNTER_PROCESSED,
			       cnt_packets);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (srv6_ad4_rewrite_node) = {
  .function = srv6_ad4_rewrite_fn,
  .name = "srv6-ad4-rewrite",
  .vector_size = sizeof (u32),
  .format_trace = format_srv6_ad_rewrite_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = SRV6_AD_REWRITE_N_COUNTERS,
  .error_strings = srv6_ad_rewrite_counter_strings,
  .n_next_nodes = SRV6_AD_REWRITE_N_NEXT,
  .next_nodes = {
      [SRV6_AD_REWRITE_NEXT_LOOKUP] = "ip6-lookup",
      [SRV6_AD_REWRITE_NEXT_ERROR] = "error-drop",
  },
};
/* *INDENT-ON* */


/**
 * @brief Graph node for applying a SR policy into an IPv6 packet. Encapsulation
 */
static uword
srv6_ad6_rewrite_fn (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  ip6_sr_main_t *srm = &sr_main;
  srv6_ad_main_t *sm = &srv6_ad_main;
  u32 n_left_from, next_index, *from, *to_next;
  u32 cnt_packets = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* TODO: Dual/quad loop */

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0 = 0, *ip0_encap = 0;
	  ip6_sr_localsid_t *ls0;
	  srv6_ad_localsid_t *ls0_mem;
	  u32 next0 = SRV6_AD_REWRITE_NEXT_LOOKUP;
	  u16 new_l0 = 0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip0_encap = vlib_buffer_get_current (b0);
	  ls0 = pool_elt_at_index (srm->localsids,
				   sm->sw_iface_localsid6[vnet_buffer
							  (b0)->sw_if_index
							  [VLIB_RX]]);
	  ls0_mem = ls0->plugin_mem;

	  if (PREDICT_FALSE (ls0_mem == NULL || ls0_mem->rewrite == NULL))
	    {
	      next0 = SRV6_AD_REWRITE_NEXT_ERROR;
	      b0->error = node->errors[SRV6_AD_REWRITE_COUNTER_NO_RW];
	    }
	  else
	    {
	      ASSERT (VLIB_BUFFER_PRE_DATA_SIZE >=
		      (ls0_mem->rw_len + b0->current_data));

	      clib_memcpy_fast (((u8 *) ip0_encap) - ls0_mem->rw_len,
				ls0_mem->rewrite, ls0_mem->rw_len);
	      vlib_buffer_advance (b0, -(word) ls0_mem->rw_len);

	      ip0 = vlib_buffer_get_current (b0);

	      /* Update inner IPv6 hop limit */
	      ip0_encap->hop_limit -= 1;

	      /* Update outer IPv6 length (in case it has changed) */
	      new_l0 = ls0_mem->rw_len +
		clib_net_to_host_u16 (ip0_encap->payload_length);
	      ip0->payload_length = clib_host_to_net_u16 (new_l0);
	    }

	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	      PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      srv6_ad_rewrite_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof *tr);
	      tr->error = 0;

	      if (next0 == SRV6_AD_REWRITE_NEXT_ERROR)
		{
		  tr->error = 1;
		}
	      else
		{
		  clib_memcpy_fast (tr->src.as_u8, ip0->src_address.as_u8,
				    sizeof tr->src.as_u8);
		  clib_memcpy_fast (tr->dst.as_u8, ip0->dst_address.as_u8,
				    sizeof tr->dst.as_u8);
		}
	    }

	  /* Increment per-SID AD rewrite counters */
	  vlib_increment_combined_counter (((next0 ==
					     SRV6_AD_LOCALSID_NEXT_ERROR) ?
					    &(sm->invalid_counters) :
					    &(sm->valid_counters)),
					   vm->thread_index, ls0_mem->index,
					   1, vlib_buffer_length_in_chain (vm,
									   b0));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	  cnt_packets++;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Update counters */
  vlib_node_increment_counter (vm, srv6_ad6_rewrite_node.index,
			       SRV6_AD_REWRITE_COUNTER_PROCESSED,
			       cnt_packets);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (srv6_ad6_rewrite_node) = {
  .function = srv6_ad6_rewrite_fn,
  .name = "srv6-ad6-rewrite",
  .vector_size = sizeof (u32),
  .format_trace = format_srv6_ad_rewrite_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = SRV6_AD_REWRITE_N_COUNTERS,
  .error_strings = srv6_ad_rewrite_counter_strings,
  .n_next_nodes = SRV6_AD_REWRITE_N_NEXT,
  .next_nodes = {
      [SRV6_AD_REWRITE_NEXT_LOOKUP] = "ip6-lookup",
      [SRV6_AD_REWRITE_NEXT_ERROR] = "error-drop",
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
