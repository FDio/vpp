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
#include <srv6-ad-flow/ad-flow.h>

/****************************** Packet tracing ******************************/

typedef struct
{
  u32 localsid_index;
} srv6_ad_flow_localsid_trace_t;

typedef struct
{
  u8 error;
  ip6_address_t src, dst;
} srv6_ad_flow_rewrite_trace_t;

static u8 *
format_srv6_ad_flow_localsid_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  srv6_ad_flow_localsid_trace_t *t =
    va_arg (*args, srv6_ad_flow_localsid_trace_t *);

  return format (s, "SRv6-AD-Flow-localsid: localsid_index %d",
		 t->localsid_index);
}

static u8 *
format_srv6_ad_flow_rewrite_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  srv6_ad_flow_rewrite_trace_t *t =
    va_arg (*args, srv6_ad_flow_rewrite_trace_t *);

  if (PREDICT_FALSE (t->error != 0))
    {
      return format (s, "SRv6-AD-Flow-rewrite: cache is empty");
    }

  return format (s, "SRv6-AD-Flow-rewrite: src %U dst %U", format_ip6_address,
		 &t->src, format_ip6_address, &t->dst);
}

/**************************** Nodes registration *****************************/

vlib_node_registration_t srv6_ad4_flow_rewrite_node;
vlib_node_registration_t srv6_ad6_flow_rewrite_node;

/****************************** Packet counters ******************************/

#define foreach_srv6_ad_flow_rewrite_counter                                  \
  _ (PROCESSED, "srv6-ad-flow rewritten packets")                             \
  _ (NO_RW, "(Error) No header for rewriting.")

typedef enum
{
#define _(sym, str) SRV6_AD_FLOW_REWRITE_COUNTER_##sym,
  foreach_srv6_ad_flow_rewrite_counter
#undef _
    SRV6_AD_FLOW_REWRITE_N_COUNTERS,
} srv6_ad_flow_rewrite_counters;

static char *srv6_ad_flow_rewrite_counter_strings[] = {
#define _(sym, string) string,
  foreach_srv6_ad_flow_rewrite_counter
#undef _
};

/******************************** Next nodes *********************************/

typedef enum
{
  SRV6_AD_FLOW_LOCALSID_NEXT_ERROR,
  SRV6_AD_FLOW_LOCALSID_NEXT_REWRITE4,
  SRV6_AD_FLOW_LOCALSID_NEXT_REWRITE6,
  SRV6_AD_FLOW_LOCALSID_NEXT_BYPASS,
  SRV6_AD_FLOW_LOCALSID_NEXT_PUNT,
  SRV6_AD_FLOW_LOCALSID_N_NEXT,
} srv6_ad_flow_localsid_next_t;

typedef enum
{
  SRV6_AD_FLOW_REWRITE_NEXT_ERROR,
  SRV6_AD_FLOW_REWRITE_NEXT_LOOKUP,
  SRV6_AD_FLOW_REWRITE_N_NEXT,
} srv6_ad_flow_rewrite_next_t;

/***************************** Inline functions ******************************/

static_always_inline int
ad_flow_lru_insert (srv6_ad_flow_localsid_t *ls, srv6_ad_flow_entry_t *e,
		    f64 now)
{
  dlist_elt_t *lru_list_elt;
  pool_get (ls->lru_pool, lru_list_elt);
  e->lru_index = lru_list_elt - ls->lru_pool;
  clib_dlist_addtail (ls->lru_pool, ls->lru_head_index, e->lru_index);
  lru_list_elt->value = e - ls->cache;
  e->last_lru_update = now;
  return 1;
}

always_inline void
ad_flow_entry_update_lru (srv6_ad_flow_localsid_t *ls, srv6_ad_flow_entry_t *e)
{
  /* don't update too often - timeout is in magnitude of seconds anyway */
  if (e->last_heard > e->last_lru_update + 1)
    {
      clib_dlist_remove (ls->lru_pool, e->lru_index);
      clib_dlist_addtail (ls->lru_pool, ls->lru_head_index, e->lru_index);
      e->last_lru_update = e->last_heard;
    }
}

always_inline void
ad_flow_entry_delete (srv6_ad_flow_localsid_t *ls, srv6_ad_flow_entry_t *e,
		      int lru_delete)
{
  clib_bihash_kv_40_8_t kv;

  if (ls->inner_type == AD_TYPE_IP4)
    {
      kv.key[0] = ((u64) e->key.s_addr.ip4.as_u32 << 32) |
		  (u64) e->key.d_addr.ip4.as_u32;
      kv.key[1] = ((u64) e->key.s_port << 16) | ((u64) e->key.d_port);
      kv.key[2] = 0;
      kv.key[3] = 0;
      kv.key[4] = 0;
    }
  else
    {
      kv.key[0] = e->key.s_addr.ip6.as_u64[0];
      kv.key[1] = e->key.s_addr.ip6.as_u64[1];
      kv.key[2] = e->key.d_addr.ip6.as_u64[0];
      kv.key[3] = e->key.d_addr.ip6.as_u64[1];
      kv.key[4] = ((u64) e->key.s_port << 16) | ((u64) e->key.d_port);
    }

  clib_bihash_add_del_40_8 (&ls->ftable, &kv, 0);

  vec_free (e->rw_data);

  if (lru_delete)
    {
      clib_dlist_remove (ls->lru_pool, e->lru_index);
    }
  pool_put_index (ls->lru_pool, e->lru_index);
  pool_put (ls->cache, e);
}

static_always_inline int
ad_flow_lru_free_one (srv6_ad_flow_localsid_t *ls, f64 now)
{
  srv6_ad_flow_entry_t *e = NULL;
  dlist_elt_t *oldest_elt;
  f64 entry_timeout_time;
  u32 oldest_index;
  oldest_index = clib_dlist_remove_head (ls->lru_pool, ls->lru_head_index);
  if (~0 != oldest_index)
    {
      oldest_elt = pool_elt_at_index (ls->lru_pool, oldest_index);
      e = pool_elt_at_index (ls->cache, oldest_elt->value);

      entry_timeout_time = e->last_heard + (f64) SRV6_AD_CACHE_TIMEOUT;
      if (now >= entry_timeout_time)
	{
	  ad_flow_entry_delete (ls, e, 0);
	  return 1;
	}
      else
	{
	  clib_dlist_addhead (ls->lru_pool, ls->lru_head_index, oldest_index);
	}
    }
  return 0;
}

static_always_inline srv6_ad_flow_entry_t *
ad_flow_entry_alloc (srv6_ad_flow_localsid_t *ls, f64 now)
{
  srv6_ad_flow_entry_t *e;

  ad_flow_lru_free_one (ls, now);

  pool_get (ls->cache, e);
  clib_memset (e, 0, sizeof *e);

  ad_flow_lru_insert (ls, e, now);

  return e;
}

always_inline u32
ad_flow_value_get_session_index (clib_bihash_kv_40_8_t *value)
{
  return value->value & ~(u32) 0;
}

int
ad_flow_is_idle_entry_cb (clib_bihash_kv_40_8_t *kv, void *arg)
{
  srv6_ad_is_idle_entry_ctx_t *ctx = arg;
  srv6_ad_flow_entry_t *e;
  u64 entry_timeout_time;
  srv6_ad_flow_localsid_t *ls = ctx->ls;

  e = pool_elt_at_index (ls->cache, ad_flow_value_get_session_index (kv));
  entry_timeout_time = e->last_heard + (f64) SRV6_AD_CACHE_TIMEOUT;
  if (ctx->now >= entry_timeout_time)
    {
      ad_flow_entry_delete (ls, e, 1);
      return 1;
    }
  return 0;
}

/****************************** Local SID node *******************************/

/**
 * @brief Function doing SRH processing for AD behavior
 */
static_always_inline int
end_ad_flow_walk_expect_first_hdr (vlib_main_t *vm, vlib_buffer_t *b,
				   ip6_ext_header_t *first_hdr,
				   u8 first_hdr_type, u8 expected_hdr_type,
				   u32 *encap_length, u8 **found_hdr)
{
  if (PREDICT_TRUE (first_hdr_type == expected_hdr_type))
    {
      *found_hdr = (void *) first_hdr;
    }
  else
    {
      u8 ext_hdr_type = first_hdr_type;
      ip6_ext_header_t *ext_hdr = first_hdr;

      if (!ip6_ext_hdr (ext_hdr_type))
	{
	  *found_hdr = NULL;
	  return -1;
	}

      u32 ext_hdr_length = ip6_ext_header_len (ext_hdr);
      if (!vlib_object_within_buffer_data (vm, b, ext_hdr, ext_hdr_length))
	{
	  *found_hdr = NULL;
	  return -2;
	}
      *encap_length += ext_hdr_length;
      ext_hdr_type = ext_hdr->next_hdr;

      while (ext_hdr_type != expected_hdr_type && ip6_ext_hdr (ext_hdr_type))
	{
	  ext_hdr = ip6_ext_next_header (ext_hdr);
	  ext_hdr_length = ip6_ext_header_len (ext_hdr);
	  if (!vlib_object_within_buffer_data (vm, b, ext_hdr, ext_hdr_length))
	    {
	      *found_hdr = NULL;
	      return -2;
	    }
	  *encap_length += ext_hdr_length;
	  ext_hdr_type = ext_hdr->next_hdr;
	}

      if (ext_hdr_type != expected_hdr_type)
	{
	  *found_hdr = NULL;
	  return -1;
	}

      *found_hdr = ip6_ext_next_header (ext_hdr);
    }

  return 0;
}

/**
 * @brief Function doing SRH processing for per-flow AD behavior (IPv6 inner
 * traffic)
 */
static_always_inline void
end_ad_flow_processing_v6 (vlib_main_t *vm, vlib_buffer_t *b, ip6_header_t *ip,
			   srv6_ad_flow_localsid_t *ls_mem, u32 *next,
			   vlib_combined_counter_main_t **cnt, u32 *cnt_idx,
			   f64 now)
{
  ip6_sr_main_t *srm = &sr_main;
  srv6_ad_flow_main_t *sm = &srv6_ad_flow_main;
  ip6_address_t *new_dst;
  u32 encap_length = sizeof (ip6_header_t);
  ip6_sr_header_t *srh;
  clib_bihash_40_8_t *h = &ls_mem->ftable;
  ip6_header_t *ulh = NULL;
  u16 src_port = 0, dst_port = 0;
  srv6_ad_flow_entry_t *e = NULL;
  clib_bihash_kv_40_8_t kv, value;
  srv6_ad_is_idle_entry_ctx_t ctx;

  /* Find SRH in the extension header chain */
  end_ad_flow_walk_expect_first_hdr (vm, b, (void *) (ip + 1), ip->protocol,
				     IP_PROTOCOL_IPV6_ROUTE, &encap_length,
				     (u8 **) &srh);

  /* Punt the packet if no SRH or SRH with SL = 0 */
  if (PREDICT_FALSE (srh == NULL || srh->type != ROUTING_HEADER_TYPE_SR ||
		     srh->segments_left == 0))
    {
      *next = SRV6_AD_FLOW_LOCALSID_NEXT_PUNT;
      *cnt = &(sm->sid_punt_counters);
      *cnt_idx = ls_mem->index;
      return;
    }

  /* Decrement Segments Left and update Destination Address */
  srh->segments_left -= 1;
  new_dst = (ip6_address_t *) (srh->segments) + srh->segments_left;
  ip->dst_address.as_u64[0] = new_dst->as_u64[0];
  ip->dst_address.as_u64[1] = new_dst->as_u64[1];

  /* Compute the total encapsulation size and determine ULH type */
  encap_length += ip6_ext_header_len ((ip6_ext_header_t *) srh);

  /* Find the inner IPv6 header (ULH) */
  int ret = end_ad_flow_walk_expect_first_hdr (
    vm, b, ip6_ext_next_header ((ip6_ext_header_t *) srh), srh->protocol,
    IP_PROTOCOL_IPV6, &encap_length, (u8 **) &ulh);

  if (PREDICT_FALSE (ulh == NULL))
    {
      if (ret == -1) /* Bypass the NF if ULH is not of expected type */
	{
	  *next = SRV6_AD_FLOW_LOCALSID_NEXT_BYPASS;
	  *cnt = &(sm->sid_bypass_counters);
	  *cnt_idx = ls_mem->index;
	}
      else
	{
	  *next = SRV6_AD_FLOW_LOCALSID_NEXT_ERROR;
	  *cnt = &(srm->sr_ls_invalid_counters);
	}
      return;
    }

  /* Compute flow hash on ULH */
  if (PREDICT_TRUE (ulh->protocol == IP_PROTOCOL_UDP ||
		    ulh->protocol == IP_PROTOCOL_TCP))
    {
      udp_header_t *ulh_l4_hdr = (udp_header_t *) (ulh + 1);
      src_port = ulh_l4_hdr->src_port;
      dst_port = ulh_l4_hdr->dst_port;
    }

  kv.key[0] = ulh->src_address.as_u64[0];
  kv.key[1] = ulh->src_address.as_u64[1];
  kv.key[2] = ulh->dst_address.as_u64[0];
  kv.key[3] = ulh->dst_address.as_u64[1];
  kv.key[4] = ((u64) src_port << 16) | ((u64) dst_port);

  /* Lookup flow in hashtable */
  if (!clib_bihash_search_40_8 (h, &kv, &value))
    {
      e = pool_elt_at_index (ls_mem->cache,
			     ad_flow_value_get_session_index (&value));
    }

  if (!e)
    {
      if (pool_elts (ls_mem->cache) >= ls_mem->cache_size)
	{
	  if (!ad_flow_lru_free_one (ls_mem, now))
	    {
	      *next = SRV6_AD_FLOW_LOCALSID_NEXT_ERROR;
	      *cnt = &(sm->sid_cache_full_counters);
	      *cnt_idx = ls_mem->index;
	      return;
	    }
	}

      e = ad_flow_entry_alloc (ls_mem, now);
      ASSERT (e);
      e->key.s_addr.ip6.as_u64[0] = ulh->src_address.as_u64[0];
      e->key.s_addr.ip6.as_u64[1] = ulh->src_address.as_u64[1];
      e->key.d_addr.ip6.as_u64[0] = ulh->dst_address.as_u64[0];
      e->key.d_addr.ip6.as_u64[1] = ulh->dst_address.as_u64[1];
      e->key.s_port = src_port;
      e->key.d_port = dst_port;
      e->key.proto = ulh->protocol;

      kv.value = (u64) (e - ls_mem->cache);

      ctx.now = now;
      ctx.ls = ls_mem;
      clib_bihash_add_or_overwrite_stale_40_8 (h, &kv,
					       ad_flow_is_idle_entry_cb, &ctx);
    }
  e->last_heard = now;

  /* Cache encapsulation headers */
  if (PREDICT_FALSE (encap_length > e->rw_len))
    {
      vec_validate (e->rw_data, encap_length - 1);
    }
  clib_memcpy_fast (e->rw_data, ip, encap_length);
  e->rw_len = encap_length;

  /* Update LRU */
  ad_flow_entry_update_lru (ls_mem, e);

  /* Decapsulate the packet */
  vlib_buffer_advance (b, encap_length);

  /* Set next node */
  *next = SRV6_AD_FLOW_LOCALSID_NEXT_REWRITE6;

  /* Set Xconnect adjacency to VNF */
  vnet_buffer (b)->ip.adj_index[VLIB_TX] = ls_mem->nh_adj;
}

static_always_inline void
end_ad_flow_processing_v4 (vlib_main_t *vm, vlib_buffer_t *b, ip6_header_t *ip,
			   srv6_ad_flow_localsid_t *ls_mem, u32 *next,
			   vlib_combined_counter_main_t **cnt, u32 *cnt_idx,
			   f64 now)
{
  ip6_sr_main_t *srm = &sr_main;
  srv6_ad_flow_main_t *sm = &srv6_ad_flow_main;
  ip6_address_t *new_dst;
  u32 encap_length = sizeof (ip6_header_t);
  ip6_sr_header_t *srh;
  clib_bihash_40_8_t *h = &ls_mem->ftable;
  ip4_header_t *ulh = NULL;
  u16 src_port = 0, dst_port = 0;
  srv6_ad_flow_entry_t *e = NULL;
  clib_bihash_kv_40_8_t kv, value;
  srv6_ad_is_idle_entry_ctx_t ctx;

  /* Find SRH in the extension header chain */
  end_ad_flow_walk_expect_first_hdr (vm, b, (void *) (ip + 1), ip->protocol,
				     IP_PROTOCOL_IPV6_ROUTE, &encap_length,
				     (u8 **) &srh);

  /* Punt the packet if no SRH or SRH with SL = 0 */
  if (PREDICT_FALSE (srh == NULL || srh->type != ROUTING_HEADER_TYPE_SR ||
		     srh->segments_left == 0))
    {
      *next = SRV6_AD_FLOW_LOCALSID_NEXT_PUNT;
      *cnt = &(sm->sid_punt_counters);
      *cnt_idx = ls_mem->index;
      return;
    }

  /* Decrement Segments Left and update Destination Address */
  srh->segments_left -= 1;
  new_dst = (ip6_address_t *) (srh->segments) + srh->segments_left;
  ip->dst_address.as_u64[0] = new_dst->as_u64[0];
  ip->dst_address.as_u64[1] = new_dst->as_u64[1];

  /* Add SRH length to the total encapsulation size */
  encap_length += ip6_ext_header_len ((ip6_ext_header_t *) srh);

  /* Find the inner IPv6 header (ULH) */
  int ret = end_ad_flow_walk_expect_first_hdr (
    vm, b, ip6_ext_next_header ((ip6_ext_header_t *) srh), srh->protocol,
    IP_PROTOCOL_IP_IN_IP, &encap_length, (u8 **) &ulh);

  if (PREDICT_FALSE (ulh == NULL))
    {
      if (ret == -1) /* Bypass the NF if ULH is not of expected type */
	{
	  *next = SRV6_AD_FLOW_LOCALSID_NEXT_BYPASS;
	  *cnt = &(sm->sid_bypass_counters);
	  *cnt_idx = ls_mem->index;
	}
      else
	{
	  *next = SRV6_AD_FLOW_LOCALSID_NEXT_ERROR;
	  *cnt = &(srm->sr_ls_invalid_counters);
	}
      return;
    }

  /* Compute flow hash on ULH */
  if (PREDICT_TRUE (ulh->protocol == IP_PROTOCOL_UDP ||
		    ulh->protocol == IP_PROTOCOL_TCP))
    {
      udp_header_t *ulh_l4_hdr = (udp_header_t *) (ulh + 1);
      src_port = ulh_l4_hdr->src_port;
      dst_port = ulh_l4_hdr->dst_port;
    }

  kv.key[0] = *((u64 *) &ulh->address_pair);
  kv.key[1] = ((u64) src_port << 16) | ((u64) dst_port);
  kv.key[2] = 0;
  kv.key[3] = 0;
  kv.key[4] = 0;

  /* Lookup flow in hashtable */
  if (!clib_bihash_search_40_8 (h, &kv, &value))
    {
      e = pool_elt_at_index (ls_mem->cache,
			     ad_flow_value_get_session_index (&value));
    }

  if (!e)
    {
      if (pool_elts (ls_mem->cache) >= ls_mem->cache_size)
	{
	  if (!ad_flow_lru_free_one (ls_mem, now))
	    {
	      *next = SRV6_AD_FLOW_LOCALSID_NEXT_ERROR;
	      *cnt = &(sm->sid_cache_full_counters);
	      *cnt_idx = ls_mem->index;
	      return;
	    }
	}

      e = ad_flow_entry_alloc (ls_mem, now);
      ASSERT (e);
      e->key.s_addr.ip4 = ulh->src_address;
      e->key.d_addr.ip4 = ulh->dst_address;
      e->key.s_port = src_port;
      e->key.d_port = dst_port;
      e->key.proto = ulh->protocol;

      kv.value = (u64) (e - ls_mem->cache);

      ctx.now = now;
      ctx.ls = ls_mem;
      clib_bihash_add_or_overwrite_stale_40_8 (h, &kv,
					       ad_flow_is_idle_entry_cb, &ctx);
    }
  e->last_heard = now;

  /* Cache encapsulation headers */
  if (PREDICT_FALSE (encap_length > e->rw_len))
    {
      vec_validate (e->rw_data, encap_length - 1);
    }
  clib_memcpy_fast (e->rw_data, ip, encap_length);
  e->rw_len = encap_length;

  /* Update LRU */
  ad_flow_entry_update_lru (ls_mem, e);

  /* Decapsulate the packet */
  vlib_buffer_advance (b, encap_length);

  /* Set next node */
  *next = SRV6_AD_FLOW_LOCALSID_NEXT_REWRITE4;

  /* Set Xconnect adjacency to VNF */
  vnet_buffer (b)->ip.adj_index[VLIB_TX] = ls_mem->nh_adj;
}

/**
 * @brief SRv6 AD Localsid graph node
 */
static uword
srv6_ad_flow_localsid_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_frame_t *frame)
{
  ip6_sr_main_t *srm = &sr_main;
  f64 now = vlib_time_now (vm);
  u32 n_left_from, next_index, *from, *to_next, n_left_to_next;
  u32 thread_index = vm->thread_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* TODO: Dual/quad loop */

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0 = 0;
	  ip6_sr_localsid_t *ls0;
	  srv6_ad_flow_localsid_t *ls_mem0;
	  u32 next0;
	  vlib_combined_counter_main_t *cnt0 = &(srm->sr_ls_valid_counters);
	  u32 cnt_idx0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (b0);

	  /* Retrieve local SID context based on IP DA (adj) */
	  ls0 = pool_elt_at_index (srm->localsids,
				   vnet_buffer (b0)->ip.adj_index[VLIB_TX]);

	  cnt_idx0 = ls0 - srm->localsids;

	  /* Retrieve local SID's plugin memory */
	  ls_mem0 = ls0->plugin_mem;

	  /* SRH processing */
	  if (ls_mem0->inner_type == AD_TYPE_IP6)
	    end_ad_flow_processing_v6 (vm, b0, ip0, ls_mem0, &next0, &cnt0,
				       &cnt_idx0, now);
	  else
	    end_ad_flow_processing_v4 (vm, b0, ip0, ls_mem0, &next0, &cnt0,
				       &cnt_idx0, now);

	  /* Trace packet (if enabled) */
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      srv6_ad_flow_localsid_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof *tr);
	      tr->localsid_index = ls_mem0->index;
	    }

	  /* Increment the appropriate per-SID counter */
	  vlib_increment_combined_counter (
	    cnt0, thread_index, cnt_idx0, 1,
	    vlib_buffer_length_in_chain (vm, b0));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (srv6_ad_flow_localsid_node) = {
  .function = srv6_ad_flow_localsid_fn,
  .name = "srv6-ad-flow-localsid",
  .vector_size = sizeof (u32),
  .format_trace = format_srv6_ad_flow_localsid_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = SRV6_AD_FLOW_LOCALSID_N_NEXT,
  .next_nodes = {
		[SRV6_AD_FLOW_LOCALSID_NEXT_PUNT] = "ip6-local",
		[SRV6_AD_FLOW_LOCALSID_NEXT_BYPASS] = "ip6-lookup",
    [SRV6_AD_FLOW_LOCALSID_NEXT_REWRITE4] = "ip4-rewrite",
    [SRV6_AD_FLOW_LOCALSID_NEXT_REWRITE6] = "ip6-rewrite",
    [SRV6_AD_FLOW_LOCALSID_NEXT_ERROR] = "error-drop",
  },
};

/****************************** Rewriting node *******************************/

/**
 * @brief Graph node for applying a SR policy into an IPv6 packet.
 * Encapsulation
 */
static uword
srv6_ad4_flow_rewrite_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_frame_t *frame)
{
  ip6_sr_main_t *srm = &sr_main;
  srv6_ad_flow_main_t *sm = &srv6_ad_flow_main;
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
	  srv6_ad_flow_localsid_t *ls0_mem;
	  srv6_ad_flow_entry_t *s0;
	  u32 next0 = SRV6_AD_FLOW_REWRITE_NEXT_LOOKUP;
	  u16 new_l0 = 0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip0_encap = vlib_buffer_get_current (b0);
	  ls0 = pool_elt_at_index (
	    srm->localsids,
	    sm->sw_iface_localsid4[vnet_buffer (b0)->sw_if_index[VLIB_RX]]);
	  ls0_mem = ls0->plugin_mem;

	  if (PREDICT_FALSE (ls0_mem == NULL))
	    {
	      next0 = SRV6_AD_FLOW_REWRITE_NEXT_ERROR;
	      b0->error = node->errors[SRV6_AD_FLOW_REWRITE_COUNTER_NO_RW];
	    }
	  else
	    {
	      clib_bihash_kv_40_8_t kv0, value0;

	      /* Compute flow hash */
	      u64 ports = 0;
	      if (PREDICT_TRUE (ip0_encap->protocol == IP_PROTOCOL_UDP ||
				ip0_encap->protocol == IP_PROTOCOL_TCP))
		{
		  udp_header_t *udp0 = (udp_header_t *) (ip0_encap + 1);
		  ports =
		    ((u64) udp0->src_port << 16) | ((u64) udp0->dst_port);
		}

	      kv0.key[0] = *((u64 *) &ip0_encap->address_pair);
	      kv0.key[1] = ports;
	      kv0.key[2] = 0;
	      kv0.key[3] = 0;
	      kv0.key[4] = 0;

	      /* Lookup flow in hashtable */
	      if (clib_bihash_search_40_8 (&ls0_mem->ftable, &kv0, &value0) <
		  0)
		{
		  /* not found */
		  next0 = SRV6_AD_FLOW_REWRITE_NEXT_ERROR;
		  b0->error = node->errors[SRV6_AD_FLOW_REWRITE_COUNTER_NO_RW];
		}
	      else
		{
		  /* found */
		  s0 = pool_elt_at_index (
		    ls0_mem->cache, ad_flow_value_get_session_index (&value0));
		  ASSERT (s0);
		  ASSERT (VLIB_BUFFER_PRE_DATA_SIZE >=
			  (s0->rw_len + b0->current_data));

		  clib_memcpy_fast (((u8 *) ip0_encap) - s0->rw_len,
				    s0->rw_data, s0->rw_len);
		  vlib_buffer_advance (b0, -(word) s0->rw_len);

		  ip0 = vlib_buffer_get_current (b0);

		  /* Update inner IPv4 TTL and checksum */
		  u32 checksum0;
		  ip0_encap->ttl -= 1;
		  checksum0 =
		    ip0_encap->checksum + clib_host_to_net_u16 (0x0100);
		  checksum0 += checksum0 >= 0xffff;
		  ip0_encap->checksum = checksum0;

		  /* Update outer IPv6 length (in case it has changed) */
		  new_l0 = s0->rw_len - sizeof (ip6_header_t) +
			   clib_net_to_host_u16 (ip0_encap->length);
		  ip0->payload_length = clib_host_to_net_u16 (new_l0);
		}
	    }

	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	      PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      srv6_ad_flow_rewrite_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof *tr);
	      tr->error = 0;

	      if (next0 == SRV6_AD_FLOW_REWRITE_NEXT_ERROR)
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
	  vlib_increment_combined_counter (
	    ((next0 == SRV6_AD_FLOW_REWRITE_NEXT_ERROR) ?
	       &(sm->rw_invalid_counters) :
	       &(sm->rw_valid_counters)),
	    vm->thread_index, ls0_mem->index, 1,
	    vlib_buffer_length_in_chain (vm, b0));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	  cnt_packets++;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Update counters */
  vlib_node_increment_counter (vm, srv6_ad4_flow_rewrite_node.index,
			       SRV6_AD_FLOW_REWRITE_COUNTER_PROCESSED,
			       cnt_packets);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (srv6_ad4_flow_rewrite_node) = {
  .function = srv6_ad4_flow_rewrite_fn,
  .name = "srv6-ad4-flow-rewrite",
  .vector_size = sizeof (u32),
  .format_trace = format_srv6_ad_flow_rewrite_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = SRV6_AD_FLOW_REWRITE_N_COUNTERS,
  .error_strings = srv6_ad_flow_rewrite_counter_strings,
  .n_next_nodes = SRV6_AD_FLOW_REWRITE_N_NEXT,
  .next_nodes = {
      [SRV6_AD_FLOW_REWRITE_NEXT_LOOKUP] = "ip6-lookup",
      [SRV6_AD_FLOW_REWRITE_NEXT_ERROR] = "error-drop",
  },
};

/**
 * @brief Graph node for applying a SR policy into an IPv6 packet.
 * Encapsulation
 */
static uword
srv6_ad6_flow_rewrite_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_frame_t *frame)
{
  ip6_sr_main_t *srm = &sr_main;
  srv6_ad_flow_main_t *sm = &srv6_ad_flow_main;
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
	  srv6_ad_flow_localsid_t *ls0_mem;
	  srv6_ad_flow_entry_t *s0;
	  u32 next0 = SRV6_AD_FLOW_REWRITE_NEXT_LOOKUP;
	  u16 new_l0 = 0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip0_encap = vlib_buffer_get_current (b0);
	  ls0 = pool_elt_at_index (
	    srm->localsids,
	    sm->sw_iface_localsid6[vnet_buffer (b0)->sw_if_index[VLIB_RX]]);
	  ls0_mem = ls0->plugin_mem;

	  if (PREDICT_FALSE (ls0_mem == NULL))
	    {
	      next0 = SRV6_AD_FLOW_REWRITE_NEXT_ERROR;
	      b0->error = node->errors[SRV6_AD_FLOW_REWRITE_COUNTER_NO_RW];
	    }
	  else
	    {
	      /* ############################################# */
	      clib_bihash_kv_40_8_t kv0, value0;

	      /* Compute flow hash */
	      u64 ports = 0;
	      if (PREDICT_TRUE (ip0_encap->protocol == IP_PROTOCOL_UDP ||
				ip0_encap->protocol == IP_PROTOCOL_TCP))
		{
		  udp_header_t *udp0 = (udp_header_t *) (ip0_encap + 1);
		  ports =
		    ((u64) udp0->src_port << 16) | ((u64) udp0->dst_port);
		}

	      kv0.key[0] = ip0_encap->src_address.as_u64[0];
	      kv0.key[1] = ip0_encap->src_address.as_u64[1];
	      kv0.key[2] = ip0_encap->dst_address.as_u64[0];
	      kv0.key[3] = ip0_encap->dst_address.as_u64[1];
	      kv0.key[4] = ports;

	      /* Lookup flow in hashtable */
	      if (clib_bihash_search_40_8 (&ls0_mem->ftable, &kv0, &value0))
		{
		  /* not found */
		  next0 = SRV6_AD_FLOW_REWRITE_NEXT_ERROR;
		  b0->error = node->errors[SRV6_AD_FLOW_REWRITE_COUNTER_NO_RW];
		}
	      else
		{
		  /* found */
		  s0 = pool_elt_at_index (
		    ls0_mem->cache, ad_flow_value_get_session_index (&value0));
		  ASSERT (s0);

		  ASSERT (VLIB_BUFFER_PRE_DATA_SIZE >=
			  (s0->rw_len + b0->current_data));

		  clib_memcpy_fast (((u8 *) ip0_encap) - s0->rw_len,
				    s0->rw_data, s0->rw_len);
		  vlib_buffer_advance (b0, -(word) s0->rw_len);

		  ip0 = vlib_buffer_get_current (b0);

		  /* Update inner IPv6 hop limit */
		  ip0_encap->hop_limit -= 1;

		  /* Update outer IPv6 length (in case it has changed) */
		  new_l0 = s0->rw_len +
			   clib_net_to_host_u16 (ip0_encap->payload_length);
		  ip0->payload_length = clib_host_to_net_u16 (new_l0);
		}
	    }

	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	      PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      srv6_ad_flow_rewrite_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof *tr);
	      tr->error = 0;

	      if (next0 == SRV6_AD_FLOW_REWRITE_NEXT_ERROR)
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
	  vlib_increment_combined_counter (
	    ((next0 == SRV6_AD_FLOW_REWRITE_NEXT_ERROR) ?
	       &(sm->rw_invalid_counters) :
	       &(sm->rw_valid_counters)),
	    vm->thread_index, ls0_mem->index, 1,
	    vlib_buffer_length_in_chain (vm, b0));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	  cnt_packets++;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Update counters */
  vlib_node_increment_counter (vm, srv6_ad6_flow_rewrite_node.index,
			       SRV6_AD_FLOW_REWRITE_COUNTER_PROCESSED,
			       cnt_packets);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (srv6_ad6_flow_rewrite_node) = {
  .function = srv6_ad6_flow_rewrite_fn,
  .name = "srv6-ad6-flow-rewrite",
  .vector_size = sizeof (u32),
  .format_trace = format_srv6_ad_flow_rewrite_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = SRV6_AD_FLOW_REWRITE_N_COUNTERS,
  .error_strings = srv6_ad_flow_rewrite_counter_strings,
  .n_next_nodes = SRV6_AD_FLOW_REWRITE_N_NEXT,
  .next_nodes = {
      [SRV6_AD_FLOW_REWRITE_NEXT_LOOKUP] = "ip6-lookup",
      [SRV6_AD_FLOW_REWRITE_NEXT_ERROR] = "error-drop",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
