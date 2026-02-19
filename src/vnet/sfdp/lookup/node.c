/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/error.h>
#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_48_8.h>
#include <vnet/sfdp/common.h>
#include <vnet/sfdp/service.h>
#include <vnet/sfdp/sfdp_funcs.h>
#include "lookup_inlines.h"
#include "lookup.h"

static int sfdp_flow_offload_create (u32 session_index, u32 hw_if_index);

#define foreach_sfdp_handoff_error                                            \
  _ (SESS_DROP, sess_drop, INFO, "Session expired during handoff")            \
  _ (NOERROR, noerror, INFO, "no error")

typedef enum
{
#define _(f, n, s, d) SFDP_HANDOFF_ERROR_##f,
  foreach_sfdp_handoff_error
#undef _
    SFDP_HANDOFF_N_ERROR,
} sfdp_handoff_error_t;

static vlib_error_desc_t sfdp_handoff_error_counters[] = {
#define _(f, n, s, d) { #n, d, VL_COUNTER_SEVERITY_##s },
  foreach_sfdp_handoff_error
#undef _
};

typedef struct
{
  u32 sw_if_index;
  union
  {
    sfdp_session_ip4_key_t k4;
    sfdp_session_ip6_key_t k6;
  };
  u8 is_ip6;
  u8 is_sp;
  union
  {
    struct
    {
      u32 next_index;
      u64 hash;
      u32 flow_id;
    };
    struct
    {
      u32 sp_index;
      u32 sp_node_index;
    };
  };
} sfdp_lookup_trace_t;

typedef struct
{
  u32 next_index;
  u32 flow_id;
} sfdp_handoff_trace_t;

static_always_inline int
sfdp_create_session_v4 (sfdp_main_t *sfdp, sfdp_per_thread_data_t *ptd,
			sfdp_tenant_t *tenant, u16 tenant_idx,
			u32 thread_index, f64 time_now, void *k, u64 *h,
			u64 *lookup_val, u32 scope_index)
{
  return sfdp_create_session_inline (sfdp, ptd, tenant, tenant_idx,
				     thread_index, time_now, k, h, lookup_val,
				     scope_index, 0);
}

static_always_inline int
sfdp_create_session_v6 (sfdp_main_t *sfdp, sfdp_per_thread_data_t *ptd,
			sfdp_tenant_t *tenant, u16 tenant_idx,
			u32 thread_index, f64 time_now, void *k, u64 *h,
			u64 *lookup_val, u32 scope_index)
{
  return sfdp_create_session_inline (sfdp, ptd, tenant, tenant_idx,
				     thread_index, time_now, k, h, lookup_val,
				     scope_index, 1);
}

static_always_inline u8
sfdp_lookup_four_v4 (vlib_buffer_t **b, sfdp_session_ip4_key_t *k,
		     u64 *lookup_val, u64 *h, i16 *l4_hdr_offset,
		     int prefetch_buffer_stride, u8 slowpath)
{
  vlib_buffer_t **pb = b + prefetch_buffer_stride;
  u8 slowpath_needed = 0;
  if (prefetch_buffer_stride)
    {
      clib_prefetch_load (pb[0]);
      clib_prefetch_load (pb[0]->data);
    }

  slowpath_needed |=
    sfdp_calc_key_v4 (b[0], b[0]->flow_id, k + 0, lookup_val + 0, h + 0,
		      l4_hdr_offset + 0, slowpath);

  if (prefetch_buffer_stride)
    {
      clib_prefetch_load (pb[1]);
      clib_prefetch_load (pb[1]->data);
    }

  slowpath_needed |=
    sfdp_calc_key_v4 (b[1], b[1]->flow_id, k + 1, lookup_val + 1, h + 1,
		      l4_hdr_offset + 1, slowpath);

  if (prefetch_buffer_stride)
    {
      clib_prefetch_load (pb[2]);
      clib_prefetch_load (pb[2]->data);
    }

  slowpath_needed |=
    sfdp_calc_key_v4 (b[2], b[2]->flow_id, k + 2, lookup_val + 2, h + 2,
		      l4_hdr_offset + 2, slowpath);

  if (prefetch_buffer_stride)
    {
      clib_prefetch_load (pb[3]);
      clib_prefetch_load (pb[3]->data);
    }

  slowpath_needed |=
    sfdp_calc_key_v4 (b[3], b[3]->flow_id, k + 3, lookup_val + 3, h + 3,
		      l4_hdr_offset + 3, slowpath);
  return slowpath_needed;
}

static_always_inline u8
sfdp_lookup_four_v6 (vlib_buffer_t **b, sfdp_session_ip6_key_t *k,
		     u64 *lookup_val, u64 *h, i16 *l4_hdr_offset,
		     int prefetch_buffer_stride, u8 slowpath)
{
  vlib_buffer_t **pb = b + prefetch_buffer_stride;
  u8 slowpath_needed = 0;
  if (prefetch_buffer_stride)
    {
      clib_prefetch_load (pb[0]);
      clib_prefetch_load (pb[0]->data);
    }

  slowpath_needed |=
    sfdp_calc_key_v6 (b[0], b[0]->flow_id, k + 0, lookup_val + 0, h + 0,
		      l4_hdr_offset + 0, slowpath);

  if (prefetch_buffer_stride)
    {
      clib_prefetch_load (pb[1]);
      clib_prefetch_load (pb[1]->data);
    }

  slowpath_needed |=
    sfdp_calc_key_v6 (b[1], b[1]->flow_id, k + 1, lookup_val + 1, h + 1,
		      l4_hdr_offset + 1, slowpath);

  if (prefetch_buffer_stride)
    {
      clib_prefetch_load (pb[2]);
      clib_prefetch_load (pb[2]->data);
    }

  slowpath_needed |=
    sfdp_calc_key_v6 (b[2], b[2]->flow_id, k + 2, lookup_val + 2, h + 2,
		      l4_hdr_offset + 2, slowpath);

  if (prefetch_buffer_stride)
    {
      clib_prefetch_load (pb[3]);
      clib_prefetch_load (pb[3]->data);
    }

  slowpath_needed |=
    sfdp_calc_key_v6 (b[3], b[3]->flow_id, k + 3, lookup_val + 3, h + 3,
		      l4_hdr_offset + 3, slowpath);
  return slowpath_needed;
}

static_always_inline void
sfdp_prepare_all_keys_v4_slow (vlib_buffer_t **b, sfdp_session_ip4_key_t *k,
			       u64 *lv, u64 *h, i16 *l4_hdr_offset,
			       u32 n_left);

static_always_inline void
sfdp_prepare_all_keys_v6_slow (vlib_buffer_t **b, sfdp_session_ip6_key_t *k,
			       u64 *lv, u64 *h, i16 *l4_hdr_offset,
			       u32 n_left);

static_always_inline uword
sfdp_prepare_all_keys_v4 (vlib_buffer_t **b, sfdp_session_ip4_key_t *k,
			  u64 *lv, u64 *h, i16 *l4_hdr_offset, u32 n_left,
			  u8 slowpath)
{
  /* main loop - prefetch next 4 buffers,
   * prefetch previous 4 buckets */
  while (n_left >= 8)
    {
      if (sfdp_lookup_four_v4 (b, k, lv, h, l4_hdr_offset, 4, slowpath) &&
	  !slowpath)
	return n_left;

      b += 4;
      k += 4;
      lv += 4;
      h += 4;
      l4_hdr_offset += 4;
      n_left -= 4;
    }

  /* last 4 packets - dont prefetch next 4 buffers,
   * prefetch previous 4 buckets */
  if (n_left >= 4)
    {
      if (sfdp_lookup_four_v4 (b, k, lv, h, l4_hdr_offset, 0, slowpath) &&
	  !slowpath)
	return n_left;

      b += 4;
      k += 4;
      lv += 4;
      h += 4;
      l4_hdr_offset += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      if (sfdp_calc_key_v4 (b[0], b[0]->flow_id, k + 0, lv + 0, h + 0,
			    l4_hdr_offset + 0, slowpath) &&
	  !slowpath)
	return n_left;

      b += 1;
      k += 1;
      lv += 1;
      h += 1;
      l4_hdr_offset += 1;
      n_left -= 1;
    }
  return 0;
}

static_always_inline uword
sfdp_prepare_all_keys_v6 (vlib_buffer_t **b, sfdp_session_ip6_key_t *k,
			  u64 *lv, u64 *h, i16 *l4_hdr_offset, u32 n_left,
			  u8 slowpath)
{
  /* main loop - prefetch next 4 buffers,
   * prefetch previous 4 buckets */
  while (n_left >= 8)
    {
      if (sfdp_lookup_four_v6 (b, k, lv, h, l4_hdr_offset, 4, slowpath) &&
	  !slowpath)
	return n_left;

      b += 4;
      k += 4;
      lv += 4;
      h += 4;
      l4_hdr_offset += 4;
      n_left -= 4;
    }

  /* last 4 packets - dont prefetch next 4 buffers,
   * prefetch previous 4 buckets */
  if (n_left >= 4)
    {
      if (sfdp_lookup_four_v6 (b, k, lv, h, l4_hdr_offset, 0, slowpath) &&
	  !slowpath)
	return n_left;

      b += 4;
      k += 4;
      lv += 4;
      h += 4;
      l4_hdr_offset += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      if (sfdp_calc_key_v6 (b[0], b[0]->flow_id, k + 0, lv + 0, h + 0,
			    l4_hdr_offset, slowpath) &&
	  !slowpath)
	return n_left;

      b += 1;
      k += 1;
      lv += 1;
      h += 1;
      l4_hdr_offset += 1;
      n_left -= 1;
    }
  return 0;
}

static_always_inline void
sfdp_prepare_all_keys_v4_slow (vlib_buffer_t **b, sfdp_session_ip4_key_t *k,
			       u64 *lv, u64 *h, i16 *l4_hdr_offset, u32 n_left)
{
  sfdp_prepare_all_keys_v4 (b, k, lv, h, l4_hdr_offset, n_left, 1);
}
static_always_inline uword
sfdp_prepare_all_keys_v4_fast (vlib_buffer_t **b, sfdp_session_ip4_key_t *k,
			       u64 *lv, u64 *h, i16 *l4_hdr_offset, u32 n_left)
{
  return sfdp_prepare_all_keys_v4 (b, k, lv, h, l4_hdr_offset, n_left, 0);
}

static_always_inline void
sfdp_prepare_all_keys_v6_slow (vlib_buffer_t **b, sfdp_session_ip6_key_t *k,
			       u64 *lv, u64 *h, i16 *l4_hdr_offset, u32 n_left)
{
  sfdp_prepare_all_keys_v6 (b, k, lv, h, l4_hdr_offset, n_left, 1);
}

static_always_inline uword
sfdp_prepare_all_keys_v6_fast (vlib_buffer_t **b, sfdp_session_ip6_key_t *k,
			       u64 *lv, u64 *h, i16 *l4_hdr_offset, u32 n_left)
{
  return sfdp_prepare_all_keys_v6 (b, k, lv, h, l4_hdr_offset, n_left, 0);
}

static_always_inline uword
sfdp_lookup_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, u8 is_ipv6,
		    u8 is_offloaded)
{
  sfdp_main_t *sfdp = &sfdp_main;
  u32 thread_index = vm->thread_index;
  sfdp_per_thread_data_t *ptd =
    vec_elt_at_index (sfdp->per_thread_data, thread_index);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  sfdp_bihash_kv46_t kv = {};
  sfdp_tenant_t *tenant;
  sfdp_session_t *session;
  u32 session_index;
  u32 *bi, *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 to_local[VLIB_FRAME_SIZE], n_local = 0;
  u32 to_remote[VLIB_FRAME_SIZE], n_remote = 0;
  u32 to_sp[VLIB_FRAME_SIZE], n_to_sp = 0;
  u16 thread_indices[VLIB_FRAME_SIZE];
  u16 local_next_indices[VLIB_FRAME_SIZE];
  u32 sp_indices[VLIB_FRAME_SIZE];
  u32 sp_node_indices[VLIB_FRAME_SIZE];
  vlib_buffer_t *local_bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t *to_sp_bufs[VLIB_FRAME_SIZE];
  u32 local_flow_indices[VLIB_FRAME_SIZE];
  u32 created_session_indices[VLIB_FRAME_SIZE], n_created = 0;
  SFDP_SESSION_IP46_KEYS_TYPE (VLIB_FRAME_SIZE) keys;

  sfdp_session_ip4_key_t *k4 = keys.keys4;
  sfdp_session_ip6_key_t *k6 = keys.keys6;

  u64 hashes[VLIB_FRAME_SIZE], *h = hashes;
  u32 lengths[VLIB_FRAME_SIZE], *len = lengths;
  i16 l4_hdr_off[VLIB_FRAME_SIZE], *l4o = l4_hdr_off;
  f64 time_now = vlib_time_now (vm);
  /* lookup_vals contains:
   * - (Phase 1) to_slow_path_node (1bit)
		  ||| slow_path_node_index (31bits)
   *              ||| zeros(31bits)
   *              |||
   *              ||| packet_dir (1bit)
   *
   * - (Phase 2) session_version + thread_index + flow_index . Cf. sfdp.h
      OR same as Phase 1 if slow path
      ASSUMPTION: thread index < 2^31 */
  u64 __attribute__ ((aligned (32))) lookup_vals[VLIB_FRAME_SIZE],
    *lv = lookup_vals;
  __clib_unused u16 hit_count = 0;
  uword n_left_slow_keys;
  sfdp_lookup_node_runtime_data_t *rt = (void *) node->runtime_data;
  u32 scope_index = rt->scope_index;
  u32 fqi =
    vec_elt_at_index (sfdp->frame_queue_index_per_scope, scope_index)[0];

  vlib_get_buffers (vm, from, bufs, n_left);
  b = bufs;

  if (is_offloaded == 2)
    {
      goto offloaded_lookup;
    }

  if (is_ipv6)
    {
      if (PREDICT_FALSE ((n_left_slow_keys = sfdp_prepare_all_keys_v6_fast (
			    b, k6, lv, h, l4o, n_left))))
	{
	  uword n_done = n_left - n_left_slow_keys;
	  sfdp_prepare_all_keys_v6_slow (b + n_done, k6 + n_done, lv + n_done,
					 h + n_done, l4o + n_done,
					 n_left_slow_keys);
	}
    }
  else
    {
      if (PREDICT_FALSE ((n_left_slow_keys = sfdp_prepare_all_keys_v4_fast (
			    b, k4, lv, h, l4o, n_left))))
	{
	  uword n_done = n_left - n_left_slow_keys;
	  sfdp_prepare_all_keys_v4_slow (b + n_done, k4 + n_done, lv + n_done,
					 h + n_done, l4o + n_done,
					 n_left_slow_keys);
	}
    }

  if (is_ipv6)
    while (n_left)
      {
	if (PREDICT_TRUE (n_left > 8))
	  clib_bihash_prefetch_bucket_48_8 (&sfdp->table6, h[8]);

	if (PREDICT_TRUE (n_left > 1))
	  vlib_prefetch_buffer_header (b[1], STORE);

	if (PREDICT_FALSE (lv[0] & SFDP_LV_TO_SP))
	  goto next_pkt6;

	clib_memcpy_fast (&kv.kv6.key, k6, 48);
	if (clib_bihash_search_inline_with_hash_48_8 (&sfdp->table6, h[0],
						      &kv.kv6))
	  {
	    u16 tenant_idx = sfdp_buffer (b[0])->tenant_index;
	    int rv;
	    tenant = sfdp_tenant_at_index (sfdp, tenant_idx);
	    rv = sfdp_create_session_v6 (sfdp, ptd, tenant, tenant_idx,
					 thread_index, time_now, k6, h, lv,
					 scope_index);
	    if (PREDICT_FALSE (rv == 1))
	      {
		vlib_node_increment_counter (
		  vm, node->node_index, SFDP_LOOKUP_ERROR_TABLE_OVERFLOW, 1);
		lv[0] =
		  (u64) SFDP_SP_NODE_IP6_TABLE_OVERFLOW << 32 | SFDP_LV_TO_SP;
		goto next_pkt6;
	      }
	    else if (rv == 2)
	      {
		vlib_node_increment_counter (vm, node->node_index,
					     SFDP_LOOKUP_ERROR_COLLISION, 1);
		continue; /* if there is colision, we just reiterate */
	      }
	    created_session_indices[n_created] =
	      sfdp_session_index_from_lookup (lv[0]);
	    n_created++;
	  }
	else
	  {
	    lv[0] ^= kv.kv6.value;
	    hit_count++;
	  }

	b[0]->flow_id = sfdp_pseudo_flow_index_from_lookup (lv[0]);

      next_pkt6:
	b[0]->flags |= VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
	vnet_buffer (b[0])->l4_hdr_offset = l4o[0];
	len[0] = vlib_buffer_length_in_chain (vm, b[0]);

	b += 1;
	n_left -= 1;
	k6 += 1;
	h += 1;
	lv += 1;
	len += 1;
      }
  else
    while (n_left)
      {
	if (PREDICT_TRUE (n_left > 8))
	  clib_bihash_prefetch_bucket_24_8 (&sfdp->table4, h[8]);

	if (PREDICT_TRUE (n_left > 1))
	  vlib_prefetch_buffer_header (b[1], STORE);

	if (PREDICT_FALSE (lv[0] & SFDP_LV_TO_SP))
	  goto next_pkt4;

	clib_memcpy_fast (&kv.kv4.key, k4, 24);
	if (clib_bihash_search_inline_with_hash_24_8 (&sfdp->table4, h[0],
						      &kv.kv4))
	  {
	    u16 tenant_idx = sfdp_buffer (b[0])->tenant_index;
	    int rv;
	    tenant = sfdp_tenant_at_index (sfdp, tenant_idx);
	    rv = sfdp_create_session_v4 (sfdp, ptd, tenant, tenant_idx,
					 thread_index, time_now, k4, h, lv,
					 scope_index);
	    if (PREDICT_FALSE (rv == 1))
	      {
		vlib_node_increment_counter (
		  vm, node->node_index, SFDP_LOOKUP_ERROR_TABLE_OVERFLOW, 1);
		lv[0] =
		  (u64) SFDP_SP_NODE_IP4_TABLE_OVERFLOW << 32 | SFDP_LV_TO_SP;
		goto next_pkt4;
	      }
	    else if (rv == 2)
	      {
		vlib_node_increment_counter (vm, node->node_index,
					     SFDP_LOOKUP_ERROR_COLLISION, 1);
		continue; /* if there is colision, we just reiterate */
	      }
	    created_session_indices[n_created] =
	      sfdp_session_index_from_lookup (lv[0]);
	    sfdp_session_t *session =
	      pool_elt_at_index (sfdp->sessions, created_session_indices[n_created]);
	    session->flow_index = ~0;
	    session->lv = (lv[0] & ~(SFDP_LV_TO_SP));
	    n_created++;
	  }
	else
	  {
	    lv[0] ^= kv.kv4.value;
	    hit_count++;
	  }

	b[0]->flow_id = sfdp_pseudo_flow_index_from_lookup (lv[0]);

      next_pkt4:
	b[0]->flags |= VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
	vnet_buffer (b[0])->l4_hdr_offset = l4o[0];
	len[0] = vlib_buffer_length_in_chain (vm, b[0]);

	b += 1;
	n_left -= 1;
	k4 += 1;
	h += 1;
	lv += 1;
	len += 1;
	l4o += 1;
      }

  // Notify created sessions
  if (n_created)
    {
      if (is_offloaded == 1)
	{
	  for (u32 i = 0; i < n_created; i++)
	    {
	      u32 session_idx = created_session_indices[i];
	      u32 rx_sw_if_index = vnet_buffer (bufs[i])->sw_if_index[VLIB_RX];
	      if (!sfdp_flow_offload_create (session_idx, rx_sw_if_index))
		{
		  session = sfdp_session_at_index (session_idx);
		  session->rx_sw_if_index = rx_sw_if_index;
		}
	    }
	}

      sfdp_notify_new_sessions (sfdp, created_session_indices, n_created);
    }

offloaded_lookup:

  if (is_offloaded == 2)
    {
      n_left = frame->n_vectors;
      lv = lookup_vals;
      b = bufs;
      l4o = l4_hdr_off;
      len = lengths;
      while (n_left)
	{
	  // b->flow_id contains the session index+1 marked in the packet buffer
	  session = sfdp_session_at_index (b[0]->flow_id - 1);
	  lv[0] = session->lv;

	  ip4_header_t *ip = vlib_buffer_get_current (b[0]);
	  u8 *next_header = ip4_next_header (ip);
	  i16 l4_hdr_offset = (u8 *) next_header - b[0]->data;

	  l4o[0] = l4_hdr_offset;
	  b[0]->flow_id = sfdp_pseudo_flow_index_from_lookup (lv[0]);
	  b[0]->flags |= VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
	  vnet_buffer (b[0])->l4_hdr_offset = l4o[0];
	  len[0] = vlib_buffer_length_in_chain (vm, b[0]);

	  lv += 1;
	  b += 1;
	  l4o += 1;
	  len += 1;
	  n_left -= 1;
	}
    }

  n_left = frame->n_vectors;
  lv = lookup_vals;
  b = bufs;
  bi = from;
  len = lengths;
  while (n_left)
    {
      u16 flow_thread_index;
      u32 flow_index;
      session_version_t session_version;
      vlib_combined_counter_main_t *vcm;

      if (is_offloaded < 2 && lv[0] & SFDP_LV_TO_SP)
	{
	  to_sp[n_to_sp] = bi[0];
	  sp_indices[n_to_sp] = (lv[0] & ~(SFDP_LV_TO_SP)) >> 32;
	  to_sp_bufs[n_to_sp] = b[0];
	  n_to_sp++;
	  goto next_packet2;
	}

      flow_thread_index = sfdp_thread_index_from_lookup (lv[0]);
      flow_index = sfdp_pseudo_flow_index_from_lookup (lv[0]);
      session_index = flow_index >> 1;
      vcm = &sfdp->per_session_ctr[SFDP_FLOW_COUNTER_LOOKUP];
      session_version = sfdp_session_version_from_lookup (lv[0]);
      vlib_increment_combined_counter (vcm, thread_index, flow_index, 1,
				       len[0]);
      if (PREDICT_FALSE (flow_thread_index == SFDP_UNBOUND_THREAD_INDEX))
	{
	  flow_thread_index = thread_index;
	  sfdp_session_bind_to_thread (session_index, &flow_thread_index, 1);
	  /* flow_thread_index now necessarily contains the actual thread index
	   * of the session */
	}
      if (flow_thread_index == thread_index)
	{
	  /* known flow which belongs to this thread */
	  to_local[n_local] = bi[0];
	  local_flow_indices[n_local] = flow_index;
	  local_bufs[n_local] = b[0];
	  n_local++;
	}
      else
	{
	  /* known flow which belongs to remote thread */
	  to_remote[n_remote] = bi[0];
	  thread_indices[n_remote] = flow_thread_index;
	  /* Store the current session version in buffer to check if it's still
	   * valid after handoff */
	  sfdp_buffer (b[0])->session_version_before_handoff = session_version;
	  n_remote++;
	}
    next_packet2:
      n_left -= 1;
      lv += 1;
      b += 1;
      bi += 1;
      len += 1;
    }

  /* handover buffers to remote node */
  if (n_remote)
    {
      u32 n_remote_enq;
      n_remote_enq = vlib_buffer_enqueue_to_thread (
	vm, node, fqi, to_remote, thread_indices, n_remote, 1);
      vlib_node_increment_counter (vm, node->node_index,
				   SFDP_LOOKUP_ERROR_REMOTE, n_remote_enq);
      vlib_node_increment_counter (vm, node->node_index,
				   SFDP_LOOKUP_ERROR_CON_DROP,
				   n_remote - n_remote_enq);
    }

  /* enqueue local */
  if (n_local)
    {
      u16 *current_next = local_next_indices;
      u32 *local_flow_index = local_flow_indices;
      uword session_scope_index;
      b = local_bufs;
      n_left = n_local;

      /* TODO: prefetch session and buffer + 4 loop */
      while (n_left)
	{
	  session_index = local_flow_index[0] >> 1;
	  session = sfdp_session_at_index (session_index);
	  session_scope_index = session->scope_index;
	  if (PREDICT_TRUE (session_scope_index == scope_index))
	    {
	      sfdp_bitmap_t pbmp =
		session->bitmaps[sfdp_direction_from_flow_index (
		  local_flow_index[0])];
	      sfdp_buffer (b[0])->service_bitmap = pbmp;

	      /* The tenant of the buffer is the tenant of the session */
	      sfdp_buffer (b[0])->tenant_index = session->tenant_idx;

	      sfdp_next (b[0], current_next);
	    }
	  else
	    current_next[0] =
	      SFDP_LOOKUP_NEXT_INDEX_FOR_SCOPE (session_scope_index);

	  local_flow_index += 1;
	  current_next += 1;
	  b += 1;
	  n_left -= 1;
	}
      vlib_buffer_enqueue_to_next (vm, node, to_local, local_next_indices,
				   n_local);
      vlib_node_increment_counter (vm, node->node_index,
				   SFDP_LOOKUP_ERROR_LOCAL, n_local);
    }

  if (is_offloaded < 2 && n_to_sp)
    {
      vlib_frame_t *f = NULL;
      u32 *current_next_slot = NULL;
      u32 current_left_to_next = 0;
      u32 *current_to_sp = to_sp;
      u32 *sp_index = sp_indices;
      u32 *sp_node_index = sp_node_indices;
      u32 last_node_index = VLIB_INVALID_NODE_INDEX;

      b = to_sp_bufs;
      n_left = n_to_sp;

      while (n_left)
	{
	  u32 node_index;
	  u16 tenant_idx;
	  sfdp_tenant_t *tenant;

	  tenant_idx = sfdp_buffer (b[0])->tenant_index;
	  tenant = sfdp_tenant_at_index (sfdp, tenant_idx);
	  node_index = tenant->sp_node_indices[sp_index[0]];
	  sp_node_index[0] = node_index;

	  if (PREDICT_FALSE (node_index != last_node_index) ||
	      current_left_to_next == 0)
	    {
	      if (f != NULL)
		vlib_put_frame_to_node (vm, last_node_index, f);
	      f = vlib_get_frame_to_node (vm, node_index);
	      f->frame_flags |= node->flags & VLIB_NODE_FLAG_TRACE;
	      current_next_slot = vlib_frame_vector_args (f);
	      current_left_to_next = VLIB_FRAME_SIZE;
	      last_node_index = node_index;
	    }

	  current_next_slot[0] = current_to_sp[0];

	  f->n_vectors += 1;
	  current_to_sp += 1;
	  b += 1;
	  sp_index += 1;
	  sp_node_index += 1;
	  current_next_slot += 1;

	  current_left_to_next -= 1;
	  n_left -= 1;
	}
      vlib_put_frame_to_node (vm, last_node_index, f);
    }

  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      int i;
      b = bufs;
      bi = from;
      h = hashes;
      u32 *in_local = to_local;
      u32 *in_remote = to_remote;
      u32 *in_sp = to_sp;
      for (i = 0; i < frame->n_vectors; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      sfdp_lookup_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	      t->flow_id = b[0]->flow_id;
	      t->hash = h[0];
	      t->is_sp = 0;
	      if (bi[0] == in_local[0])
		{
		  t->next_index = local_next_indices[(in_local++) - to_local];
		}
	      else if (bi[0] == in_remote[0])
		{
		  t->next_index = ~0;
		  in_remote++;
		}
	      else
		{
		  t->is_sp = 1;
		  t->sp_index = sp_indices[in_sp - to_sp];
		  t->sp_node_index = sp_node_indices[in_sp - to_sp];
		  in_sp++;
		}

	      if ((t->is_ip6 = is_ipv6))
		clib_memcpy (&t->k6, &keys.keys6[i], sizeof (t->k6));
	      else
		clib_memcpy (&t->k4, &keys.keys4[i], sizeof (t->k4));

	      bi++;
	      b++;
	      h++;
	    }
	  else
	    break;
	}
    }
  return frame->n_vectors;
}

VLIB_NODE_FN (sfdp_lookup_ip4_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return sfdp_lookup_inline (vm, node, frame, 0, 0);
}

VLIB_NODE_FN (sfdp_lookup_ip6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return sfdp_lookup_inline (vm, node, frame, 1, 0);
}

VLIB_NODE_FN (sfdp_lookup_ip4_offload_1st_packet_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return sfdp_lookup_inline (vm, node, frame, 0, 1);
}

VLIB_NODE_FN (sfdp_lookup_ip6_offload_1st_packet_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return sfdp_lookup_inline (vm, node, frame, 1, 1);
}

VLIB_NODE_FN (sfdp_lookup_ip4_offload_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return sfdp_lookup_inline (vm, node, frame, 0, 2);
}

VLIB_NODE_FN (sfdp_lookup_ip6_offload_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return sfdp_lookup_inline (vm, node, frame, 1, 2);
}

VLIB_NODE_FN (sfdp_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 *from = vlib_frame_vector_args (frame), *bi = from;
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *current_next;
  u32 next_buffers[VLIB_FRAME_SIZE], *next_buffer = next_buffers;
  u32 drop_buffers[VLIB_FRAME_SIZE], *drop_buffer = drop_buffers;
  size_t n_next = 0, n_drop = 0;
  sfdp_lookup_node_runtime_data_t *rt = (void *) node->runtime_data;
  u32 scope_index = rt->scope_index;

  vlib_get_buffers (vm, from, bufs, n_left);
  b = bufs;
  current_next = next_indices;

  /*TODO: prefetch, quad or octo loop...*/
  while (n_left)
    {
      u32 flow_index = b[0]->flow_id;
      u32 session_index = flow_index >> 1;

      // Get session if valid and if session_version didn't change
      sfdp_session_t *session = sfdp_session_at_index_if_valid (session_index);
      if (PREDICT_TRUE (session &&
			session->session_version ==
			  sfdp_buffer (b[0])->session_version_before_handoff))
	{
	  u32 session_scope_index = session->scope_index;
	  if (PREDICT_TRUE (scope_index == session_scope_index))
	    {
	      sfdp_bitmap_t pbmp =
		session->bitmaps[sfdp_direction_from_flow_index (flow_index)];
	      sfdp_buffer (b[0])->service_bitmap = pbmp;
	      sfdp_next (b[0], current_next);
	    }
	  else
	    current_next[0] =
	      SFDP_LOOKUP_NEXT_INDEX_FOR_SCOPE (session_scope_index);

	  *next_buffer = *bi;
	  current_next += 1;
	  next_buffer += 1;
	  n_next += 1;
	}
      else
	{
	  // drop if session doesn't exist anymore
	  *drop_buffer = *bi;
	  drop_buffer += 1;
	  n_drop++;
	}

      b += 1;
      bi += 1;
      n_left -= 1;
    }
  vlib_buffer_enqueue_to_next (vm, node, next_buffers, next_indices, n_next);
  vlib_buffer_free (vm, drop_buffers, n_drop);
  vlib_node_increment_counter (vm, node->node_index,
			       SFDP_HANDOFF_ERROR_SESS_DROP, n_drop);
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      int i;
      b = bufs;
      current_next = next_indices;
      for (i = 0; i < frame->n_vectors; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      sfdp_handoff_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->flow_id = b[0]->flow_id;
	      t->next_index = current_next[0];
	      b++;
	      current_next++;
	    }
	  else
	    break;
	}
    }
  return frame->n_vectors;
}

static u8 *
format_sfdp_lookup_trace (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  sfdp_lookup_trace_t *t = va_arg (*args, sfdp_lookup_trace_t *);

  if (!t->is_sp)
    s = format (s,
		"sfdp-lookup: sw_if_index %d, next index %d hash 0x%x "
		"flow-id %u (session %u, %s) key 0x%U",
		t->sw_if_index, t->next_index, t->hash, t->flow_id,
		t->flow_id >> 1, t->flow_id & 0x1 ? "reverse" : "forward",
		format_hex_bytes_no_wrap,
		t->is_ip6 ? (u8 *) &t->k6 : (u8 *) &t->k4,
		t->is_ip6 ? sizeof (t->k6) : sizeof (t->k4));
  else
    s = format (s,
		"sfdp-lookup: sw_if_index %d, slow-path (%U) "
		"slow-path node %U key 0x%U",
		t->sw_if_index, format_sfdp_sp_node, t->sp_index,
		format_vlib_node_name, vm, t->sp_node_index,
		format_hex_bytes_no_wrap,
		t->is_ip6 ? (u8 *) &t->k6 : (u8 *) &t->k4,
		t->is_ip6 ? sizeof (t->k6) : sizeof (t->k4));
  return s;
}

static u8 *
format_sfdp_handoff_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  sfdp_handoff_trace_t *t = va_arg (*args, sfdp_handoff_trace_t *);

  s = format (s,
	      "sfdp-handoff: next index %d "
	      "flow-id %u (session %u, %s)",
	      t->next_index, t->flow_id, t->flow_id >> 1,
	      t->flow_id & 0x1 ? "reverse" : "forward");
  return s;
}

static sfdp_lookup_node_runtime_data_t lookup_rt_data_default = {
  .scope_index = 0
};

VLIB_REGISTER_NODE (sfdp_lookup_ip4_node) = {
  .name = "sfdp-lookup-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_lookup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .flags = VLIB_NODE_FLAG_ALLOW_LAZY_NEXT_NODES,
  .runtime_data = &lookup_rt_data_default,
  .runtime_data_bytes = sizeof (lookup_rt_data_default),
  .n_errors = ARRAY_LEN (sfdp_lookup_error_strings),
  .error_strings = sfdp_lookup_error_strings,
};

VLIB_REGISTER_NODE (sfdp_lookup_ip6_node) = {
  .name = "sfdp-lookup-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_lookup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .flags = VLIB_NODE_FLAG_ALLOW_LAZY_NEXT_NODES,
  .runtime_data = &lookup_rt_data_default,
  .runtime_data_bytes = sizeof (lookup_rt_data_default),
  .n_errors = ARRAY_LEN (sfdp_lookup_error_strings),
  .error_strings = sfdp_lookup_error_strings,
};

VLIB_REGISTER_NODE (sfdp_lookup_ip4_offload_1st_packet_node) = {
  .name = "sfdp-lookup-ip4-offload-1st-packet",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_lookup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .flags = VLIB_NODE_FLAG_ALLOW_LAZY_NEXT_NODES,
  .runtime_data = &lookup_rt_data_default,
  .runtime_data_bytes = sizeof (lookup_rt_data_default),
  .n_errors = ARRAY_LEN (sfdp_lookup_error_strings),
  .error_strings = sfdp_lookup_error_strings,
  .sibling_of = "sfdp-lookup-ip4",
};

VLIB_REGISTER_NODE (sfdp_lookup_ip6_offload_1st_packet_node) = {
  .name = "sfdp-lookup-ip6-offload-1st-packet",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_lookup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .flags = VLIB_NODE_FLAG_ALLOW_LAZY_NEXT_NODES,
  .runtime_data = &lookup_rt_data_default,
  .runtime_data_bytes = sizeof (lookup_rt_data_default),
  .n_errors = ARRAY_LEN (sfdp_lookup_error_strings),
  .error_strings = sfdp_lookup_error_strings,
  .sibling_of = "sfdp-lookup-ip6",
};
VLIB_REGISTER_NODE (sfdp_lookup_ip4_offload_node) = {
  .name = "sfdp-lookup-ip4-offload",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_lookup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .flags = VLIB_NODE_FLAG_ALLOW_LAZY_NEXT_NODES,
  .runtime_data = &lookup_rt_data_default,
  .runtime_data_bytes = sizeof (lookup_rt_data_default),
  .n_errors = ARRAY_LEN (sfdp_lookup_error_strings),
  .error_strings = sfdp_lookup_error_strings,
  .sibling_of = "sfdp-lookup-ip4",
};

VLIB_REGISTER_NODE (sfdp_lookup_ip6_offload_node) = {
  .name = "sfdp-lookup-ip6-offload",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_lookup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .flags = VLIB_NODE_FLAG_ALLOW_LAZY_NEXT_NODES,
  .runtime_data = &lookup_rt_data_default,
  .runtime_data_bytes = sizeof (lookup_rt_data_default),
  .n_errors = ARRAY_LEN (sfdp_lookup_error_strings),
  .error_strings = sfdp_lookup_error_strings,
  .sibling_of = "sfdp-lookup-ip6",
};

VLIB_REGISTER_NODE (sfdp_handoff_node) = {
  .name = "sfdp-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .flags = VLIB_NODE_FLAG_ALLOW_LAZY_NEXT_NODES,
  .n_errors = ARRAY_LEN (sfdp_handoff_error_counters),
  .error_counters = sfdp_handoff_error_counters,
  .runtime_data = &lookup_rt_data_default,
  .runtime_data_bytes = sizeof (lookup_rt_data_default),
};

#include "vnet/flow/flow.h"

static int
sfdp_flow_offload_create (u32 session_index, u32 hw_if_index)
{
  vnet_main_t *vnm = &vnet_main;
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_session_t *session = pool_elt_at_index (sfdp->sessions, session_index);

  vnet_flow_t flow = { 0 };
  u32 flow_index = 0;
  int rv = 0;

  if (session->proto != IP_PROTOCOL_TCP && session->proto != IP_PROTOCOL_UDP)
    {
      return VNET_FLOW_ERROR_NOT_SUPPORTED;
    }

  memset (&flow, 0, sizeof (flow));
  flow.type = VNET_FLOW_TYPE_IP4_N_TUPLE;
  flow.ip4_n_tuple.src_addr.addr.data_u32 =
    session->keys[SFDP_SESSION_KEY_PRIMARY].key4.ip4_key.ip_addr_lo;
  flow.ip4_n_tuple.dst_addr.addr.data_u32 =
    session->keys[SFDP_SESSION_KEY_PRIMARY].key4.ip4_key.ip_addr_hi;
  flow.ip4_n_tuple.src_addr.mask.data_u32 = 0xFFFFFFFF;
  flow.ip4_n_tuple.dst_addr.mask.data_u32 = 0xFFFFFFFF;
  flow.ip4_n_tuple.protocol.prot = (ip_protocol_t) session->proto;
  flow.ip4_n_tuple.protocol.mask = 0xFF;

  flow.ip4_n_tuple.src_port.port =
    clib_net_to_host_u16 (session->keys[SFDP_SESSION_KEY_PRIMARY].key4.ip4_key.port_lo);
  flow.ip4_n_tuple.dst_port.port =
    clib_net_to_host_u16 (session->keys[SFDP_SESSION_KEY_PRIMARY].key4.ip4_key.port_hi);
  flow.ip4_n_tuple.src_port.mask = 0xFFFF;
  flow.ip4_n_tuple.dst_port.mask = 0xFFFF;

  flow.actions = VNET_FLOW_ACTION_MARK | VNET_FLOW_ACTION_REDIRECT_TO_QUEUE;
  flow.mark_flow_id = session_index + 1; // +1 because b->flow_id == 0 means first packet

  rv = vnet_flow_add (vnm, &flow, &flow_index);
  if (rv != 0)
    {
      clib_warning ("Failed to add flow %u: %d", session->flow_index, rv);
      return rv;
    }

  /* Enable the flow on the hardware interface */
  rv = vnet_flow_enable (vnm, flow_index, hw_if_index);
  if (rv != 0)
    {
      clib_warning ("Failed to enable flow %u for session %u on interface %U: %d",
		    session->flow_index, session_index, format_vnet_hw_if_index_name, vnm,
		    hw_if_index, rv);
      clib_warning ("LV 0x%lx", session->lv);
      clib_warning ("IP4 src addr %U", format_ip4_address,
		    &session->keys[SFDP_SESSION_KEY_PRIMARY].key4.ip4_key.ip_addr_lo);
      clib_warning ("IP4 dst addr %U", format_ip4_address,
		    &session->keys[SFDP_SESSION_KEY_PRIMARY].key4.ip4_key.ip_addr_hi);
      clib_warning ("IP4 src port %U", format_tcp_udp_port,
		    session->keys[SFDP_SESSION_KEY_PRIMARY].key4.ip4_key.port_lo);
      clib_warning ("IP4 dst port %U", format_tcp_udp_port,
		    session->keys[SFDP_SESSION_KEY_PRIMARY].key4.ip4_key.port_hi);
      return rv;
    }

  session->flow_index = flow_index;

  return 0;
}
