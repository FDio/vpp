/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_lookup_parser_inlines_h__
#define __included_lookup_parser_inlines_h__
#include <vnet/sfdp/sfdp.h>
#include <vnet/sfdp/sfdp_funcs.h>
#include <vnet/sfdp/service.h>
#include <vnet/sfdp/lookup/parser.h>
#include <vnet/sfdp/lookup/lookup.h>
#include <vnet/sfdp/lookup/sfdp_bihashes.h>

#if defined(__clang__) && __clang_major__ > 17
#undef always_inline
#define __sfdp_inline_here [[clang::always_inline]]
#else
#define __sfdp_inline_here
#endif

#define SFDP_PARSER_BIHASH_CALL_INLINE_FN(args...)                            \
  ({ __sfdp_inline_here SFDP_PARSER_BIHASH_CALL_FN (args); })

typedef struct
{
  u32 sw_if_index;
  u8 key_data[64];
  u16 parser_index;
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
} sfdp_parser_lookup_trace_t;

static_always_inline u8
sfdp_parser_lookup_four (const sfdp_parser_registration_t *reg,
			 vlib_buffer_t **b, void *k, u64 *lookup_val, u64 *h,
			 i16 *l4_hdr_offset, int prefetch_buffer_stride,
			 u8 slowpath)
{
  vlib_buffer_t **pb = b + prefetch_buffer_stride;
  u8 slowpath_needed = 0;
  if (prefetch_buffer_stride)
    {
      clib_prefetch_load (pb[0]);
      clib_prefetch_load (pb[0]->data);
    }

  __sfdp_inline_here slowpath_needed |=
    reg->calc_key_fn (b[0], b[0]->flow_id, k + 0, lookup_val + 0, h + 0,
		      l4_hdr_offset + 0, slowpath);

  if (prefetch_buffer_stride)
    {
      clib_prefetch_load (pb[1]);
      clib_prefetch_load (pb[1]->data);
    }

  __sfdp_inline_here slowpath_needed |=
    reg->calc_key_fn (b[1], b[1]->flow_id, k + 1, lookup_val + 1, h + 1,
		      l4_hdr_offset + 1, slowpath);

  if (prefetch_buffer_stride)
    {
      clib_prefetch_load (pb[2]);
      clib_prefetch_load (pb[2]->data);
    }

  __sfdp_inline_here slowpath_needed |=
    reg->calc_key_fn (b[2], b[2]->flow_id, k + 2, lookup_val + 2, h + 2,
		      l4_hdr_offset + 2, slowpath);

  if (prefetch_buffer_stride)
    {
      clib_prefetch_load (pb[3]);
      clib_prefetch_load (pb[3]->data);
    }

  __sfdp_inline_here slowpath_needed |=
    reg->calc_key_fn (b[3], b[3]->flow_id, k + 3, lookup_val + 3, h + 3,
		      l4_hdr_offset + 3, slowpath);
  return slowpath_needed;
}

static_always_inline uword
sfdp_parser_prepare_all_keys (const sfdp_parser_registration_t *reg,
			      vlib_buffer_t **b, sfdp_session_ip4_key_t *k,
			      u64 *lv, u64 *h, i16 *l4_hdr_offset, u32 n_left,
			      u8 slowpath)
{
  /* main loop - prefetch next 4 buffers,
   * prefetch previous 4 buckets */
  while (n_left >= 8)
    {
      if (sfdp_parser_lookup_four (reg, b, k, lv, h, l4_hdr_offset, 4,
				   slowpath) &&
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
      if (sfdp_parser_lookup_four (reg, b, k, lv, h, l4_hdr_offset, 0,
				   slowpath) &&
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
      __sfdp_inline_here if (reg->calc_key_fn (b[0], b[0]->flow_id, k + 0,
					       lv + 0, h + 0,
					       l4_hdr_offset + 0, slowpath) &&
			     !slowpath) return n_left;

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
sfdp_parser_prepare_all_keys_slow (const sfdp_parser_registration_t *reg,
				   vlib_buffer_t **b,
				   sfdp_session_ip4_key_t *k, u64 *lv, u64 *h,
				   i16 *l4_hdr_offset, u32 n_left)
{
  sfdp_parser_prepare_all_keys (reg, b, k, lv, h, l4_hdr_offset, n_left, 1);
}

static_always_inline uword
sfdp_parser_prepare_all_keys_fast (const sfdp_parser_registration_t *reg,
				   vlib_buffer_t **b,
				   sfdp_session_ip4_key_t *k, u64 *lv, u64 *h,
				   i16 *l4_hdr_offset, u32 n_left)
{
  return sfdp_parser_prepare_all_keys (reg, b, k, lv, h, l4_hdr_offset, n_left,
				       0);
}

static_always_inline int
sfdp_parser_create_session_inline (const sfdp_parser_registration_t *reg, uword parser_data_index,
				   sfdp_main_t *sfdp, sfdp_per_thread_data_t *ptd,
				   sfdp_tenant_t *tenant, sfdp_tenant_index_t tenant_idx,
				   u16 thread_index, f64 time_now, void *k, u64 *h, u64 *lookup_val,
				   u32 scope_index, void *kv, const uword key_size,
				   void *table_bihash)
{
  u64 value;
  u8 proto;
  sfdp_session_t *session;
  u32 session_idx;
  u32 pseudo_flow_idx;

  session_idx =
    sfdp_alloc_session (sfdp, ptd, thread_index != SFDP_UNBOUND_THREAD_INDEX);

  if (session_idx == ~0)
    return 1;

  session = pool_elt_at_index (sfdp->sessions, session_idx);

  pseudo_flow_idx = (lookup_val[0] & 0x1) | (session_idx << 1);
  value = sfdp_session_mk_table_value (thread_index, pseudo_flow_idx,
				       session->session_version + 1);

  clib_memcpy_fast (kv, k, key_size);
  clib_memcpy_fast (kv + key_size, &value, sizeof (value));
  clib_memcpy_fast (&proto, k + reg->proto_offset, 1);
  if (SFDP_PARSER_BIHASH_CALL_INLINE_FN (reg, sfdp_parser_bihash_add_del_fn,
					 table_bihash, kv, 2))
    {
      /* colision - remote thread created same entry */
      sfdp_free_session (sfdp, ptd, session_idx);
      return 2;
    }
  session->type = reg->type;
  session->parser_index[SFDP_SESSION_KEY_PRIMARY] = parser_data_index;
  session->key_flags = SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_USER;

  // TODO: Would be nice to do this upon free instead to have avoid having to
  // check
  //       if the session is valid at all when checking invalidation.
  session->session_version += 1;
  session->tenant_idx = tenant_idx;
  session->state = SFDP_SESSION_STATE_FSOL;
  session->owning_thread_index = thread_index;
  session->scope_index = scope_index;
  if (ptd)
    sfdp_session_generate_and_set_id (sfdp, ptd, session);

  clib_memcpy_fast (session->bitmaps, tenant->bitmaps,
		    sizeof (session->bitmaps));
  clib_memcpy_fast (&session->keys_data[SFDP_SESSION_KEY_PRIMARY], k,
		    key_size);

  session->pseudo_dir[SFDP_SESSION_KEY_PRIMARY] = lookup_val[0] & 0x1;
  session->proto = proto;

  lookup_val[0] ^= value;
  /* Bidirectional counter zeroing */
  vlib_zero_combined_counter (&sfdp->per_session_ctr[SFDP_FLOW_COUNTER_LOOKUP],
			      lookup_val[0]);
  vlib_zero_combined_counter (&sfdp->per_session_ctr[SFDP_FLOW_COUNTER_LOOKUP],
			      lookup_val[0] | 0x1);
  vlib_increment_simple_counter (
    &sfdp->tenant_session_ctr[SFDP_TENANT_SESSION_COUNTER_CREATED],
    thread_index, tenant_idx, 1);
  return 0;
}

static_always_inline uword
sfdp_parser_lookup_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			   vlib_frame_t *frame,
			   const sfdp_parser_registration_t *reg,
			   uword parser_data_index)
{
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_parser_main_t *pm = &sfdp_parser_main;
  u32 thread_index = vm->thread_index;
  sfdp_per_thread_data_t *ptd =
    vec_elt_at_index (sfdp->per_thread_data, thread_index);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  const uword key_size = reg->key_size;
  sfdp_parser_data_t *parser =
    vec_elt_at_index (pm->parsers, parser_data_index);
  void *kv = vec_elt (parser->kv_ptd, thread_index);
  void *table_bihash = parser->bihash_table;
  void *keys = vec_elt (parser->keys_ptd, thread_index);
  void *key = keys;
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

  if (PREDICT_FALSE ((n_left_slow_keys = sfdp_parser_prepare_all_keys_fast (
			reg, b, keys, lv, h, l4o, n_left))))
    {
      uword n_done = n_left - n_left_slow_keys;
      sfdp_parser_prepare_all_keys_slow (
	reg, b + n_done, keys + key_size * n_done, lv + n_done, h + n_done,
	l4o + n_done, n_left_slow_keys);
    }

  while (n_left)
    {
      if (PREDICT_TRUE (n_left > 8))
	SFDP_PARSER_BIHASH_CALL_INLINE_FN (
	  reg, sfdp_parser_bihash_prefetch_bucket_fn, table_bihash, h[8]);

      if (PREDICT_TRUE (n_left > 1))
	vlib_prefetch_buffer_header (b[1], STORE);

      if (PREDICT_FALSE (lv[0] & SFDP_LV_TO_SP))
	goto next_pkt;

      clib_memcpy_fast (kv, key, key_size);
      if (SFDP_PARSER_BIHASH_CALL_INLINE_FN (
	    reg, sfdp_parser_bihash_search_with_hash_fn, table_bihash, h[0],
	    kv))
	{
	  sfdp_tenant_index_t tenant_idx = sfdp_buffer (b[0])->tenant_index;
	  int rv;
	  tenant = sfdp_tenant_at_index (sfdp, tenant_idx);
	  rv = sfdp_parser_create_session_inline (
	    reg, parser_data_index, sfdp, ptd, tenant, tenant_idx,
	    thread_index, time_now, key, h, lv, scope_index, kv, key_size,
	    table_bihash);

	  if (PREDICT_FALSE (rv == 1))
	    {
	      vlib_node_increment_counter (
		vm, node->node_index, SFDP_LOOKUP_ERROR_TABLE_OVERFLOW, 1);
	      lv[0] =
		(u64) SFDP_SP_NODE_IP6_TABLE_OVERFLOW << 32 | SFDP_LV_TO_SP;
	      goto next_pkt;
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
	  lv[0] ^= *(u64 *) (kv + key_size);
	  hit_count++;
	}

      b[0]->flow_id = sfdp_pseudo_flow_index_from_lookup (lv[0]);

    next_pkt:
      b[0]->flags |= VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
      vnet_buffer (b[0])->l4_hdr_offset = l4o[0];
      len[0] = vlib_buffer_length_in_chain (vm, b[0]);

      b += 1;
      n_left -= 1;
      key += key_size;
      h += 1;
      lv += 1;
      len += 1;
    }

  // Notify created sessions
  if (n_created)
    {
      sfdp_notify_new_sessions (sfdp, created_session_indices, n_created);
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

      if (lv[0] & SFDP_LV_TO_SP)
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

  if (n_to_sp)
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
	  sfdp_tenant_index_t tenant_idx;
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
	      sfdp_parser_lookup_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	      t->flow_id = b[0]->flow_id;
	      t->hash = h[0];
	      t->is_sp = 0;
	      t->parser_index = parser_data_index;
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

	      clib_memcpy (&t->key_data, i * key_size + keys, key_size);

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

#ifndef CLIB_MARCH_VARIANT
#define _SFDP_PARSER_DEFINE_NODE_AUX(x)                                       \
  static void __sfdp_parser_definition_add_name__##x (void)                   \
    __attribute__ ((__constructor__));                                        \
  static void __sfdp_parser_definition_add_name__##x (void)                   \
  {                                                                           \
    x##_node.name = sfdp_parser_registration_##x.name;                        \
    sfdp_parser_registration_mutable_##x.node_reg = &x##_node;                \
  }

#else
#define _SFDP_PARSER_DEFINE_NODE_AUX(x)
#endif
#define SFDP_PARSER_DEFINE_NODE(x)                                            \
  VLIB_REGISTER_NODE (x##_node) = {                                           \
    .vector_size = sizeof (u32),                                              \
    .format_trace = 0,                                                        \
    .type = VLIB_NODE_TYPE_INTERNAL,                                          \
    .flags = VLIB_NODE_FLAG_ALLOW_LAZY_NEXT_NODES,                            \
    .runtime_data = 0,                                                        \
    .runtime_data_bytes = sizeof (u8),                                        \
    .n_errors = ARRAY_LEN (sfdp_lookup_error_strings),                        \
    .error_strings = sfdp_lookup_error_strings,                               \
  };                                                                          \
                                                                              \
  VLIB_NODE_FN (x##_node)                                                     \
  (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)        \
  {                                                                           \
    return sfdp_parser_lookup_inline (                                        \
      vm, node, frame, &sfdp_parser_registration_##x,                         \
      sfdp_parser_registration_mutable_##x.sfdp_parser_data_index);           \
  }                                                                           \
  _SFDP_PARSER_DEFINE_NODE_AUX (x)

#if defined(__clang__) && __clang_major__ > 17
#if CLIB_DEBUG > 0
#define always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#endif
#endif

#endif