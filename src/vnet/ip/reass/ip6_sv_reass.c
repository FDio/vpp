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

/**
 * @file
 * @brief IPv6 Shallow Virtual Reassembly.
 *
 * This file contains the source code for IPv6 Shallow Virtual reassembly.
 */

#include <vppinfra/vec.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip6_to_ip4.h>
#include <vppinfra/bihash_48_8.h>
#include <vnet/ip/reass/ip6_sv_reass.h>
#include <vnet/ip/ip6_inlines.h>

#define MSEC_PER_SEC			1000
#define IP6_SV_REASS_TIMEOUT_DEFAULT_MS 100
#define IP6_SV_REASS_EXPIRE_WALK_INTERVAL_DEFAULT_MS                          \
  10000 // 10 seconds default
#define IP6_SV_REASS_MAX_REASSEMBLIES_DEFAULT	   1024
#define IP6_SV_REASS_MAX_REASSEMBLY_LENGTH_DEFAULT 3
#define IP6_SV_REASS_HT_LOAD_FACTOR		   (0.75)

typedef enum
{
  IP6_SV_REASS_RC_OK,
  IP6_SV_REASS_RC_TOO_MANY_FRAGMENTS,
  IP6_SV_REASS_RC_INTERNAL_ERROR,
  IP6_SV_REASS_RC_UNSUPP_IP_PROTO,
  IP6_SV_REASS_RC_INVALID_FRAG_LEN,
} ip6_sv_reass_rc_t;

typedef struct
{
  union
  {
    struct
    {
      ip6_address_t src;
      ip6_address_t dst;
      u32 fib_index;
      u32 frag_id;
      u8 unused[7];
      u8 proto;
    };
    u64 as_u64[6];
  };
} ip6_sv_reass_key_t;

typedef union
{
  struct
  {
    u32 reass_index;
    clib_thread_index_t thread_index;
  };
  u64 as_u64;
} ip6_sv_reass_val_t;

typedef union
{
  struct
  {
    ip6_sv_reass_key_t k;
    ip6_sv_reass_val_t v;
  };
  clib_bihash_kv_48_8_t kv;
} ip6_sv_reass_kv_t;

typedef struct
{
  // hash table key
  ip6_sv_reass_key_t key;
  // time when last packet was received
  f64 last_heard;
  // internal id of this reassembly
  u64 id;
  // trace operation counter
  u32 trace_op_counter;
  // buffer indexes of buffers in this reassembly in chronological order -
  // including overlaps and duplicate fragments
  u32 *cached_buffers;

  bool first_fragment_seen;
  bool last_fragment_seen;

  // vnet_buffer data
  u8 ip_proto;
  u8 icmp_type_or_tcp_flags;
  u32 tcp_ack_number;
  u32 tcp_seq_number;
  u16 l4_src_port;
  u16 l4_dst_port;

  // vnet_buffer2 data
  u32 total_ip_payload_length;
  u32 first_fragment_total_ip_header_length;
  u32 first_fragment_clone_bi;

  // lru indexes
  u32 lru_prev;
  u32 lru_next;
} ip6_sv_reass_t;

typedef struct
{
  ip6_sv_reass_t *pool;
  u32 reass_n;
  u32 id_counter;
  clib_spinlock_t lock;
  // lru indexes
  u32 lru_first;
  u32 lru_last;
} ip6_sv_reass_per_thread_t;

typedef struct
{
  // IPv6 config
  u32 timeout_ms;
  f64 timeout;
  u32 expire_walk_interval_ms;
  // maximum number of fragments in one reassembly
  u32 max_reass_len;
  // maximum number of reassemblies
  u32 max_reass_n;

  // IPv6 runtime
  clib_bihash_48_8_t hash;

  // per-thread data
  ip6_sv_reass_per_thread_t *per_thread_data;

  // convenience
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  u32 ip6_sv_reass_expire_node_idx;

  /** Worker handoff */
  u32 fq_index;
  u32 fq_feature_index;
  u32 fq_output_feature_index;
  u32 fq_custom_context_index;

  // reference count for enabling/disabling feature - per interface
  u32 *feature_use_refcount_per_intf;
  // reference count for enabling/disabling output feature - per interface
  u32 *output_feature_use_refcount_per_intf;

  // extended reassembly refcount - see ip6_sv_reass_enable_disable_extended()
  u32 extended_refcount;
} ip6_sv_reass_main_t;

extern ip6_sv_reass_main_t ip6_sv_reass_main;

#ifndef CLIB_MARCH_VARIANT
ip6_sv_reass_main_t ip6_sv_reass_main;
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  IP6_SV_REASSEMBLY_NEXT_INPUT,
  IP6_SV_REASSEMBLY_NEXT_DROP,
  IP6_SV_REASSEMBLY_NEXT_ICMP_ERROR,
  IP6_SV_REASSEMBLY_NEXT_HANDOFF,
  IP6_SV_REASSEMBLY_N_NEXT,
} ip6_sv_reass_next_t;

typedef enum
{
  REASS_FRAGMENT_CACHE,
  REASS_FIRST_FRAG,
  REASS_LAST_FRAG,
  REASS_FRAGMENT_FORWARD,
  REASS_PASSTHROUGH,
} ip6_sv_reass_trace_operation_e;

typedef struct
{
  ip6_sv_reass_trace_operation_e action;
  u32 reass_id;
  u32 op_id;
  u8 ip_proto;
  u16 l4_src_port;
  u16 l4_dst_port;
} ip6_sv_reass_trace_t;

static u8 *
format_ip6_sv_reass_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_sv_reass_trace_t *t = va_arg (*args, ip6_sv_reass_trace_t *);
  if (REASS_PASSTHROUGH != t->action)
    {
      s = format (s, "reass id: %u, op id: %u ", t->reass_id, t->op_id);
    }
  switch (t->action)
    {
    case REASS_FRAGMENT_CACHE:
      s = format (s, "[cached]");
      break;
    case REASS_FIRST_FRAG:
      s =
	format (s, "[first-frag-seen, ip proto=%u, src_port=%u, dst_port=%u]",
		t->ip_proto, clib_net_to_host_u16 (t->l4_src_port),
		clib_net_to_host_u16 (t->l4_dst_port));
      break;
    case REASS_LAST_FRAG:
      s = format (s, "[last-frag-seen]");
      break;
    case REASS_FRAGMENT_FORWARD:
      s = format (s, "[forward, ip proto=%u, src_port=%u, dst_port=%u]",
		  t->ip_proto, clib_net_to_host_u16 (t->l4_src_port),
		  clib_net_to_host_u16 (t->l4_dst_port));
      break;
    case REASS_PASSTHROUGH:
      s = format (s, "[not fragmented or atomic fragment]");
      break;
    }
  return s;
}

static void
ip6_sv_reass_add_trace (vlib_main_t *vm, vlib_node_runtime_t *node,
			ip6_sv_reass_t *reass, u32 bi,
			ip6_sv_reass_trace_operation_e action, u32 ip_proto,
			u16 l4_src_port, u16 l4_dst_port)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  if (pool_is_free_index (vm->trace_main.trace_buffer_pool,
			  vlib_buffer_get_trace_index (b)))
    {
      // this buffer's trace is gone
      b->flags &= ~VLIB_BUFFER_IS_TRACED;
      return;
    }
  ip6_sv_reass_trace_t *t = vlib_add_trace (vm, node, b, sizeof (t[0]));
  if (reass)
    {
      t->reass_id = reass->id;
      t->op_id = reass->trace_op_counter;
      ++reass->trace_op_counter;
    }
  t->action = action;
  t->ip_proto = ip_proto;
  t->l4_src_port = l4_src_port;
  t->l4_dst_port = l4_dst_port;
#if 0
  static u8 *s = NULL;
  s = format (s, "%U", format_ip6_sv_reass_trace, NULL, NULL, t);
  printf ("%.*s\n", vec_len (s), s);
  fflush (stdout);
  vec_reset_length (s);
#endif
}

always_inline void
ip6_sv_reass_free (vlib_main_t *vm, ip6_sv_reass_main_t *rm,
		   ip6_sv_reass_per_thread_t *rt, ip6_sv_reass_t *reass,
		   bool del_bihash)
{
  if (del_bihash)
    {
      clib_bihash_kv_48_8_t kv;
      kv.key[0] = reass->key.as_u64[0];
      kv.key[1] = reass->key.as_u64[1];
      kv.key[2] = reass->key.as_u64[2];
      kv.key[3] = reass->key.as_u64[3];
      kv.key[4] = reass->key.as_u64[4];
      kv.key[5] = reass->key.as_u64[5];
      clib_bihash_add_del_48_8 (&rm->hash, &kv, 0);
    }
  vlib_buffer_free (vm, reass->cached_buffers,
		    vec_len (reass->cached_buffers));
  vec_free (reass->cached_buffers);
  reass->cached_buffers = NULL;
  if (~0 != reass->first_fragment_clone_bi)
    vlib_buffer_free_one (vm, reass->first_fragment_clone_bi);
  if (~0 != reass->lru_prev)
    {
      ip6_sv_reass_t *lru_prev = pool_elt_at_index (rt->pool, reass->lru_prev);
      lru_prev->lru_next = reass->lru_next;
    }
  if (~0 != reass->lru_next)
    {
      ip6_sv_reass_t *lru_next = pool_elt_at_index (rt->pool, reass->lru_next);
      lru_next->lru_prev = reass->lru_prev;
    }
  if (rt->lru_first == reass - rt->pool)
    {
      rt->lru_first = reass->lru_next;
    }
  if (rt->lru_last == reass - rt->pool)
    {
      rt->lru_last = reass->lru_prev;
    }
  pool_put (rt->pool, reass);
  --rt->reass_n;
}

always_inline ip6_sv_reass_t *
ip6_sv_reass_find_or_create (vlib_main_t *vm, ip6_sv_reass_main_t *rm,
			     ip6_sv_reass_per_thread_t *rt,
			     ip6_sv_reass_kv_t *kv, u8 *do_handoff)
{
  ip6_sv_reass_t *reass = NULL;
  f64 now = vlib_time_now (vm);

again:

  if (!clib_bihash_search_48_8 (&rm->hash, &kv->kv, &kv->kv))
    {
      if (vm->thread_index != kv->v.thread_index)
	{
	  *do_handoff = 1;
	  return NULL;
	}
      reass = pool_elt_at_index (rt->pool, kv->v.reass_index);

      if (now > reass->last_heard + rm->timeout)
	{
	  ip6_sv_reass_free (vm, rm, rt, reass, true);
	  reass = NULL;
	}
    }

  if (reass)
    {
      reass->last_heard = now;
      return reass;
    }

  if (rt->reass_n >= rm->max_reass_n && rm->max_reass_n)
    {
      reass = pool_elt_at_index (rt->pool, rt->lru_first);
      ip6_sv_reass_free (vm, rm, rt, reass, true);
    }

  pool_get_zero (rt->pool, reass);
  reass->first_fragment_clone_bi = ~0;
  reass->id = ((u64) vm->thread_index * 1000000000) + rt->id_counter;
  ++rt->id_counter;
  ++rt->reass_n;
  reass->lru_prev = reass->lru_next = ~0;

  if (~0 != rt->lru_last)
    {
      ip6_sv_reass_t *lru_last = pool_elt_at_index (rt->pool, rt->lru_last);
      reass->lru_prev = rt->lru_last;
      lru_last->lru_next = rt->lru_last = reass - rt->pool;
    }

  if (~0 == rt->lru_first)
    {
      rt->lru_first = rt->lru_last = reass - rt->pool;
    }

  reass->key.as_u64[0] = kv->kv.key[0];
  reass->key.as_u64[1] = kv->kv.key[1];
  reass->key.as_u64[2] = kv->kv.key[2];
  reass->key.as_u64[3] = kv->kv.key[3];
  reass->key.as_u64[4] = kv->kv.key[4];
  reass->key.as_u64[5] = kv->kv.key[5];
  kv->v.reass_index = (reass - rt->pool);
  kv->v.thread_index = vm->thread_index;
  reass->last_heard = now;

  int rv = clib_bihash_add_del_48_8 (&rm->hash, &kv->kv, 2);
  if (rv)
    {
      ip6_sv_reass_free (vm, rm, rt, reass, false);
      reass = NULL;
      // if other worker created a context already work with the other copy
      if (-2 == rv)
	goto again;
    }

  return reass;
}

always_inline bool
ip6_sv_reass_is_complete (ip6_sv_reass_t *reass, bool extended)
{
  /*
   * Both first and last fragments have to be seen for extended reassembly to
   * be complete. Otherwise first fragment is enough.
   */
  if (extended)
    return reass->first_fragment_seen && reass->last_fragment_seen;

  return reass->first_fragment_seen;
}

always_inline ip6_sv_reass_rc_t
ip6_sv_reass_update (vlib_main_t *vm, vlib_node_runtime_t *node,
		     ip6_sv_reass_main_t *rm, ip6_sv_reass_t *reass, u32 bi0,
		     ip6_frag_hdr_t *frag_hdr, bool extended)
{
  vlib_buffer_t *fb = vlib_get_buffer (vm, bi0);
  vnet_buffer_opaque_t *fvnb = vnet_buffer (fb);
  fvnb->ip.reass.ip6_frag_hdr_offset =
    (u8 *) frag_hdr - (u8 *) vlib_buffer_get_current (fb);
  ip6_header_t *fip = vlib_buffer_get_current (fb);
  if (fb->current_length < sizeof (*fip) ||
      fvnb->ip.reass.ip6_frag_hdr_offset == 0 ||
      fvnb->ip.reass.ip6_frag_hdr_offset >= fb->current_length)
    {
      return IP6_SV_REASS_RC_INTERNAL_ERROR;
    }

  u32 fragment_first = fvnb->ip.reass.fragment_first =
    ip6_frag_hdr_offset_bytes (frag_hdr);
  u32 fragment_length =
    vlib_buffer_length_in_chain (vm, fb) -
    (fvnb->ip.reass.ip6_frag_hdr_offset + sizeof (*frag_hdr));
  if (0 == fragment_length)
    {
      return IP6_SV_REASS_RC_INVALID_FRAG_LEN;
    }
  u32 fragment_last = fvnb->ip.reass.fragment_last =
    fragment_first + fragment_length - 1;
  fvnb->ip.reass.range_first = fragment_first;
  fvnb->ip.reass.range_last = fragment_last;
  fvnb->ip.reass.next_range_bi = ~0;
  void *l4_hdr = NULL;
  if (0 == fragment_first)
    {
      if (!ip6_get_port (vm, fb, fip, fb->current_length, &reass->ip_proto,
			 &reass->l4_src_port, &reass->l4_dst_port,
			 &reass->icmp_type_or_tcp_flags,
			 &reass->tcp_ack_number, &reass->tcp_seq_number,
			 &l4_hdr))
	return IP6_SV_REASS_RC_UNSUPP_IP_PROTO;

      reass->first_fragment_seen = true;
      if (extended)
	{
	  reass->first_fragment_total_ip_header_length =
	    (u8 *) l4_hdr - (u8 *) fip;
	  vlib_buffer_t *clone = vlib_buffer_copy_no_chain (
	    vm, fb, &reass->first_fragment_clone_bi);
	  if (!clone)
	    reass->first_fragment_clone_bi = ~0;
	}

      vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ip6_sv_reass_add_trace (vm, node, reass, bi0, REASS_FIRST_FRAG,
				  reass->ip_proto, reass->l4_src_port,
				  reass->l4_dst_port);
	}
    }

  if (!ip6_frag_hdr_more (frag_hdr))
    {
      reass->last_fragment_seen = true;
      reass->total_ip_payload_length = fragment_last - 1;
      vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ip6_sv_reass_add_trace (vm, node, reass, bi0, REASS_LAST_FRAG, ~0,
				  ~0, ~0);
	}
    }

  vec_add1 (reass->cached_buffers, bi0);

  if (!ip6_sv_reass_is_complete (reass, extended))
    {
      if (PREDICT_FALSE (fb->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ip6_sv_reass_add_trace (vm, node, reass, bi0, REASS_FRAGMENT_CACHE,
				  reass->ip_proto, reass->l4_src_port,
				  reass->l4_dst_port);
	}
      if (vec_len (reass->cached_buffers) > rm->max_reass_len)
	{
	  return IP6_SV_REASS_RC_TOO_MANY_FRAGMENTS;
	}
    }
  return IP6_SV_REASS_RC_OK;
}

always_inline bool
ip6_sv_reass_verify_upper_layer_present (vlib_buffer_t *b,
					 ip6_ext_hdr_chain_t *hc)
{
  int nh = hc->eh[hc->length - 1].protocol;
  /* Checking to see if it's a terminating header */
  if (ip6_ext_hdr (nh))
    {
      icmp6_error_set_vnet_buffer (
	b, ICMP6_parameter_problem,
	ICMP6_parameter_problem_first_fragment_has_incomplete_header_chain, 0);
      return false;
    }
  return true;
}

always_inline bool
ip6_sv_reass_verify_fragment_multiple_8 (vlib_main_t *vm, vlib_buffer_t *b,
					 ip6_frag_hdr_t *frag_hdr)
{
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  ip6_header_t *ip = vlib_buffer_get_current (b);
  int more_fragments = ip6_frag_hdr_more (frag_hdr);
  u32 fragment_length =
    vlib_buffer_length_in_chain (vm, b) -
    (vnb->ip.reass.ip6_frag_hdr_offset + sizeof (*frag_hdr));
  if (more_fragments && 0 != fragment_length % 8)
    {
      icmp6_error_set_vnet_buffer (
	b, ICMP6_parameter_problem,
	ICMP6_parameter_problem_erroneous_header_field,
	(u8 *) &ip->payload_length - (u8 *) ip);
      return false;
    }
  return true;
}

always_inline bool
ip6_sv_reass_verify_packet_size_lt_64k (vlib_main_t *vm, vlib_buffer_t *b,
					ip6_frag_hdr_t *frag_hdr)
{
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  u32 fragment_first = ip6_frag_hdr_offset_bytes (frag_hdr);
  u32 fragment_length =
    vlib_buffer_length_in_chain (vm, b) -
    (vnb->ip.reass.ip6_frag_hdr_offset + sizeof (*frag_hdr));
  if (fragment_first + fragment_length > 65535)
    {
      ip6_header_t *ip0 = vlib_buffer_get_current (b);
      icmp6_error_set_vnet_buffer (
	b, ICMP6_parameter_problem,
	ICMP6_parameter_problem_erroneous_header_field,
	(u8 *) &frag_hdr->fragment_offset_and_more - (u8 *) ip0);
      return false;
    }
  return true;
}

always_inline void
ip6_sv_reass_reset_vnet_buffer2 (vlib_buffer_t *b)
{
  vnet_buffer2 (b)->ip.reass.pool_index = ~0;
  vnet_buffer2 (b)->ip.reass.thread_index = ~0;
  vnet_buffer2 (b)->ip.reass.id = ~0;
}

always_inline void
ip6_sv_reass_set_vnet_buffer2_from_reass (vlib_main_t *vm, vlib_buffer_t *b,
					  ip6_sv_reass_t *reass)
{
  vnet_buffer2 (b)->ip.reass.thread_index = vm->thread_index;
  vnet_buffer2 (b)->ip.reass.id = reass->id;
  vnet_buffer2 (b)->ip.reass.pool_index =
    reass - ip6_sv_reass_main.per_thread_data[vm->thread_index].pool;
}

struct ip6_sv_reass_args
{
  bool is_feature;
  bool is_output_feature;
  bool custom_next;
  bool custom_context;
  bool extended;
};

always_inline uword
ip6_sv_reassembly_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_frame_t *frame, struct ip6_sv_reass_args a)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from, n_left_to_next, *to_next, *to_next_aux, next_index;
  ip6_sv_reass_main_t *rm = &ip6_sv_reass_main;
  ip6_sv_reass_per_thread_t *rt = &rm->per_thread_data[vm->thread_index];
  u32 *context;
  if (a.custom_context)
    context = vlib_frame_aux_args (frame);

  clib_spinlock_lock (&rt->lock);

  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      if (a.custom_context)
	vlib_get_next_frame_with_aux_safe (vm, node, next_index, to_next,
					   to_next_aux, n_left_to_next);
      else
	vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = IP6_SV_REASSEMBLY_NEXT_DROP;
	  u32 error0 = IP6_ERROR_NONE;
	  u8 forward_context = 0;
	  bi0 = from[0];
	  b0 = vlib_get_buffer (vm, bi0);

	  ip6_header_t *ip0 = (ip6_header_t *) u8_ptr_add (
	    vlib_buffer_get_current (b0),
	    (ptrdiff_t) (a.is_output_feature ? 1 : 0) *
	      vnet_buffer (b0)->ip.save_rewrite_length);

	  ip6_frag_hdr_t *frag_hdr;
	  ip6_ext_hdr_chain_t hdr_chain;
	  bool is_atomic_fragment = false;

	  int res = ip6_ext_header_walk (
	    b0, ip0, IP_PROTOCOL_IPV6_FRAGMENTATION, &hdr_chain);
	  if (res >= 0 &&
	      hdr_chain.eh[res].protocol == IP_PROTOCOL_IPV6_FRAGMENTATION)
	    {
	      frag_hdr =
		ip6_ext_next_header_offset (ip0, hdr_chain.eh[res].offset);
	      is_atomic_fragment = (0 == ip6_frag_hdr_offset (frag_hdr) &&
				    !ip6_frag_hdr_more (frag_hdr));
	    }

	  if (res < 0 ||
	      hdr_chain.eh[res].protocol != IP_PROTOCOL_IPV6_FRAGMENTATION ||
	      is_atomic_fragment)
	    {
	      void *l4_hdr;
	      // this is a regular unfragmented packet or an atomic
	      // fragment
	      if (!ip6_get_port (
		    vm, b0, ip0, b0->current_length,
		    &(vnet_buffer (b0)->ip.reass.ip_proto),
		    &(vnet_buffer (b0)->ip.reass.l4_src_port),
		    &(vnet_buffer (b0)->ip.reass.l4_dst_port),
		    &(vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags),
		    &(vnet_buffer (b0)->ip.reass.tcp_ack_number),
		    &(vnet_buffer (b0)->ip.reass.tcp_seq_number), &l4_hdr))
		{
		  error0 = IP6_ERROR_REASS_UNSUPP_IP_PROTO;
		  b0->error = node->errors[error0];
		  next0 = IP6_SV_REASSEMBLY_NEXT_DROP;
		  goto packet_enqueue;
		}
	      if (a.extended)
		ip6_sv_reass_reset_vnet_buffer2 (b0);
	      vnet_buffer (b0)->ip.reass.l4_hdr_truncated = 0;
	      vnet_buffer (b0)->ip.reass.is_non_first_fragment = 0;
	      next0 = a.custom_next ? vnet_buffer (b0)->ip.reass.next_index :
				      IP6_SV_REASSEMBLY_NEXT_INPUT;
	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  ip6_sv_reass_add_trace (
		    vm, node, NULL, bi0, REASS_PASSTHROUGH,
		    vnet_buffer (b0)->ip.reass.ip_proto,
		    vnet_buffer (b0)->ip.reass.l4_src_port,
		    vnet_buffer (b0)->ip.reass.l4_dst_port);
		}
	      goto packet_enqueue;
	    }

	  vnet_buffer (b0)->ip.reass.ip6_frag_hdr_offset =
	    hdr_chain.eh[res].offset;

	  if (0 == ip6_frag_hdr_offset (frag_hdr))
	    {
	      // first fragment - verify upper-layer is present
	      if (!ip6_sv_reass_verify_upper_layer_present (b0, &hdr_chain))
		{
		  error0 = IP6_ERROR_REASS_MISSING_UPPER;
		  b0->error = node->errors[error0];
		  next0 = IP6_SV_REASSEMBLY_NEXT_ICMP_ERROR;
		  goto packet_enqueue;
		}
	    }
	  if (!ip6_sv_reass_verify_fragment_multiple_8 (vm, b0, frag_hdr) ||
	      !ip6_sv_reass_verify_packet_size_lt_64k (vm, b0, frag_hdr))
	    {
	      error0 = IP6_ERROR_REASS_INVALID_FRAG_LEN;
	      b0->error = node->errors[error0];
	      next0 = IP6_SV_REASSEMBLY_NEXT_ICMP_ERROR;
	      goto packet_enqueue;
	    }

	  ip6_sv_reass_kv_t kv;
	  u8 do_handoff = 0;

	  kv.k.as_u64[0] = ip0->src_address.as_u64[0];
	  kv.k.as_u64[1] = ip0->src_address.as_u64[1];
	  kv.k.as_u64[2] = ip0->dst_address.as_u64[0];
	  kv.k.as_u64[3] = ip0->dst_address.as_u64[1];
	  if (a.custom_context)
	    kv.k.as_u64[4] =
	      (u64) *context << 32 | (u64) frag_hdr->identification;
	  else
	    kv.k.as_u64[4] =
	      ((u64) vec_elt (ip6_main.fib_index_by_sw_if_index,
			      vnet_buffer (b0)->sw_if_index[VLIB_RX]))
		<< 32 |
	      (u64) frag_hdr->identification;
	  kv.k.as_u64[5] = ip0->protocol;

	  ip6_sv_reass_t *reass =
	    ip6_sv_reass_find_or_create (vm, rm, rt, &kv, &do_handoff);

	  if (PREDICT_FALSE (do_handoff))
	    {
	      next0 = IP6_SV_REASSEMBLY_NEXT_HANDOFF;
	      vnet_buffer (b0)->ip.reass.owner_thread_index =
		kv.v.thread_index;
	      if (a.custom_context)
		forward_context = 1;
	      goto packet_enqueue;
	    }

	  if (!reass)
	    {
	      next0 = IP6_SV_REASSEMBLY_NEXT_DROP;
	      error0 = IP6_ERROR_REASS_LIMIT_REACHED;
	      b0->error = node->errors[error0];
	      goto packet_enqueue;
	    }

	  if (ip6_sv_reass_is_complete (reass, a.extended))
	    {
	      vnet_buffer (b0)->ip.reass.l4_hdr_truncated = 0;
	      vnet_buffer (b0)->ip.reass.is_non_first_fragment =
		!!ip6_frag_hdr_offset (frag_hdr);
	      vnet_buffer (b0)->ip.reass.ip_proto = reass->ip_proto;
	      vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags =
		reass->icmp_type_or_tcp_flags;
	      vnet_buffer (b0)->ip.reass.tcp_ack_number =
		reass->tcp_ack_number;
	      vnet_buffer (b0)->ip.reass.tcp_seq_number =
		reass->tcp_seq_number;
	      vnet_buffer (b0)->ip.reass.l4_src_port = reass->l4_src_port;
	      vnet_buffer (b0)->ip.reass.l4_dst_port = reass->l4_dst_port;

	      if (a.extended)
		ip6_sv_reass_set_vnet_buffer2_from_reass (vm, b0, reass);

	      next0 = a.custom_next ? vnet_buffer (b0)->ip.reass.next_index :
				      IP6_SV_REASSEMBLY_NEXT_INPUT;
	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  ip6_sv_reass_add_trace (
		    vm, node, reass, bi0, REASS_FRAGMENT_FORWARD,
		    reass->ip_proto, reass->l4_src_port, reass->l4_dst_port);
		}
	      goto packet_enqueue;
	    }

	  u32 counter = ~0;
	  switch (ip6_sv_reass_update (vm, node, rm, reass, bi0, frag_hdr,
				       a.extended))
	    {
	    case IP6_SV_REASS_RC_OK:
	      /* nothing to do here */
	      break;
	    case IP6_SV_REASS_RC_TOO_MANY_FRAGMENTS:
	      counter = IP6_ERROR_REASS_FRAGMENT_CHAIN_TOO_LONG;
	      break;
	    case IP6_SV_REASS_RC_UNSUPP_IP_PROTO:
	      counter = IP6_ERROR_REASS_UNSUPP_IP_PROTO;
	      break;
	    case IP6_SV_REASS_RC_INTERNAL_ERROR:
	      counter = IP6_ERROR_REASS_INTERNAL_ERROR;
	      break;
	    case IP6_SV_REASS_RC_INVALID_FRAG_LEN:
	      counter = IP6_ERROR_REASS_INVALID_FRAG_LEN;
	      break;
	    }
	  if (~0 != counter)
	    {
	      vlib_node_increment_counter (vm, node->node_index, counter, 1);
	      ip6_sv_reass_free (vm, rm, rt, reass, true);
	      goto next_packet;
	    }

	  if (ip6_sv_reass_is_complete (reass, a.extended))
	    {
	      u32 idx;
	      vec_foreach_index (idx, reass->cached_buffers)
		{
		  u32 bi0 = vec_elt (reass->cached_buffers, idx);
		  if (0 == n_left_to_next)
		    {
		      vlib_put_next_frame (vm, node, next_index,
					   n_left_to_next);
		      vlib_get_next_frame (vm, node, next_index, to_next,
					   n_left_to_next);
		    }
		  to_next[0] = bi0;
		  to_next += 1;
		  n_left_to_next -= 1;
		  b0 = vlib_get_buffer (vm, bi0);
		  if (a.is_feature || a.is_output_feature)
		    {
		      vnet_feature_next (&next0, b0);
		    }
		  frag_hdr = vlib_buffer_get_current (b0) +
			     vnet_buffer (b0)->ip.reass.ip6_frag_hdr_offset;
		  vnet_buffer (b0)->ip.reass.l4_hdr_truncated = 0;
		  vnet_buffer (b0)->ip.reass.is_non_first_fragment =
		    !!ip6_frag_hdr_offset (frag_hdr);
		  vnet_buffer (b0)->ip.reass.ip_proto = reass->ip_proto;
		  vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags =
		    reass->icmp_type_or_tcp_flags;
		  vnet_buffer (b0)->ip.reass.tcp_ack_number =
		    reass->tcp_ack_number;
		  vnet_buffer (b0)->ip.reass.tcp_seq_number =
		    reass->tcp_seq_number;
		  vnet_buffer (b0)->ip.reass.l4_src_port = reass->l4_src_port;
		  vnet_buffer (b0)->ip.reass.l4_dst_port = reass->l4_dst_port;
		  if (a.extended)
		    ip6_sv_reass_set_vnet_buffer2_from_reass (vm, b0, reass);
		  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		    {
		      ip6_sv_reass_add_trace (
			vm, node, reass, bi0, REASS_FRAGMENT_FORWARD,
			reass->ip_proto, reass->l4_src_port,
			reass->l4_dst_port);
		    }
		  vlib_validate_buffer_enqueue_x1 (
		    vm, node, next_index, to_next, n_left_to_next, bi0, next0);
		}
	      vec_set_len (reass->cached_buffers,
			   0); // buffers are owned by frame now
	    }
	  goto next_packet;

	packet_enqueue:
	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next -= 1;
	  if ((a.is_feature || a.is_output_feature) &&
	      IP6_ERROR_NONE == error0 &&
	      IP6_SV_REASSEMBLY_NEXT_HANDOFF != next0)
	    {
	      b0 = vlib_get_buffer (vm, bi0);
	      vnet_feature_next (&next0, b0);
	    }
	  if (a.custom_context && forward_context)
	    {
	      if (to_next_aux)
		{
		  to_next_aux[0] = *context;
		  to_next_aux += 1;
		}
	      vlib_validate_buffer_enqueue_with_aux_x1 (
		vm, node, next_index, to_next, to_next_aux, n_left_to_next,
		bi0, *context, next0);
	    }
	  else
	    vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					     n_left_to_next, bi0, next0);

	next_packet:
	  from += 1;
	  if (a.custom_context)
	    context += 1;
	  n_left_from -= 1;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  clib_spinlock_unlock (&rt->lock);
  return frame->n_vectors;
}

VLIB_NODE_FN (ip6_sv_reass_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  /*
   * Extended reassembly not supported for non-feature nodes.
   */
  return ip6_sv_reassembly_inline (vm, node, frame,
				   (struct ip6_sv_reass_args){
				     .is_feature = false,
				     .is_output_feature = false,
				     .custom_context = false,
				     .custom_next = false,
				     .extended = false,
				   });
}

VLIB_REGISTER_NODE (ip6_sv_reass_node) = {
    .name = "ip6-sv-reassembly",
    .vector_size = sizeof (u32),
    .format_trace = format_ip6_sv_reass_trace,
    .n_errors = IP6_N_ERROR,
    .error_counters = ip6_error_counters,
    .n_next_nodes = IP6_SV_REASSEMBLY_N_NEXT,
    .next_nodes =
        {
                [IP6_SV_REASSEMBLY_NEXT_INPUT] = "ip6-input",
                [IP6_SV_REASSEMBLY_NEXT_DROP] = "ip6-drop",
                [IP6_SV_REASSEMBLY_NEXT_ICMP_ERROR] = "ip6-icmp-error",
                [IP6_SV_REASSEMBLY_NEXT_HANDOFF] = "ip6-sv-reassembly-handoff",
        },
};

VLIB_NODE_FN (ip6_sv_reass_node_feature)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (ip6_sv_reass_main.extended_refcount > 0)
    return ip6_sv_reassembly_inline (vm, node, frame,
				     (struct ip6_sv_reass_args){
				       .is_feature = true,
				       .is_output_feature = false,
				       .custom_context = false,
				       .custom_next = false,
				       .extended = true,
				     });
  return ip6_sv_reassembly_inline (vm, node, frame,
				   (struct ip6_sv_reass_args){
				     .is_feature = true,
				     .is_output_feature = false,
				     .custom_context = false,
				     .custom_next = false,
				     .extended = false,
				   });
}

VLIB_REGISTER_NODE (ip6_sv_reass_node_feature) = {
    .name = "ip6-sv-reassembly-feature",
    .vector_size = sizeof (u32),
    .format_trace = format_ip6_sv_reass_trace,
    .n_errors = IP6_N_ERROR,
    .error_counters = ip6_error_counters,
    .n_next_nodes = IP6_SV_REASSEMBLY_N_NEXT,
    .next_nodes =
        {
                [IP6_SV_REASSEMBLY_NEXT_INPUT] = "ip6-input",
                [IP6_SV_REASSEMBLY_NEXT_DROP] = "ip6-drop",
                [IP6_SV_REASSEMBLY_NEXT_ICMP_ERROR] = "ip6-icmp-error",
                [IP6_SV_REASSEMBLY_NEXT_HANDOFF] = "ip6-sv-reass-feature-hoff",
        },
};

VNET_FEATURE_INIT (ip6_sv_reassembly_feature) = {
  .arc_name = "ip6-unicast",
  .node_name = "ip6-sv-reassembly-feature",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
  .runs_after = 0,
};

VLIB_NODE_FN (ip6_sv_reass_node_output_feature)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (ip6_sv_reass_main.extended_refcount > 0)
    return ip6_sv_reassembly_inline (vm, node, frame,
				     (struct ip6_sv_reass_args){
				       .is_feature = false,
				       .is_output_feature = true,
				       .custom_context = false,
				       .custom_next = false,
				       .extended = true,
				     });
  return ip6_sv_reassembly_inline (vm, node, frame,
				   (struct ip6_sv_reass_args){
				     .is_feature = false,
				     .is_output_feature = true,
				     .custom_context = false,
				     .custom_next = false,
				     .extended = false,
				   });
}

VLIB_REGISTER_NODE (ip6_sv_reass_node_output_feature) = {
    .name = "ip6-sv-reassembly-output-feature",
    .vector_size = sizeof (u32),
    .format_trace = format_ip6_sv_reass_trace,
    .n_errors = IP6_N_ERROR,
    .error_counters = ip6_error_counters,
    .n_next_nodes = IP6_SV_REASSEMBLY_N_NEXT,
    .next_nodes =
        {
                [IP6_SV_REASSEMBLY_NEXT_INPUT] = "ip6-input",
                [IP6_SV_REASSEMBLY_NEXT_DROP] = "ip6-drop",
                [IP6_SV_REASSEMBLY_NEXT_ICMP_ERROR] = "ip6-icmp-error",
                [IP6_SV_REASSEMBLY_NEXT_HANDOFF] = "ip6-sv-reass-output-feature-hoff",
        },
};

VNET_FEATURE_INIT (ip6_sv_reassembly_output_feature) = {
  .arc_name = "ip6-output",
  .node_name = "ip6-sv-reassembly-output-feature",
  .runs_after = 0,
};

VLIB_NODE_FN (ip6_sv_reass_custom_context_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  /*
   * Extended reassembly not supported for non-feature nodes.
   */
  return ip6_sv_reassembly_inline (vm, node, frame,
				   (struct ip6_sv_reass_args){
				     .is_feature = false,
				     .is_output_feature = false,
				     .custom_context = true,
				     .custom_next = true,
				     .extended = false,
				   });
}

VLIB_REGISTER_NODE (ip6_sv_reass_custom_context_node) = {
    .name = "ip6-sv-reassembly-custom-context",
    .vector_size = sizeof (u32),
    .aux_size = sizeof (u32),
    .format_trace = format_ip6_sv_reass_trace,
    .n_errors = IP6_N_ERROR,
    .error_counters = ip6_error_counters,
    .n_next_nodes = IP6_SV_REASSEMBLY_N_NEXT,
    .next_nodes =
        {
                [IP6_SV_REASSEMBLY_NEXT_INPUT] = "ip6-input",
                [IP6_SV_REASSEMBLY_NEXT_DROP] = "ip6-drop",
                [IP6_SV_REASSEMBLY_NEXT_ICMP_ERROR] = "ip6-icmp-error",
                [IP6_SV_REASSEMBLY_NEXT_HANDOFF] = "ip6-sv-reassembly-custom-context-handoff",
        },
};

#ifndef CLIB_MARCH_VARIANT
static u32
ip6_sv_reass_get_nbuckets ()
{
  ip6_sv_reass_main_t *rm = &ip6_sv_reass_main;
  u32 nbuckets;
  u8 i;

  nbuckets = (u32) (rm->max_reass_n / IP6_SV_REASS_HT_LOAD_FACTOR);

  for (i = 0; i < 31; i++)
    if ((1 << i) >= nbuckets)
      break;
  nbuckets = 1 << i;

  return nbuckets;
}
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  IP6_EVENT_CONFIG_CHANGED = 1,
} ip6_sv_reass_event_t;

#ifndef CLIB_MARCH_VARIANT
typedef struct
{
  int failure;
  clib_bihash_48_8_t *new_hash;
} ip6_rehash_cb_ctx;

static int
ip6_rehash_cb (clib_bihash_kv_48_8_t *kv, void *_ctx)
{
  ip6_rehash_cb_ctx *ctx = _ctx;
  if (clib_bihash_add_del_48_8 (ctx->new_hash, kv, 1))
    {
      ctx->failure = 1;
    }
  return (BIHASH_WALK_CONTINUE);
}

static void
ip6_sv_reass_set_params (u32 timeout_ms, u32 max_reassemblies,
			 u32 max_reassembly_length,
			 u32 expire_walk_interval_ms)
{
  ip6_sv_reass_main.timeout_ms = timeout_ms;
  ip6_sv_reass_main.timeout = (f64) timeout_ms / (f64) MSEC_PER_SEC;
  ip6_sv_reass_main.max_reass_n = max_reassemblies;
  ip6_sv_reass_main.max_reass_len = max_reassembly_length;
  ip6_sv_reass_main.expire_walk_interval_ms = expire_walk_interval_ms;
}

vnet_api_error_t
ip6_sv_reass_set (u32 timeout_ms, u32 max_reassemblies,
		  u32 max_reassembly_length, u32 expire_walk_interval_ms)
{
  u32 old_nbuckets = ip6_sv_reass_get_nbuckets ();
  ip6_sv_reass_set_params (timeout_ms, max_reassemblies, max_reassembly_length,
			   expire_walk_interval_ms);
  vlib_process_signal_event (ip6_sv_reass_main.vlib_main,
			     ip6_sv_reass_main.ip6_sv_reass_expire_node_idx,
			     IP6_EVENT_CONFIG_CHANGED, 0);
  u32 new_nbuckets = ip6_sv_reass_get_nbuckets ();
  if (ip6_sv_reass_main.max_reass_n > 0 && new_nbuckets > old_nbuckets)
    {
      clib_bihash_48_8_t new_hash;
      clib_memset (&new_hash, 0, sizeof (new_hash));
      ip6_rehash_cb_ctx ctx;
      ctx.failure = 0;
      ctx.new_hash = &new_hash;
      clib_bihash_init_48_8 (&new_hash, "ip6-sv-reass", new_nbuckets,
			     (uword) new_nbuckets * 1024);
      clib_bihash_foreach_key_value_pair_48_8 (&ip6_sv_reass_main.hash,
					       ip6_rehash_cb, &ctx);
      if (ctx.failure)
	{
	  clib_bihash_free_48_8 (&new_hash);
	  return -1;
	}
      else
	{
	  clib_bihash_free_48_8 (&ip6_sv_reass_main.hash);
	  clib_memcpy_fast (&ip6_sv_reass_main.hash, &new_hash,
			    sizeof (ip6_sv_reass_main.hash));
	  clib_bihash_copied (&ip6_sv_reass_main.hash, &new_hash);
	}
    }
  return 0;
}

vnet_api_error_t
ip6_sv_reass_get (u32 *timeout_ms, u32 *max_reassemblies,
		  u32 *max_reassembly_length, u32 *expire_walk_interval_ms)
{
  *timeout_ms = ip6_sv_reass_main.timeout_ms;
  *max_reassemblies = ip6_sv_reass_main.max_reass_n;
  *max_reassembly_length = ip6_sv_reass_main.max_reass_len;
  *expire_walk_interval_ms = ip6_sv_reass_main.expire_walk_interval_ms;
  return 0;
}

static clib_error_t *
ip6_sv_reass_init_function (vlib_main_t *vm)
{
  ip6_sv_reass_main_t *rm = &ip6_sv_reass_main;
  clib_error_t *error = 0;
  u32 nbuckets;
  vlib_node_t *node;

  rm->vlib_main = vm;
  rm->vnet_main = vnet_get_main ();

  vec_validate (rm->per_thread_data, vlib_num_workers ());
  ip6_sv_reass_per_thread_t *rt;
  vec_foreach (rt, rm->per_thread_data)
    {
      clib_spinlock_init (&rt->lock);
      pool_alloc (rt->pool, rm->max_reass_n);
      rt->lru_first = rt->lru_last = ~0;
    }

  node = vlib_get_node_by_name (vm, (u8 *) "ip6-sv-reassembly-expire-walk");
  ASSERT (node);
  rm->ip6_sv_reass_expire_node_idx = node->index;

  ip6_sv_reass_set_params (IP6_SV_REASS_TIMEOUT_DEFAULT_MS,
			   IP6_SV_REASS_MAX_REASSEMBLIES_DEFAULT,
			   IP6_SV_REASS_MAX_REASSEMBLY_LENGTH_DEFAULT,
			   IP6_SV_REASS_EXPIRE_WALK_INTERVAL_DEFAULT_MS);

  nbuckets = ip6_sv_reass_get_nbuckets ();
  clib_bihash_init_48_8 (&rm->hash, "ip6-sv-reass", nbuckets,
			 (uword) nbuckets * 1024);

  if ((error = vlib_call_init_function (vm, ip_main_init)))
    return error;

  rm->fq_index = vlib_frame_queue_main_init (ip6_sv_reass_node.index, 0);
  rm->fq_feature_index =
    vlib_frame_queue_main_init (ip6_sv_reass_node_feature.index, 0);
  rm->fq_output_feature_index =
    vlib_frame_queue_main_init (ip6_sv_reass_node_output_feature.index, 0);
  rm->fq_custom_context_index =
    vlib_frame_queue_main_init (ip6_sv_reass_custom_context_node.index, 0);

  rm->feature_use_refcount_per_intf = NULL;

  return error;
}

VLIB_INIT_FUNCTION (ip6_sv_reass_init_function);
#endif /* CLIB_MARCH_VARIANT */

static uword
ip6_sv_reass_walk_expired (vlib_main_t *vm,
			   CLIB_UNUSED (vlib_node_runtime_t *node),
			   CLIB_UNUSED (vlib_frame_t *f))
{
  ip6_sv_reass_main_t *rm = &ip6_sv_reass_main;
  uword event_type, *event_data = 0;

  while (true)
    {
      vlib_process_wait_for_event_or_clock (
	vm, (f64) rm->expire_walk_interval_ms / (f64) MSEC_PER_SEC);
      event_type = vlib_process_get_events (vm, &event_data);

      switch (event_type)
	{
	case ~0:
	  /* no events => timeout */
	  /* fallthrough */
	case IP6_EVENT_CONFIG_CHANGED:
	  /* nothing to do here */
	  break;
	default:
	  clib_warning ("BUG: event type 0x%wx", event_type);
	  break;
	}
      f64 now = vlib_time_now (vm);

      ip6_sv_reass_t *reass;
      int *pool_indexes_to_free = NULL;

      uword thread_index = 0;
      int index;
      const uword nthreads = vlib_num_workers () + 1;
      for (thread_index = 0; thread_index < nthreads; ++thread_index)
	{
	  ip6_sv_reass_per_thread_t *rt = &rm->per_thread_data[thread_index];
	  clib_spinlock_lock (&rt->lock);

	  vec_reset_length (pool_indexes_to_free);
	  pool_foreach_index (index, rt->pool)
	    {
	      reass = pool_elt_at_index (rt->pool, index);
	      if (now > reass->last_heard + rm->timeout)
		{
		  vec_add1 (pool_indexes_to_free, index);
		}
	    }
	  int *i;
	  vec_foreach (i, pool_indexes_to_free)
	    {
	      ip6_sv_reass_t *reass = pool_elt_at_index (rt->pool, i[0]);
	      ip6_sv_reass_free (vm, rm, rt, reass, true);
	    }

	  clib_spinlock_unlock (&rt->lock);
	}

      vec_free (pool_indexes_to_free);
      if (event_data)
	{
	  vec_set_len (event_data, 0);
	}
    }

  return 0;
}

VLIB_REGISTER_NODE (ip6_sv_reass_expire_node) = {
  .function = ip6_sv_reass_walk_expired,
  .format_trace = format_ip6_sv_reass_trace,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "ip6-sv-reassembly-expire-walk",

  .n_errors = IP6_N_ERROR,
  .error_counters = ip6_error_counters,
};

static u8 *
format_ip6_sv_reass_key (u8 *s, va_list *args)
{
  ip6_sv_reass_key_t *key = va_arg (*args, ip6_sv_reass_key_t *);
  s =
    format (s, "fib_index: %u, src: %U, dst: %U, frag_id: %u, proto: %u",
	    key->fib_index, format_ip6_address, &key->src, format_ip6_address,
	    &key->dst, clib_net_to_host_u16 (key->frag_id), key->proto);
  return s;
}

static u8 *
format_ip6_sv_reass (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  ip6_sv_reass_t *reass = va_arg (*args, ip6_sv_reass_t *);

  s = format (s, "ID: %lu, key: %U, trace_op_counter: %u\n", reass->id,
	      format_ip6_sv_reass_key, &reass->key, reass->trace_op_counter);
  vlib_buffer_t *b;
  u32 *bip;
  u32 counter = 0;
  vec_foreach (bip, reass->cached_buffers)
    {
      u32 bi = *bip;
      do
	{
	  b = vlib_get_buffer (vm, bi);
	  s = format (s, "  #%03u: bi: %u\n", counter, bi);
	  ++counter;
	  bi = b->next_buffer;
	}
      while (b->flags & VLIB_BUFFER_NEXT_PRESENT);
    }
  return s;
}

static clib_error_t *
show_ip6_sv_reass (vlib_main_t *vm, unformat_input_t *input,
		   CLIB_UNUSED (vlib_cli_command_t *lmd))
{
  ip6_sv_reass_main_t *rm = &ip6_sv_reass_main;

  vlib_cli_output (vm, "---------------------");
  vlib_cli_output (vm, "IP6 reassembly status");
  vlib_cli_output (vm, "---------------------");
  bool details = false;
  if (unformat (input, "details"))
    {
      details = true;
    }

  u32 sum_reass_n = 0;
  u64 sum_buffers_n = 0;
  ip6_sv_reass_t *reass;
  uword thread_index;
  const uword nthreads = vlib_num_workers () + 1;
  for (thread_index = 0; thread_index < nthreads; ++thread_index)
    {
      ip6_sv_reass_per_thread_t *rt = &rm->per_thread_data[thread_index];
      clib_spinlock_lock (&rt->lock);
      if (details)
	{
	  pool_foreach (reass, rt->pool)
	    {
	      vlib_cli_output (vm, "%U", format_ip6_sv_reass, vm, reass);
	    }
	}
      sum_reass_n += rt->reass_n;
      clib_spinlock_unlock (&rt->lock);
    }
  vlib_cli_output (vm, "---------------------");
  vlib_cli_output (vm, "Current IP6 reassemblies count: %lu\n",
		   (long unsigned) sum_reass_n);
  vlib_cli_output (vm,
		   "Maximum configured concurrent shallow virtual IP6 "
		   "reassemblies per worker-thread: %lu\n",
		   (long unsigned) rm->max_reass_n);
  vlib_cli_output (vm,
		   "Maximum configured amount of fragments per shallow "
		   "virtual IP6 reassembly: %lu\n",
		   (long unsigned) rm->max_reass_len);
  vlib_cli_output (
    vm, "Maximum configured shallow virtual IP6 reassembly timeout: %lums\n",
    (long unsigned) rm->timeout_ms);
  vlib_cli_output (vm,
		   "Maximum configured shallow virtual IP6 reassembly expire "
		   "walk interval: %lums\n",
		   (long unsigned) rm->expire_walk_interval_ms);
  vlib_cli_output (vm, "Buffers in use: %lu\n", (long unsigned) sum_buffers_n);
  return 0;
}

VLIB_CLI_COMMAND (show_ip6_sv_reassembly_cmd, static) = {
  .path = "show ip6-sv-reassembly",
  .short_help = "show ip6-sv-reassembly [details]",
  .function = show_ip6_sv_reass,
};

#ifndef CLIB_MARCH_VARIANT
vnet_api_error_t
ip6_sv_reass_enable_disable (u32 sw_if_index, u8 enable_disable)
{
  return ip6_sv_reass_enable_disable_with_refcnt (sw_if_index, enable_disable);
}
#endif /* CLIB_MARCH_VARIANT */

#define foreach_ip6_sv_reassembly_handoff_error                               \
  _ (CONGESTION_DROP, "congestion drop")

typedef enum
{
#define _(sym, str) IP6_SV_REASSEMBLY_HANDOFF_ERROR_##sym,
  foreach_ip6_sv_reassembly_handoff_error
#undef _
    IP6_SV_REASSEMBLY_HANDOFF_N_ERROR,
} ip6_sv_reassembly_handoff_error_t;

static char *ip6_sv_reassembly_handoff_error_strings[] = {
#define _(sym, string) string,
  foreach_ip6_sv_reassembly_handoff_error
#undef _
};

typedef struct
{
  clib_thread_index_t thread_index;
} ip6_sv_reassembly_handoff_trace_t;

static u8 *
format_ip6_sv_reassembly_handoff_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_sv_reassembly_handoff_trace_t *t =
    va_arg (*args, ip6_sv_reassembly_handoff_trace_t *);

  s = format (s, "to thread-index: %u", t->thread_index);

  return s;
}

struct ip6_sv_reass_hoff_args
{
  bool is_feature;
  bool is_output_feature;
  bool custom_context;
};

always_inline uword
ip6_sv_reassembly_handoff_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
				  vlib_frame_t *frame,
				  struct ip6_sv_reass_hoff_args a)
{
  ip6_sv_reass_main_t *rm = &ip6_sv_reass_main;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 n_enq, n_left_from, *from, *context;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti;

  from = vlib_frame_vector_args (frame);
  if (a.custom_context)
    context = vlib_frame_aux_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  b = bufs;
  ti = thread_indices;

  const u32 fq_index = a.is_output_feature ? rm->fq_output_feature_index :
		       a.is_feature	   ? rm->fq_feature_index :
		       a.custom_context	   ? rm->fq_custom_context_index :
					     rm->fq_index;

  while (n_left_from > 0)
    {
      ti[0] = vnet_buffer (b[0])->ip.reass.owner_thread_index;

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  ip6_sv_reassembly_handoff_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->thread_index = ti[0];
	}

      n_left_from -= 1;
      ti += 1;
      b += 1;
    }
  if (a.custom_context)
    n_enq = vlib_buffer_enqueue_to_thread_with_aux (
      vm, node, fq_index, from, context, thread_indices, frame->n_vectors, 1);
  else
    n_enq = vlib_buffer_enqueue_to_thread (
      vm, node, fq_index, from, thread_indices, frame->n_vectors, 1);

  if (n_enq < frame->n_vectors)
    vlib_node_increment_counter (
      vm, node->node_index, IP6_SV_REASSEMBLY_HANDOFF_ERROR_CONGESTION_DROP,
      frame->n_vectors - n_enq);
  return frame->n_vectors;
}

VLIB_NODE_FN (ip6_sv_reassembly_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ip6_sv_reassembly_handoff_inline (
    vm, node, frame,
    (struct ip6_sv_reass_hoff_args){ .is_feature = false,
				     .is_output_feature = false,
				     .custom_context = false });
}

VLIB_REGISTER_NODE (ip6_sv_reassembly_handoff_node) = {
  .name = "ip6-sv-reassembly-handoff",
  .vector_size = sizeof (u32),
  .n_errors = ARRAY_LEN(ip6_sv_reassembly_handoff_error_strings),
  .error_strings = ip6_sv_reassembly_handoff_error_strings,
  .format_trace = format_ip6_sv_reassembly_handoff_trace,

  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FN (ip6_sv_reassembly_feature_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ip6_sv_reassembly_handoff_inline (
    vm, node, frame,
    (struct ip6_sv_reass_hoff_args){ .is_feature = true,
				     .is_output_feature = false,
				     .custom_context = false });
}

VLIB_REGISTER_NODE (ip6_sv_reassembly_feature_handoff_node) = {
  .name = "ip6-sv-reass-feature-hoff",
  .vector_size = sizeof (u32),
  .n_errors = ARRAY_LEN(ip6_sv_reassembly_handoff_error_strings),
  .error_strings = ip6_sv_reassembly_handoff_error_strings,
  .format_trace = format_ip6_sv_reassembly_handoff_trace,

  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FN (ip6_sv_reassembly_output_feature_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ip6_sv_reassembly_handoff_inline (
    vm, node, frame,
    (struct ip6_sv_reass_hoff_args){ .is_feature = false,
				     .is_output_feature = true,
				     .custom_context = false });
}

VLIB_REGISTER_NODE (ip6_sv_reassembly_output_feature_handoff_node) = {
  .name = "ip6-sv-reass-output-feature-hoff",
  .vector_size = sizeof (u32),
  .n_errors = ARRAY_LEN(ip6_sv_reassembly_handoff_error_strings),
  .error_strings = ip6_sv_reassembly_handoff_error_strings,
  .format_trace = format_ip6_sv_reassembly_handoff_trace,

  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FN (ip6_sv_reassembly_custom_context_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ip6_sv_reassembly_handoff_inline (
    vm, node, frame,
    (struct ip6_sv_reass_hoff_args){ .is_feature = false,
				     .is_output_feature = false,
				     .custom_context = true });
}

VLIB_REGISTER_NODE (ip6_sv_reassembly_custom_context_handoff_node) = {
  .name = "ip6-sv-reassembly-custom-context-handoff",
  .vector_size = sizeof (u32),
  .aux_size = sizeof (u32),
  .n_errors = ARRAY_LEN(ip6_sv_reassembly_handoff_error_strings),
  .error_strings = ip6_sv_reassembly_handoff_error_strings,
  .format_trace = format_ip6_sv_reassembly_handoff_trace,

  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "error-drop",
  },
};

#ifndef CLIB_MARCH_VARIANT
int
ip6_sv_reass_enable_disable_with_refcnt (u32 sw_if_index, int is_enable)
{
  ip6_sv_reass_main_t *rm = &ip6_sv_reass_main;
  vec_validate (rm->feature_use_refcount_per_intf, sw_if_index);
  if (is_enable)
    {
      if (!rm->feature_use_refcount_per_intf[sw_if_index])
	{
	  int rv = vnet_feature_enable_disable (
	    "ip6-unicast", "ip6-sv-reassembly-feature", sw_if_index, 1, 0, 0);
	  if (0 != rv)
	    return rv;
	}
      ++rm->feature_use_refcount_per_intf[sw_if_index];
    }
  else
    {
      --rm->feature_use_refcount_per_intf[sw_if_index];
      if (!rm->feature_use_refcount_per_intf[sw_if_index])
	return vnet_feature_enable_disable (
	  "ip6-unicast", "ip6-sv-reassembly-feature", sw_if_index, 0, 0, 0);
    }
  return 0;
}

vnet_api_error_t
ip6_sv_reass_output_enable_disable_with_refcnt (u32 sw_if_index, int is_enable)
{
  ip6_sv_reass_main_t *rm = &ip6_sv_reass_main;
  vec_validate (rm->output_feature_use_refcount_per_intf, sw_if_index);
  if (is_enable)
    {
      if (!rm->output_feature_use_refcount_per_intf[sw_if_index])
	{
	  int rv = vnet_feature_enable_disable (
	    "ip6-output", "ip6-sv-reassembly-output-feature", sw_if_index, 1,
	    0, 0);
	  if (0 != rv)
	    return rv;
	}
      ++rm->output_feature_use_refcount_per_intf[sw_if_index];
    }
  else
    {
      --rm->output_feature_use_refcount_per_intf[sw_if_index];
      if (!rm->output_feature_use_refcount_per_intf[sw_if_index])
	return vnet_feature_enable_disable ("ip6-output",
					    "ip6-sv-reassembly-output-feature",
					    sw_if_index, 0, 0, 0);
    }
  return 0;
}

uword
ip6_sv_reass_custom_context_register_next_node (uword node_index)
{
  return vlib_node_add_next (
    vlib_get_main (), ip6_sv_reassembly_custom_context_handoff_node.index,
    node_index);
}

void
ip6_sv_reass_enable_disable_extended (bool is_enable)
{
  if (is_enable)
    ++ip6_sv_reass_main.extended_refcount;
  else
    --ip6_sv_reass_main.extended_refcount;
}

int
ip6_sv_reass_extended_lock (vlib_buffer_t *b,
			    struct ip6_sv_lock_unlock_args *a)
{
  ip6_sv_reass_per_thread_t *per_thread =
    &ip6_sv_reass_main
       .per_thread_data[vnet_buffer2 (b)->ip.reass.thread_index];

  if (!vec_is_member (ip6_sv_reass_main.per_thread_data, per_thread))
    return -1;

  clib_spinlock_lock (&per_thread->lock);
  if (pool_is_free_index (per_thread->pool,
			  vnet_buffer2 (b)->ip.reass.pool_index))
    goto fail;

  ip6_sv_reass_t *reass = pool_elt_at_index (
    per_thread->pool, vnet_buffer2 (b)->ip.reass.pool_index);
  if (vnet_buffer2 (b)->ip.reass.id == reass->id)
    {
      *a->total_ip_payload_length = reass->total_ip_payload_length;

      *a->first_fragment_buffer_index = reass->first_fragment_clone_bi;
      *a->first_fragment_total_ip_header_length =
	reass->first_fragment_total_ip_header_length;
      return 0;
    }

fail:
  clib_spinlock_unlock (&per_thread->lock);
  return -1;
}

void
ip6_sv_reass_extended_unlock (vlib_buffer_t *b)
{
  ip6_sv_reass_per_thread_t *per_thread =
    &ip6_sv_reass_main
       .per_thread_data[vnet_buffer2 (b)->ip.reass.thread_index];
  clib_spinlock_unlock (&per_thread->lock);
}
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
