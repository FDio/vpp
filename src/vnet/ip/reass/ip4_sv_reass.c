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
 * @brief IPv4 Shallow Virtual Reassembly.
 *
 * This file contains the source code for IPv4 Shallow Virtual reassembly.
 */

#include <vppinfra/vec.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4_to_ip6.h>
#include <vppinfra/fifo.h>
#include <vppinfra/bihash_16_8.h>
#include <vnet/ip/reass/ip4_sv_reass.h>

#define MSEC_PER_SEC			1000
#define IP4_SV_REASS_TIMEOUT_DEFAULT_MS 100
#define IP4_SV_REASS_EXPIRE_WALK_INTERVAL_DEFAULT_MS                          \
  10000 // 10 seconds default
#define IP4_SV_REASS_MAX_REASSEMBLIES_DEFAULT	   1024
#define IP4_SV_REASS_MAX_REASSEMBLY_LENGTH_DEFAULT 3
#define IP4_SV_REASS_HT_LOAD_FACTOR		   (0.75)

typedef enum
{
  IP4_SV_REASS_RC_OK,
  IP4_SV_REASS_RC_TOO_MANY_FRAGMENTS,
  IP4_SV_REASS_RC_UNSUPP_IP_PROTO,
} ip4_sv_reass_rc_t;

typedef struct
{
  union
  {
    struct
    {
      u32 fib_index;
      ip4_address_t src;
      ip4_address_t dst;
      u16 frag_id;
      u8 proto;
      u8 unused;
    };
    u64 as_u64[2];
  };
} ip4_sv_reass_key_t;

typedef union
{
  struct
  {
    u32 reass_index;
    clib_thread_index_t thread_index;
  };
  u64 as_u64;
} ip4_sv_reass_val_t;

typedef union
{
  struct
  {
    ip4_sv_reass_key_t k;
    ip4_sv_reass_val_t v;
  };
  clib_bihash_kv_16_8_t kv;
} ip4_sv_reass_kv_t;

typedef struct
{
  // hash table key
  ip4_sv_reass_key_t key;
  // time when last packet was received
  f64 last_heard;
  // internal id of this reassembly
  u64 id;
  // trace operation counter
  u32 trace_op_counter;
  // minimum fragment length for this reassembly - used to estimate MTU
  u16 min_fragment_length;
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

  u32 next_index;
  // lru indexes
  u32 lru_prev;
  u32 lru_next;
} ip4_sv_reass_t;

typedef struct
{
  ip4_sv_reass_t *pool;
  u32 id_counter;
  clib_spinlock_t lock;
  // lru indexes
  u32 lru_first;
  u32 lru_last;
} ip4_sv_reass_per_thread_t;

typedef struct
{
  // IPv4 config
  u32 timeout_ms;
  f64 timeout;
  u32 expire_walk_interval_ms;
  // maximum number of fragments in one reassembly
  u32 max_reass_len;
  // maximum number of reassemblies
  u32 max_reass_n;

  // IPv4 runtime
  clib_bihash_16_8_t hash;
  // per-thread data
  ip4_sv_reass_per_thread_t *per_thread_data;

  // convenience
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  u32 ip4_sv_reass_expire_node_idx;

  /** Worker handoff */
  u32 fq_index;
  u32 fq_feature_index;
  u32 fq_output_feature_index;
  u32 fq_custom_context_index;

  // reference count for enabling/disabling feature - per interface
  u32 *feature_use_refcount_per_intf;

  // reference count for enabling/disabling feature - per interface
  u32 *output_feature_use_refcount_per_intf;

  // extended reassembly refcount - see ip4_sv_reass_enable_disable_extended()
  u32 extended_refcount;
} ip4_sv_reass_main_t;

extern ip4_sv_reass_main_t ip4_sv_reass_main;

#ifndef CLIB_MARCH_VARIANT
ip4_sv_reass_main_t ip4_sv_reass_main;
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  IP4_SV_REASSEMBLY_NEXT_INPUT,
  IP4_SV_REASSEMBLY_NEXT_DROP,
  IP4_SV_REASSEMBLY_NEXT_HANDOFF,
  IP4_SV_REASSEMBLY_N_NEXT,
} ip4_sv_reass_next_t;

typedef enum
{
  REASS_FRAGMENT_CACHE,
  REASS_FIRST_FRAG,
  REASS_LAST_FRAG,
  REASS_FRAGMENT_FORWARD,
  REASS_PASSTHROUGH,
  REASS_HANDOFF,
  REASS_KEY,
  REASS_FREE_TIMEOUT,
  REASS_FREE_LRU,
  REASS_FREE_ERROR,
} ip4_sv_reass_trace_operation_e;

typedef struct
{
  ip4_sv_reass_trace_operation_e action;
  u32 reass_id;
  u32 op_id;
  u8 ip_proto;
  u16 l4_src_port;
  u16 l4_dst_port;
  int l4_hdr_truncated;
  u32 handoff_thread_index;
  clib_bihash_kv_16_8_t kv;
} ip4_sv_reass_trace_t;

extern vlib_node_registration_t ip4_sv_reass_node;
extern vlib_node_registration_t ip4_sv_reass_node_feature;

static u8 *
format_ip4_sv_reass_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip4_sv_reass_trace_t *t = va_arg (*args, ip4_sv_reass_trace_t *);
  if (REASS_PASSTHROUGH != t->action && REASS_HANDOFF != t->action &&
      REASS_KEY != t->action && REASS_FREE_TIMEOUT != t->action &&
      REASS_FREE_LRU != t->action && REASS_FREE_ERROR != t->action)
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
    case REASS_HANDOFF:
      s = format (s, "[handoff, thread index: %u]", t->handoff_thread_index);
      break;
    case REASS_KEY:
      s = format (s, "[lookup, key: %U]", format_bihash_kvp_16_8, &t->kv);
      break;
    case REASS_FREE_LRU:
      s = format (s, "[free, LRU pressure]");
      break;
    case REASS_FREE_TIMEOUT:
      s = format (s, "[free, timed out]");
      break;
    case REASS_FREE_ERROR:
      s = format (s, "[free, error occurred]");
      break;
    case REASS_FRAGMENT_FORWARD:
      s = format (s, "[forward, ip proto=%u, src_port=%u, dst_port=%u]",
		  t->ip_proto, clib_net_to_host_u16 (t->l4_src_port),
		  clib_net_to_host_u16 (t->l4_dst_port));
      break;
    case REASS_PASSTHROUGH:
      s = format (s, "[not-fragmented]");
      break;
    }
  if (t->l4_hdr_truncated)
    {
      s = format (s, " [l4-hdr-truncated]");
    }
  return s;
}

static void
ip4_sv_reass_add_trace (vlib_main_t *vm, vlib_node_runtime_t *node,
			ip4_sv_reass_t *reass, u32 bi,
			ip4_sv_reass_trace_operation_e action, u32 ip_proto,
			u16 l4_src_port, u16 l4_dst_port, int l4_hdr_truncated,
			u32 handoff_thread_index)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  if (pool_is_free_index (vm->trace_main.trace_buffer_pool,
			  vlib_buffer_get_trace_index (b)))
    {
      // this buffer's trace is gone
      b->flags &= ~VLIB_BUFFER_IS_TRACED;
      return;
    }
  ip4_sv_reass_trace_t *t = vlib_add_trace (vm, node, b, sizeof (t[0]));
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
  t->l4_hdr_truncated = l4_hdr_truncated;
  t->handoff_thread_index = handoff_thread_index;
#if 0
  static u8 *s = NULL;
  s = format (s, "%U", format_ip4_sv_reass_trace, NULL, NULL, t);
  printf ("%.*s\n", vec_len (s), s);
  fflush (stdout);
  vec_reset_length (s);
#endif
}

static void
ip4_sv_reass_trace_timeout (vlib_main_t *vm, vlib_node_runtime_t *node,
			    ip4_sv_reass_t *reass, u32 bi)
{
  return ip4_sv_reass_add_trace (vm, node, reass, bi, REASS_FREE_TIMEOUT, ~0,
				 ~0, ~0, 0, ~0);
}

static void
ip4_sv_reass_trace_lru_free (vlib_main_t *vm, vlib_node_runtime_t *node,
			     ip4_sv_reass_t *reass, u32 bi)
{
  return ip4_sv_reass_add_trace (vm, node, reass, bi, REASS_FREE_LRU, ~0, ~0,
				 ~0, 0, ~0);
}

static void
ip4_sv_reass_trace_error_free (vlib_main_t *vm, vlib_node_runtime_t *node,
			       ip4_sv_reass_t *reass, u32 bi)
{
  return ip4_sv_reass_add_trace (vm, node, reass, bi, REASS_FREE_ERROR, ~0, ~0,
				 ~0, 0, ~0);
}

always_inline void
ip4_sv_reass_free (vlib_main_t *vm, ip4_sv_reass_main_t *rm,
		   ip4_sv_reass_per_thread_t *rt, ip4_sv_reass_t *reass,
		   bool del_bihash)
{
  if (del_bihash)
    {
      clib_bihash_kv_16_8_t kv;
      kv.key[0] = reass->key.as_u64[0];
      kv.key[1] = reass->key.as_u64[1];
      clib_bihash_add_del_16_8 (&rm->hash, &kv, 0);
    }
  vlib_buffer_free (vm, reass->cached_buffers,
		    vec_len (reass->cached_buffers));
  vec_free (reass->cached_buffers);
  reass->cached_buffers = NULL;
  if (~0 != reass->first_fragment_clone_bi)
    vlib_buffer_free_one (vm, reass->first_fragment_clone_bi);
  if (~0 != reass->lru_prev)
    {
      ip4_sv_reass_t *lru_prev = pool_elt_at_index (rt->pool, reass->lru_prev);
      lru_prev->lru_next = reass->lru_next;
    }
  if (~0 != reass->lru_next)
    {
      ip4_sv_reass_t *lru_next = pool_elt_at_index (rt->pool, reass->lru_next);
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
}

always_inline ip4_sv_reass_t *
ip4_sv_reass_find_or_create (vlib_main_t *vm, vlib_node_runtime_t *node,
			     u32 bi, ip4_sv_reass_main_t *rm,
			     ip4_sv_reass_per_thread_t *rt,
			     ip4_sv_reass_kv_t *kv, u8 *do_handoff)
{
  ip4_sv_reass_t *reass = NULL;
  f64 now = vlib_time_now (vm);

again:

  if (!clib_bihash_search_16_8 (&rm->hash, &kv->kv, &kv->kv))
    {
      if (vm->thread_index != kv->v.thread_index)
	{
	  *do_handoff = 1;
	  return NULL;
	}
      reass = pool_elt_at_index (rt->pool, kv->v.reass_index);

      if (now > reass->last_heard + rm->timeout)
	{
	  ip4_sv_reass_trace_timeout (vm, node, reass, bi);
	  ip4_sv_reass_free (vm, rm, rt, reass, true);
	  reass = NULL;
	}
    }

  if (reass)
    {
      reass->last_heard = now;
      return reass;
    }

  if (pool_elts (rt->pool) >= rm->max_reass_n && rm->max_reass_n)
    {
      reass = pool_elt_at_index (rt->pool, rt->lru_first);
      ip4_sv_reass_trace_lru_free (vm, node, reass, bi);
      ip4_sv_reass_free (vm, rm, rt, reass, true);
    }

  pool_get_zero (rt->pool, reass);
  reass->first_fragment_clone_bi = ~0;
  reass->id = ((u64) vm->thread_index * 1000000000) + rt->id_counter;
  ++rt->id_counter;
  reass->lru_prev = reass->lru_next = ~0;

  if (~0 != rt->lru_last)
    {
      ip4_sv_reass_t *lru_last = pool_elt_at_index (rt->pool, rt->lru_last);
      reass->lru_prev = rt->lru_last;
      lru_last->lru_next = rt->lru_last = reass - rt->pool;
    }

  if (~0 == rt->lru_first)
    {
      rt->lru_first = rt->lru_last = reass - rt->pool;
    }

  reass->key.as_u64[0] = kv->kv.key[0];
  reass->key.as_u64[1] = kv->kv.key[1];
  kv->v.reass_index = (reass - rt->pool);
  kv->v.thread_index = vm->thread_index;
  reass->last_heard = now;

  int rv = clib_bihash_add_del_16_8 (&rm->hash, &kv->kv, 2);
  if (rv)
    {
      ip4_sv_reass_free (vm, rm, rt, reass, false);
      reass = NULL;
      // if other worker created a context already work with the other copy
      if (-2 == rv)
	goto again;
    }

  return reass;
}

always_inline bool
ip4_sv_reass_is_complete (ip4_sv_reass_t *reass, bool extended)
{
  /*
   * Both first and last fragments have to be seen for extended reassembly to
   * be complete. Otherwise first fragment is enough.
   */
  if (extended)
    return reass->first_fragment_seen && reass->last_fragment_seen;

  return reass->first_fragment_seen;
}

always_inline ip4_sv_reass_rc_t
ip4_sv_reass_update (vlib_main_t *vm, vlib_node_runtime_t *node,
		     ip4_sv_reass_main_t *rm, ip4_header_t *ip0,
		     ip4_sv_reass_t *reass, u32 bi0, bool extended)
{
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  ip4_sv_reass_rc_t rc = IP4_SV_REASS_RC_OK;
  const u32 fragment_first = ip4_get_fragment_offset_bytes (ip0);
  if (0 == fragment_first)
    {
      reass->ip_proto = ip0->protocol;
      reass->l4_src_port = ip4_get_port (ip0, 1);
      reass->l4_dst_port = ip4_get_port (ip0, 0);
      if (!reass->l4_src_port || !reass->l4_dst_port)
	return IP4_SV_REASS_RC_UNSUPP_IP_PROTO;
      if (IP_PROTOCOL_TCP == reass->ip_proto)
	{
	  tcp_header_t *th = ip4_next_header (ip0);
	  reass->icmp_type_or_tcp_flags = th->flags;
	  reass->tcp_ack_number = th->ack_number;
	  reass->tcp_seq_number = th->seq_number;
	}
      else if (IP_PROTOCOL_ICMP == reass->ip_proto)
	{
	  reass->icmp_type_or_tcp_flags =
	    ((icmp46_header_t *) (ip4_next_header (ip0)))->type;
	}
      reass->first_fragment_seen = true;
      if (extended)
	{
	  reass->first_fragment_total_ip_header_length =
	    ip4_header_bytes (ip0);
	  vlib_buffer_t *clone = vlib_buffer_copy_no_chain (
	    vm, b0, &reass->first_fragment_clone_bi);
	  if (!clone)
	    reass->first_fragment_clone_bi = ~0;
	}
      vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ip4_sv_reass_add_trace (
	    vm, node, reass, bi0, REASS_FIRST_FRAG, reass->ip_proto,
	    reass->l4_src_port, reass->l4_dst_port,
	    vnet_buffer (b0)->ip.reass.l4_hdr_truncated, ~0);
	}
    }
  if (!ip4_get_fragment_more (ip0))
    {
      const u32 fragment_length =
	clib_net_to_host_u16 (ip0->length) - ip4_header_bytes (ip0);
      reass->last_fragment_seen = true;
      reass->total_ip_payload_length = fragment_first + fragment_length;
      vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ip4_sv_reass_add_trace (
	    vm, node, reass, bi0, REASS_LAST_FRAG, ~0, ~0, ~0,
	    vnet_buffer (b0)->ip.reass.l4_hdr_truncated, ~0);
	}
    }

  vec_add1 (reass->cached_buffers, bi0);

  if (!ip4_sv_reass_is_complete (reass, extended))
    {
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ip4_sv_reass_add_trace (
	    vm, node, reass, bi0, REASS_FRAGMENT_CACHE, ~0, ~0, ~0,
	    vnet_buffer (b0)->ip.reass.l4_hdr_truncated, ~0);
	}
      if (vec_len (reass->cached_buffers) > rm->max_reass_len)
	{
	  rc = IP4_SV_REASS_RC_TOO_MANY_FRAGMENTS;
	}
    }
  return rc;
}

always_inline int
l4_hdr_truncated (ip4_header_t *ip)
{
  if (IP_PROTOCOL_UDP == ip->protocol)
    return ((u8 *) ip + ip4_header_bytes (ip) + sizeof (udp_header_t) >
	    (u8 *) ip + clib_net_to_host_u16 (ip->length));
  if (IP_PROTOCOL_ICMP == ip->protocol)
    return ((u8 *) ip + ip4_header_bytes (ip) + sizeof (icmp46_header_t) >
	    (u8 *) ip + clib_net_to_host_u16 (ip->length));

  if (IP_PROTOCOL_TCP != ip->protocol)
    return false;

  tcp_header_t *th = ip4_next_header (ip);
  const u32 tcp_opts_len = (tcp_doff (th) << 2) - sizeof (tcp_header_t);

  return ((u8 *) ip + ip4_header_bytes (ip) + sizeof (tcp_header_t) +
	    tcp_opts_len >
	  (u8 *) ip + clib_net_to_host_u16 (ip->length));
}

always_inline void
ip4_sv_reass_reset_vnet_buffer2 (vlib_buffer_t *b)
{
  vnet_buffer2 (b)->ip.reass.pool_index = ~0;
  vnet_buffer2 (b)->ip.reass.thread_index = ~0;
  vnet_buffer2 (b)->ip.reass.id = ~0;
}

always_inline void
ip4_sv_reass_set_vnet_buffer2_from_reass (vlib_main_t *vm, vlib_buffer_t *b,
					  ip4_sv_reass_t *reass)
{
  vnet_buffer2 (b)->ip.reass.thread_index = vm->thread_index;
  vnet_buffer2 (b)->ip.reass.id = reass->id;
  vnet_buffer2 (b)->ip.reass.pool_index =
    reass - ip4_sv_reass_main.per_thread_data[vm->thread_index].pool;
}

struct ip4_sv_reass_args
{
  bool is_feature;
  bool is_output_feature;
  bool is_custom;
  bool with_custom_context;
  bool extended;
};

always_inline uword
ip4_sv_reass_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		     vlib_frame_t *frame, struct ip4_sv_reass_args a)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from, n_left_to_next, *to_next, *to_next_aux, next_index;
  ip4_sv_reass_main_t *rm = &ip4_sv_reass_main;
  ip4_sv_reass_per_thread_t *rt = &rm->per_thread_data[vm->thread_index];
  u32 *context;
  if (a.with_custom_context)
    context = vlib_frame_aux_args (frame);

  clib_spinlock_lock (&rt->lock);

  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  vlib_get_buffers (vm, from, bufs, n_left_from);
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  b = bufs;

  /* optimistic case first - no fragments */
  while (n_left_from >= 2)
    {
      vlib_buffer_t *b0, *b1;
      u32 next0, next1;
      b0 = *b;
      b++;
      b1 = *b;
      b++;

      /* Prefetch next iteration. */
      if (PREDICT_TRUE (n_left_from >= 4))
	{
	  vlib_buffer_t *p2, *p3;

	  p2 = *b;
	  p3 = *(b + 1);

	  vlib_prefetch_buffer_header (p2, LOAD);
	  vlib_prefetch_buffer_header (p3, LOAD);

	  clib_prefetch_load (p2->data);
	  clib_prefetch_load (p3->data);
	}

      ip4_header_t *ip0 = (ip4_header_t *) u8_ptr_add (
	vlib_buffer_get_current (b0),
	(ptrdiff_t) (a.is_output_feature ? 1 : 0) *
	  vnet_buffer (b0)->ip.save_rewrite_length);
      ip4_header_t *ip1 = (ip4_header_t *) u8_ptr_add (
	vlib_buffer_get_current (b1),
	(ptrdiff_t) (a.is_output_feature ? 1 : 0) *
	  vnet_buffer (b1)->ip.save_rewrite_length);

      if (PREDICT_FALSE (ip4_get_fragment_more (ip0) ||
			 ip4_get_fragment_offset (ip0)) ||
	  (ip4_get_fragment_more (ip1) || ip4_get_fragment_offset (ip1)))
	{
	  // fragment found, go slow path
	  b -= 2;
	  if (b - bufs > 0)
	    {
	      vlib_buffer_enqueue_to_next (vm, node, from, (u16 *) nexts,
					   b - bufs);
	    }
	  goto slow_path;
	}
      if (a.is_feature)
	{
	  vnet_feature_next (&next0, b0);
	}
      else
	{
	  next0 = a.is_custom ? vnet_buffer (b0)->ip.reass.next_index :
				IP4_SV_REASSEMBLY_NEXT_INPUT;
	}
      vnet_buffer (b0)->ip.reass.is_non_first_fragment = 0;
      vnet_buffer (b0)->ip.reass.ip_proto = ip0->protocol;

      if (a.extended)
	ip4_sv_reass_reset_vnet_buffer2 (b0);

      if (l4_hdr_truncated (ip0))
	{
	  vnet_buffer (b0)->ip.reass.l4_hdr_truncated = 1;
	}
      else
	{
	  vnet_buffer (b0)->ip.reass.l4_hdr_truncated = 0;
	  if (IP_PROTOCOL_TCP == ip0->protocol)
	    {
	      vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags =
		((tcp_header_t *) (ip4_next_header (ip0)))->flags;
	      vnet_buffer (b0)->ip.reass.tcp_ack_number =
		((tcp_header_t *) (ip4_next_header (ip0)))->ack_number;
	      vnet_buffer (b0)->ip.reass.tcp_seq_number =
		((tcp_header_t *) (ip4_next_header (ip0)))->seq_number;
	    }
	  else if (IP_PROTOCOL_ICMP == ip0->protocol)
	    {
	      vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags =
		((icmp46_header_t *) (ip4_next_header (ip0)))->type;
	    }
	  vnet_buffer (b0)->ip.reass.l4_src_port = ip4_get_port (ip0, 1);
	  vnet_buffer (b0)->ip.reass.l4_dst_port = ip4_get_port (ip0, 0);
	}
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ip4_sv_reass_add_trace (
	    vm, node, NULL, from[(b - 2) - bufs], REASS_PASSTHROUGH,
	    vnet_buffer (b0)->ip.reass.ip_proto,
	    vnet_buffer (b0)->ip.reass.l4_src_port,
	    vnet_buffer (b0)->ip.reass.l4_dst_port,
	    vnet_buffer (b0)->ip.reass.l4_hdr_truncated, ~0);
	}
      if (a.is_feature)
	{
	  vnet_feature_next (&next1, b1);
	}
      else
	{
	  next1 = a.is_custom ? vnet_buffer (b1)->ip.reass.next_index :
				IP4_SV_REASSEMBLY_NEXT_INPUT;
	}
      vnet_buffer (b1)->ip.reass.is_non_first_fragment = 0;
      vnet_buffer (b1)->ip.reass.ip_proto = ip1->protocol;

      if (a.extended)
	ip4_sv_reass_reset_vnet_buffer2 (b1);

      if (l4_hdr_truncated (ip1))
	{
	  vnet_buffer (b1)->ip.reass.l4_hdr_truncated = 1;
	}
      else
	{
	  vnet_buffer (b1)->ip.reass.l4_hdr_truncated = 0;
	  if (IP_PROTOCOL_TCP == ip1->protocol)
	    {
	      vnet_buffer (b1)->ip.reass.icmp_type_or_tcp_flags =
		((tcp_header_t *) (ip4_next_header (ip1)))->flags;
	      vnet_buffer (b1)->ip.reass.tcp_ack_number =
		((tcp_header_t *) (ip4_next_header (ip1)))->ack_number;
	      vnet_buffer (b1)->ip.reass.tcp_seq_number =
		((tcp_header_t *) (ip4_next_header (ip1)))->seq_number;
	    }
	  else if (IP_PROTOCOL_ICMP == ip1->protocol)
	    {
	      vnet_buffer (b1)->ip.reass.icmp_type_or_tcp_flags =
		((icmp46_header_t *) (ip4_next_header (ip1)))->type;
	    }
	  vnet_buffer (b1)->ip.reass.l4_src_port = ip4_get_port (ip1, 1);
	  vnet_buffer (b1)->ip.reass.l4_dst_port = ip4_get_port (ip1, 0);
	}
      if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ip4_sv_reass_add_trace (
	    vm, node, NULL, from[(b - 1) - bufs], REASS_PASSTHROUGH,
	    vnet_buffer (b1)->ip.reass.ip_proto,
	    vnet_buffer (b1)->ip.reass.l4_src_port,
	    vnet_buffer (b1)->ip.reass.l4_dst_port,
	    vnet_buffer (b1)->ip.reass.l4_hdr_truncated, ~0);
	}

      n_left_from -= 2;
      next[0] = next0;
      next[1] = next1;
      next += 2;
      if (a.with_custom_context)
	context += 2;
    }

  while (n_left_from > 0)
    {
      vlib_buffer_t *b0;
      u32 next0;
      b0 = *b;
      b++;

      ip4_header_t *ip0 = (ip4_header_t *) u8_ptr_add (
	vlib_buffer_get_current (b0),
	(ptrdiff_t) (a.is_output_feature ? 1 : 0) *
	  vnet_buffer (b0)->ip.save_rewrite_length);
      if (PREDICT_FALSE (ip4_get_fragment_more (ip0) ||
			 ip4_get_fragment_offset (ip0)))
	{
	  // fragment found, go slow path
	  b -= 1;
	  if (b - bufs > 0)
	    {
	      vlib_buffer_enqueue_to_next (vm, node, from, (u16 *) nexts,
					   b - bufs);
	    }
	  goto slow_path;
	}
      if (a.is_feature)
	{
	  vnet_feature_next (&next0, b0);
	}
      else
	{
	  next0 = a.is_custom ? vnet_buffer (b0)->ip.reass.next_index :
				IP4_SV_REASSEMBLY_NEXT_INPUT;
	}
      vnet_buffer (b0)->ip.reass.is_non_first_fragment = 0;
      vnet_buffer (b0)->ip.reass.ip_proto = ip0->protocol;

      if (a.extended)
	ip4_sv_reass_reset_vnet_buffer2 (b0);

      if (l4_hdr_truncated (ip0))
	{
	  vnet_buffer (b0)->ip.reass.l4_hdr_truncated = 1;
	}
      else
	{
	  vnet_buffer (b0)->ip.reass.l4_hdr_truncated = 0;
	  if (IP_PROTOCOL_TCP == ip0->protocol)
	    {
	      vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags =
		((tcp_header_t *) (ip4_next_header (ip0)))->flags;
	      vnet_buffer (b0)->ip.reass.tcp_ack_number =
		((tcp_header_t *) (ip4_next_header (ip0)))->ack_number;
	      vnet_buffer (b0)->ip.reass.tcp_seq_number =
		((tcp_header_t *) (ip4_next_header (ip0)))->seq_number;
	    }
	  else if (IP_PROTOCOL_ICMP == ip0->protocol)
	    {
	      vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags =
		((icmp46_header_t *) (ip4_next_header (ip0)))->type;
	    }
	  vnet_buffer (b0)->ip.reass.l4_src_port = ip4_get_port (ip0, 1);
	  vnet_buffer (b0)->ip.reass.l4_dst_port = ip4_get_port (ip0, 0);
	}
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ip4_sv_reass_add_trace (
	    vm, node, NULL, from[(b - 1) - bufs], REASS_PASSTHROUGH,
	    vnet_buffer (b0)->ip.reass.ip_proto,
	    vnet_buffer (b0)->ip.reass.l4_src_port,
	    vnet_buffer (b0)->ip.reass.l4_dst_port,
	    vnet_buffer (b0)->ip.reass.l4_hdr_truncated, ~0);
	}

      n_left_from -= 1;
      next[0] = next0;
      next += 1;
      if (a.with_custom_context)
	context += 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, (u16 *) nexts,
			       frame->n_vectors);

  goto done;

slow_path:

  from += b - bufs;

  while (n_left_from > 0)
    {
      if (a.with_custom_context)
	vlib_get_next_frame_with_aux_safe (vm, node, next_index, to_next,
					   to_next_aux, n_left_to_next);
      else
	vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  u32 error0 = IP4_ERROR_NONE;
	  u8 forward_context = 0;

	  bi0 = from[0];
	  b0 = vlib_get_buffer (vm, bi0);

	  ip4_header_t *ip0 = (ip4_header_t *) u8_ptr_add (
	    vlib_buffer_get_current (b0),
	    (ptrdiff_t) (a.is_output_feature ? 1 : 0) *
	      vnet_buffer (b0)->ip.save_rewrite_length);
	  if (!ip4_get_fragment_more (ip0) && !ip4_get_fragment_offset (ip0))
	    {
	      // this is a regular packet - no fragmentation
	      if (a.is_custom)
		{
		  next0 = vnet_buffer (b0)->ip.reass.next_index;
		}
	      else
		{
		  next0 = IP4_SV_REASSEMBLY_NEXT_INPUT;
		}
	      vnet_buffer (b0)->ip.reass.is_non_first_fragment = 0;
	      vnet_buffer (b0)->ip.reass.ip_proto = ip0->protocol;
	      if (l4_hdr_truncated (ip0))
		{
		  vnet_buffer (b0)->ip.reass.l4_hdr_truncated = 1;
		  vnet_buffer (b0)->ip.reass.l4_src_port = 0;
		  vnet_buffer (b0)->ip.reass.l4_dst_port = 0;
		}
	      else
		{
		  vnet_buffer (b0)->ip.reass.l4_hdr_truncated = 0;
		  if (IP_PROTOCOL_TCP == ip0->protocol)
		    {
		      vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags =
			((tcp_header_t *) (ip4_next_header (ip0)))->flags;
		      vnet_buffer (b0)->ip.reass.tcp_ack_number =
			((tcp_header_t *) (ip4_next_header (ip0)))->ack_number;
		      vnet_buffer (b0)->ip.reass.tcp_seq_number =
			((tcp_header_t *) (ip4_next_header (ip0)))->seq_number;
		    }
		  else if (IP_PROTOCOL_ICMP == ip0->protocol)
		    {
		      vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags =
			((icmp46_header_t *) (ip4_next_header (ip0)))->type;
		    }
		  vnet_buffer (b0)->ip.reass.l4_src_port =
		    ip4_get_port (ip0, 1);
		  vnet_buffer (b0)->ip.reass.l4_dst_port =
		    ip4_get_port (ip0, 0);
		}
	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  ip4_sv_reass_add_trace (
		    vm, node, NULL, bi0, REASS_PASSTHROUGH,
		    vnet_buffer (b0)->ip.reass.ip_proto,
		    vnet_buffer (b0)->ip.reass.l4_src_port,
		    vnet_buffer (b0)->ip.reass.l4_dst_port,
		    vnet_buffer (b0)->ip.reass.l4_hdr_truncated, ~0);
		}
	      goto packet_enqueue;
	    }
	  const u32 fragment_first = ip4_get_fragment_offset_bytes (ip0);
	  const u32 fragment_length =
	    clib_net_to_host_u16 (ip0->length) - ip4_header_bytes (ip0);
	  const u32 fragment_last = fragment_first + fragment_length - 1;
	  if (fragment_first > fragment_last ||
	      fragment_first + fragment_length > UINT16_MAX - 20 ||
	      (fragment_length < 8 &&
	       ip4_get_fragment_more (
		 ip0))) // 8 is minimum frag length per RFC 791
	    {
	      next0 = IP4_SV_REASSEMBLY_NEXT_DROP;
	      error0 = IP4_ERROR_REASS_MALFORMED_PACKET;
	      b0->error = node->errors[error0];
	      goto packet_enqueue;
	    }
	  ip4_sv_reass_kv_t kv;
	  u8 do_handoff = 0;

	  if (a.with_custom_context)
	    kv.k.as_u64[0] = (u64) *context | (u64) ip0->src_address.as_u32
						<< 32;
	  else
	    kv.k.as_u64[0] =
	      (u64) vec_elt (ip4_main.fib_index_by_sw_if_index,
			     vnet_buffer (b0)->sw_if_index[VLIB_RX]) |
	      (u64) ip0->src_address.as_u32 << 32;
	  kv.k.as_u64[1] = (u64) ip0->dst_address.as_u32 |
			   (u64) ip0->fragment_id << 32 |
			   (u64) ip0->protocol << 48;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ip4_sv_reass_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (t[0]));
	      t->action = REASS_KEY;
	      STATIC_ASSERT_SIZEOF (t->kv, sizeof (kv));
	      clib_memcpy (&t->kv, &kv, sizeof (kv));
	    }

	  ip4_sv_reass_t *reass = ip4_sv_reass_find_or_create (
	    vm, node, bi0, rm, rt, &kv, &do_handoff);

	  if (PREDICT_FALSE (do_handoff))
	    {
	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  ip4_sv_reass_add_trace (vm, node, reass, bi0, REASS_HANDOFF,
					  ~0, ~0, ~0, 0, kv.v.thread_index);
		}
	      next0 = IP4_SV_REASSEMBLY_NEXT_HANDOFF;
	      vnet_buffer (b0)->ip.reass.owner_thread_index =
		kv.v.thread_index;
	      if (a.with_custom_context)
		forward_context = 1;
	      goto packet_enqueue;
	    }

	  if (!reass)
	    {
	      next0 = IP4_SV_REASSEMBLY_NEXT_DROP;
	      error0 = IP4_ERROR_REASS_LIMIT_REACHED;
	      b0->error = node->errors[error0];
	      goto packet_enqueue;
	    }

	  if (ip4_sv_reass_is_complete (reass, a.extended))
	    {
	      if (a.is_custom)
		{
		  next0 = vnet_buffer (b0)->ip.reass.next_index;
		}
	      else
		{
		  next0 = IP4_SV_REASSEMBLY_NEXT_INPUT;
		}
	      vnet_buffer (b0)->ip.reass.is_non_first_fragment =
		!!fragment_first;
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
		ip4_sv_reass_set_vnet_buffer2_from_reass (vm, b0, reass);
	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  ip4_sv_reass_add_trace (
		    vm, node, reass, bi0, REASS_FRAGMENT_FORWARD,
		    reass->ip_proto, reass->l4_src_port, reass->l4_dst_port,
		    vnet_buffer (b0)->ip.reass.l4_hdr_truncated, ~0);
		}
	      goto packet_enqueue;
	    }

	  ip4_sv_reass_rc_t rc =
	    ip4_sv_reass_update (vm, node, rm, ip0, reass, bi0, a.extended);
	  u32 counter = ~0;
	  switch (rc)
	    {
	    case IP4_SV_REASS_RC_OK:
	      /* nothing to do here */
	      break;
	    case IP4_SV_REASS_RC_TOO_MANY_FRAGMENTS:
	      counter = IP4_ERROR_REASS_FRAGMENT_CHAIN_TOO_LONG;
	      break;
	    case IP4_SV_REASS_RC_UNSUPP_IP_PROTO:
	      counter = IP4_ERROR_REASS_UNSUPP_IP_PROT;
	      break;
	    }
	  if (~0 != counter)
	    {
	      vlib_node_increment_counter (vm, node->node_index, counter, 1);
	      ip4_sv_reass_trace_error_free (vm, node, reass, bi0);
	      ip4_sv_reass_free (vm, rm, rt, reass, true);
	      goto next_packet;
	    }
	  if (ip4_sv_reass_is_complete (reass, a.extended))
	    {
	      u32 idx;
	      vec_foreach_index (idx, reass->cached_buffers)
		{
		  u32 bi0 = vec_elt (reass->cached_buffers, idx);
		  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
		  ip0 = (ip4_header_t *) u8_ptr_add (
		    vlib_buffer_get_current (b0),
		    (ptrdiff_t) (a.is_output_feature ? 1 : 0) *
		      vnet_buffer (b0)->ip.save_rewrite_length);
		  u32 next0 = IP4_SV_REASSEMBLY_NEXT_INPUT;
		  if (a.is_feature)
		    {
		      vnet_feature_next (&next0, b0);
		    }
		  if (a.is_custom)
		    {
		      next0 = vnet_buffer (b0)->ip.reass.next_index;
		    }
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
		  vnet_buffer (b0)->ip.reass.is_non_first_fragment =
		    !!ip4_get_fragment_offset (ip0);
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
		    ip4_sv_reass_set_vnet_buffer2_from_reass (vm, b0, reass);
		  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		    {
		      ip4_sv_reass_add_trace (
			vm, node, reass, bi0, REASS_FRAGMENT_FORWARD,
			reass->ip_proto, reass->l4_src_port,
			reass->l4_dst_port,
			vnet_buffer (b0)->ip.reass.l4_hdr_truncated, ~0);
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
	  if (a.is_feature && IP4_ERROR_NONE == error0 &&
	      IP4_SV_REASSEMBLY_NEXT_HANDOFF != next0)
	    {
	      b0 = vlib_get_buffer (vm, bi0);
	      vnet_feature_next (&next0, b0);
	    }
	  if (a.with_custom_context && forward_context)
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
	  n_left_from -= 1;
	  if (a.with_custom_context)
	    context += 1;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

done:
  clib_spinlock_unlock (&rt->lock);
  return frame->n_vectors;
}

VLIB_NODE_FN (ip4_sv_reass_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  /*
   * Extended reassembly is not supported for non-feature nodes.
   */
  return ip4_sv_reass_inline (vm, node, frame,
			      (struct ip4_sv_reass_args){
				.is_feature = false,
				.is_output_feature = false,
				.is_custom = false,
				.with_custom_context = false,
				.extended = false,
			      });
}

VLIB_REGISTER_NODE (ip4_sv_reass_node) = {
    .name = "ip4-sv-reassembly",
    .vector_size = sizeof (u32),
    .format_trace = format_ip4_sv_reass_trace,
    .n_errors = IP4_N_ERROR,
    .error_counters = ip4_error_counters,
    .n_next_nodes = IP4_SV_REASSEMBLY_N_NEXT,
    .next_nodes =
        {
                [IP4_SV_REASSEMBLY_NEXT_INPUT] = "ip4-input",
                [IP4_SV_REASSEMBLY_NEXT_DROP] = "ip4-drop",
                [IP4_SV_REASSEMBLY_NEXT_HANDOFF] = "ip4-sv-reassembly-handoff",

        },
};

VLIB_NODE_FN (ip4_sv_reass_node_feature)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (ip4_sv_reass_main.extended_refcount > 0)
    return ip4_sv_reass_inline (vm, node, frame,
				(struct ip4_sv_reass_args){
				  .is_feature = true,
				  .is_output_feature = false,
				  .is_custom = false,
				  .with_custom_context = false,
				  .extended = true,
				});

  return ip4_sv_reass_inline (vm, node, frame,
			      (struct ip4_sv_reass_args){
				.is_feature = true,
				.is_output_feature = false,
				.is_custom = false,
				.with_custom_context = false,
				.extended = false,
			      });
}

VLIB_REGISTER_NODE (ip4_sv_reass_node_feature) = {
    .name = "ip4-sv-reassembly-feature",
    .vector_size = sizeof (u32),
    .format_trace = format_ip4_sv_reass_trace,
    .n_errors = IP4_N_ERROR,
    .error_counters = ip4_error_counters,
    .n_next_nodes = IP4_SV_REASSEMBLY_N_NEXT,
    .next_nodes =
        {
                [IP4_SV_REASSEMBLY_NEXT_INPUT] = "ip4-input",
                [IP4_SV_REASSEMBLY_NEXT_DROP] = "ip4-drop",
                [IP4_SV_REASSEMBLY_NEXT_HANDOFF] = "ip4-sv-reass-feature-hoff",
        },
};

VNET_FEATURE_INIT (ip4_sv_reass_feature) = {
  .arc_name = "ip4-unicast",
  .node_name = "ip4-sv-reassembly-feature",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
  .runs_after = 0,
};

VLIB_NODE_FN (ip4_sv_reass_node_output_feature)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (ip4_sv_reass_main.extended_refcount > 0)
    return ip4_sv_reass_inline (vm, node, frame,
				(struct ip4_sv_reass_args){
				  .is_feature = true,
				  .is_output_feature = true,
				  .is_custom = false,
				  .with_custom_context = false,
				  .extended = true,
				});

  return ip4_sv_reass_inline (vm, node, frame,
			      (struct ip4_sv_reass_args){
				.is_feature = true,
				.is_output_feature = true,
				.is_custom = false,
				.with_custom_context = false,
				.extended = false,
			      });
}

VLIB_REGISTER_NODE (ip4_sv_reass_node_output_feature) = {
    .name = "ip4-sv-reassembly-output-feature",
    .vector_size = sizeof (u32),
    .format_trace = format_ip4_sv_reass_trace,
    .n_errors = IP4_N_ERROR,
    .error_counters = ip4_error_counters,
    .n_next_nodes = IP4_SV_REASSEMBLY_N_NEXT,
    .next_nodes =
        {
                [IP4_SV_REASSEMBLY_NEXT_INPUT] = "ip4-input",
                [IP4_SV_REASSEMBLY_NEXT_DROP] = "ip4-drop",
                [IP4_SV_REASSEMBLY_NEXT_HANDOFF] = "ip4-sv-reass-output-feature-hoff",
        },
};

VNET_FEATURE_INIT (ip4_sv_reass_output_feature) = {
  .arc_name = "ip4-output",
  .node_name = "ip4-sv-reassembly-output-feature",
  .runs_before = 0,
  .runs_after = 0,
};

VLIB_REGISTER_NODE (ip4_sv_reass_custom_node) = {
    .name = "ip4-sv-reassembly-custom-next",
    .vector_size = sizeof (u32),
    .format_trace = format_ip4_sv_reass_trace,
    .n_errors = IP4_N_ERROR,
    .error_counters = ip4_error_counters,
    .n_next_nodes = IP4_SV_REASSEMBLY_N_NEXT,
    .next_nodes =
        {
                [IP4_SV_REASSEMBLY_NEXT_INPUT] = "ip4-input",
                [IP4_SV_REASSEMBLY_NEXT_DROP] = "ip4-drop",
                [IP4_SV_REASSEMBLY_NEXT_HANDOFF] = "ip4-sv-reassembly-handoff",

        },
};

VLIB_NODE_FN (ip4_sv_reass_custom_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  /*
   * Extended reassembly is not supported for non-feature nodes.
   */
  return ip4_sv_reass_inline (vm, node, frame,
			      (struct ip4_sv_reass_args){
				.is_feature = false,
				.is_output_feature = false,
				.is_custom = true,
				.with_custom_context = false,
				.extended = false,
			      });
}

VLIB_REGISTER_NODE (ip4_sv_reass_custom_context_node) = {
    .name = "ip4-sv-reassembly-custom-context",
    .vector_size = sizeof (u32),
    .aux_size = sizeof(u32),
    .format_trace = format_ip4_sv_reass_trace,
    .n_errors = IP4_N_ERROR,
    .error_counters = ip4_error_counters,
    .n_next_nodes = IP4_SV_REASSEMBLY_N_NEXT,
    .next_nodes =
        {
                [IP4_SV_REASSEMBLY_NEXT_INPUT] = "ip4-input",
                [IP4_SV_REASSEMBLY_NEXT_DROP] = "ip4-drop",
                [IP4_SV_REASSEMBLY_NEXT_HANDOFF] = "ip4-sv-reassembly-custom-context-handoff",

        },
};

VLIB_NODE_FN (ip4_sv_reass_custom_context_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  /*
   * Extended reassembly is not supported for non-feature nodes.
   */
  return ip4_sv_reass_inline (vm, node, frame,
			      (struct ip4_sv_reass_args){
				.is_feature = false,
				.is_output_feature = false,
				.is_custom = true,
				.with_custom_context = true,
				.extended = false,
			      });
}

#ifndef CLIB_MARCH_VARIANT
always_inline u32
ip4_sv_reass_get_nbuckets ()
{
  ip4_sv_reass_main_t *rm = &ip4_sv_reass_main;
  u32 nbuckets;
  u8 i;

  nbuckets = (u32) (rm->max_reass_n / IP4_SV_REASS_HT_LOAD_FACTOR);

  for (i = 0; i < 31; i++)
    if ((1 << i) >= nbuckets)
      break;
  nbuckets = 1 << i;

  return nbuckets;
}
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  IP4_EVENT_CONFIG_CHANGED = 1,
} ip4_sv_reass_event_t;

typedef struct
{
  int failure;
  clib_bihash_16_8_t *new_hash;
} ip4_rehash_cb_ctx;

#ifndef CLIB_MARCH_VARIANT
static int
ip4_rehash_cb (clib_bihash_kv_16_8_t *kv, void *_ctx)
{
  ip4_rehash_cb_ctx *ctx = _ctx;
  if (clib_bihash_add_del_16_8 (ctx->new_hash, kv, 1))
    {
      ctx->failure = 1;
    }
  return (BIHASH_WALK_CONTINUE);
}

static void
ip4_sv_reass_set_params (u32 timeout_ms, u32 max_reassemblies,
			 u32 max_reassembly_length,
			 u32 expire_walk_interval_ms)
{
  ip4_sv_reass_main.timeout_ms = timeout_ms;
  ip4_sv_reass_main.timeout = (f64) timeout_ms / (f64) MSEC_PER_SEC;
  ip4_sv_reass_main.max_reass_n = max_reassemblies;
  ip4_sv_reass_main.max_reass_len = max_reassembly_length;
  ip4_sv_reass_main.expire_walk_interval_ms = expire_walk_interval_ms;
}

vnet_api_error_t
ip4_sv_reass_set (u32 timeout_ms, u32 max_reassemblies,
		  u32 max_reassembly_length, u32 expire_walk_interval_ms)
{
  u32 old_nbuckets = ip4_sv_reass_get_nbuckets ();
  ip4_sv_reass_set_params (timeout_ms, max_reassemblies, max_reassembly_length,
			   expire_walk_interval_ms);
  vlib_process_signal_event (ip4_sv_reass_main.vlib_main,
			     ip4_sv_reass_main.ip4_sv_reass_expire_node_idx,
			     IP4_EVENT_CONFIG_CHANGED, 0);
  u32 new_nbuckets = ip4_sv_reass_get_nbuckets ();
  if (ip4_sv_reass_main.max_reass_n > 0 && new_nbuckets > old_nbuckets)
    {
      clib_bihash_16_8_t new_hash;
      clib_memset (&new_hash, 0, sizeof (new_hash));
      ip4_rehash_cb_ctx ctx;
      ctx.failure = 0;
      ctx.new_hash = &new_hash;
      clib_bihash_init_16_8 (&new_hash, "ip4-dr", new_nbuckets,
			     (uword) new_nbuckets * 1024);
      clib_bihash_foreach_key_value_pair_16_8 (&ip4_sv_reass_main.hash,
					       ip4_rehash_cb, &ctx);
      if (ctx.failure)
	{
	  clib_bihash_free_16_8 (&new_hash);
	  return -1;
	}
      else
	{
	  clib_bihash_free_16_8 (&ip4_sv_reass_main.hash);
	  clib_memcpy_fast (&ip4_sv_reass_main.hash, &new_hash,
			    sizeof (ip4_sv_reass_main.hash));
	  clib_bihash_copied (&ip4_sv_reass_main.hash, &new_hash);
	}
    }
  return 0;
}

vnet_api_error_t
ip4_sv_reass_get (u32 *timeout_ms, u32 *max_reassemblies,
		  u32 *max_reassembly_length, u32 *expire_walk_interval_ms)
{
  *timeout_ms = ip4_sv_reass_main.timeout_ms;
  *max_reassemblies = ip4_sv_reass_main.max_reass_n;
  *max_reassembly_length = ip4_sv_reass_main.max_reass_len;
  *expire_walk_interval_ms = ip4_sv_reass_main.expire_walk_interval_ms;
  return 0;
}

static clib_error_t *
ip4_sv_reass_init_function (vlib_main_t *vm)
{
  ip4_sv_reass_main_t *rm = &ip4_sv_reass_main;
  clib_error_t *error = 0;
  u32 nbuckets;
  vlib_node_t *node;

  rm->vlib_main = vm;
  rm->vnet_main = vnet_get_main ();

  vec_validate (rm->per_thread_data, vlib_num_workers ());
  ip4_sv_reass_per_thread_t *rt;
  vec_foreach (rt, rm->per_thread_data)
    {
      clib_spinlock_init (&rt->lock);
      pool_alloc (rt->pool, rm->max_reass_n);
      rt->lru_first = rt->lru_last = ~0;
    }

  node = vlib_get_node_by_name (vm, (u8 *) "ip4-sv-reassembly-expire-walk");
  ASSERT (node);
  rm->ip4_sv_reass_expire_node_idx = node->index;

  ip4_sv_reass_set_params (IP4_SV_REASS_TIMEOUT_DEFAULT_MS,
			   IP4_SV_REASS_MAX_REASSEMBLIES_DEFAULT,
			   IP4_SV_REASS_MAX_REASSEMBLY_LENGTH_DEFAULT,
			   IP4_SV_REASS_EXPIRE_WALK_INTERVAL_DEFAULT_MS);

  nbuckets = ip4_sv_reass_get_nbuckets ();
  clib_bihash_init_16_8 (&rm->hash, "ip4-dr", nbuckets,
			 (uword) nbuckets * 1024);

  rm->fq_index = vlib_frame_queue_main_init (ip4_sv_reass_node.index, 0);
  rm->fq_feature_index =
    vlib_frame_queue_main_init (ip4_sv_reass_node_feature.index, 0);
  rm->fq_output_feature_index =
    vlib_frame_queue_main_init (ip4_sv_reass_node_output_feature.index, 0);
  rm->fq_custom_context_index =
    vlib_frame_queue_main_init (ip4_sv_reass_custom_context_node.index, 0);

  rm->feature_use_refcount_per_intf = NULL;
  rm->output_feature_use_refcount_per_intf = NULL;

  return error;
}

VLIB_INIT_FUNCTION (ip4_sv_reass_init_function);
#endif /* CLIB_MARCH_VARIANT */

static uword
ip4_sv_reass_walk_expired (vlib_main_t *vm,
			   CLIB_UNUSED (vlib_node_runtime_t *node),
			   CLIB_UNUSED (vlib_frame_t *f))
{
  ip4_sv_reass_main_t *rm = &ip4_sv_reass_main;
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
	case IP4_EVENT_CONFIG_CHANGED:
	  /* nothing to do here */
	  break;
	default:
	  clib_warning ("BUG: event type 0x%wx", event_type);
	  break;
	}
      f64 now = vlib_time_now (vm);

      ip4_sv_reass_t *reass;
      int *pool_indexes_to_free = NULL;

      uword thread_index = 0;
      int index;
      const uword nthreads = vlib_num_workers () + 1;
      for (thread_index = 0; thread_index < nthreads; ++thread_index)
	{
	  ip4_sv_reass_per_thread_t *rt = &rm->per_thread_data[thread_index];
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
	      ip4_sv_reass_t *reass = pool_elt_at_index (rt->pool, i[0]);
	      ip4_sv_reass_free (vm, rm, rt, reass, true);
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

VLIB_REGISTER_NODE (ip4_sv_reass_expire_node) = {
  .function = ip4_sv_reass_walk_expired,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "ip4-sv-reassembly-expire-walk",
  .format_trace = format_ip4_sv_reass_trace,
  .n_errors = IP4_N_ERROR,
  .error_counters = ip4_error_counters,
};

static u8 *
format_ip4_sv_reass_key (u8 *s, va_list *args)
{
  ip4_sv_reass_key_t *key = va_arg (*args, ip4_sv_reass_key_t *);
  s =
    format (s, "fib_index: %u, src: %U, dst: %U, frag_id: %u, proto: %u",
	    key->fib_index, format_ip4_address, &key->src, format_ip4_address,
	    &key->dst, clib_net_to_host_u16 (key->frag_id), key->proto);
  return s;
}

static u8 *
format_ip4_sv_reass (u8 *s, va_list *args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  ip4_sv_reass_t *reass = va_arg (*args, ip4_sv_reass_t *);

  s = format (s, "ID: %lu, key: %U trace_op_counter: %u\n", reass->id,
	      format_ip4_sv_reass_key, &reass->key, reass->trace_op_counter);

  vlib_buffer_t *b;
  u32 *bip;
  u32 counter = 0;
  vec_foreach (bip, reass->cached_buffers)
    {
      u32 bi = *bip;
      do
	{
	  b = vlib_get_buffer (vm, bi);
	  s = format (s, "  #%03u: bi: %u, ", counter, bi);
	  ++counter;
	  bi = b->next_buffer;
	}
      while (b->flags & VLIB_BUFFER_NEXT_PRESENT);
    }
  return s;
}

static clib_error_t *
show_ip4_reass (vlib_main_t *vm, unformat_input_t *input,
		CLIB_UNUSED (vlib_cli_command_t *lmd))
{
  ip4_sv_reass_main_t *rm = &ip4_sv_reass_main;

  vlib_cli_output (vm, "---------------------");
  vlib_cli_output (vm, "IP4 reassembly status");
  vlib_cli_output (vm, "---------------------");
  bool details = false;
  if (unformat (input, "details"))
    {
      details = true;
    }

  u32 sum_reass_n = 0;
  ip4_sv_reass_t *reass;
  uword thread_index;
  const uword nthreads = vlib_num_workers () + 1;
  for (thread_index = 0; thread_index < nthreads; ++thread_index)
    {
      ip4_sv_reass_per_thread_t *rt = &rm->per_thread_data[thread_index];
      clib_spinlock_lock (&rt->lock);
      if (details)
	{
	  pool_foreach (reass, rt->pool)
	    {
	      vlib_cli_output (vm, "%U", format_ip4_sv_reass, vm, reass);
	    }
	}
      sum_reass_n += pool_elts (rt->pool);
      clib_spinlock_unlock (&rt->lock);
    }
  vlib_cli_output (vm, "---------------------");
  vlib_cli_output (vm, "Current IP4 reassemblies count: %lu\n",
		   (long unsigned) sum_reass_n);
  vlib_cli_output (vm,
		   "Maximum configured concurrent shallow virtual IP4 "
		   "reassemblies per worker-thread: %lu\n",
		   (long unsigned) rm->max_reass_n);
  vlib_cli_output (vm,
		   "Maximum configured amount of fragments per shallow "
		   "virtual IP4 reassembly: %lu\n",
		   (long unsigned) rm->max_reass_len);
  vlib_cli_output (
    vm, "Maximum configured shallow virtual IP4 reassembly timeout: %lums\n",
    (long unsigned) rm->timeout_ms);
  vlib_cli_output (vm,
		   "Maximum configured shallow virtual IP4 reassembly expire "
		   "walk interval: %lums\n",
		   (long unsigned) rm->expire_walk_interval_ms);

  return 0;
}

VLIB_CLI_COMMAND (show_ip4_sv_reass_cmd, static) = {
  .path = "show ip4-sv-reassembly",
  .short_help = "show ip4-sv-reassembly [details]",
  .function = show_ip4_reass,
};

#ifndef CLIB_MARCH_VARIANT
vnet_api_error_t
ip4_sv_reass_enable_disable (u32 sw_if_index, u8 enable_disable)
{
  return ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, enable_disable);
}
#endif /* CLIB_MARCH_VARIANT */

#define foreach_ip4_sv_reass_handoff_error                                    \
  _ (CONGESTION_DROP, "congestion drop")

typedef enum
{
#define _(sym, str) IP4_SV_REASSEMBLY_HANDOFF_ERROR_##sym,
  foreach_ip4_sv_reass_handoff_error
#undef _
    IP4_SV_REASSEMBLY_HANDOFF_N_ERROR,
} ip4_sv_reass_handoff_error_t;

static char *ip4_sv_reass_handoff_error_strings[] = {
#define _(sym, string) string,
  foreach_ip4_sv_reass_handoff_error
#undef _
};

typedef struct
{
  clib_thread_index_t thread_index;
} ip4_sv_reass_handoff_trace_t;

static u8 *
format_ip4_sv_reass_handoff_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip4_sv_reass_handoff_trace_t *t =
    va_arg (*args, ip4_sv_reass_handoff_trace_t *);

  s = format (s, "to thread-index: %u", t->thread_index);

  return s;
}

struct ip4_sv_reass_hoff_args
{
  bool is_feature;
  bool is_output_feature;
  bool is_custom_context;
};

always_inline uword
ip4_sv_reass_handoff_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
				  vlib_frame_t *frame,
				  struct ip4_sv_reass_hoff_args a)
{
  ip4_sv_reass_main_t *rm = &ip4_sv_reass_main;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 n_enq, n_left_from, *from, *context;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti;

  from = vlib_frame_vector_args (frame);
  if (a.is_custom_context)
    context = vlib_frame_aux_args (frame);

  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  b = bufs;
  ti = thread_indices;

  const u32 fq_index = a.is_output_feature ? rm->fq_output_feature_index :
		       a.is_feature	   ? rm->fq_feature_index :
		       a.is_custom_context ? rm->fq_custom_context_index :
						   rm->fq_index;

  while (n_left_from > 0)
    {
      ti[0] = vnet_buffer (b[0])->ip.reass.owner_thread_index;

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  ip4_sv_reass_handoff_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->thread_index = ti[0];
	}

      n_left_from -= 1;
      ti += 1;
      b += 1;
    }
  if (a.is_custom_context)
    n_enq = vlib_buffer_enqueue_to_thread_with_aux (
      vm, node, fq_index, from, context, thread_indices, frame->n_vectors, 1);
  else
    n_enq = vlib_buffer_enqueue_to_thread (
      vm, node, fq_index, from, thread_indices, frame->n_vectors, 1);

  if (n_enq < frame->n_vectors)
    vlib_node_increment_counter (
      vm, node->node_index, IP4_SV_REASSEMBLY_HANDOFF_ERROR_CONGESTION_DROP,
      frame->n_vectors - n_enq);
  return frame->n_vectors;
}

VLIB_NODE_FN (ip4_sv_reass_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ip4_sv_reass_handoff_node_inline (
    vm, node, frame,
    (struct ip4_sv_reass_hoff_args){ .is_feature = false,
				     .is_output_feature = false,
				     .is_custom_context = false });
}

VLIB_REGISTER_NODE (ip4_sv_reass_handoff_node) = {
  .name = "ip4-sv-reassembly-handoff",
  .vector_size = sizeof (u32),
  .n_errors = ARRAY_LEN(ip4_sv_reass_handoff_error_strings),
  .error_strings = ip4_sv_reass_handoff_error_strings,
  .format_trace = format_ip4_sv_reass_handoff_trace,

  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FN (ip4_sv_reass_custom_context_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ip4_sv_reass_handoff_node_inline (
    vm, node, frame,
    (struct ip4_sv_reass_hoff_args){ .is_feature = false,
				     .is_output_feature = false,
				     .is_custom_context = true });
}

VLIB_REGISTER_NODE (ip4_sv_reass_custom_context_handoff_node) = {
  .name = "ip4-sv-reassembly-custom-context-handoff",
  .vector_size = sizeof (u32),
  .aux_size = sizeof (u32),
  .n_errors = ARRAY_LEN(ip4_sv_reass_handoff_error_strings),
  .error_strings = ip4_sv_reass_handoff_error_strings,
  .format_trace = format_ip4_sv_reass_handoff_trace,

  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FN (ip4_sv_reass_feature_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ip4_sv_reass_handoff_node_inline (
    vm, node, frame,
    (struct ip4_sv_reass_hoff_args){ .is_feature = true,
				     .is_output_feature = false,
				     .is_custom_context = false });
}

VLIB_REGISTER_NODE (ip4_sv_reass_feature_handoff_node) = {
  .name = "ip4-sv-reass-feature-hoff",
  .vector_size = sizeof (u32),
  .n_errors = ARRAY_LEN(ip4_sv_reass_handoff_error_strings),
  .error_strings = ip4_sv_reass_handoff_error_strings,
  .format_trace = format_ip4_sv_reass_handoff_trace,

  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FN (ip4_sv_reass_output_feature_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ip4_sv_reass_handoff_node_inline (
    vm, node, frame,
    (struct ip4_sv_reass_hoff_args){ .is_feature = false,
				     .is_output_feature = true,
				     .is_custom_context = false });
}

VLIB_REGISTER_NODE (ip4_sv_reass_output_feature_handoff_node) = {
  .name = "ip4-sv-reass-output-feature-hoff",
  .vector_size = sizeof (u32),
  .n_errors = ARRAY_LEN(ip4_sv_reass_handoff_error_strings),
  .error_strings = ip4_sv_reass_handoff_error_strings,
  .format_trace = format_ip4_sv_reass_handoff_trace,

  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "error-drop",
  },
};

#ifndef CLIB_MARCH_VARIANT
int
ip4_sv_reass_enable_disable_with_refcnt (u32 sw_if_index, int is_enable)
{
  ip4_sv_reass_main_t *rm = &ip4_sv_reass_main;
  vec_validate (rm->feature_use_refcount_per_intf, sw_if_index);
  if (is_enable)
    {
      if (!rm->feature_use_refcount_per_intf[sw_if_index])
	{
	  int rv = vnet_feature_enable_disable (
	    "ip4-unicast", "ip4-sv-reassembly-feature", sw_if_index, 1, 0, 0);
	  if (0 != rv)
	    return rv;
	}
      ++rm->feature_use_refcount_per_intf[sw_if_index];
    }
  else
    {
      if (rm->feature_use_refcount_per_intf[sw_if_index])
	--rm->feature_use_refcount_per_intf[sw_if_index];
      if (!rm->feature_use_refcount_per_intf[sw_if_index])
	{
	  return vnet_feature_enable_disable (
	    "ip4-unicast", "ip4-sv-reassembly-feature", sw_if_index, 0, 0, 0);
	}
    }
  return 0;
}

uword
ip4_sv_reass_custom_register_next_node (uword node_index)
{
  return vlib_node_add_next (vlib_get_main (), ip4_sv_reass_custom_node.index,
			     node_index);
}

uword
ip4_sv_reass_custom_context_register_next_node (uword node_index)
{
  return vlib_node_add_next (
    vlib_get_main (), ip4_sv_reass_custom_context_node.index, node_index);
}

int
ip4_sv_reass_output_enable_disable_with_refcnt (u32 sw_if_index, int is_enable)
{
  ip4_sv_reass_main_t *rm = &ip4_sv_reass_main;
  vec_validate (rm->output_feature_use_refcount_per_intf, sw_if_index);
  if (is_enable)
    {
      if (!rm->output_feature_use_refcount_per_intf[sw_if_index])
	{
	  int rv = vnet_feature_enable_disable (
	    "ip4-output", "ip4-sv-reassembly-output-feature", sw_if_index, 1,
	    0, 0);
	  if (0 != rv)
	    return rv;
	}
      ++rm->output_feature_use_refcount_per_intf[sw_if_index];
    }
  else
    {
      if (rm->output_feature_use_refcount_per_intf[sw_if_index])
	--rm->output_feature_use_refcount_per_intf[sw_if_index];
      if (!rm->output_feature_use_refcount_per_intf[sw_if_index])
	{
	  return vnet_feature_enable_disable (
	    "ip4-output", "ip4-sv-reassembly-output-feature", sw_if_index, 0,
	    0, 0);
	}
    }
  return 0;
}

void
ip4_sv_reass_enable_disable_extended (bool is_enable)
{
  if (is_enable)
    ++ip4_sv_reass_main.extended_refcount;
  else
    --ip4_sv_reass_main.extended_refcount;
}

int
ip4_sv_reass_extended_lock (vlib_buffer_t *b,
			    struct ip4_sv_lock_unlock_args *a)
{
  ip4_sv_reass_per_thread_t *per_thread =
    &ip4_sv_reass_main
       .per_thread_data[vnet_buffer2 (b)->ip.reass.thread_index];

  if (!vec_is_member (ip4_sv_reass_main.per_thread_data, per_thread))
    return -1;

  clib_spinlock_lock (&per_thread->lock);
  if (pool_is_free_index (per_thread->pool,
			  vnet_buffer2 (b)->ip.reass.pool_index))
    goto fail;

  ip4_sv_reass_t *reass = pool_elt_at_index (
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
ip4_sv_reass_extended_unlock (vlib_buffer_t *b)
{
  ip4_sv_reass_per_thread_t *per_thread =
    &ip4_sv_reass_main
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
