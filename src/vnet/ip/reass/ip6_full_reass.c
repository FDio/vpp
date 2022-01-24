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
 * @brief IPv6 Full Reassembly.
 *
 * This file contains the source code for IPv6 full reassembly.
 */

#include <vppinfra/vec.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vppinfra/bihash_48_8.h>
#include <vnet/ip/reass/ip6_full_reass.h>
#include <vnet/ip/ip6_inlines.h>

#define MSEC_PER_SEC 1000
#define IP6_FULL_REASS_TIMEOUT_DEFAULT_MS 100
#define IP6_FULL_REASS_EXPIRE_WALK_INTERVAL_DEFAULT_MS 10000	// 10 seconds default
#define IP6_FULL_REASS_MAX_REASSEMBLIES_DEFAULT 1024
#define IP6_FULL_REASS_MAX_REASSEMBLY_LENGTH_DEFAULT 3
#define IP6_FULL_REASS_HT_LOAD_FACTOR (0.75)

typedef enum
{
  IP6_FULL_REASS_RC_OK,
  IP6_FULL_REASS_RC_INTERNAL_ERROR,
  IP6_FULL_REASS_RC_TOO_MANY_FRAGMENTS,
  IP6_FULL_REASS_RC_NO_BUF,
  IP6_FULL_REASS_RC_HANDOFF,
  IP6_FULL_REASS_RC_INVALID_FRAG_LEN,
} ip6_full_reass_rc_t;

typedef struct
{
  union
  {
    struct
    {
      ip6_address_t src;
      ip6_address_t dst;
      u32 xx_id;
      u32 frag_id;
      u8 unused[7];
      u8 proto;
    };
    u64 as_u64[6];
  };
} ip6_full_reass_key_t;

typedef union
{
  struct
  {
    u32 reass_index;
    u32 memory_owner_thread_index;
  };
  u64 as_u64;
} ip6_full_reass_val_t;

typedef union
{
  struct
  {
    ip6_full_reass_key_t k;
    ip6_full_reass_val_t v;
  };
  clib_bihash_kv_48_8_t kv;
} ip6_full_reass_kv_t;


always_inline u32
ip6_full_reass_buffer_get_data_offset (vlib_buffer_t * b)
{
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  return vnb->ip.reass.range_first - vnb->ip.reass.fragment_first;
}

always_inline u16
ip6_full_reass_buffer_get_data_len (vlib_buffer_t * b)
{
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  return clib_min (vnb->ip.reass.range_last, vnb->ip.reass.fragment_last) -
    (vnb->ip.reass.fragment_first +
     ip6_full_reass_buffer_get_data_offset (b)) + 1;
}

typedef struct
{
  // hash table key
  ip6_full_reass_key_t key;
  // time when last packet was received
  f64 last_heard;
  // internal id of this reassembly
  u64 id;
  // buffer index of first buffer in this reassembly context
  u32 first_bi;
  // last octet of packet, ~0 until fragment without more_fragments arrives
  u32 last_packet_octet;
  // length of data collected so far
  u32 data_len;
  // trace operation counter
  u32 trace_op_counter;
  // next index - used by custom apps (~0 if not set)
  u32 next_index;
  // error next index - used by custom apps (~0 if not set)
  u32 error_next_index;
  // minimum fragment length for this reassembly - used to estimate MTU
  u16 min_fragment_length;
  // number of fragments for this reassembly
  u32 fragments_n;
  // thread owning memory for this context (whose pool contains this ctx)
  u32 memory_owner_thread_index;
  // thread which received fragment with offset 0 and which sends out the
  // completed reassembly
  u32 sendout_thread_index;
} ip6_full_reass_t;

typedef struct
{
  ip6_full_reass_t *pool;
  u32 reass_n;
  u32 id_counter;
  clib_spinlock_t lock;
} ip6_full_reass_per_thread_t;

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
  ip6_full_reass_per_thread_t *per_thread_data;

  // convenience
  vlib_main_t *vlib_main;

  // node index of ip6-drop node
  u32 ip6_drop_idx;
  u32 ip6_icmp_error_idx;
  u32 ip6_full_reass_expire_node_idx;

  /** Worker handoff */
  u32 fq_index;
  u32 fq_feature_index;

  // reference count for enabling/disabling feature - per interface
  u32 *feature_use_refcount_per_intf;
} ip6_full_reass_main_t;

extern ip6_full_reass_main_t ip6_full_reass_main;

#ifndef CLIB_MARCH_VARIANT
ip6_full_reass_main_t ip6_full_reass_main;
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  IP6_FULL_REASSEMBLY_NEXT_INPUT,
  IP6_FULL_REASSEMBLY_NEXT_DROP,
  IP6_FULL_REASSEMBLY_NEXT_ICMP_ERROR,
  IP6_FULL_REASSEMBLY_NEXT_HANDOFF,
  IP6_FULL_REASSEMBLY_N_NEXT,
} ip6_full_reass_next_t;

typedef enum
{
  RANGE_NEW,
  RANGE_OVERLAP,
  ICMP_ERROR_RT_EXCEEDED,
  ICMP_ERROR_FL_TOO_BIG,
  ICMP_ERROR_FL_NOT_MULT_8,
  FINALIZE,
  HANDOFF,
} ip6_full_reass_trace_operation_e;

typedef struct
{
  u16 range_first;
  u16 range_last;
  u32 range_bi;
  i32 data_offset;
  u32 data_len;
  u32 first_bi;
} ip6_full_reass_range_trace_t;

typedef struct
{
  ip6_full_reass_trace_operation_e action;
  u32 reass_id;
  ip6_full_reass_range_trace_t trace_range;
  u32 op_id;
  u32 fragment_first;
  u32 fragment_last;
  u32 total_data_len;
  u32 thread_id;
  u32 thread_id_to;
  bool is_after_handoff;
  ip6_header_t ip6_header;
  ip6_frag_hdr_t ip6_frag_header;
} ip6_full_reass_trace_t;

static void
ip6_full_reass_trace_details (vlib_main_t * vm, u32 bi,
			      ip6_full_reass_range_trace_t * trace)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  trace->range_first = vnb->ip.reass.range_first;
  trace->range_last = vnb->ip.reass.range_last;
  trace->data_offset = ip6_full_reass_buffer_get_data_offset (b);
  trace->data_len = ip6_full_reass_buffer_get_data_len (b);
  trace->range_bi = bi;
}

static u8 *
format_ip6_full_reass_range_trace (u8 * s, va_list * args)
{
  ip6_full_reass_range_trace_t *trace =
    va_arg (*args, ip6_full_reass_range_trace_t *);
  s =
    format (s, "range: [%u, %u], off %d, len %u, bi %u", trace->range_first,
	    trace->range_last, trace->data_offset, trace->data_len,
	    trace->range_bi);
  return s;
}

static u8 *
format_ip6_full_reass_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_full_reass_trace_t *t = va_arg (*args, ip6_full_reass_trace_t *);
  u32 indent = 0;
  if (~0 != t->reass_id)
    {
      if (t->is_after_handoff)
	{
	  s =
	    format (s, "%U\n", format_ip6_header, &t->ip6_header,
		    sizeof (t->ip6_header));
	  s =
	    format (s, "  %U\n", format_ip6_frag_hdr, &t->ip6_frag_header,
		    sizeof (t->ip6_frag_header));
	  indent = 2;
	}
      s =
	format (s, "%Ureass id: %u, op id: %u, ", format_white_space, indent,
		t->reass_id, t->op_id);
      indent = format_get_indent (s);
      s = format (s, "first bi: %u, data len: %u, ip/fragment[%u, %u]",
		  t->trace_range.first_bi, t->total_data_len,
		  t->fragment_first, t->fragment_last);
    }
  switch (t->action)
    {
    case RANGE_NEW:
      s = format (s, "\n%Unew %U", format_white_space, indent,
		  format_ip6_full_reass_range_trace, &t->trace_range);
      break;
    case RANGE_OVERLAP:
      s = format (s, "\n%Uoverlap %U", format_white_space, indent,
		  format_ip6_full_reass_range_trace, &t->trace_range);
      break;
    case ICMP_ERROR_FL_TOO_BIG:
      s = format (s, "\n%Uicmp-error - frag_len > 65535 %U",
		  format_white_space, indent,
		  format_ip6_full_reass_range_trace, &t->trace_range);
      break;
    case ICMP_ERROR_FL_NOT_MULT_8:
      s = format (s, "\n%Uicmp-error - frag_len mod 8 != 0 %U",
		  format_white_space, indent,
		  format_ip6_full_reass_range_trace, &t->trace_range);
      break;
    case ICMP_ERROR_RT_EXCEEDED:
      s = format (s, "\n%Uicmp-error - reassembly time exceeded",
		  format_white_space, indent);
      break;
    case FINALIZE:
      s = format (s, "\n%Ufinalize reassembly", format_white_space, indent);
      break;
    case HANDOFF:
      s =
	format (s, "handoff from thread #%u to thread #%u", t->thread_id,
		t->thread_id_to);
      break;
    }
  return s;
}

static void
ip6_full_reass_add_trace (vlib_main_t * vm, vlib_node_runtime_t * node,
			  ip6_full_reass_t * reass, u32 bi,
			  ip6_frag_hdr_t * ip6_frag_header,
			  ip6_full_reass_trace_operation_e action,
			  u32 thread_id_to)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  bool is_after_handoff = false;
  if (pool_is_free_index
      (vm->trace_main.trace_buffer_pool, vlib_buffer_get_trace_index (b)))
    {
      // this buffer's trace is gone
      b->flags &= ~VLIB_BUFFER_IS_TRACED;
      return;
    }
  if (vlib_buffer_get_trace_thread (b) != vm->thread_index)
    {
      is_after_handoff = true;
    }
  ip6_full_reass_trace_t *t = vlib_add_trace (vm, node, b, sizeof (t[0]));
  t->is_after_handoff = is_after_handoff;
  if (t->is_after_handoff)
    {
      clib_memcpy (&t->ip6_header, vlib_buffer_get_current (b),
		   clib_min (sizeof (t->ip6_header), b->current_length));
      if (ip6_frag_header)
	{
	  clib_memcpy (&t->ip6_frag_header, ip6_frag_header,
		       sizeof (t->ip6_frag_header));
	}
      else
	{
	  clib_memset (&t->ip6_frag_header, 0, sizeof (t->ip6_frag_header));
	}
    }
  if (reass)
    {
      t->reass_id = reass->id;
      t->op_id = reass->trace_op_counter;
      t->trace_range.first_bi = reass->first_bi;
      t->total_data_len = reass->data_len;
      ++reass->trace_op_counter;
    }
  else
    {
      t->reass_id = ~0;
    }
  t->action = action;
  t->thread_id = vm->thread_index;
  t->thread_id_to = thread_id_to;
  ip6_full_reass_trace_details (vm, bi, &t->trace_range);
  t->fragment_first = vnb->ip.reass.fragment_first;
  t->fragment_last = vnb->ip.reass.fragment_last;
#if 0
  static u8 *s = NULL;
  s = format (s, "%U", format_ip6_full_reass_trace, NULL, NULL, t);
  printf ("%.*s\n", vec_len (s), s);
  fflush (stdout);
  vec_reset_length (s);
#endif
}

always_inline void
ip6_full_reass_free_ctx (ip6_full_reass_per_thread_t * rt,
			 ip6_full_reass_t * reass)
{
  pool_put (rt->pool, reass);
  --rt->reass_n;
}

always_inline void
ip6_full_reass_free (ip6_full_reass_main_t * rm,
		     ip6_full_reass_per_thread_t * rt,
		     ip6_full_reass_t * reass)
{
  clib_bihash_kv_48_8_t kv;
  kv.key[0] = reass->key.as_u64[0];
  kv.key[1] = reass->key.as_u64[1];
  kv.key[2] = reass->key.as_u64[2];
  kv.key[3] = reass->key.as_u64[3];
  kv.key[4] = reass->key.as_u64[4];
  kv.key[5] = reass->key.as_u64[5];
  clib_bihash_add_del_48_8 (&rm->hash, &kv, 0);
  ip6_full_reass_free_ctx (rt, reass);
}

always_inline void
ip6_full_reass_drop_all (vlib_main_t *vm, vlib_node_runtime_t *node,
			 ip6_full_reass_t *reass)
{
  u32 range_bi = reass->first_bi;
  vlib_buffer_t *range_b;
  vnet_buffer_opaque_t *range_vnb;
  u32 *to_free = NULL;
  while (~0 != range_bi)
    {
      range_b = vlib_get_buffer (vm, range_bi);
      range_vnb = vnet_buffer (range_b);
      u32 bi = range_bi;
      while (~0 != bi)
	{
	  vec_add1 (to_free, bi);
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	  if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      bi = b->next_buffer;
	      b->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
	    }
	  else
	    {
	      bi = ~0;
	    }
	}
      range_bi = range_vnb->ip.reass.next_range_bi;
    }
  /* send to next_error_index */
  if (~0 != reass->error_next_index)
    {
      u32 n_left_to_next, *to_next, next_index;

      next_index = reass->error_next_index;
      u32 bi = ~0;

      while (vec_len (to_free) > 0)
	{
	  vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

	  while (vec_len (to_free) > 0 && n_left_to_next > 0)
	    {
	      bi = vec_pop (to_free);

	      if (~0 != bi)
		{
		  to_next[0] = bi;
		  to_next += 1;
		  n_left_to_next -= 1;
		}
	    }
	  vlib_put_next_frame (vm, node, next_index, n_left_to_next);
	}
    }
  else
    {
      vlib_buffer_free (vm, to_free, vec_len (to_free));
    }
  vec_free (to_free);
}

always_inline void
ip6_full_reass_on_timeout (vlib_main_t * vm, vlib_node_runtime_t * node,
			   ip6_full_reass_t * reass, u32 * icmp_bi)
{
  if (~0 == reass->first_bi)
    {
      return;
    }
  if (~0 == reass->next_index)	// custom apps don't want icmp
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, reass->first_bi);
      if (0 == vnet_buffer (b)->ip.reass.fragment_first)
	{
	  *icmp_bi = reass->first_bi;
	  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ip6_full_reass_add_trace (vm, node, reass, reass->first_bi, NULL,
					ICMP_ERROR_RT_EXCEEDED, ~0);
	    }
	  // fragment with offset zero received - send icmp message back
	  if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      // separate first buffer from chain and steer it towards icmp node
	      b->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
	      reass->first_bi = b->next_buffer;
	    }
	  else
	    {
	      reass->first_bi = vnet_buffer (b)->ip.reass.next_range_bi;
	    }
	  icmp6_error_set_vnet_buffer (b, ICMP6_time_exceeded,
				       ICMP6_time_exceeded_fragment_reassembly_time_exceeded,
				       0);
	}
    }
  ip6_full_reass_drop_all (vm, node, reass);
}

always_inline ip6_full_reass_t *
ip6_full_reass_find_or_create (vlib_main_t *vm, vlib_node_runtime_t *node,
			       ip6_full_reass_main_t *rm,
			       ip6_full_reass_per_thread_t *rt,
			       ip6_full_reass_kv_t *kv, u32 *icmp_bi,
			       u8 *do_handoff, int skip_bihash)
{
  ip6_full_reass_t *reass;
  f64 now;

again:

  reass = NULL;
  now = vlib_time_now (vm);

  if (!skip_bihash && !clib_bihash_search_48_8 (&rm->hash, &kv->kv, &kv->kv))
    {
      if (vm->thread_index != kv->v.memory_owner_thread_index)
	{
	  *do_handoff = 1;
	  return NULL;
	}

      reass =
	pool_elt_at_index (rm->per_thread_data
			   [kv->v.memory_owner_thread_index].pool,
			   kv->v.reass_index);

      if (now > reass->last_heard + rm->timeout)
	{
	  ip6_full_reass_on_timeout (vm, node, reass, icmp_bi);
	  ip6_full_reass_free (rm, rt, reass);
	  reass = NULL;
	}
    }

  if (reass)
    {
      reass->last_heard = now;
      return reass;
    }

  if (rt->reass_n >= rm->max_reass_n)
    {
      reass = NULL;
      return reass;
    }
  else
    {
      pool_get (rt->pool, reass);
      clib_memset (reass, 0, sizeof (*reass));
      reass->id = ((u64) vm->thread_index * 1000000000) + rt->id_counter;
      ++rt->id_counter;
      reass->first_bi = ~0;
      reass->last_packet_octet = ~0;
      reass->data_len = 0;
      reass->next_index = ~0;
      reass->error_next_index = ~0;
      reass->memory_owner_thread_index = vm->thread_index;
      ++rt->reass_n;
    }

  kv->v.reass_index = (reass - rt->pool);
  kv->v.memory_owner_thread_index = vm->thread_index;
  reass->last_heard = now;

  if (!skip_bihash)
    {
      reass->key.as_u64[0] = kv->kv.key[0];
      reass->key.as_u64[1] = kv->kv.key[1];
      reass->key.as_u64[2] = kv->kv.key[2];
      reass->key.as_u64[3] = kv->kv.key[3];
      reass->key.as_u64[4] = kv->kv.key[4];
      reass->key.as_u64[5] = kv->kv.key[5];

      int rv = clib_bihash_add_del_48_8 (&rm->hash, &kv->kv, 2);
      if (rv)
	{
	  ip6_full_reass_free (rm, rt, reass);
	  reass = NULL;
	  // if other worker created a context already work with the other copy
	  if (-2 == rv)
	    goto again;
	}
    }
  else
    {
      reass->key.as_u64[0] = ~0;
      reass->key.as_u64[1] = ~0;
      reass->key.as_u64[2] = ~0;
      reass->key.as_u64[3] = ~0;
      reass->key.as_u64[4] = ~0;
      reass->key.as_u64[5] = ~0;
    }

  return reass;
}

always_inline ip6_full_reass_rc_t
ip6_full_reass_finalize (vlib_main_t * vm, vlib_node_runtime_t * node,
			 ip6_full_reass_main_t * rm,
			 ip6_full_reass_per_thread_t * rt,
			 ip6_full_reass_t * reass, u32 * bi0, u32 * next0,
			 u32 * error0, bool is_custom_app)
{
  *bi0 = reass->first_bi;
  *error0 = IP6_ERROR_NONE;
  ip6_frag_hdr_t *frag_hdr;
  vlib_buffer_t *last_b = NULL;
  u32 sub_chain_bi = reass->first_bi;
  u32 total_length = 0;
  u32 buf_cnt = 0;
  u32 dropped_cnt = 0;
  u32 *vec_drop_compress = NULL;
  ip6_full_reass_rc_t rv = IP6_FULL_REASS_RC_OK;
  do
    {
      u32 tmp_bi = sub_chain_bi;
      vlib_buffer_t *tmp = vlib_get_buffer (vm, tmp_bi);
      vnet_buffer_opaque_t *vnb = vnet_buffer (tmp);
      if (!(vnb->ip.reass.range_first >= vnb->ip.reass.fragment_first) &&
	  !(vnb->ip.reass.range_last > vnb->ip.reass.fragment_first))
	{
	  rv = IP6_FULL_REASS_RC_INTERNAL_ERROR;
	  goto free_buffers_and_return;
	}

      u32 data_len = ip6_full_reass_buffer_get_data_len (tmp);
      u32 trim_front = vnet_buffer (tmp)->ip.reass.ip6_frag_hdr_offset +
	sizeof (*frag_hdr) + ip6_full_reass_buffer_get_data_offset (tmp);
      u32 trim_end =
	vlib_buffer_length_in_chain (vm, tmp) - trim_front - data_len;
      if (tmp_bi == reass->first_bi)
	{
	  /* first buffer - keep ip6 header */
	  if (0 != ip6_full_reass_buffer_get_data_offset (tmp))
	    {
	      rv = IP6_FULL_REASS_RC_INTERNAL_ERROR;
	      goto free_buffers_and_return;
	    }
	  trim_front = 0;
	  trim_end = vlib_buffer_length_in_chain (vm, tmp) - data_len -
	    (vnet_buffer (tmp)->ip.reass.ip6_frag_hdr_offset +
	     sizeof (*frag_hdr));
	  if (!(vlib_buffer_length_in_chain (vm, tmp) - trim_end > 0))
	    {
	      rv = IP6_FULL_REASS_RC_INTERNAL_ERROR;
	      goto free_buffers_and_return;
	    }
	}
      u32 keep_data =
	vlib_buffer_length_in_chain (vm, tmp) - trim_front - trim_end;
      while (1)
	{
	  ++buf_cnt;
	  if (trim_front)
	    {
	      if (trim_front > tmp->current_length)
		{
		  /* drop whole buffer */
		  vec_add1 (vec_drop_compress, tmp_bi);
		  trim_front -= tmp->current_length;
		  if (!(tmp->flags & VLIB_BUFFER_NEXT_PRESENT))
		    {
		      rv = IP6_FULL_REASS_RC_INTERNAL_ERROR;
		      goto free_buffers_and_return;
		    }
		  tmp->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
		  tmp_bi = tmp->next_buffer;
		  tmp = vlib_get_buffer (vm, tmp_bi);
		  continue;
		}
	      else
		{
		  vlib_buffer_advance (tmp, trim_front);
		  trim_front = 0;
		}
	    }
	  if (keep_data)
	    {
	      if (last_b)
		{
		  last_b->flags |= VLIB_BUFFER_NEXT_PRESENT;
		  last_b->next_buffer = tmp_bi;
		}
	      last_b = tmp;
	      if (keep_data <= tmp->current_length)
		{
		  tmp->current_length = keep_data;
		  keep_data = 0;
		}
	      else
		{
		  keep_data -= tmp->current_length;
		  if (!(tmp->flags & VLIB_BUFFER_NEXT_PRESENT))
		    {
		      rv = IP6_FULL_REASS_RC_INTERNAL_ERROR;
		      goto free_buffers_and_return;
		    }
		}
	      total_length += tmp->current_length;
	    }
	  else
	    {
	      vec_add1 (vec_drop_compress, tmp_bi);
	      if (reass->first_bi == tmp_bi)
		{
		  rv = IP6_FULL_REASS_RC_INTERNAL_ERROR;
		  goto free_buffers_and_return;
		}
	      ++dropped_cnt;
	    }
	  if (tmp->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      tmp_bi = tmp->next_buffer;
	      tmp = vlib_get_buffer (vm, tmp->next_buffer);
	    }
	  else
	    {
	      break;
	    }
	}
      sub_chain_bi =
	vnet_buffer (vlib_get_buffer (vm, sub_chain_bi))->ip.
	reass.next_range_bi;
    }
  while (~0 != sub_chain_bi);

  if (!last_b)
    {
      rv = IP6_FULL_REASS_RC_INTERNAL_ERROR;
      goto free_buffers_and_return;
    }
  last_b->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
  vlib_buffer_t *first_b = vlib_get_buffer (vm, reass->first_bi);
  if (total_length < first_b->current_length)
    {
      rv = IP6_FULL_REASS_RC_INTERNAL_ERROR;
      goto free_buffers_and_return;
    }
  total_length -= first_b->current_length;
  first_b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  first_b->total_length_not_including_first_buffer = total_length;
  // drop fragment header
  vnet_buffer_opaque_t *first_b_vnb = vnet_buffer (first_b);
  ip6_header_t *ip = vlib_buffer_get_current (first_b);
  u16 ip6_frag_hdr_offset = first_b_vnb->ip.reass.ip6_frag_hdr_offset;
  ip6_ext_hdr_chain_t hdr_chain;
  ip6_ext_header_t *prev_hdr = 0;
  int res = ip6_ext_header_walk (first_b, ip, IP_PROTOCOL_IPV6_FRAGMENTATION,
				 &hdr_chain);
  if (res < 0 ||
      (hdr_chain.eh[res].protocol != IP_PROTOCOL_IPV6_FRAGMENTATION))
    {
      rv = IP6_FULL_REASS_RC_INTERNAL_ERROR;
      goto free_buffers_and_return;
    }
  frag_hdr = ip6_ext_next_header_offset (ip, hdr_chain.eh[res].offset);
  if (res > 0)
    {
      prev_hdr = ip6_ext_next_header_offset (ip, hdr_chain.eh[res - 1].offset);
      prev_hdr->next_hdr = frag_hdr->next_hdr;
    }
  else
    {
      ip->protocol = frag_hdr->next_hdr;
    }
  if (hdr_chain.eh[res].offset != ip6_frag_hdr_offset)
    {
      rv = IP6_FULL_REASS_RC_INTERNAL_ERROR;
      goto free_buffers_and_return;
    }
  memmove (frag_hdr, (u8 *) frag_hdr + sizeof (*frag_hdr),
	   first_b->current_length - ip6_frag_hdr_offset -
	   sizeof (ip6_frag_hdr_t));
  first_b->current_length -= sizeof (*frag_hdr);
  ip->payload_length =
    clib_host_to_net_u16 (total_length + first_b->current_length -
			  sizeof (*ip));
  if (!vlib_buffer_chain_linearize (vm, first_b))
    {
      rv = IP6_FULL_REASS_RC_NO_BUF;
      goto free_buffers_and_return;
    }
  first_b->flags &= ~VLIB_BUFFER_EXT_HDR_VALID;
  if (PREDICT_FALSE (first_b->flags & VLIB_BUFFER_IS_TRACED))
    {
      ip6_full_reass_add_trace (vm, node, reass, reass->first_bi, NULL,
				FINALIZE, ~0);
#if 0
      // following code does a hexdump of packet fragments to stdout ...
      do
	{
	  u32 bi = reass->first_bi;
	  u8 *s = NULL;
	  while (~0 != bi)
	    {
	      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	      s = format (s, "%u: %U\n", bi, format_hexdump,
			  vlib_buffer_get_current (b), b->current_length);
	      if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
		{
		  bi = b->next_buffer;
		}
	      else
		{
		  break;
		}
	    }
	  printf ("%.*s\n", vec_len (s), s);
	  fflush (stdout);
	  vec_free (s);
	}
      while (0);
#endif
    }
  if (!is_custom_app)
    {
      *next0 = IP6_FULL_REASSEMBLY_NEXT_INPUT;
    }
  else
    {
      *next0 = reass->next_index;
    }
  vnet_buffer (first_b)->ip.reass.estimated_mtu = reass->min_fragment_length;
  ip6_full_reass_free (rm, rt, reass);
  reass = NULL;
free_buffers_and_return:
  vlib_buffer_free (vm, vec_drop_compress, vec_len (vec_drop_compress));
  vec_free (vec_drop_compress);
  return rv;
}

always_inline void
ip6_full_reass_insert_range_in_chain (vlib_main_t * vm,
				      ip6_full_reass_t * reass,
				      u32 prev_range_bi, u32 new_next_bi)
{

  vlib_buffer_t *new_next_b = vlib_get_buffer (vm, new_next_bi);
  vnet_buffer_opaque_t *new_next_vnb = vnet_buffer (new_next_b);
  if (~0 != prev_range_bi)
    {
      vlib_buffer_t *prev_b = vlib_get_buffer (vm, prev_range_bi);
      vnet_buffer_opaque_t *prev_vnb = vnet_buffer (prev_b);
      new_next_vnb->ip.reass.next_range_bi = prev_vnb->ip.reass.next_range_bi;
      prev_vnb->ip.reass.next_range_bi = new_next_bi;
    }
  else
    {
      if (~0 != reass->first_bi)
	{
	  new_next_vnb->ip.reass.next_range_bi = reass->first_bi;
	}
      reass->first_bi = new_next_bi;
    }
  reass->data_len += ip6_full_reass_buffer_get_data_len (new_next_b);
}

always_inline ip6_full_reass_rc_t
ip6_full_reass_update (vlib_main_t *vm, vlib_node_runtime_t *node,
		       ip6_full_reass_main_t *rm,
		       ip6_full_reass_per_thread_t *rt,
		       ip6_full_reass_t *reass, u32 *bi0, u32 *next0,
		       u32 *error0, ip6_frag_hdr_t *frag_hdr,
		       bool is_custom_app, u32 *handoff_thread_idx,
		       int skip_bihash)
{
  int consumed = 0;
  vlib_buffer_t *fb = vlib_get_buffer (vm, *bi0);
  vnet_buffer_opaque_t *fvnb = vnet_buffer (fb);
  if (is_custom_app)
    {
      reass->next_index = fvnb->ip.reass.next_index;	// store next_index before it's overwritten
      reass->error_next_index = fvnb->ip.reass.error_next_index;	// store error_next_index before it is overwritten
    }

  fvnb->ip.reass.ip6_frag_hdr_offset =
    (u8 *) frag_hdr - (u8 *) vlib_buffer_get_current (fb);
  ip6_header_t *fip = vlib_buffer_get_current (fb);
  if (fb->current_length < sizeof (*fip) ||
      fvnb->ip.reass.ip6_frag_hdr_offset == 0 ||
      fvnb->ip.reass.ip6_frag_hdr_offset >= fb->current_length)
    {
      return IP6_FULL_REASS_RC_INTERNAL_ERROR;
    }

  u32 fragment_first = fvnb->ip.reass.fragment_first =
    ip6_frag_hdr_offset_bytes (frag_hdr);
  u32 fragment_length =
    vlib_buffer_length_in_chain (vm, fb) -
    (fvnb->ip.reass.ip6_frag_hdr_offset + sizeof (*frag_hdr));
  if (0 == fragment_length)
    {
      return IP6_FULL_REASS_RC_INVALID_FRAG_LEN;
    }
  u32 fragment_last = fvnb->ip.reass.fragment_last =
    fragment_first + fragment_length - 1;
  int more_fragments = ip6_frag_hdr_more (frag_hdr);
  u32 candidate_range_bi = reass->first_bi;
  u32 prev_range_bi = ~0;
  fvnb->ip.reass.range_first = fragment_first;
  fvnb->ip.reass.range_last = fragment_last;
  fvnb->ip.reass.next_range_bi = ~0;
  if (!more_fragments)
    {
      reass->last_packet_octet = fragment_last;
    }
  if (~0 == reass->first_bi)
    {
      // starting a new reassembly
      ip6_full_reass_insert_range_in_chain (vm, reass, prev_range_bi, *bi0);
      reass->min_fragment_length = clib_net_to_host_u16 (fip->payload_length);
      consumed = 1;
      reass->fragments_n = 1;
      goto check_if_done_maybe;
    }
  reass->min_fragment_length =
    clib_min (clib_net_to_host_u16 (fip->payload_length),
	      fvnb->ip.reass.estimated_mtu);
  while (~0 != candidate_range_bi)
    {
      vlib_buffer_t *candidate_b = vlib_get_buffer (vm, candidate_range_bi);
      vnet_buffer_opaque_t *candidate_vnb = vnet_buffer (candidate_b);
      if (fragment_first > candidate_vnb->ip.reass.range_last)
	{
	  // this fragments starts after candidate range
	  prev_range_bi = candidate_range_bi;
	  candidate_range_bi = candidate_vnb->ip.reass.next_range_bi;
	  if (candidate_vnb->ip.reass.range_last < fragment_last &&
	      ~0 == candidate_range_bi)
	    {
	      // special case - this fragment falls beyond all known ranges
	      ip6_full_reass_insert_range_in_chain (vm, reass, prev_range_bi,
						    *bi0);
	      consumed = 1;
	      break;
	    }
	  continue;
	}
      if (fragment_last < candidate_vnb->ip.reass.range_first)
	{
	  // this fragment ends before candidate range without any overlap
	  ip6_full_reass_insert_range_in_chain (vm, reass, prev_range_bi,
						*bi0);
	  consumed = 1;
	}
      else if (fragment_first == candidate_vnb->ip.reass.range_first &&
	       fragment_last == candidate_vnb->ip.reass.range_last)
	{
	  // duplicate fragment - ignore
	}
      else
	{
	  // overlapping fragment - not allowed by RFC 8200
	  if (PREDICT_FALSE (fb->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ip6_full_reass_add_trace (vm, node, reass, *bi0, frag_hdr,
					RANGE_OVERLAP, ~0);
	    }
	  ip6_full_reass_drop_all (vm, node, reass);
	  ip6_full_reass_free (rm, rt, reass);
	  *next0 = IP6_FULL_REASSEMBLY_NEXT_DROP;
	  *error0 = IP6_ERROR_REASS_OVERLAPPING_FRAGMENT;
	  return IP6_FULL_REASS_RC_OK;
	}
      break;
    }
  ++reass->fragments_n;
check_if_done_maybe:
  if (consumed)
    {
      if (PREDICT_FALSE (fb->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ip6_full_reass_add_trace (vm, node, reass, *bi0, frag_hdr, RANGE_NEW,
				    ~0);
	}
    }
  else if (skip_bihash)
    {
      // if this reassembly is not in bihash, then the packet must have been
      // consumed
      return IP6_FULL_REASS_RC_INTERNAL_ERROR;
    }
  if (~0 != reass->last_packet_octet &&
      reass->data_len == reass->last_packet_octet + 1)
    {
      *handoff_thread_idx = reass->sendout_thread_index;
      int handoff =
	reass->memory_owner_thread_index != reass->sendout_thread_index;
      ip6_full_reass_rc_t rc =
	ip6_full_reass_finalize (vm, node, rm, rt, reass, bi0, next0, error0,
				 is_custom_app);
      if (IP6_FULL_REASS_RC_OK == rc && handoff)
	{
	  return IP6_FULL_REASS_RC_HANDOFF;
	}
      return rc;
    }
  else
    {
      if (skip_bihash)
	{
	  // if this reassembly is not in bihash, it should've been an atomic
	  // fragment and thus finalized
	  return IP6_FULL_REASS_RC_INTERNAL_ERROR;
	}
      if (consumed)
	{
	  *bi0 = ~0;
	  if (reass->fragments_n > rm->max_reass_len)
	    {
	      return IP6_FULL_REASS_RC_TOO_MANY_FRAGMENTS;
	    }
	}
      else
	{
	  *next0 = IP6_FULL_REASSEMBLY_NEXT_DROP;
	  *error0 = IP6_ERROR_REASS_DUPLICATE_FRAGMENT;
	}
    }
  return IP6_FULL_REASS_RC_OK;
}

always_inline bool
ip6_full_reass_verify_upper_layer_present (vlib_node_runtime_t *node,
					   vlib_buffer_t *b,
					   ip6_ext_hdr_chain_t *hc)
{
  int nh = hc->eh[hc->length - 1].protocol;
  /* Checking to see if it's a terminating header */
  if (ip6_ext_hdr (nh))
    {
      icmp6_error_set_vnet_buffer (
	b, ICMP6_parameter_problem,
	ICMP6_parameter_problem_first_fragment_has_incomplete_header_chain, 0);
      b->error = node->errors[IP6_ERROR_REASS_MISSING_UPPER];
      return false;
    }
  return true;
}

always_inline bool
ip6_full_reass_verify_fragment_multiple_8 (vlib_main_t * vm,
					   vlib_buffer_t * b,
					   ip6_frag_hdr_t * frag_hdr)
{
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  ip6_header_t *ip = vlib_buffer_get_current (b);
  int more_fragments = ip6_frag_hdr_more (frag_hdr);
  u32 fragment_length =
    vlib_buffer_length_in_chain (vm, b) -
    (vnb->ip.reass.ip6_frag_hdr_offset + sizeof (*frag_hdr));
  if (more_fragments && 0 != fragment_length % 8)
    {
      icmp6_error_set_vnet_buffer (b, ICMP6_parameter_problem,
				   ICMP6_parameter_problem_erroneous_header_field,
				   (u8 *) & ip->payload_length - (u8 *) ip);
      return false;
    }
  return true;
}

always_inline bool
ip6_full_reass_verify_packet_size_lt_64k (vlib_main_t * vm,
					  vlib_buffer_t * b,
					  ip6_frag_hdr_t * frag_hdr)
{
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  u32 fragment_first = ip6_frag_hdr_offset_bytes (frag_hdr);
  u32 fragment_length =
    vlib_buffer_length_in_chain (vm, b) -
    (vnb->ip.reass.ip6_frag_hdr_offset + sizeof (*frag_hdr));
  if (fragment_first + fragment_length > 65535)
    {
      ip6_header_t *ip0 = vlib_buffer_get_current (b);
      icmp6_error_set_vnet_buffer (b, ICMP6_parameter_problem,
				   ICMP6_parameter_problem_erroneous_header_field,
				   (u8 *) & frag_hdr->fragment_offset_and_more
				   - (u8 *) ip0);
      return false;
    }
  return true;
}

always_inline uword
ip6_full_reassembly_inline (vlib_main_t * vm,
			    vlib_node_runtime_t * node,
			    vlib_frame_t * frame, bool is_feature,
			    bool is_custom_app)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from, n_left_to_next, *to_next, next_index;
  ip6_full_reass_main_t *rm = &ip6_full_reass_main;
  ip6_full_reass_per_thread_t *rt = &rm->per_thread_data[vm->thread_index];
  clib_spinlock_lock (&rt->lock);

  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = IP6_FULL_REASSEMBLY_NEXT_DROP;
	  u32 error0 = IP6_ERROR_NONE;
	  u32 icmp_bi = ~0;

	  bi0 = from[0];
	  b0 = vlib_get_buffer (vm, bi0);

	  ip6_header_t *ip0 = vlib_buffer_get_current (b0);
	  ip6_frag_hdr_t *frag_hdr;
	  ip6_ext_hdr_chain_t hdr_chain;
	  int res = ip6_ext_header_walk (
	    b0, ip0, IP_PROTOCOL_IPV6_FRAGMENTATION, &hdr_chain);
	  if (res < 0 ||
	      hdr_chain.eh[res].protocol != IP_PROTOCOL_IPV6_FRAGMENTATION)
	    {
	      // this is a mangled packet - no fragmentation
	      next0 = IP6_FULL_REASSEMBLY_NEXT_DROP;
	      goto skip_reass;
	    }
	  frag_hdr =
	    ip6_ext_next_header_offset (ip0, hdr_chain.eh[res].offset);
	  vnet_buffer (b0)->ip.reass.ip6_frag_hdr_offset =
	    hdr_chain.eh[res].offset;

	  if (0 == ip6_frag_hdr_offset (frag_hdr))
	    {
	      // first fragment - verify upper-layer is present
	      if (!ip6_full_reass_verify_upper_layer_present (node, b0,
							      &hdr_chain))
		{
		  next0 = IP6_FULL_REASSEMBLY_NEXT_ICMP_ERROR;
		  goto skip_reass;
		}
	    }
	  if (!ip6_full_reass_verify_fragment_multiple_8 (vm, b0, frag_hdr) ||
	      !ip6_full_reass_verify_packet_size_lt_64k (vm, b0, frag_hdr))
	    {
	      next0 = IP6_FULL_REASSEMBLY_NEXT_ICMP_ERROR;
	      goto skip_reass;
	    }

	  int skip_bihash = 0;
	  ip6_full_reass_kv_t kv;
	  u8 do_handoff = 0;

	  if (0 == ip6_frag_hdr_offset (frag_hdr) &&
	      !ip6_frag_hdr_more (frag_hdr))
	    {
	      // this is atomic fragment and needs to be processed separately
	      skip_bihash = 1;
	    }
	  else
	    {
	      kv.k.as_u64[0] = ip0->src_address.as_u64[0];
	      kv.k.as_u64[1] = ip0->src_address.as_u64[1];
	      kv.k.as_u64[2] = ip0->dst_address.as_u64[0];
	      kv.k.as_u64[3] = ip0->dst_address.as_u64[1];
	      kv.k.as_u64[4] =
		((u64) vec_elt (ip6_main.fib_index_by_sw_if_index,
				vnet_buffer (b0)->sw_if_index[VLIB_RX]))
		  << 32 |
		(u64) frag_hdr->identification;
	      kv.k.as_u64[5] = ip0->protocol;
	    }

	  ip6_full_reass_t *reass = ip6_full_reass_find_or_create (
	    vm, node, rm, rt, &kv, &icmp_bi, &do_handoff, skip_bihash);

	  if (reass)
	    {
	      const u32 fragment_first = ip6_frag_hdr_offset (frag_hdr);
	      if (0 == fragment_first)
		{
		  reass->sendout_thread_index = vm->thread_index;
		}
	    }
	  if (PREDICT_FALSE (do_handoff))
	    {
	      next0 = IP6_FULL_REASSEMBLY_NEXT_HANDOFF;
	      vnet_buffer (b0)->ip.reass.owner_thread_index =
		kv.v.memory_owner_thread_index;
	    }
	  else if (reass)
	    {
	      u32 handoff_thread_idx;
	      u32 counter = ~0;
	      switch (ip6_full_reass_update (
		vm, node, rm, rt, reass, &bi0, &next0, &error0, frag_hdr,
		is_custom_app, &handoff_thread_idx, skip_bihash))
		{
		case IP6_FULL_REASS_RC_OK:
		  /* nothing to do here */
		  break;
		case IP6_FULL_REASS_RC_HANDOFF:
		  next0 = IP6_FULL_REASSEMBLY_NEXT_HANDOFF;
		  b0 = vlib_get_buffer (vm, bi0);
		  vnet_buffer (b0)->ip.reass.owner_thread_index =
		    handoff_thread_idx;
		  break;
		case IP6_FULL_REASS_RC_TOO_MANY_FRAGMENTS:
		  counter = IP6_ERROR_REASS_FRAGMENT_CHAIN_TOO_LONG;
		  break;
		case IP6_FULL_REASS_RC_NO_BUF:
		  counter = IP6_ERROR_REASS_NO_BUF;
		  break;
		case IP6_FULL_REASS_RC_INTERNAL_ERROR:
		  counter = IP6_ERROR_REASS_INTERNAL_ERROR;
		  break;
		case IP6_FULL_REASS_RC_INVALID_FRAG_LEN:
		  counter = IP6_ERROR_REASS_INVALID_FRAG_LEN;
		  break;
		}
	      if (~0 != counter)
		{
		  vlib_node_increment_counter (vm, node->node_index, counter,
					       1);
		  ip6_full_reass_drop_all (vm, node, reass);
		  ip6_full_reass_free (rm, rt, reass);
		  goto next_packet;
		}
	    }
	  else
	    {
	      if (is_feature)
		{
		  next0 = IP6_FULL_REASSEMBLY_NEXT_DROP;
		}
	      else
		{
		  vnet_buffer_opaque_t *fvnb = vnet_buffer (b0);
		  next0 = fvnb->ip.reass.error_next_index;
		}
	      error0 = IP6_ERROR_REASS_LIMIT_REACHED;
	    }

	  if (~0 != bi0)
	    {
	    skip_reass:
	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;

	      /* bi0 might have been updated by reass_finalize, reload */
	      b0 = vlib_get_buffer (vm, bi0);
	      if (IP6_ERROR_NONE != error0)
		{
		  b0->error = node->errors[error0];
		}

	      if (next0 == IP6_FULL_REASSEMBLY_NEXT_HANDOFF)
		{
		  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		    {
		      ip6_full_reass_add_trace (
			vm, node, NULL, bi0, frag_hdr, HANDOFF,
			vnet_buffer (b0)->ip.reass.owner_thread_index);
		    }
		}
	      else if (is_feature && IP6_ERROR_NONE == error0)
		{
		  vnet_feature_next (&next0, b0);
		}
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, bi0, next0);
	    }

	  if (~0 != icmp_bi)
	    {
	      next0 = IP6_FULL_REASSEMBLY_NEXT_ICMP_ERROR;
	      to_next[0] = icmp_bi;
	      to_next += 1;
	      n_left_to_next -= 1;
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, icmp_bi,
					       next0);
	    }
	next_packet:
	  from += 1;
	  n_left_from -= 1;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  clib_spinlock_unlock (&rt->lock);
  return frame->n_vectors;
}

static char *ip6_full_reassembly_error_strings[] = {
#define _(sym, string) string,
  foreach_ip6_error
#undef _
};

VLIB_NODE_FN (ip6_full_reass_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return ip6_full_reassembly_inline (vm, node, frame, false /* is_feature */ ,
				     false /* is_custom_app */ );
}

VLIB_REGISTER_NODE (ip6_full_reass_node) = {
    .name = "ip6-full-reassembly",
    .vector_size = sizeof (u32),
    .format_trace = format_ip6_full_reass_trace,
    .n_errors = ARRAY_LEN (ip6_full_reassembly_error_strings),
    .error_strings = ip6_full_reassembly_error_strings,
    .n_next_nodes = IP6_FULL_REASSEMBLY_N_NEXT,
    .next_nodes =
        {
                [IP6_FULL_REASSEMBLY_NEXT_INPUT] = "ip6-input",
                [IP6_FULL_REASSEMBLY_NEXT_DROP] = "ip6-drop",
                [IP6_FULL_REASSEMBLY_NEXT_ICMP_ERROR] = "ip6-icmp-error",
                [IP6_FULL_REASSEMBLY_NEXT_HANDOFF] = "ip6-full-reassembly-handoff",
        },
};

VLIB_NODE_FN (ip6_full_reass_node_feature) (vlib_main_t * vm,
					    vlib_node_runtime_t * node,
					    vlib_frame_t * frame)
{
  return ip6_full_reassembly_inline (vm, node, frame, true /* is_feature */ ,
				     false /* is_custom_app */ );
}

VLIB_REGISTER_NODE (ip6_full_reass_node_feature) = {
    .name = "ip6-full-reassembly-feature",
    .vector_size = sizeof (u32),
    .format_trace = format_ip6_full_reass_trace,
    .n_errors = ARRAY_LEN (ip6_full_reassembly_error_strings),
    .error_strings = ip6_full_reassembly_error_strings,
    .n_next_nodes = IP6_FULL_REASSEMBLY_N_NEXT,
    .next_nodes =
        {
                [IP6_FULL_REASSEMBLY_NEXT_INPUT] = "ip6-input",
                [IP6_FULL_REASSEMBLY_NEXT_DROP] = "ip6-drop",
                [IP6_FULL_REASSEMBLY_NEXT_ICMP_ERROR] = "ip6-icmp-error",
                [IP6_FULL_REASSEMBLY_NEXT_HANDOFF] = "ip6-full-reass-feature-hoff",
        },
};

VNET_FEATURE_INIT (ip6_full_reassembly_feature, static) = {
    .arc_name = "ip6-unicast",
    .node_name = "ip6-full-reassembly-feature",
    .runs_before = VNET_FEATURES ("ip6-lookup",
                                  "ipsec6-input-feature"),
    .runs_after = 0,
};

#ifndef CLIB_MARCH_VARIANT
static u32
ip6_full_reass_get_nbuckets ()
{
  ip6_full_reass_main_t *rm = &ip6_full_reass_main;
  u32 nbuckets;
  u8 i;

  nbuckets = (u32) (rm->max_reass_n / IP6_FULL_REASS_HT_LOAD_FACTOR);

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
} ip6_full_reass_event_t;

#ifndef CLIB_MARCH_VARIANT
typedef struct
{
  int failure;
  clib_bihash_48_8_t *new_hash;
} ip6_rehash_cb_ctx;

static int
ip6_rehash_cb (clib_bihash_kv_48_8_t * kv, void *_ctx)
{
  ip6_rehash_cb_ctx *ctx = _ctx;
  if (clib_bihash_add_del_48_8 (ctx->new_hash, kv, 1))
    {
      ctx->failure = 1;
    }
  return (BIHASH_WALK_CONTINUE);
}

static void
ip6_full_reass_set_params (u32 timeout_ms, u32 max_reassemblies,
			   u32 max_reassembly_length,
			   u32 expire_walk_interval_ms)
{
  ip6_full_reass_main.timeout_ms = timeout_ms;
  ip6_full_reass_main.timeout = (f64) timeout_ms / (f64) MSEC_PER_SEC;
  ip6_full_reass_main.max_reass_n = max_reassemblies;
  ip6_full_reass_main.max_reass_len = max_reassembly_length;
  ip6_full_reass_main.expire_walk_interval_ms = expire_walk_interval_ms;
}

vnet_api_error_t
ip6_full_reass_set (u32 timeout_ms, u32 max_reassemblies,
		    u32 max_reassembly_length, u32 expire_walk_interval_ms)
{
  u32 old_nbuckets = ip6_full_reass_get_nbuckets ();
  ip6_full_reass_set_params (timeout_ms, max_reassemblies,
			     max_reassembly_length, expire_walk_interval_ms);
  vlib_process_signal_event (ip6_full_reass_main.vlib_main,
			     ip6_full_reass_main.ip6_full_reass_expire_node_idx,
			     IP6_EVENT_CONFIG_CHANGED, 0);
  u32 new_nbuckets = ip6_full_reass_get_nbuckets ();
  if (ip6_full_reass_main.max_reass_n > 0 && new_nbuckets > old_nbuckets)
    {
      clib_bihash_48_8_t new_hash;
      clib_memset (&new_hash, 0, sizeof (new_hash));
      ip6_rehash_cb_ctx ctx;
      ctx.failure = 0;
      ctx.new_hash = &new_hash;
      clib_bihash_init_48_8 (&new_hash, "ip6-full-reass", new_nbuckets,
			     new_nbuckets * 1024);
      clib_bihash_foreach_key_value_pair_48_8 (&ip6_full_reass_main.hash,
					       ip6_rehash_cb, &ctx);
      if (ctx.failure)
	{
	  clib_bihash_free_48_8 (&new_hash);
	  return -1;
	}
      else
	{
	  clib_bihash_free_48_8 (&ip6_full_reass_main.hash);
	  clib_memcpy_fast (&ip6_full_reass_main.hash, &new_hash,
			    sizeof (ip6_full_reass_main.hash));
	  clib_bihash_copied (&ip6_full_reass_main.hash, &new_hash);
	}
    }
  return 0;
}

vnet_api_error_t
ip6_full_reass_get (u32 * timeout_ms, u32 * max_reassemblies,
		    u32 * max_reassembly_length,
		    u32 * expire_walk_interval_ms)
{
  *timeout_ms = ip6_full_reass_main.timeout_ms;
  *max_reassemblies = ip6_full_reass_main.max_reass_n;
  *max_reassembly_length = ip6_full_reass_main.max_reass_len;
  *expire_walk_interval_ms = ip6_full_reass_main.expire_walk_interval_ms;
  return 0;
}

static clib_error_t *
ip6_full_reass_init_function (vlib_main_t * vm)
{
  ip6_full_reass_main_t *rm = &ip6_full_reass_main;
  clib_error_t *error = 0;
  u32 nbuckets;
  vlib_node_t *node;

  rm->vlib_main = vm;

  vec_validate (rm->per_thread_data, vlib_num_workers ());
  ip6_full_reass_per_thread_t *rt;
  vec_foreach (rt, rm->per_thread_data)
  {
    clib_spinlock_init (&rt->lock);
    pool_alloc (rt->pool, rm->max_reass_n);
  }

  node = vlib_get_node_by_name (vm, (u8 *) "ip6-full-reassembly-expire-walk");
  ASSERT (node);
  rm->ip6_full_reass_expire_node_idx = node->index;

  ip6_full_reass_set_params (IP6_FULL_REASS_TIMEOUT_DEFAULT_MS,
			     IP6_FULL_REASS_MAX_REASSEMBLIES_DEFAULT,
			     IP6_FULL_REASS_MAX_REASSEMBLY_LENGTH_DEFAULT,
			     IP6_FULL_REASS_EXPIRE_WALK_INTERVAL_DEFAULT_MS);

  nbuckets = ip6_full_reass_get_nbuckets ();
  clib_bihash_init_48_8 (&rm->hash, "ip6-full-reass", nbuckets,
			 nbuckets * 1024);

  node = vlib_get_node_by_name (vm, (u8 *) "ip6-drop");
  ASSERT (node);
  rm->ip6_drop_idx = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "ip6-icmp-error");
  ASSERT (node);
  rm->ip6_icmp_error_idx = node->index;

  if ((error = vlib_call_init_function (vm, ip_main_init)))
    return error;
  ip6_register_protocol (IP_PROTOCOL_IPV6_FRAGMENTATION,
			 ip6_full_reass_node.index);

  rm->fq_index = vlib_frame_queue_main_init (ip6_full_reass_node.index, 0);
  rm->fq_feature_index =
    vlib_frame_queue_main_init (ip6_full_reass_node_feature.index, 0);

  rm->feature_use_refcount_per_intf = NULL;
  return error;
}

VLIB_INIT_FUNCTION (ip6_full_reass_init_function);
#endif /* CLIB_MARCH_VARIANT */

static uword
ip6_full_reass_walk_expired (vlib_main_t *vm, vlib_node_runtime_t *node,
			     CLIB_UNUSED (vlib_frame_t *f))
{
  ip6_full_reass_main_t *rm = &ip6_full_reass_main;
  uword event_type, *event_data = 0;

  while (true)
    {
      vlib_process_wait_for_event_or_clock (vm,
					    (f64) rm->expire_walk_interval_ms
					    / (f64) MSEC_PER_SEC);
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

      ip6_full_reass_t *reass;
      int *pool_indexes_to_free = NULL;

      uword thread_index = 0;
      int index;
      const uword nthreads = vlib_num_workers () + 1;
      u32 *vec_icmp_bi = NULL;
      for (thread_index = 0; thread_index < nthreads; ++thread_index)
	{
	  ip6_full_reass_per_thread_t *rt =
	    &rm->per_thread_data[thread_index];
	  clib_spinlock_lock (&rt->lock);

	  vec_reset_length (pool_indexes_to_free);
          pool_foreach_index (index, rt->pool)  {
                                reass = pool_elt_at_index (rt->pool, index);
                                if (now > reass->last_heard + rm->timeout)
                                  {
                                    vec_add1 (pool_indexes_to_free, index);
                                  }
                              }
	  int *i;
          vec_foreach (i, pool_indexes_to_free)
          {
            ip6_full_reass_t *reass = pool_elt_at_index (rt->pool, i[0]);
            u32 icmp_bi = ~0;
	    ip6_full_reass_on_timeout (vm, node, reass, &icmp_bi);
	    if (~0 != icmp_bi)
	      vec_add1 (vec_icmp_bi, icmp_bi);

	    ip6_full_reass_free (rm, rt, reass);
	  }

	  clib_spinlock_unlock (&rt->lock);
	}

      while (vec_len (vec_icmp_bi) > 0)
	{
	  vlib_frame_t *f =
	    vlib_get_frame_to_node (vm, rm->ip6_icmp_error_idx);
	  u32 *to_next = vlib_frame_vector_args (f);
	  u32 n_left_to_next = VLIB_FRAME_SIZE - f->n_vectors;
	  int trace_frame = 0;
	  while (vec_len (vec_icmp_bi) > 0 && n_left_to_next > 0)
	    {
	      u32 bi = vec_pop (vec_icmp_bi);
	      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	      if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
		trace_frame = 1;
	      b->error = node->errors[IP6_ERROR_REASS_TIMEOUT];
	      to_next[0] = bi;
	      ++f->n_vectors;
	      to_next += 1;
	      n_left_to_next -= 1;
	    }
	  f->frame_flags |= (trace_frame * VLIB_FRAME_TRACE);
	  vlib_put_frame_to_node (vm, rm->ip6_icmp_error_idx, f);
	}

      vec_free (pool_indexes_to_free);
      vec_free (vec_icmp_bi);
      if (event_data)
	{
	  _vec_len (event_data) = 0;
	}
    }

  return 0;
}

VLIB_REGISTER_NODE (ip6_full_reass_expire_node) = {
    .function = ip6_full_reass_walk_expired,
    .format_trace = format_ip6_full_reass_trace,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "ip6-full-reassembly-expire-walk",

    .n_errors = ARRAY_LEN (ip6_full_reassembly_error_strings),
    .error_strings = ip6_full_reassembly_error_strings,

};

static u8 *
format_ip6_full_reass_key (u8 * s, va_list * args)
{
  ip6_full_reass_key_t *key = va_arg (*args, ip6_full_reass_key_t *);
  s = format (s, "xx_id: %u, src: %U, dst: %U, frag_id: %u, proto: %u",
	      key->xx_id, format_ip6_address, &key->src, format_ip6_address,
	      &key->dst, clib_net_to_host_u16 (key->frag_id), key->proto);
  return s;
}

static u8 *
format_ip6_full_reass (u8 * s, va_list * args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  ip6_full_reass_t *reass = va_arg (*args, ip6_full_reass_t *);

  s = format (s, "ID: %lu, key: %U\n  first_bi: %u, data_len: %u, "
	      "last_packet_octet: %u, trace_op_counter: %u\n",
	      reass->id, format_ip6_full_reass_key, &reass->key,
	      reass->first_bi, reass->data_len, reass->last_packet_octet,
	      reass->trace_op_counter);
  u32 bi = reass->first_bi;
  u32 counter = 0;
  while (~0 != bi)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
      vnet_buffer_opaque_t *vnb = vnet_buffer (b);
      s = format (s, "  #%03u: range: [%u, %u], bi: %u, off: %d, len: %u, "
		  "fragment[%u, %u]\n",
		  counter, vnb->ip.reass.range_first,
		  vnb->ip.reass.range_last, bi,
		  ip6_full_reass_buffer_get_data_offset (b),
		  ip6_full_reass_buffer_get_data_len (b),
		  vnb->ip.reass.fragment_first, vnb->ip.reass.fragment_last);
      if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  bi = b->next_buffer;
	}
      else
	{
	  bi = ~0;
	}
    }
  return s;
}

static clib_error_t *
show_ip6_full_reass (vlib_main_t * vm, unformat_input_t * input,
		     CLIB_UNUSED (vlib_cli_command_t * lmd))
{
  ip6_full_reass_main_t *rm = &ip6_full_reass_main;

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
  ip6_full_reass_t *reass;
  uword thread_index;
  const uword nthreads = vlib_num_workers () + 1;
  for (thread_index = 0; thread_index < nthreads; ++thread_index)
    {
      ip6_full_reass_per_thread_t *rt = &rm->per_thread_data[thread_index];
      clib_spinlock_lock (&rt->lock);
      if (details)
	{
          pool_foreach (reass, rt->pool) {
            vlib_cli_output (vm, "%U", format_ip6_full_reass, vm, reass);
          }
	}
      sum_reass_n += rt->reass_n;
      clib_spinlock_unlock (&rt->lock);
    }
  vlib_cli_output (vm, "---------------------");
  vlib_cli_output (vm, "Current IP6 reassemblies count: %lu\n",
		   (long unsigned) sum_reass_n);
  vlib_cli_output (vm,
		   "Maximum configured concurrent full IP6 reassemblies per worker-thread: %lu\n",
		   (long unsigned) rm->max_reass_n);
  vlib_cli_output (vm,
		   "Maximum configured amount of fragments "
		   "per full IP6 reassembly: %lu\n",
		   (long unsigned) rm->max_reass_len);
  vlib_cli_output (vm,
		   "Maximum configured full IP6 reassembly timeout: %lums\n",
		   (long unsigned) rm->timeout_ms);
  vlib_cli_output (vm,
		   "Maximum configured full IP6 reassembly expire walk interval: %lums\n",
		   (long unsigned) rm->expire_walk_interval_ms);
  vlib_cli_output (vm, "Buffers in use: %lu\n",
		   (long unsigned) sum_buffers_n);
  return 0;
}

VLIB_CLI_COMMAND (show_ip6_full_reassembly_cmd, static) = {
    .path = "show ip6-full-reassembly",
    .short_help = "show ip6-full-reassembly [details]",
    .function = show_ip6_full_reass,
};

#ifndef CLIB_MARCH_VARIANT
vnet_api_error_t
ip6_full_reass_enable_disable (u32 sw_if_index, u8 enable_disable)
{
  return vnet_feature_enable_disable ("ip6-unicast",
				      "ip6-full-reassembly-feature",
				      sw_if_index, enable_disable, 0, 0);
}
#endif /* CLIB_MARCH_VARIANT */

#define foreach_ip6_full_reassembly_handoff_error                       \
_(CONGESTION_DROP, "congestion drop")


typedef enum
{
#define _(sym,str) IP6_FULL_REASSEMBLY_HANDOFF_ERROR_##sym,
  foreach_ip6_full_reassembly_handoff_error
#undef _
    IP6_FULL_REASSEMBLY_HANDOFF_N_ERROR,
} ip6_full_reassembly_handoff_error_t;

static char *ip6_full_reassembly_handoff_error_strings[] = {
#define _(sym,string) string,
  foreach_ip6_full_reassembly_handoff_error
#undef _
};

typedef struct
{
  u32 next_worker_index;
} ip6_full_reassembly_handoff_trace_t;

static u8 *
format_ip6_full_reassembly_handoff_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_full_reassembly_handoff_trace_t *t =
    va_arg (*args, ip6_full_reassembly_handoff_trace_t *);

  s =
    format (s, "ip6-full-reassembly-handoff: next-worker %d",
	    t->next_worker_index);

  return s;
}

always_inline uword
ip6_full_reassembly_handoff_inline (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame, bool is_feature)
{
  ip6_full_reass_main_t *rm = &ip6_full_reass_main;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 n_enq, n_left_from, *from;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti;
  u32 fq_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  b = bufs;
  ti = thread_indices;

  fq_index = (is_feature) ? rm->fq_feature_index : rm->fq_index;

  while (n_left_from > 0)
    {
      ti[0] = vnet_buffer (b[0])->ip.reass.owner_thread_index;

      if (PREDICT_FALSE
	  ((node->flags & VLIB_NODE_FLAG_TRACE)
	   && (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  ip6_full_reassembly_handoff_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->next_worker_index = ti[0];
	}

      n_left_from -= 1;
      ti += 1;
      b += 1;
    }
  n_enq = vlib_buffer_enqueue_to_thread (vm, node, fq_index, from,
					 thread_indices, frame->n_vectors, 1);

  if (n_enq < frame->n_vectors)
    vlib_node_increment_counter (vm, node->node_index,
				 IP6_FULL_REASSEMBLY_HANDOFF_ERROR_CONGESTION_DROP,
				 frame->n_vectors - n_enq);
  return frame->n_vectors;
}

VLIB_NODE_FN (ip6_full_reassembly_handoff_node) (vlib_main_t * vm,
						 vlib_node_runtime_t * node,
						 vlib_frame_t * frame)
{
  return ip6_full_reassembly_handoff_inline (vm, node, frame,
					     false /* is_feature */ );
}

VLIB_REGISTER_NODE (ip6_full_reassembly_handoff_node) = {
  .name = "ip6-full-reassembly-handoff",
  .vector_size = sizeof (u32),
  .n_errors = ARRAY_LEN(ip6_full_reassembly_handoff_error_strings),
  .error_strings = ip6_full_reassembly_handoff_error_strings,
  .format_trace = format_ip6_full_reassembly_handoff_trace,

  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "error-drop",
  },
};


VLIB_NODE_FN (ip6_full_reassembly_feature_handoff_node) (vlib_main_t * vm,
                               vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return ip6_full_reassembly_handoff_inline (vm, node, frame, true /* is_feature */ );
}


VLIB_REGISTER_NODE (ip6_full_reassembly_feature_handoff_node) = {
  .name = "ip6-full-reass-feature-hoff",
  .vector_size = sizeof (u32),
  .n_errors = ARRAY_LEN(ip6_full_reassembly_handoff_error_strings),
  .error_strings = ip6_full_reassembly_handoff_error_strings,
  .format_trace = format_ip6_full_reassembly_handoff_trace,

  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "error-drop",
  },
};

#ifndef CLIB_MARCH_VARIANT
int
ip6_full_reass_enable_disable_with_refcnt (u32 sw_if_index, int is_enable)
{
  ip6_full_reass_main_t *rm = &ip6_full_reass_main;
  vec_validate (rm->feature_use_refcount_per_intf, sw_if_index);
  if (is_enable)
    {
      if (!rm->feature_use_refcount_per_intf[sw_if_index])
	{
	  ++rm->feature_use_refcount_per_intf[sw_if_index];
	  return vnet_feature_enable_disable ("ip6-unicast",
					      "ip6-full-reassembly-feature",
					      sw_if_index, 1, 0, 0);
	}
      ++rm->feature_use_refcount_per_intf[sw_if_index];
    }
  else
    {
      --rm->feature_use_refcount_per_intf[sw_if_index];
      if (!rm->feature_use_refcount_per_intf[sw_if_index])
	return vnet_feature_enable_disable ("ip6-unicast",
					    "ip6-full-reassembly-feature",
					    sw_if_index, 0, 0, 0);
    }
  return -1;
}
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
