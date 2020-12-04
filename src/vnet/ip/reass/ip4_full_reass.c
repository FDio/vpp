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
 * @brief IPv4 Full Reassembly.
 *
 * This file contains the source code for IPv4 full reassembly.
 */

#include <vppinfra/vec.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vppinfra/fifo.h>
#include <vppinfra/bihash_16_8.h>
#include <vnet/ip/reass/ip4_full_reass.h>
#include <stddef.h>

#define MSEC_PER_SEC 1000
#define IP4_REASS_TIMEOUT_DEFAULT_MS 100
#define IP4_REASS_EXPIRE_WALK_INTERVAL_DEFAULT_MS 10000	// 10 seconds default
#define IP4_REASS_MAX_REASSEMBLIES_DEFAULT 1024
#define IP4_REASS_MAX_REASSEMBLY_LENGTH_DEFAULT 3
#define IP4_REASS_HT_LOAD_FACTOR (0.75)

#define IP4_REASS_DEBUG_BUFFERS 0
#if IP4_REASS_DEBUG_BUFFERS
#define IP4_REASS_DEBUG_BUFFER(bi, what)             \
  do                                                 \
    {                                                \
      u32 _bi = bi;                                  \
      printf (#what "buffer %u", _bi);               \
      vlib_buffer_t *_b = vlib_get_buffer (vm, _bi); \
      while (_b->flags & VLIB_BUFFER_NEXT_PRESENT)   \
        {                                            \
          _bi = _b->next_buffer;                     \
          printf ("[%u]", _bi);                      \
          _b = vlib_get_buffer (vm, _bi);            \
        }                                            \
      printf ("\n");                                 \
      fflush (stdout);                               \
    }                                                \
  while (0)
#else
#define IP4_REASS_DEBUG_BUFFER(...)
#endif

typedef enum
{
  IP4_REASS_RC_OK,
  IP4_REASS_RC_TOO_MANY_FRAGMENTS,
  IP4_REASS_RC_INTERNAL_ERROR,
  IP4_REASS_RC_NO_BUF,
  IP4_REASS_RC_HANDOFF,
} ip4_full_reass_rc_t;

typedef struct
{
  union
  {
    struct
    {
      u32 xx_id;
      ip4_address_t src;
      ip4_address_t dst;
      u16 frag_id;
      u8 proto;
      u8 unused;
    };
    u64 as_u64[2];
  };
} ip4_full_reass_key_t;

typedef union
{
  struct
  {
    u32 reass_index;
    u32 memory_owner_thread_index;
  };
  u64 as_u64;
} ip4_full_reass_val_t;

typedef union
{
  struct
  {
    ip4_full_reass_key_t k;
    ip4_full_reass_val_t v;
  };
  clib_bihash_kv_16_8_t kv;
} ip4_full_reass_kv_t;

always_inline u32
ip4_full_reass_buffer_get_data_offset (vlib_buffer_t * b)
{
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  return vnb->ip.reass.range_first - vnb->ip.reass.fragment_first;
}

always_inline u16
ip4_full_reass_buffer_get_data_len (vlib_buffer_t * b)
{
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  return clib_min (vnb->ip.reass.range_last, vnb->ip.reass.fragment_last) -
    (vnb->ip.reass.fragment_first +
     ip4_full_reass_buffer_get_data_offset (b)) + 1;
}

typedef struct
{
  // hash table key
  ip4_full_reass_key_t key;
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
  // next index - used by non-feature node
  u32 next_index;
  // error next index - used by custom apps (~0 if not used)
  u32 error_next_index;
  // minimum fragment length for this reassembly - used to estimate MTU
  u16 min_fragment_length;
  // number of fragments in this reassembly
  u32 fragments_n;
  // thread owning memory for this context (whose pool contains this ctx)
  u32 memory_owner_thread_index;
  // thread which received fragment with offset 0 and which sends out the
  // completed reassembly
  u32 sendout_thread_index;
} ip4_full_reass_t;

typedef struct
{
  ip4_full_reass_t *pool;
  u32 reass_n;
  u32 id_counter;
  clib_spinlock_t lock;
} ip4_full_reass_per_thread_t;

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
  ip4_full_reass_per_thread_t *per_thread_data;

  // convenience
  vlib_main_t *vlib_main;

  // node index of ip4-drop node
  u32 ip4_drop_idx;
  u32 ip4_full_reass_expire_node_idx;

  /** Worker handoff */
  u32 fq_index;
  u32 fq_feature_index;
  u32 fq_custom_index;

  // reference count for enabling/disabling feature - per interface
  u32 *feature_use_refcount_per_intf;
} ip4_full_reass_main_t;

extern ip4_full_reass_main_t ip4_full_reass_main;

#ifndef CLIB_MARCH_VARIANT
ip4_full_reass_main_t ip4_full_reass_main;
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  IP4_FULL_REASS_NEXT_INPUT,
  IP4_FULL_REASS_NEXT_DROP,
  IP4_FULL_REASS_NEXT_HANDOFF,
  IP4_FULL_REASS_N_NEXT,
} ip4_full_reass_next_t;

typedef enum
{
  NORMAL,
  FEATURE,
  CUSTOM
} ip4_full_reass_node_type_t;

typedef enum
{
  RANGE_NEW,
  RANGE_SHRINK,
  RANGE_DISCARD,
  RANGE_OVERLAP,
  FINALIZE,
  HANDOFF,
} ip4_full_reass_trace_operation_e;

typedef struct
{
  u16 range_first;
  u16 range_last;
  u32 range_bi;
  i32 data_offset;
  u32 data_len;
  u32 first_bi;
} ip4_full_reass_range_trace_t;

typedef struct
{
  ip4_full_reass_trace_operation_e action;
  u32 reass_id;
  ip4_full_reass_range_trace_t trace_range;
  u32 size_diff;
  u32 op_id;
  u32 thread_id;
  u32 thread_id_to;
  u32 fragment_first;
  u32 fragment_last;
  u32 total_data_len;
  bool is_after_handoff;
  ip4_header_t ip4_header;
} ip4_full_reass_trace_t;

extern vlib_node_registration_t ip4_full_reass_node;
extern vlib_node_registration_t ip4_full_reass_node_feature;
extern vlib_node_registration_t ip4_full_reass_node_custom;

static void
ip4_full_reass_trace_details (vlib_main_t * vm, u32 bi,
			      ip4_full_reass_range_trace_t * trace)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  trace->range_first = vnb->ip.reass.range_first;
  trace->range_last = vnb->ip.reass.range_last;
  trace->data_offset = ip4_full_reass_buffer_get_data_offset (b);
  trace->data_len = ip4_full_reass_buffer_get_data_len (b);
  trace->range_bi = bi;
}

static u8 *
format_ip4_full_reass_range_trace (u8 * s, va_list * args)
{
  ip4_full_reass_range_trace_t *trace =
    va_arg (*args, ip4_full_reass_range_trace_t *);
  s =
    format (s, "range: [%u, %u], off %d, len %u, bi %u", trace->range_first,
	    trace->range_last, trace->data_offset, trace->data_len,
	    trace->range_bi);
  return s;
}

static u8 *
format_ip4_full_reass_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip4_full_reass_trace_t *t = va_arg (*args, ip4_full_reass_trace_t *);
  u32 indent = 0;
  if (~0 != t->reass_id)
    {
      if (t->is_after_handoff)
	{
	  s =
	    format (s, "%U\n", format_ip4_header, &t->ip4_header,
		    sizeof (t->ip4_header));
	  indent = 2;
	}
      s =
	format (s, "%Ureass id: %u, op id: %u, ", format_white_space, indent,
		t->reass_id, t->op_id);
      indent = format_get_indent (s);
      s =
	format (s,
		"first bi: %u, data len: %u, ip/fragment[%u, %u]",
		t->trace_range.first_bi, t->total_data_len, t->fragment_first,
		t->fragment_last);
    }
  switch (t->action)
    {
    case RANGE_SHRINK:
      s = format (s, "\n%Ushrink %U by %u", format_white_space, indent,
		  format_ip4_full_reass_range_trace, &t->trace_range,
		  t->size_diff);
      break;
    case RANGE_DISCARD:
      s = format (s, "\n%Udiscard %U", format_white_space, indent,
		  format_ip4_full_reass_range_trace, &t->trace_range);
      break;
    case RANGE_NEW:
      s = format (s, "\n%Unew %U", format_white_space, indent,
		  format_ip4_full_reass_range_trace, &t->trace_range);
      break;
    case RANGE_OVERLAP:
      s = format (s, "\n%Uoverlapping/ignored %U", format_white_space, indent,
		  format_ip4_full_reass_range_trace, &t->trace_range);
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
ip4_full_reass_add_trace (vlib_main_t * vm, vlib_node_runtime_t * node,
			  ip4_full_reass_main_t * rm,
			  ip4_full_reass_t * reass, u32 bi,
			  ip4_full_reass_trace_operation_e action,
			  u32 size_diff, u32 thread_id_to)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  bool is_after_handoff = false;
  if (vlib_buffer_get_trace_thread (b) != vm->thread_index)
    {
      is_after_handoff = true;
    }
  ip4_full_reass_trace_t *t = vlib_add_trace (vm, node, b, sizeof (t[0]));
  t->is_after_handoff = is_after_handoff;
  if (t->is_after_handoff)
    {
      clib_memcpy (&t->ip4_header, vlib_buffer_get_current (b),
		   clib_min (sizeof (t->ip4_header), b->current_length));
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
      t->op_id = 0;
      t->trace_range.first_bi = 0;
      t->total_data_len = 0;
    }
  t->action = action;
  ip4_full_reass_trace_details (vm, bi, &t->trace_range);
  t->size_diff = size_diff;
  t->thread_id = vm->thread_index;
  t->thread_id_to = thread_id_to;
  t->fragment_first = vnb->ip.reass.fragment_first;
  t->fragment_last = vnb->ip.reass.fragment_last;
#if 0
  static u8 *s = NULL;
  s = format (s, "%U", format_ip4_full_reass_trace, NULL, NULL, t);
  printf ("%.*s\n", vec_len (s), s);
  fflush (stdout);
  vec_reset_length (s);
#endif
}

always_inline void
ip4_full_reass_free_ctx (ip4_full_reass_per_thread_t * rt,
			 ip4_full_reass_t * reass)
{
  pool_put (rt->pool, reass);
  --rt->reass_n;
}

always_inline void
ip4_full_reass_free (ip4_full_reass_main_t * rm,
		     ip4_full_reass_per_thread_t * rt,
		     ip4_full_reass_t * reass)
{
  clib_bihash_kv_16_8_t kv;
  kv.key[0] = reass->key.as_u64[0];
  kv.key[1] = reass->key.as_u64[1];
  clib_bihash_add_del_16_8 (&rm->hash, &kv, 0);
  return ip4_full_reass_free_ctx (rt, reass);
}

always_inline void
ip4_full_reass_drop_all (vlib_main_t * vm, vlib_node_runtime_t * node,
			 ip4_full_reass_main_t * rm, ip4_full_reass_t * reass)
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
ip4_full_reass_init (ip4_full_reass_t * reass)
{
  reass->first_bi = ~0;
  reass->last_packet_octet = ~0;
  reass->data_len = 0;
  reass->next_index = ~0;
  reass->error_next_index = ~0;
}

always_inline ip4_full_reass_t *
ip4_full_reass_find_or_create (vlib_main_t * vm, vlib_node_runtime_t * node,
			       ip4_full_reass_main_t * rm,
			       ip4_full_reass_per_thread_t * rt,
			       ip4_full_reass_kv_t * kv, u8 * do_handoff)
{
  ip4_full_reass_t *reass;
  f64 now;

again:

  reass = NULL;
  now = vlib_time_now (vm);
  if (!clib_bihash_search_16_8 (&rm->hash, &kv->kv, &kv->kv))
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
	  ip4_full_reass_drop_all (vm, node, rm, reass);
	  ip4_full_reass_free (rm, rt, reass);
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
      reass->memory_owner_thread_index = vm->thread_index;
      ++rt->id_counter;
      ip4_full_reass_init (reass);
      ++rt->reass_n;
    }

  reass->key.as_u64[0] = kv->kv.key[0];
  reass->key.as_u64[1] = kv->kv.key[1];
  kv->v.reass_index = (reass - rt->pool);
  kv->v.memory_owner_thread_index = vm->thread_index;
  reass->last_heard = now;

  int rv = clib_bihash_add_del_16_8 (&rm->hash, &kv->kv, 2);
  if (rv)
    {
      ip4_full_reass_free_ctx (rt, reass);
      reass = NULL;
      // if other worker created a context already work with the other copy
      if (-2 == rv)
	goto again;
    }

  return reass;
}

always_inline ip4_full_reass_rc_t
ip4_full_reass_finalize (vlib_main_t * vm, vlib_node_runtime_t * node,
			 ip4_full_reass_main_t * rm,
			 ip4_full_reass_per_thread_t * rt,
			 ip4_full_reass_t * reass, u32 * bi0,
			 u32 * next0, u32 * error0, bool is_custom)
{
  vlib_buffer_t *first_b = vlib_get_buffer (vm, reass->first_bi);
  vlib_buffer_t *last_b = NULL;
  u32 sub_chain_bi = reass->first_bi;
  u32 total_length = 0;
  u32 buf_cnt = 0;
  do
    {
      u32 tmp_bi = sub_chain_bi;
      vlib_buffer_t *tmp = vlib_get_buffer (vm, tmp_bi);
      ip4_header_t *ip = vlib_buffer_get_current (tmp);
      vnet_buffer_opaque_t *vnb = vnet_buffer (tmp);
      if (!(vnb->ip.reass.range_first >= vnb->ip.reass.fragment_first) &&
	  !(vnb->ip.reass.range_last > vnb->ip.reass.fragment_first))
	{
	  return IP4_REASS_RC_INTERNAL_ERROR;
	}

      u32 data_len = ip4_full_reass_buffer_get_data_len (tmp);
      u32 trim_front =
	ip4_header_bytes (ip) + ip4_full_reass_buffer_get_data_offset (tmp);
      u32 trim_end =
	vlib_buffer_length_in_chain (vm, tmp) - trim_front - data_len;
      if (tmp_bi == reass->first_bi)
	{
	  /* first buffer - keep ip4 header */
	  if (0 != ip4_full_reass_buffer_get_data_offset (tmp))
	    {
	      return IP4_REASS_RC_INTERNAL_ERROR;
	    }
	  trim_front = 0;
	  trim_end = vlib_buffer_length_in_chain (vm, tmp) - data_len -
	    ip4_header_bytes (ip);
	  if (!(vlib_buffer_length_in_chain (vm, tmp) - trim_end > 0))
	    {
	      return IP4_REASS_RC_INTERNAL_ERROR;
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
		  u32 to_be_freed_bi = tmp_bi;
		  trim_front -= tmp->current_length;
		  if (!(tmp->flags & VLIB_BUFFER_NEXT_PRESENT))
		    {
		      return IP4_REASS_RC_INTERNAL_ERROR;
		    }
		  tmp->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
		  tmp_bi = tmp->next_buffer;
		  tmp->next_buffer = 0;
		  tmp = vlib_get_buffer (vm, tmp_bi);
		  vlib_buffer_free_one (vm, to_be_freed_bi);
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
		      return IP4_REASS_RC_INTERNAL_ERROR;
		    }
		}
	      total_length += tmp->current_length;
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
	  else
	    {
	      u32 to_be_freed_bi = tmp_bi;
	      if (reass->first_bi == tmp_bi)
		{
		  return IP4_REASS_RC_INTERNAL_ERROR;
		}
	      if (tmp->flags & VLIB_BUFFER_NEXT_PRESENT)
		{
		  tmp->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
		  tmp_bi = tmp->next_buffer;
		  tmp->next_buffer = 0;
		  tmp = vlib_get_buffer (vm, tmp_bi);
		  vlib_buffer_free_one (vm, to_be_freed_bi);
		}
	      else
		{
		  tmp->next_buffer = 0;
		  vlib_buffer_free_one (vm, to_be_freed_bi);
		  break;
		}
	    }
	}
      sub_chain_bi =
	vnet_buffer (vlib_get_buffer (vm, sub_chain_bi))->ip.
	reass.next_range_bi;
    }
  while (~0 != sub_chain_bi);

  if (!last_b)
    {
      return IP4_REASS_RC_INTERNAL_ERROR;
    }
  last_b->flags &= ~VLIB_BUFFER_NEXT_PRESENT;

  if (total_length < first_b->current_length)
    {
      return IP4_REASS_RC_INTERNAL_ERROR;
    }
  total_length -= first_b->current_length;
  first_b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  first_b->total_length_not_including_first_buffer = total_length;
  ip4_header_t *ip = vlib_buffer_get_current (first_b);
  ip->flags_and_fragment_offset = 0;
  ip->length = clib_host_to_net_u16 (first_b->current_length + total_length);
  ip->checksum = ip4_header_checksum (ip);
  if (!vlib_buffer_chain_linearize (vm, first_b))
    {
      return IP4_REASS_RC_NO_BUF;
    }
  // reset to reconstruct the mbuf linking
  first_b->flags &= ~VLIB_BUFFER_EXT_HDR_VALID;
  if (PREDICT_FALSE (first_b->flags & VLIB_BUFFER_IS_TRACED))
    {
      ip4_full_reass_add_trace (vm, node, rm, reass, reass->first_bi,
				FINALIZE, 0, ~0);
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
  *bi0 = reass->first_bi;
  if (!is_custom)
    {
      *next0 = IP4_FULL_REASS_NEXT_INPUT;
    }
  else
    {
      *next0 = reass->next_index;
    }
  vnet_buffer (first_b)->ip.reass.estimated_mtu = reass->min_fragment_length;
  *error0 = IP4_ERROR_NONE;
  ip4_full_reass_free (rm, rt, reass);
  reass = NULL;
  return IP4_REASS_RC_OK;
}

always_inline ip4_full_reass_rc_t
ip4_full_reass_insert_range_in_chain (vlib_main_t * vm,
				      ip4_full_reass_main_t * rm,
				      ip4_full_reass_per_thread_t * rt,
				      ip4_full_reass_t * reass,
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
  vnet_buffer_opaque_t *vnb = vnet_buffer (new_next_b);
  if (!(vnb->ip.reass.range_first >= vnb->ip.reass.fragment_first) &&
      !(vnb->ip.reass.range_last > vnb->ip.reass.fragment_first))
    {
      return IP4_REASS_RC_INTERNAL_ERROR;
    }
  reass->data_len += ip4_full_reass_buffer_get_data_len (new_next_b);
  return IP4_REASS_RC_OK;
}

always_inline ip4_full_reass_rc_t
ip4_full_reass_remove_range_from_chain (vlib_main_t * vm,
					vlib_node_runtime_t * node,
					ip4_full_reass_main_t * rm,
					ip4_full_reass_t * reass,
					u32 prev_range_bi, u32 discard_bi)
{
  vlib_buffer_t *discard_b = vlib_get_buffer (vm, discard_bi);
  vnet_buffer_opaque_t *discard_vnb = vnet_buffer (discard_b);
  if (~0 != prev_range_bi)
    {
      vlib_buffer_t *prev_b = vlib_get_buffer (vm, prev_range_bi);
      vnet_buffer_opaque_t *prev_vnb = vnet_buffer (prev_b);
      if (!(prev_vnb->ip.reass.next_range_bi == discard_bi))
	{
	  return IP4_REASS_RC_INTERNAL_ERROR;
	}
      prev_vnb->ip.reass.next_range_bi = discard_vnb->ip.reass.next_range_bi;
    }
  else
    {
      reass->first_bi = discard_vnb->ip.reass.next_range_bi;
    }
  vnet_buffer_opaque_t *vnb = vnet_buffer (discard_b);
  if (!(vnb->ip.reass.range_first >= vnb->ip.reass.fragment_first) &&
      !(vnb->ip.reass.range_last > vnb->ip.reass.fragment_first))
    {
      return IP4_REASS_RC_INTERNAL_ERROR;
    }
  reass->data_len -= ip4_full_reass_buffer_get_data_len (discard_b);
  while (1)
    {
      u32 to_be_freed_bi = discard_bi;
      if (PREDICT_FALSE (discard_b->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ip4_full_reass_add_trace (vm, node, rm, reass, discard_bi,
				    RANGE_DISCARD, 0, ~0);
	}
      if (discard_b->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  discard_b->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
	  discard_bi = discard_b->next_buffer;
	  discard_b->next_buffer = 0;
	  discard_b = vlib_get_buffer (vm, discard_bi);
	  vlib_buffer_free_one (vm, to_be_freed_bi);
	}
      else
	{
	  discard_b->next_buffer = 0;
	  vlib_buffer_free_one (vm, to_be_freed_bi);
	  break;
	}
    }
  return IP4_REASS_RC_OK;
}

always_inline ip4_full_reass_rc_t
ip4_full_reass_update (vlib_main_t * vm, vlib_node_runtime_t * node,
		       ip4_full_reass_main_t * rm,
		       ip4_full_reass_per_thread_t * rt,
		       ip4_full_reass_t * reass, u32 * bi0, u32 * next0,
		       u32 * error0, bool is_custom, u32 * handoff_thread_idx)
{
  vlib_buffer_t *fb = vlib_get_buffer (vm, *bi0);
  vnet_buffer_opaque_t *fvnb = vnet_buffer (fb);
  if (is_custom)
    {
      // store (error_)next_index before it's overwritten
      reass->next_index = fvnb->ip.reass.next_index;
      reass->error_next_index = fvnb->ip.reass.error_next_index;
    }
  ip4_full_reass_rc_t rc = IP4_REASS_RC_OK;
  int consumed = 0;
  ip4_header_t *fip = vlib_buffer_get_current (fb);
  const u32 fragment_first = ip4_get_fragment_offset_bytes (fip);
  const u32 fragment_length =
    clib_net_to_host_u16 (fip->length) - ip4_header_bytes (fip);
  const u32 fragment_last = fragment_first + fragment_length - 1;
  fvnb->ip.reass.fragment_first = fragment_first;
  fvnb->ip.reass.fragment_last = fragment_last;
  int more_fragments = ip4_get_fragment_more (fip);
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
      rc =
	ip4_full_reass_insert_range_in_chain (vm, rm, rt, reass,
					      prev_range_bi, *bi0);
      if (IP4_REASS_RC_OK != rc)
	{
	  return rc;
	}
      if (PREDICT_FALSE (fb->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ip4_full_reass_add_trace (vm, node, rm, reass, *bi0, RANGE_NEW, 0,
				    ~0);
	}
      *bi0 = ~0;
      reass->min_fragment_length = clib_net_to_host_u16 (fip->length);
      reass->fragments_n = 1;
      return IP4_REASS_RC_OK;
    }
  reass->min_fragment_length =
    clib_min (clib_net_to_host_u16 (fip->length),
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
	      rc =
		ip4_full_reass_insert_range_in_chain (vm, rm, rt, reass,
						      prev_range_bi, *bi0);
	      if (IP4_REASS_RC_OK != rc)
		{
		  return rc;
		}
	      consumed = 1;
	      break;
	    }
	  continue;
	}
      if (fragment_last < candidate_vnb->ip.reass.range_first)
	{
	  // this fragment ends before candidate range without any overlap
	  rc =
	    ip4_full_reass_insert_range_in_chain (vm, rm, rt, reass,
						  prev_range_bi, *bi0);
	  if (IP4_REASS_RC_OK != rc)
	    {
	      return rc;
	    }
	  consumed = 1;
	}
      else
	{
	  if (fragment_first >= candidate_vnb->ip.reass.range_first &&
	      fragment_last <= candidate_vnb->ip.reass.range_last)
	    {
	      // this fragment is a (sub)part of existing range, ignore it
	      if (PREDICT_FALSE (fb->flags & VLIB_BUFFER_IS_TRACED))
		{
		  ip4_full_reass_add_trace (vm, node, rm, reass, *bi0,
					    RANGE_OVERLAP, 0, ~0);
		}
	      break;
	    }
	  int discard_candidate = 0;
	  if (fragment_first < candidate_vnb->ip.reass.range_first)
	    {
	      u32 overlap =
		fragment_last - candidate_vnb->ip.reass.range_first + 1;
	      if (overlap < ip4_full_reass_buffer_get_data_len (candidate_b))
		{
		  candidate_vnb->ip.reass.range_first += overlap;
		  if (reass->data_len < overlap)
		    {
		      return IP4_REASS_RC_INTERNAL_ERROR;
		    }
		  reass->data_len -= overlap;
		  if (PREDICT_FALSE (fb->flags & VLIB_BUFFER_IS_TRACED))
		    {
		      ip4_full_reass_add_trace (vm, node, rm, reass,
						candidate_range_bi,
						RANGE_SHRINK, 0, ~0);
		    }
		  rc =
		    ip4_full_reass_insert_range_in_chain (vm, rm, rt, reass,
							  prev_range_bi,
							  *bi0);
		  if (IP4_REASS_RC_OK != rc)
		    {
		      return rc;
		    }
		  consumed = 1;
		}
	      else
		{
		  discard_candidate = 1;
		}
	    }
	  else if (fragment_last > candidate_vnb->ip.reass.range_last)
	    {
	      u32 overlap =
		candidate_vnb->ip.reass.range_last - fragment_first + 1;
	      if (overlap < ip4_full_reass_buffer_get_data_len (candidate_b))
		{
		  fvnb->ip.reass.range_first += overlap;
		  if (~0 != candidate_vnb->ip.reass.next_range_bi)
		    {
		      prev_range_bi = candidate_range_bi;
		      candidate_range_bi =
			candidate_vnb->ip.reass.next_range_bi;
		      continue;
		    }
		  else
		    {
		      // special case - last range discarded
		      rc =
			ip4_full_reass_insert_range_in_chain (vm, rm, rt,
							      reass,
							      candidate_range_bi,
							      *bi0);
		      if (IP4_REASS_RC_OK != rc)
			{
			  return rc;
			}
		      consumed = 1;
		    }
		}
	      else
		{
		  discard_candidate = 1;
		}
	    }
	  else
	    {
	      discard_candidate = 1;
	    }
	  if (discard_candidate)
	    {
	      u32 next_range_bi = candidate_vnb->ip.reass.next_range_bi;
	      // discard candidate range, probe next range
	      rc =
		ip4_full_reass_remove_range_from_chain (vm, node, rm, reass,
							prev_range_bi,
							candidate_range_bi);
	      if (IP4_REASS_RC_OK != rc)
		{
		  return rc;
		}
	      if (~0 != next_range_bi)
		{
		  candidate_range_bi = next_range_bi;
		  continue;
		}
	      else
		{
		  // special case - last range discarded
		  rc =
		    ip4_full_reass_insert_range_in_chain (vm, rm, rt, reass,
							  prev_range_bi,
							  *bi0);
		  if (IP4_REASS_RC_OK != rc)
		    {
		      return rc;
		    }
		  consumed = 1;
		}
	    }
	}
      break;
    }
  ++reass->fragments_n;
  if (consumed)
    {
      if (PREDICT_FALSE (fb->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ip4_full_reass_add_trace (vm, node, rm, reass, *bi0, RANGE_NEW, 0,
				    ~0);
	}
    }
  if (~0 != reass->last_packet_octet &&
      reass->data_len == reass->last_packet_octet + 1)
    {
      *handoff_thread_idx = reass->sendout_thread_index;
      int handoff =
	reass->memory_owner_thread_index != reass->sendout_thread_index;
      rc =
	ip4_full_reass_finalize (vm, node, rm, rt, reass, bi0, next0, error0,
				 is_custom);
      if (IP4_REASS_RC_OK == rc && handoff)
	{
	  rc = IP4_REASS_RC_HANDOFF;
	}
    }
  else
    {
      if (consumed)
	{
	  *bi0 = ~0;
	  if (reass->fragments_n > rm->max_reass_len)
	    {
	      rc = IP4_REASS_RC_TOO_MANY_FRAGMENTS;
	    }
	}
      else
	{
	  *next0 = IP4_FULL_REASS_NEXT_DROP;
	  *error0 = IP4_ERROR_REASS_DUPLICATE_FRAGMENT;
	}
    }
  return rc;
}

always_inline uword
ip4_full_reass_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		       vlib_frame_t * frame, ip4_full_reass_node_type_t type)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from, n_left_to_next, *to_next, next_index;
  ip4_full_reass_main_t *rm = &ip4_full_reass_main;
  ip4_full_reass_per_thread_t *rt = &rm->per_thread_data[vm->thread_index];
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
	  u32 next0;
	  u32 error0 = IP4_ERROR_NONE;

	  bi0 = from[0];
	  b0 = vlib_get_buffer (vm, bi0);

	  ip4_header_t *ip0 = vlib_buffer_get_current (b0);
	  if (!ip4_get_fragment_more (ip0) && !ip4_get_fragment_offset (ip0))
	    {
	      // this is a whole packet - no fragmentation
	      if (CUSTOM != type)
		{
		  next0 = IP4_FULL_REASS_NEXT_INPUT;
		}
	      else
		{
		  next0 = vnet_buffer (b0)->ip.reass.next_index;
		}
	      goto packet_enqueue;
	    }
	  const u32 fragment_first = ip4_get_fragment_offset_bytes (ip0);
	  const u32 fragment_length =
	    clib_net_to_host_u16 (ip0->length) - ip4_header_bytes (ip0);
	  const u32 fragment_last = fragment_first + fragment_length - 1;
	  if (fragment_first > fragment_last || fragment_first + fragment_length > UINT16_MAX - 20 || (fragment_length < 8 && ip4_get_fragment_more (ip0)))	// 8 is minimum frag length per RFC 791
	    {
	      next0 = IP4_FULL_REASS_NEXT_DROP;
	      error0 = IP4_ERROR_REASS_MALFORMED_PACKET;
	      goto packet_enqueue;
	    }
	  ip4_full_reass_kv_t kv;
	  u8 do_handoff = 0;

	  kv.k.as_u64[0] =
	    (u64) vec_elt (ip4_main.fib_index_by_sw_if_index,
			   vnet_buffer (b0)->sw_if_index[VLIB_RX]) |
	    (u64) ip0->src_address.as_u32 << 32;
	  kv.k.as_u64[1] =
	    (u64) ip0->dst_address.
	    as_u32 | (u64) ip0->fragment_id << 32 | (u64) ip0->protocol << 48;

	  ip4_full_reass_t *reass =
	    ip4_full_reass_find_or_create (vm, node, rm, rt, &kv,
					   &do_handoff);

	  if (reass)
	    {
	      const u32 fragment_first = ip4_get_fragment_offset_bytes (ip0);
	      if (0 == fragment_first)
		{
		  reass->sendout_thread_index = vm->thread_index;
		}
	    }

	  if (PREDICT_FALSE (do_handoff))
	    {
	      next0 = IP4_FULL_REASS_NEXT_HANDOFF;
	      vnet_buffer (b0)->ip.reass.owner_thread_index =
		kv.v.memory_owner_thread_index;
	    }
	  else if (reass)
	    {
	      u32 handoff_thread_idx;
	      switch (ip4_full_reass_update
		      (vm, node, rm, rt, reass, &bi0, &next0,
		       &error0, CUSTOM == type, &handoff_thread_idx))
		{
		case IP4_REASS_RC_OK:
		  /* nothing to do here */
		  break;
		case IP4_REASS_RC_HANDOFF:
		  next0 = IP4_FULL_REASS_NEXT_HANDOFF;
		  b0 = vlib_get_buffer (vm, bi0);
		  vnet_buffer (b0)->ip.reass.owner_thread_index =
		    handoff_thread_idx;
		  break;
		case IP4_REASS_RC_TOO_MANY_FRAGMENTS:
		  vlib_node_increment_counter (vm, node->node_index,
					       IP4_ERROR_REASS_FRAGMENT_CHAIN_TOO_LONG,
					       1);
		  ip4_full_reass_drop_all (vm, node, rm, reass);
		  ip4_full_reass_free (rm, rt, reass);
		  goto next_packet;
		  break;
		case IP4_REASS_RC_NO_BUF:
		  vlib_node_increment_counter (vm, node->node_index,
					       IP4_ERROR_REASS_NO_BUF, 1);
		  ip4_full_reass_drop_all (vm, node, rm, reass);
		  ip4_full_reass_free (rm, rt, reass);
		  goto next_packet;
		  break;
		case IP4_REASS_RC_INTERNAL_ERROR:
		  /* drop everything and start with a clean slate */
		  vlib_node_increment_counter (vm, node->node_index,
					       IP4_ERROR_REASS_INTERNAL_ERROR,
					       1);
		  ip4_full_reass_drop_all (vm, node, rm, reass);
		  ip4_full_reass_free (rm, rt, reass);
		  goto next_packet;
		  break;
		}
	    }
	  else
	    {
	      next0 = IP4_FULL_REASS_NEXT_DROP;
	      error0 = IP4_ERROR_REASS_LIMIT_REACHED;
	    }


	packet_enqueue:

	  if (bi0 != ~0)
	    {
	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;

	      /* bi0 might have been updated by reass_finalize, reload */
	      b0 = vlib_get_buffer (vm, bi0);
	      if (IP4_ERROR_NONE != error0)
		{
		  b0->error = node->errors[error0];
		}

	      if (next0 == IP4_FULL_REASS_NEXT_HANDOFF)
		{
		  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		    {
		      ip4_full_reass_add_trace (vm, node, rm, NULL, bi0,
						HANDOFF, 0,
						vnet_buffer (b0)->ip.
						reass.owner_thread_index);
		    }
		}
	      else if (FEATURE == type && IP4_ERROR_NONE == error0)
		{
		  vnet_feature_next (&next0, b0);
		}
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					       to_next, n_left_to_next,
					       bi0, next0);
	      IP4_REASS_DEBUG_BUFFER (bi0, enqueue_next);
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

static char *ip4_full_reass_error_strings[] = {
#define _(sym, string) string,
  foreach_ip4_error
#undef _
};

VLIB_NODE_FN (ip4_full_reass_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return ip4_full_reass_inline (vm, node, frame, NORMAL);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_full_reass_node) = {
    .name = "ip4-full-reassembly",
    .vector_size = sizeof (u32),
    .format_trace = format_ip4_full_reass_trace,
    .n_errors = ARRAY_LEN (ip4_full_reass_error_strings),
    .error_strings = ip4_full_reass_error_strings,
    .n_next_nodes = IP4_FULL_REASS_N_NEXT,
    .next_nodes =
        {
                [IP4_FULL_REASS_NEXT_INPUT] = "ip4-input",
                [IP4_FULL_REASS_NEXT_DROP] = "ip4-drop",
                [IP4_FULL_REASS_NEXT_HANDOFF] = "ip4-full-reassembly-handoff",

        },
};
/* *INDENT-ON* */

VLIB_NODE_FN (ip4_full_reass_node_feature) (vlib_main_t * vm,
					    vlib_node_runtime_t * node,
					    vlib_frame_t * frame)
{
  return ip4_full_reass_inline (vm, node, frame, FEATURE);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_full_reass_node_feature) = {
    .name = "ip4-full-reassembly-feature",
    .vector_size = sizeof (u32),
    .format_trace = format_ip4_full_reass_trace,
    .n_errors = ARRAY_LEN (ip4_full_reass_error_strings),
    .error_strings = ip4_full_reass_error_strings,
    .n_next_nodes = IP4_FULL_REASS_N_NEXT,
    .next_nodes =
        {
                [IP4_FULL_REASS_NEXT_INPUT] = "ip4-input",
                [IP4_FULL_REASS_NEXT_DROP] = "ip4-drop",
                [IP4_FULL_REASS_NEXT_HANDOFF] = "ip4-full-reass-feature-hoff",
        },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VNET_FEATURE_INIT (ip4_full_reass_feature, static) = {
    .arc_name = "ip4-unicast",
    .node_name = "ip4-full-reassembly-feature",
    .runs_before = VNET_FEATURES ("ip4-lookup",
                                  "ipsec4-input-feature"),
    .runs_after = 0,
};
/* *INDENT-ON* */

VLIB_NODE_FN (ip4_full_reass_node_custom) (vlib_main_t * vm,
					   vlib_node_runtime_t * node,
					   vlib_frame_t * frame)
{
  return ip4_full_reass_inline (vm, node, frame, CUSTOM);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_full_reass_node_custom) = {
    .name = "ip4-full-reassembly-custom",
    .vector_size = sizeof (u32),
    .format_trace = format_ip4_full_reass_trace,
    .n_errors = ARRAY_LEN (ip4_full_reass_error_strings),
    .error_strings = ip4_full_reass_error_strings,
    .n_next_nodes = IP4_FULL_REASS_N_NEXT,
    .next_nodes =
        {
                [IP4_FULL_REASS_NEXT_INPUT] = "ip4-input",
                [IP4_FULL_REASS_NEXT_DROP] = "ip4-drop",
                [IP4_FULL_REASS_NEXT_HANDOFF] = "ip4-full-reass-custom-hoff",
        },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VNET_FEATURE_INIT (ip4_full_reass_custom, static) = {
    .arc_name = "ip4-unicast",
    .node_name = "ip4-full-reassembly-feature",
    .runs_before = VNET_FEATURES ("ip4-lookup",
                                  "ipsec4-input-feature"),
    .runs_after = 0,
};

/* *INDENT-ON* */

#ifndef CLIB_MARCH_VARIANT
uword
ip4_full_reass_custom_register_next_node (uword node_index)
{
  return vlib_node_add_next (vlib_get_main (),
			     ip4_full_reass_node_custom.index, node_index);
}

always_inline u32
ip4_full_reass_get_nbuckets ()
{
  ip4_full_reass_main_t *rm = &ip4_full_reass_main;
  u32 nbuckets;
  u8 i;

  nbuckets = (u32) (rm->max_reass_n / IP4_REASS_HT_LOAD_FACTOR);

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
} ip4_full_reass_event_t;

typedef struct
{
  int failure;
  clib_bihash_16_8_t *new_hash;
} ip4_rehash_cb_ctx;

#ifndef CLIB_MARCH_VARIANT
static int
ip4_rehash_cb (clib_bihash_kv_16_8_t * kv, void *_ctx)
{
  ip4_rehash_cb_ctx *ctx = _ctx;
  if (clib_bihash_add_del_16_8 (ctx->new_hash, kv, 1))
    {
      ctx->failure = 1;
    }
  return (BIHASH_WALK_CONTINUE);
}

static void
ip4_full_reass_set_params (u32 timeout_ms, u32 max_reassemblies,
			   u32 max_reassembly_length,
			   u32 expire_walk_interval_ms)
{
  ip4_full_reass_main.timeout_ms = timeout_ms;
  ip4_full_reass_main.timeout = (f64) timeout_ms / (f64) MSEC_PER_SEC;
  ip4_full_reass_main.max_reass_n = max_reassemblies;
  ip4_full_reass_main.max_reass_len = max_reassembly_length;
  ip4_full_reass_main.expire_walk_interval_ms = expire_walk_interval_ms;
}

vnet_api_error_t
ip4_full_reass_set (u32 timeout_ms, u32 max_reassemblies,
		    u32 max_reassembly_length, u32 expire_walk_interval_ms)
{
  u32 old_nbuckets = ip4_full_reass_get_nbuckets ();
  ip4_full_reass_set_params (timeout_ms, max_reassemblies,
			     max_reassembly_length, expire_walk_interval_ms);
  vlib_process_signal_event (ip4_full_reass_main.vlib_main,
			     ip4_full_reass_main.ip4_full_reass_expire_node_idx,
			     IP4_EVENT_CONFIG_CHANGED, 0);
  u32 new_nbuckets = ip4_full_reass_get_nbuckets ();
  if (ip4_full_reass_main.max_reass_n > 0 && new_nbuckets > old_nbuckets)
    {
      clib_bihash_16_8_t new_hash;
      clib_memset (&new_hash, 0, sizeof (new_hash));
      ip4_rehash_cb_ctx ctx;
      ctx.failure = 0;
      ctx.new_hash = &new_hash;
      clib_bihash_init_16_8 (&new_hash, "ip4-dr", new_nbuckets,
			     new_nbuckets * 1024);
      clib_bihash_foreach_key_value_pair_16_8 (&ip4_full_reass_main.hash,
					       ip4_rehash_cb, &ctx);
      if (ctx.failure)
	{
	  clib_bihash_free_16_8 (&new_hash);
	  return -1;
	}
      else
	{
	  clib_bihash_free_16_8 (&ip4_full_reass_main.hash);
	  clib_memcpy_fast (&ip4_full_reass_main.hash, &new_hash,
			    sizeof (ip4_full_reass_main.hash));
	  clib_bihash_copied (&ip4_full_reass_main.hash, &new_hash);
	}
    }
  return 0;
}

vnet_api_error_t
ip4_full_reass_get (u32 * timeout_ms, u32 * max_reassemblies,
		    u32 * max_reassembly_length,
		    u32 * expire_walk_interval_ms)
{
  *timeout_ms = ip4_full_reass_main.timeout_ms;
  *max_reassemblies = ip4_full_reass_main.max_reass_n;
  *max_reassembly_length = ip4_full_reass_main.max_reass_len;
  *expire_walk_interval_ms = ip4_full_reass_main.expire_walk_interval_ms;
  return 0;
}

static clib_error_t *
ip4_full_reass_init_function (vlib_main_t * vm)
{
  ip4_full_reass_main_t *rm = &ip4_full_reass_main;
  clib_error_t *error = 0;
  u32 nbuckets;
  vlib_node_t *node;

  rm->vlib_main = vm;

  vec_validate (rm->per_thread_data, vlib_num_workers ());
  ip4_full_reass_per_thread_t *rt;
  vec_foreach (rt, rm->per_thread_data)
  {
    clib_spinlock_init (&rt->lock);
    pool_alloc (rt->pool, rm->max_reass_n);
  }

  node = vlib_get_node_by_name (vm, (u8 *) "ip4-full-reassembly-expire-walk");
  ASSERT (node);
  rm->ip4_full_reass_expire_node_idx = node->index;

  ip4_full_reass_set_params (IP4_REASS_TIMEOUT_DEFAULT_MS,
			     IP4_REASS_MAX_REASSEMBLIES_DEFAULT,
			     IP4_REASS_MAX_REASSEMBLY_LENGTH_DEFAULT,
			     IP4_REASS_EXPIRE_WALK_INTERVAL_DEFAULT_MS);

  nbuckets = ip4_full_reass_get_nbuckets ();
  clib_bihash_init_16_8 (&rm->hash, "ip4-dr", nbuckets, nbuckets * 1024);

  node = vlib_get_node_by_name (vm, (u8 *) "ip4-drop");
  ASSERT (node);
  rm->ip4_drop_idx = node->index;

  rm->fq_index = vlib_frame_queue_main_init (ip4_full_reass_node.index, 0);
  rm->fq_feature_index =
    vlib_frame_queue_main_init (ip4_full_reass_node_feature.index, 0);
  rm->fq_custom_index =
    vlib_frame_queue_main_init (ip4_full_reass_node_custom.index, 0);

  rm->feature_use_refcount_per_intf = NULL;
  return error;
}

VLIB_INIT_FUNCTION (ip4_full_reass_init_function);
#endif /* CLIB_MARCH_VARIANT */

static uword
ip4_full_reass_walk_expired (vlib_main_t * vm,
			     vlib_node_runtime_t * node, vlib_frame_t * f)
{
  ip4_full_reass_main_t *rm = &ip4_full_reass_main;
  uword event_type, *event_data = 0;

  while (true)
    {
      vlib_process_wait_for_event_or_clock (vm,
					    (f64)
					    rm->expire_walk_interval_ms /
					    (f64) MSEC_PER_SEC);
      event_type = vlib_process_get_events (vm, &event_data);

      switch (event_type)
	{
	case ~0:		/* no events => timeout */
	  /* nothing to do here */
	  break;
	case IP4_EVENT_CONFIG_CHANGED:
	  break;
	default:
	  clib_warning ("BUG: event type 0x%wx", event_type);
	  break;
	}
      f64 now = vlib_time_now (vm);

      ip4_full_reass_t *reass;
      int *pool_indexes_to_free = NULL;

      uword thread_index = 0;
      int index;
      const uword nthreads = vlib_num_workers () + 1;
      for (thread_index = 0; thread_index < nthreads; ++thread_index)
	{
	  ip4_full_reass_per_thread_t *rt =
	    &rm->per_thread_data[thread_index];
	  clib_spinlock_lock (&rt->lock);

	  vec_reset_length (pool_indexes_to_free);
          /* *INDENT-OFF* */
          pool_foreach_index (index, rt->pool, ({
                                reass = pool_elt_at_index (rt->pool, index);
                                if (now > reass->last_heard + rm->timeout)
                                  {
                                    vec_add1 (pool_indexes_to_free, index);
                                  }
                              }));
          /* *INDENT-ON* */
	  int *i;
          /* *INDENT-OFF* */
          vec_foreach (i, pool_indexes_to_free)
          {
            ip4_full_reass_t *reass = pool_elt_at_index (rt->pool, i[0]);
            ip4_full_reass_drop_all (vm, node, rm, reass);
            ip4_full_reass_free (rm, rt, reass);
          }
          /* *INDENT-ON* */

	  clib_spinlock_unlock (&rt->lock);
	}

      vec_free (pool_indexes_to_free);
      if (event_data)
	{
	  _vec_len (event_data) = 0;
	}
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_full_reass_expire_node) = {
    .function = ip4_full_reass_walk_expired,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "ip4-full-reassembly-expire-walk",
    .format_trace = format_ip4_full_reass_trace,
    .n_errors = ARRAY_LEN (ip4_full_reass_error_strings),
    .error_strings = ip4_full_reass_error_strings,

};
/* *INDENT-ON* */

static u8 *
format_ip4_full_reass_key (u8 * s, va_list * args)
{
  ip4_full_reass_key_t *key = va_arg (*args, ip4_full_reass_key_t *);
  s =
    format (s,
	    "xx_id: %u, src: %U, dst: %U, frag_id: %u, proto: %u",
	    key->xx_id, format_ip4_address, &key->src, format_ip4_address,
	    &key->dst, clib_net_to_host_u16 (key->frag_id), key->proto);
  return s;
}

static u8 *
format_ip4_reass (u8 * s, va_list * args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  ip4_full_reass_t *reass = va_arg (*args, ip4_full_reass_t *);

  s = format (s, "ID: %lu, key: %U\n  first_bi: %u, data_len: %u, "
	      "last_packet_octet: %u, trace_op_counter: %u\n",
	      reass->id, format_ip4_full_reass_key, &reass->key,
	      reass->first_bi, reass->data_len,
	      reass->last_packet_octet, reass->trace_op_counter);

  u32 bi = reass->first_bi;
  u32 counter = 0;
  while (~0 != bi)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
      vnet_buffer_opaque_t *vnb = vnet_buffer (b);
      s =
	format (s,
		"  #%03u: range: [%u, %u], bi: %u, off: %d, len: %u, "
		"fragment[%u, %u]\n", counter, vnb->ip.reass.range_first,
		vnb->ip.reass.range_last, bi,
		ip4_full_reass_buffer_get_data_offset (b),
		ip4_full_reass_buffer_get_data_len (b),
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
show_ip4_reass (vlib_main_t * vm,
		unformat_input_t * input,
		CLIB_UNUSED (vlib_cli_command_t * lmd))
{
  ip4_full_reass_main_t *rm = &ip4_full_reass_main;

  vlib_cli_output (vm, "---------------------");
  vlib_cli_output (vm, "IP4 reassembly status");
  vlib_cli_output (vm, "---------------------");
  bool details = false;
  if (unformat (input, "details"))
    {
      details = true;
    }

  u32 sum_reass_n = 0;
  ip4_full_reass_t *reass;
  uword thread_index;
  const uword nthreads = vlib_num_workers () + 1;
  for (thread_index = 0; thread_index < nthreads; ++thread_index)
    {
      ip4_full_reass_per_thread_t *rt = &rm->per_thread_data[thread_index];
      clib_spinlock_lock (&rt->lock);
      if (details)
	{
          /* *INDENT-OFF* */
          pool_foreach (reass, rt->pool, {
            vlib_cli_output (vm, "%U", format_ip4_reass, vm, reass);
          });
          /* *INDENT-ON* */
	}
      sum_reass_n += rt->reass_n;
      clib_spinlock_unlock (&rt->lock);
    }
  vlib_cli_output (vm, "---------------------");
  vlib_cli_output (vm, "Current full IP4 reassemblies count: %lu\n",
		   (long unsigned) sum_reass_n);
  vlib_cli_output (vm,
		   "Maximum configured concurrent full IP4 reassemblies per worker-thread: %lu\n",
		   (long unsigned) rm->max_reass_n);
  vlib_cli_output (vm,
		   "Maximum configured full IP4 reassembly timeout: %lums\n",
		   (long unsigned) rm->timeout_ms);
  vlib_cli_output (vm,
		   "Maximum configured full IP4 reassembly expire walk interval: %lums\n",
		   (long unsigned) rm->expire_walk_interval_ms);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip4_full_reass_cmd, static) = {
    .path = "show ip4-full-reassembly",
    .short_help = "show ip4-full-reassembly [details]",
    .function = show_ip4_reass,
};
/* *INDENT-ON* */

#ifndef CLIB_MARCH_VARIANT
vnet_api_error_t
ip4_full_reass_enable_disable (u32 sw_if_index, u8 enable_disable)
{
  return vnet_feature_enable_disable ("ip4-unicast",
				      "ip4-full-reassembly-feature",
				      sw_if_index, enable_disable, 0, 0);
}
#endif /* CLIB_MARCH_VARIANT */


#define foreach_ip4_full_reass_handoff_error                       \
_(CONGESTION_DROP, "congestion drop")


typedef enum
{
#define _(sym,str) IP4_FULL_REASS_HANDOFF_ERROR_##sym,
  foreach_ip4_full_reass_handoff_error
#undef _
    IP4_FULL_REASS_HANDOFF_N_ERROR,
} ip4_full_reass_handoff_error_t;

static char *ip4_full_reass_handoff_error_strings[] = {
#define _(sym,string) string,
  foreach_ip4_full_reass_handoff_error
#undef _
};

typedef struct
{
  u32 next_worker_index;
} ip4_full_reass_handoff_trace_t;

static u8 *
format_ip4_full_reass_handoff_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip4_full_reass_handoff_trace_t *t =
    va_arg (*args, ip4_full_reass_handoff_trace_t *);

  s =
    format (s, "ip4-full-reassembly-handoff: next-worker %d",
	    t->next_worker_index);

  return s;
}

always_inline uword
ip4_full_reass_handoff_node_inline (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame,
				    ip4_full_reass_node_type_t type)
{
  ip4_full_reass_main_t *rm = &ip4_full_reass_main;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 n_enq, n_left_from, *from;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti;
  u32 fq_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  b = bufs;
  ti = thread_indices;

  switch (type)
    {
    case NORMAL:
      fq_index = rm->fq_index;
      break;
    case FEATURE:
      fq_index = rm->fq_feature_index;
      break;
    case CUSTOM:
      fq_index = rm->fq_custom_index;
      break;
    default:
      clib_warning ("Unexpected `type' (%d)!", type);
      ASSERT (0);
    }

  while (n_left_from > 0)
    {
      ti[0] = vnet_buffer (b[0])->ip.reass.owner_thread_index;

      if (PREDICT_FALSE
	  ((node->flags & VLIB_NODE_FLAG_TRACE)
	   && (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  ip4_full_reass_handoff_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->next_worker_index = ti[0];
	}

      n_left_from -= 1;
      ti += 1;
      b += 1;
    }
  n_enq =
    vlib_buffer_enqueue_to_thread (vm, fq_index, from, thread_indices,
				   frame->n_vectors, 1);

  if (n_enq < frame->n_vectors)
    vlib_node_increment_counter (vm, node->node_index,
				 IP4_FULL_REASS_HANDOFF_ERROR_CONGESTION_DROP,
				 frame->n_vectors - n_enq);
  return frame->n_vectors;
}

VLIB_NODE_FN (ip4_full_reass_handoff_node) (vlib_main_t * vm,
					    vlib_node_runtime_t * node,
					    vlib_frame_t * frame)
{
  return ip4_full_reass_handoff_node_inline (vm, node, frame, NORMAL);
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_full_reass_handoff_node) = {
  .name = "ip4-full-reassembly-handoff",
  .vector_size = sizeof (u32),
  .n_errors = ARRAY_LEN(ip4_full_reass_handoff_error_strings),
  .error_strings = ip4_full_reass_handoff_error_strings,
  .format_trace = format_ip4_full_reass_handoff_trace,

  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "error-drop",
  },
};
/* *INDENT-ON* */


/* *INDENT-OFF* */
VLIB_NODE_FN (ip4_full_reass_feature_handoff_node) (vlib_main_t * vm,
						    vlib_node_runtime_t *
						    node,
						    vlib_frame_t * frame)
{
  return ip4_full_reass_handoff_node_inline (vm, node, frame, FEATURE);
}
/* *INDENT-ON* */


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_full_reass_feature_handoff_node) = {
  .name = "ip4-full-reass-feature-hoff",
  .vector_size = sizeof (u32),
  .n_errors = ARRAY_LEN(ip4_full_reass_handoff_error_strings),
  .error_strings = ip4_full_reass_handoff_error_strings,
  .format_trace = format_ip4_full_reass_handoff_trace,

  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "error-drop",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_NODE_FN (ip4_full_reass_custom_handoff_node) (vlib_main_t * vm,
						    vlib_node_runtime_t *
						    node,
						    vlib_frame_t * frame)
{
  return ip4_full_reass_handoff_node_inline (vm, node, frame, CUSTOM);
}
/* *INDENT-ON* */


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_full_reass_custom_handoff_node) = {
  .name = "ip4-full-reass-custom-hoff",
  .vector_size = sizeof (u32),
  .n_errors = ARRAY_LEN(ip4_full_reass_handoff_error_strings),
  .error_strings = ip4_full_reass_handoff_error_strings,
  .format_trace = format_ip4_full_reass_handoff_trace,

  .n_next_nodes = 1,

  .next_nodes = {
    [0] = "error-drop",
  },
};
/* *INDENT-ON* */

#ifndef CLIB_MARCH_VARIANT
int
ip4_full_reass_enable_disable_with_refcnt (u32 sw_if_index, int is_enable)
{
  ip4_full_reass_main_t *rm = &ip4_full_reass_main;
  vec_validate (rm->feature_use_refcount_per_intf, sw_if_index);
  if (is_enable)
    {
      if (!rm->feature_use_refcount_per_intf[sw_if_index])
	{
	  ++rm->feature_use_refcount_per_intf[sw_if_index];
	  return vnet_feature_enable_disable ("ip4-unicast",
					      "ip4-full-reassembly-feature",
					      sw_if_index, 1, 0, 0);
	}
      ++rm->feature_use_refcount_per_intf[sw_if_index];
    }
  else
    {
      --rm->feature_use_refcount_per_intf[sw_if_index];
      if (!rm->feature_use_refcount_per_intf[sw_if_index])
	return vnet_feature_enable_disable ("ip4-unicast",
					    "ip4-full-reassembly-feature",
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
