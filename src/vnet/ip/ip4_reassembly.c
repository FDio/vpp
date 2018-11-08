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
 * @brief IPv4 Reassembly.
 *
 * This file contains the source code for IPv4 reassembly.
 */

#include <vppinfra/vec.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vppinfra/bihash_16_8.h>
#include <vnet/ip/ip4_reassembly.h>

#define MSEC_PER_SEC 1000
#define IP4_REASS_TIMEOUT_DEFAULT_MS 100
#define IP4_REASS_EXPIRE_WALK_INTERVAL_DEFAULT_MS 10000	// 10 seconds default
#define IP4_REASS_MAX_REASSEMBLIES_DEFAULT 1024
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

static vlib_node_registration_t ip4_reass_node;

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
} ip4_reass_key_t;

always_inline u32
ip4_reass_buffer_get_data_offset_no_check (vlib_buffer_t * b)
{
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  return vnb->ip.reass.range_first - vnb->ip.reass.fragment_first;
}

always_inline u32
ip4_reass_buffer_get_data_offset (vlib_buffer_t * b)
{
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  ASSERT (vnb->ip.reass.range_first >= vnb->ip.reass.fragment_first);
  return ip4_reass_buffer_get_data_offset_no_check (b);
}

always_inline u16
ip4_reass_buffer_get_data_len_no_check (vlib_buffer_t * b)
{
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  return clib_min (vnb->ip.reass.range_last, vnb->ip.reass.fragment_last) -
    (vnb->ip.reass.fragment_first + ip4_reass_buffer_get_data_offset (b)) + 1;
}

always_inline u16
ip4_reass_buffer_get_data_len (vlib_buffer_t * b)
{
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  ASSERT (vnb->ip.reass.range_last > vnb->ip.reass.fragment_first);
  return ip4_reass_buffer_get_data_len_no_check (b);
}

typedef struct
{
  // hash table key
  ip4_reass_key_t key;
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
  u8 next_index;
  // minimum fragment length for this reassembly - used to estimate MTU
  u16 min_fragment_length;
} ip4_reass_t;

typedef struct
{
  ip4_reass_t *pool;
  u32 reass_n;
  u32 buffers_n;
  u32 id_counter;
  clib_spinlock_t lock;
} ip4_reass_per_thread_t;

typedef struct
{
  // IPv4 config
  u32 timeout_ms;
  f64 timeout;
  u32 expire_walk_interval_ms;
  u32 max_reass_n;

  // IPv4 runtime
  clib_bihash_16_8_t hash;
  // per-thread data
  ip4_reass_per_thread_t *per_thread_data;

  // convenience
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  // node index of ip4-drop node
  u32 ip4_drop_idx;
  u32 ip4_reass_expire_node_idx;
} ip4_reass_main_t;

ip4_reass_main_t ip4_reass_main;

typedef enum
{
  IP4_REASSEMBLY_NEXT_INPUT,
  IP4_REASSEMBLY_NEXT_DROP,
  IP4_REASSEMBLY_N_NEXT,
} ip4_reass_next_t;

typedef enum
{
  RANGE_NEW,
  RANGE_SHRINK,
  RANGE_DISCARD,
  RANGE_OVERLAP,
  FINALIZE,
} ip4_reass_trace_operation_e;

typedef struct
{
  u16 range_first;
  u16 range_last;
  u32 range_bi;
  i32 data_offset;
  u32 data_len;
  u32 first_bi;
} ip4_reass_range_trace_t;

typedef struct
{
  ip4_reass_trace_operation_e action;
  u32 reass_id;
  ip4_reass_range_trace_t trace_range;
  u32 size_diff;
  u32 op_id;
  u32 fragment_first;
  u32 fragment_last;
  u32 total_data_len;
} ip4_reass_trace_t;

static void
ip4_reass_trace_details (vlib_main_t * vm, u32 bi,
			 ip4_reass_range_trace_t * trace)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  trace->range_first = vnb->ip.reass.range_first;
  trace->range_last = vnb->ip.reass.range_last;
  trace->data_offset = ip4_reass_buffer_get_data_offset_no_check (b);
  trace->data_len = ip4_reass_buffer_get_data_len_no_check (b);
  trace->range_bi = bi;
}

static u8 *
format_ip4_reass_range_trace (u8 * s, va_list * args)
{
  ip4_reass_range_trace_t *trace = va_arg (*args, ip4_reass_range_trace_t *);
  s = format (s, "range: [%u, %u], off %d, len %u, bi %u", trace->range_first,
	      trace->range_last, trace->data_offset, trace->data_len,
	      trace->range_bi);
  return s;
}

u8 *
format_ip4_reass_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip4_reass_trace_t *t = va_arg (*args, ip4_reass_trace_t *);
  s = format (s, "reass id: %u, op id: %u ", t->reass_id, t->op_id);
  u32 indent = format_get_indent (s);
  s = format (s, "first bi: %u, data len: %u, ip/fragment[%u, %u]",
	      t->trace_range.first_bi, t->total_data_len, t->fragment_first,
	      t->fragment_last);
  switch (t->action)
    {
    case RANGE_SHRINK:
      s = format (s, "\n%Ushrink %U by %u", format_white_space, indent,
		  format_ip4_reass_range_trace, &t->trace_range,
		  t->size_diff);
      break;
    case RANGE_DISCARD:
      s = format (s, "\n%Udiscard %U", format_white_space, indent,
		  format_ip4_reass_range_trace, &t->trace_range);
      break;
    case RANGE_NEW:
      s = format (s, "\n%Unew %U", format_white_space, indent,
		  format_ip4_reass_range_trace, &t->trace_range);
      break;
    case RANGE_OVERLAP:
      s = format (s, "\n%Uoverlapping/ignored %U", format_white_space, indent,
		  format_ip4_reass_range_trace, &t->trace_range);
      break;
    case FINALIZE:
      s = format (s, "\n%Ufinalize reassembly", format_white_space, indent);
      break;
    }
  return s;
}

static void
ip4_reass_add_trace (vlib_main_t * vm, vlib_node_runtime_t * node,
		     ip4_reass_main_t * rm, ip4_reass_t * reass, u32 bi,
		     ip4_reass_trace_operation_e action, u32 size_diff)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  if (pool_is_free_index (vm->trace_main.trace_buffer_pool, b->trace_index))
    {
      // this buffer's trace is gone
      b->flags &= ~VLIB_BUFFER_IS_TRACED;
      return;
    }
  ip4_reass_trace_t *t = vlib_add_trace (vm, node, b, sizeof (t[0]));
  t->reass_id = reass->id;
  t->action = action;
  ip4_reass_trace_details (vm, bi, &t->trace_range);
  t->size_diff = size_diff;
  t->op_id = reass->trace_op_counter;
  ++reass->trace_op_counter;
  t->fragment_first = vnb->ip.reass.fragment_first;
  t->fragment_last = vnb->ip.reass.fragment_last;
  t->trace_range.first_bi = reass->first_bi;
  t->total_data_len = reass->data_len;
#if 0
  static u8 *s = NULL;
  s = format (s, "%U", format_ip4_reass_trace, NULL, NULL, t);
  printf ("%.*s\n", vec_len (s), s);
  fflush (stdout);
  vec_reset_length (s);
#endif
}

always_inline void
ip4_reass_free (ip4_reass_main_t * rm, ip4_reass_per_thread_t * rt,
		ip4_reass_t * reass)
{
  clib_bihash_kv_16_8_t kv;
  kv.key[0] = reass->key.as_u64[0];
  kv.key[1] = reass->key.as_u64[1];
  clib_bihash_add_del_16_8 (&rm->hash, &kv, 0);
  pool_put (rt->pool, reass);
  --rt->reass_n;
}

always_inline void
ip4_reass_on_timeout (vlib_main_t * vm, ip4_reass_main_t * rm,
		      ip4_reass_t * reass, u32 ** vec_drop_timeout)
{
  u32 range_bi = reass->first_bi;
  vlib_buffer_t *range_b;
  vnet_buffer_opaque_t *range_vnb;
  while (~0 != range_bi)
    {
      range_b = vlib_get_buffer (vm, range_bi);
      range_vnb = vnet_buffer (range_b);
      u32 bi = range_bi;
      while (~0 != bi)
	{
	  vec_add1 (*vec_drop_timeout, bi);
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
}

ip4_reass_t *
ip4_reass_find_or_create (vlib_main_t * vm, ip4_reass_main_t * rm,
			  ip4_reass_per_thread_t * rt,
			  ip4_reass_key_t * k, u32 ** vec_drop_timeout)
{
  ip4_reass_t *reass = NULL;
  f64 now = vlib_time_now (rm->vlib_main);
  clib_bihash_kv_16_8_t kv, value;
  kv.key[0] = k->as_u64[0];
  kv.key[1] = k->as_u64[1];

  if (!clib_bihash_search_16_8 (&rm->hash, &kv, &value))
    {
      reass = pool_elt_at_index (rt->pool, value.value);
      if (now > reass->last_heard + rm->timeout)
	{
	  ip4_reass_on_timeout (vm, rm, reass, vec_drop_timeout);
	  ip4_reass_free (rm, rt, reass);
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
      reass->id =
	((u64) os_get_thread_index () * 1000000000) + rt->id_counter;
      ++rt->id_counter;
      reass->first_bi = ~0;
      reass->last_packet_octet = ~0;
      reass->data_len = 0;
      ++rt->reass_n;
    }

  reass->key.as_u64[0] = kv.key[0] = k->as_u64[0];
  reass->key.as_u64[1] = kv.key[1] = k->as_u64[1];
  kv.value = reass - rt->pool;
  reass->last_heard = now;

  if (clib_bihash_add_del_16_8 (&rm->hash, &kv, 1))
    {
      ip4_reass_free (rm, rt, reass);
      reass = NULL;
    }

  return reass;
}

always_inline void
ip4_reass_finalize (vlib_main_t * vm, vlib_node_runtime_t * node,
		    ip4_reass_main_t * rm, ip4_reass_per_thread_t * rt,
		    ip4_reass_t * reass, u32 * bi0, u32 * next0,
		    u32 * error0, u32 ** vec_drop_compress,
		    u32 ** vec_drop_overlap, bool is_feature)
{
  ASSERT (~0 != reass->first_bi);
  vlib_buffer_t *first_b = vlib_get_buffer (vm, reass->first_bi);
  vlib_buffer_t *last_b = NULL;
  u32 sub_chain_bi = reass->first_bi;
  u32 total_length = 0;
  u32 buf_cnt = 0;
  u32 dropped_cnt = 0;
  do
    {
      u32 tmp_bi = sub_chain_bi;
      vlib_buffer_t *tmp = vlib_get_buffer (vm, tmp_bi);
      ip4_header_t *ip = vlib_buffer_get_current (tmp);
      u32 data_len = ip4_reass_buffer_get_data_len (tmp);
      u32 trim_front =
	ip4_header_bytes (ip) + ip4_reass_buffer_get_data_offset (tmp);
      u32 trim_end =
	vlib_buffer_length_in_chain (vm, tmp) - trim_front - data_len;
      if (tmp_bi == reass->first_bi)
	{
	  /* first buffer - keep ip4 header */
	  ASSERT (0 == ip4_reass_buffer_get_data_offset (tmp));
	  trim_front = 0;
	  trim_end = vlib_buffer_length_in_chain (vm, tmp) - data_len -
	    ip4_header_bytes (ip);
	  ASSERT (vlib_buffer_length_in_chain (vm, tmp) - trim_end > 0);
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
		  vec_add1 (*vec_drop_compress, tmp_bi);
		  ++dropped_cnt;
		  trim_front -= tmp->current_length;
		  ASSERT (tmp->flags & VLIB_BUFFER_NEXT_PRESENT);
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
		  ASSERT (tmp->flags & VLIB_BUFFER_NEXT_PRESENT);
		}
	      total_length += tmp->current_length;
	    }
	  else
	    {
	      vec_add1 (*vec_drop_overlap, tmp_bi);
	      ASSERT (reass->first_bi != tmp_bi);
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

  ASSERT (last_b != NULL);
  last_b->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
  ASSERT (rt->buffers_n >= (buf_cnt - dropped_cnt));
  rt->buffers_n -= buf_cnt - dropped_cnt;
  ASSERT (total_length >= first_b->current_length);
  total_length -= first_b->current_length;
  first_b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  first_b->total_length_not_including_first_buffer = total_length;
  ip4_header_t *ip = vlib_buffer_get_current (first_b);
  ip->flags_and_fragment_offset = 0;
  ip->length = clib_host_to_net_u16 (first_b->current_length + total_length);
  ip->checksum = ip4_header_checksum (ip);
  vlib_buffer_chain_compress (vm, first_b, vec_drop_compress);
  if (PREDICT_FALSE (first_b->flags & VLIB_BUFFER_IS_TRACED))
    {
      ip4_reass_add_trace (vm, node, rm, reass, reass->first_bi, FINALIZE, 0);
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
  if (is_feature)
    {
      *next0 = IP4_REASSEMBLY_NEXT_INPUT;
    }
  else
    {
      *next0 = reass->next_index;
    }
  vnet_buffer (first_b)->ip.reass.estimated_mtu = reass->min_fragment_length;
  *error0 = IP4_ERROR_NONE;
  ip4_reass_free (rm, rt, reass);
  reass = NULL;
}

always_inline u32
ip4_reass_get_buffer_chain_length (vlib_main_t * vm, vlib_buffer_t * b)
{
  u32 len = 0;
  while (b)
    {
      ++len;
      if (PREDICT_FALSE (b->flags & VLIB_BUFFER_NEXT_PRESENT))
	{
	  b = vlib_get_buffer (vm, b->next_buffer);
	}
      else
	{
	  break;
	}
    }
  return len;
}

always_inline void
ip4_reass_insert_range_in_chain (vlib_main_t * vm,
				 ip4_reass_main_t * rm,
				 ip4_reass_per_thread_t * rt,
				 ip4_reass_t * reass,
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
  reass->data_len += ip4_reass_buffer_get_data_len (new_next_b);
  rt->buffers_n += ip4_reass_get_buffer_chain_length (vm, new_next_b);
}

always_inline void
ip4_reass_remove_range_from_chain (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   ip4_reass_main_t * rm,
				   u32 ** vec_drop_overlap,
				   ip4_reass_t * reass, u32 prev_range_bi,
				   u32 discard_bi)
{
  vlib_buffer_t *discard_b = vlib_get_buffer (vm, discard_bi);
  vnet_buffer_opaque_t *discard_vnb = vnet_buffer (discard_b);
  if (~0 != prev_range_bi)
    {
      vlib_buffer_t *prev_b = vlib_get_buffer (vm, prev_range_bi);
      vnet_buffer_opaque_t *prev_vnb = vnet_buffer (prev_b);
      ASSERT (prev_vnb->ip.reass.next_range_bi == discard_bi);
      prev_vnb->ip.reass.next_range_bi = discard_vnb->ip.reass.next_range_bi;
    }
  else
    {
      reass->first_bi = discard_vnb->ip.reass.next_range_bi;
    }
  reass->data_len -= ip4_reass_buffer_get_data_len (discard_b);
  while (1)
    {
      vec_add1 (*vec_drop_overlap, discard_bi);
      if (PREDICT_FALSE (discard_b->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ip4_reass_add_trace (vm, node, rm, reass, discard_bi, RANGE_DISCARD,
			       0);
	}
      if (discard_b->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  discard_b->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
	  discard_bi = discard_b->next_buffer;
	  discard_b = vlib_get_buffer (vm, discard_bi);
	}
      else
	{
	  break;
	}
    }
}

always_inline void
ip4_reass_update (vlib_main_t * vm, vlib_node_runtime_t * node,
		  ip4_reass_main_t * rm, ip4_reass_per_thread_t * rt,
		  ip4_reass_t * reass, u32 * bi0, u32 * next0,
		  u32 * error0, u32 ** vec_drop_overlap,
		  u32 ** vec_drop_compress, bool is_feature)
{
  int consumed = 0;
  vlib_buffer_t *fb = vlib_get_buffer (vm, *bi0);
  ip4_header_t *fip = vlib_buffer_get_current (fb);
  ASSERT (fb->current_length >= sizeof (*fip));
  vnet_buffer_opaque_t *fvnb = vnet_buffer (fb);
  reass->next_index = fvnb->ip.reass.next_index;	// store next_index before it's overwritten
  u32 fragment_first = fvnb->ip.reass.fragment_first =
    ip4_get_fragment_offset_bytes (fip);
  u32 fragment_length =
    clib_net_to_host_u16 (fip->length) - ip4_header_bytes (fip);
  u32 fragment_last = fvnb->ip.reass.fragment_last =
    fragment_first + fragment_length - 1;
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
      ip4_reass_insert_range_in_chain (vm, rm, rt, reass, prev_range_bi,
				       *bi0);
      if (PREDICT_FALSE (fb->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ip4_reass_add_trace (vm, node, rm, reass, *bi0, RANGE_NEW, 0);
	}
      *bi0 = ~0;
      reass->min_fragment_length = clib_net_to_host_u16 (fip->length);
      return;
    }
  reass->min_fragment_length = clib_min (clib_net_to_host_u16 (fip->length),
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
	      ip4_reass_insert_range_in_chain (vm, rm, rt, reass,
					       prev_range_bi, *bi0);
	      consumed = 1;
	      break;
	    }
	  continue;
	}
      if (fragment_last < candidate_vnb->ip.reass.range_first)
	{
	  // this fragment ends before candidate range without any overlap
	  ip4_reass_insert_range_in_chain (vm, rm, rt, reass, prev_range_bi,
					   *bi0);
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
		  ip4_reass_add_trace (vm, node, rm, reass, *bi0,
				       RANGE_OVERLAP, 0);
		}
	      break;
	    }
	  int discard_candidate = 0;
	  if (fragment_first < candidate_vnb->ip.reass.range_first)
	    {
	      u32 overlap =
		fragment_last - candidate_vnb->ip.reass.range_first + 1;
	      if (overlap < ip4_reass_buffer_get_data_len (candidate_b))
		{
		  candidate_vnb->ip.reass.range_first += overlap;
		  ASSERT (reass->data_len >= overlap);
		  reass->data_len -= overlap;
		  if (PREDICT_FALSE (fb->flags & VLIB_BUFFER_IS_TRACED))
		    {
		      ip4_reass_add_trace (vm, node, rm, reass,
					   candidate_range_bi, RANGE_SHRINK,
					   overlap);
		    }
		  ip4_reass_insert_range_in_chain (vm, rm, rt, reass,
						   prev_range_bi, *bi0);
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
	      if (overlap < ip4_reass_buffer_get_data_len (candidate_b))
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
		      ip4_reass_insert_range_in_chain (vm, rm, rt, reass,
						       candidate_range_bi,
						       *bi0);
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
	      ip4_reass_remove_range_from_chain (vm, node, rm,
						 vec_drop_overlap, reass,
						 prev_range_bi,
						 candidate_range_bi);
	      if (~0 != next_range_bi)
		{
		  candidate_range_bi = next_range_bi;
		  continue;
		}
	      else
		{
		  // special case - last range discarded
		  ip4_reass_insert_range_in_chain (vm, rm, rt, reass,
						   prev_range_bi, *bi0);
		  consumed = 1;
		}
	    }
	}
      break;
    }
  if (consumed)
    {
      if (PREDICT_FALSE (fb->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ip4_reass_add_trace (vm, node, rm, reass, *bi0, RANGE_NEW, 0);
	}
    }
  if (~0 != reass->last_packet_octet &&
      reass->data_len == reass->last_packet_octet + 1)
    {
      ip4_reass_finalize (vm, node, rm, rt, reass, bi0, next0, error0,
			  vec_drop_compress, vec_drop_overlap, is_feature);
    }
  else
    {
      if (consumed)
	{
	  *bi0 = ~0;
	}
      else
	{
	  *next0 = IP4_REASSEMBLY_NEXT_DROP;
	  *error0 = IP4_ERROR_REASS_DUPLICATE_FRAGMENT;
	}
    }
}

always_inline uword
ip4_reassembly_inline (vlib_main_t * vm,
		       vlib_node_runtime_t * node,
		       vlib_frame_t * frame, bool is_feature)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from, n_left_to_next, *to_next, next_index;
  ip4_reass_main_t *rm = &ip4_reass_main;
  ip4_reass_per_thread_t *rt = &rm->per_thread_data[os_get_thread_index ()];
  clib_spinlock_lock (&rt->lock);

  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  static u32 *vec_drop_timeout = NULL;	// indexes of buffers which timed out
  static u32 *vec_drop_overlap = NULL;	// indexes of buffers which were discarded due to overlap
  static u32 *vec_drop_compress = NULL;	// indexes of buffers dicarded due to buffer compression
  while (n_left_from > 0 || vec_len (vec_drop_timeout) > 0 ||
	 vec_len (vec_drop_overlap) > 0 || vec_len (vec_drop_compress) > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (vec_len (vec_drop_timeout) > 0 && n_left_to_next > 0)
	{
	  u32 bi = vec_pop (vec_drop_timeout);
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	  b->error = node->errors[IP4_ERROR_REASS_TIMEOUT];
	  to_next[0] = bi;
	  to_next += 1;
	  n_left_to_next -= 1;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi,
					   IP4_REASSEMBLY_NEXT_DROP);
	  IP4_REASS_DEBUG_BUFFER (bi, enqueue_drop_timeout);
	  ASSERT (rt->buffers_n > 0);
	  --rt->buffers_n;
	}

      while (vec_len (vec_drop_overlap) > 0 && n_left_to_next > 0)
	{
	  u32 bi = vec_pop (vec_drop_overlap);
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	  b->error = node->errors[IP4_ERROR_REASS_DUPLICATE_FRAGMENT];
	  to_next[0] = bi;
	  to_next += 1;
	  n_left_to_next -= 1;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi,
					   IP4_REASSEMBLY_NEXT_DROP);
	  IP4_REASS_DEBUG_BUFFER (bi, enqueue_drop_duplicate_fragment);
	  ASSERT (rt->buffers_n > 0);
	  --rt->buffers_n;
	}

      while (vec_len (vec_drop_compress) > 0 && n_left_to_next > 0)
	{
	  u32 bi = vec_pop (vec_drop_compress);
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	  b->error = node->errors[IP4_ERROR_NONE];
	  to_next[0] = bi;
	  to_next += 1;
	  n_left_to_next -= 1;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi,
					   IP4_REASSEMBLY_NEXT_DROP);
	  IP4_REASS_DEBUG_BUFFER (bi, enqueue_drop_compress);
	  ASSERT (rt->buffers_n > 0);
	  --rt->buffers_n;
	}

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
	      if (is_feature)
		{
		  next0 = IP4_REASSEMBLY_NEXT_INPUT;
		}
	      else
		{
		  next0 = vnet_buffer (b0)->ip.reass.next_index;
		}
	    }
	  else
	    {
	      ip4_reass_key_t k;
	      k.as_u64[0] =
		(u64) vnet_buffer (b0)->sw_if_index[VLIB_RX] << 32 | (u64)
		ip0->src_address.as_u32;
	      k.as_u64[1] =
		(u64) ip0->dst_address.
		as_u32 << 32 | (u64) ip0->fragment_id << 16 | (u64) ip0->
		protocol << 8;

	      ip4_reass_t *reass =
		ip4_reass_find_or_create (vm, rm, rt, &k, &vec_drop_timeout);

	      if (reass)
		{
		  ip4_reass_update (vm, node, rm, rt, reass, &bi0, &next0,
				    &error0, &vec_drop_overlap,
				    &vec_drop_compress, is_feature);
		}
	      else
		{
		  next0 = IP4_REASSEMBLY_NEXT_DROP;
		  error0 = IP4_ERROR_REASS_LIMIT_REACHED;
		}

	      b0->error = node->errors[error0];
	    }

	  if (bi0 != ~0)
	    {
	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	      if (is_feature && IP4_ERROR_NONE == error0)
		{
		  b0 = vlib_get_buffer (vm, bi0);
		  vnet_feature_next (&next0, b0);
		}
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, bi0, next0);
	      IP4_REASS_DEBUG_BUFFER (bi0, enqueue_next);
	    }

	  from += 1;
	  n_left_from -= 1;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  clib_spinlock_unlock (&rt->lock);
  return frame->n_vectors;
}

static char *ip4_reassembly_error_strings[] = {
#define _(sym, string) string,
  foreach_ip4_error
#undef _
};

static uword
ip4_reassembly (vlib_main_t * vm, vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{
  return ip4_reassembly_inline (vm, node, frame, false /* is_feature */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_reass_node, static) = {
    .function = ip4_reassembly,
    .name = "ip4-reassembly",
    .vector_size = sizeof (u32),
    .format_trace = format_ip4_reass_trace,
    .n_errors = ARRAY_LEN (ip4_reassembly_error_strings),
    .error_strings = ip4_reassembly_error_strings,
    .n_next_nodes = IP4_REASSEMBLY_N_NEXT,
    .next_nodes =
        {
                [IP4_REASSEMBLY_NEXT_INPUT] = "ip4-input",
                [IP4_REASSEMBLY_NEXT_DROP] = "ip4-drop",
        },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (ip4_reass_node, ip4_reassembly);

static uword
ip4_reassembly_feature (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return ip4_reassembly_inline (vm, node, frame, true /* is_feature */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_reass_node_feature, static) = {
    .function = ip4_reassembly_feature,
    .name = "ip4-reassembly-feature",
    .vector_size = sizeof (u32),
    .format_trace = format_ip4_reass_trace,
    .n_errors = ARRAY_LEN (ip4_reassembly_error_strings),
    .error_strings = ip4_reassembly_error_strings,
    .n_next_nodes = IP4_REASSEMBLY_N_NEXT,
    .next_nodes =
        {
                [IP4_REASSEMBLY_NEXT_INPUT] = "ip4-input",
                [IP4_REASSEMBLY_NEXT_DROP] = "ip4-drop",
        },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (ip4_reass_node_feature, ip4_reassembly_feature);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (ip4_reassembly_feature, static) = {
    .arc_name = "ip4-unicast",
    .node_name = "ip4-reassembly-feature",
    .runs_before = VNET_FEATURES ("ip4-lookup"),
    .runs_after = 0,
};
/* *INDENT-ON* */

always_inline u32
ip4_reass_get_nbuckets ()
{
  ip4_reass_main_t *rm = &ip4_reass_main;
  u32 nbuckets;
  u8 i;

  nbuckets = (u32) (rm->max_reass_n / IP4_REASS_HT_LOAD_FACTOR);

  for (i = 0; i < 31; i++)
    if ((1 << i) >= nbuckets)
      break;
  nbuckets = 1 << i;

  return nbuckets;
}

typedef enum
{
  IP4_EVENT_CONFIG_CHANGED = 1,
} ip4_reass_event_t;

typedef struct
{
  int failure;
  clib_bihash_16_8_t *new_hash;
} ip4_rehash_cb_ctx;

static void
ip4_rehash_cb (clib_bihash_kv_16_8_t * kv, void *_ctx)
{
  ip4_rehash_cb_ctx *ctx = _ctx;
  if (clib_bihash_add_del_16_8 (ctx->new_hash, kv, 1))
    {
      ctx->failure = 1;
    }
}

static void
ip4_reass_set_params (u32 timeout_ms, u32 max_reassemblies,
		      u32 expire_walk_interval_ms)
{
  ip4_reass_main.timeout_ms = timeout_ms;
  ip4_reass_main.timeout = (f64) timeout_ms / (f64) MSEC_PER_SEC;
  ip4_reass_main.max_reass_n = max_reassemblies;
  ip4_reass_main.expire_walk_interval_ms = expire_walk_interval_ms;
}

vnet_api_error_t
ip4_reass_set (u32 timeout_ms, u32 max_reassemblies,
	       u32 expire_walk_interval_ms)
{
  u32 old_nbuckets = ip4_reass_get_nbuckets ();
  ip4_reass_set_params (timeout_ms, max_reassemblies,
			expire_walk_interval_ms);
  vlib_process_signal_event (ip4_reass_main.vlib_main,
			     ip4_reass_main.ip4_reass_expire_node_idx,
			     IP4_EVENT_CONFIG_CHANGED, 0);
  u32 new_nbuckets = ip4_reass_get_nbuckets ();
  if (ip4_reass_main.max_reass_n > 0 && new_nbuckets > old_nbuckets)
    {
      clib_bihash_16_8_t new_hash;
      clib_memset (&new_hash, 0, sizeof (new_hash));
      ip4_rehash_cb_ctx ctx;
      ctx.failure = 0;
      ctx.new_hash = &new_hash;
      clib_bihash_init_16_8 (&new_hash, "ip4-reass", new_nbuckets,
			     new_nbuckets * 1024);
      clib_bihash_foreach_key_value_pair_16_8 (&ip4_reass_main.hash,
					       ip4_rehash_cb, &ctx);
      if (ctx.failure)
	{
	  clib_bihash_free_16_8 (&new_hash);
	  return -1;
	}
      else
	{
	  clib_bihash_free_16_8 (&ip4_reass_main.hash);
	  clib_memcpy (&ip4_reass_main.hash, &new_hash,
		       sizeof (ip4_reass_main.hash));
	}
    }
  return 0;
}

vnet_api_error_t
ip4_reass_get (u32 * timeout_ms, u32 * max_reassemblies,
	       u32 * expire_walk_interval_ms)
{
  *timeout_ms = ip4_reass_main.timeout_ms;
  *max_reassemblies = ip4_reass_main.max_reass_n;
  *expire_walk_interval_ms = ip4_reass_main.expire_walk_interval_ms;
  return 0;
}

static clib_error_t *
ip4_reass_init_function (vlib_main_t * vm)
{
  ip4_reass_main_t *rm = &ip4_reass_main;
  clib_error_t *error = 0;
  u32 nbuckets;
  vlib_node_t *node;

  rm->vlib_main = vm;
  rm->vnet_main = vnet_get_main ();

  vec_validate (rm->per_thread_data, vlib_num_workers ());
  ip4_reass_per_thread_t *rt;
  vec_foreach (rt, rm->per_thread_data)
  {
    clib_spinlock_init (&rt->lock);
    pool_alloc (rt->pool, rm->max_reass_n);
  }

  node = vlib_get_node_by_name (vm, (u8 *) "ip4-reassembly-expire-walk");
  ASSERT (node);
  rm->ip4_reass_expire_node_idx = node->index;

  ip4_reass_set_params (IP4_REASS_TIMEOUT_DEFAULT_MS,
			IP4_REASS_MAX_REASSEMBLIES_DEFAULT,
			IP4_REASS_EXPIRE_WALK_INTERVAL_DEFAULT_MS);

  nbuckets = ip4_reass_get_nbuckets ();
  clib_bihash_init_16_8 (&rm->hash, "ip4-reass", nbuckets, nbuckets * 1024);

  node = vlib_get_node_by_name (vm, (u8 *) "ip4-drop");
  ASSERT (node);
  rm->ip4_drop_idx = node->index;

  return error;
}

VLIB_INIT_FUNCTION (ip4_reass_init_function);

static uword
ip4_reass_walk_expired (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * f)
{
  ip4_reass_main_t *rm = &ip4_reass_main;
  uword event_type, *event_data = 0;

  while (true)
    {
      vlib_process_wait_for_event_or_clock (vm,
					    (f64) rm->expire_walk_interval_ms
					    / (f64) MSEC_PER_SEC);
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

      ip4_reass_t *reass;
      u32 *vec_drop_timeout = NULL;
      int *pool_indexes_to_free = NULL;

      uword thread_index = 0;
      int index;
      const uword nthreads = vlib_num_workers () + 1;
      for (thread_index = 0; thread_index < nthreads; ++thread_index)
	{
	  ip4_reass_per_thread_t *rt = &rm->per_thread_data[thread_index];
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
            ip4_reass_t *reass = pool_elt_at_index (rt->pool, i[0]);
	    u32 before = vec_len (vec_drop_timeout);
	    vlib_buffer_t *b = vlib_get_buffer (vm, reass->first_bi);
	    if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	      {
		if (pool_is_free_index (vm->trace_main.trace_buffer_pool,
					b->trace_index))
		  {
		    /* the trace is gone, don't trace this buffer anymore */
		    b->flags &= ~VLIB_BUFFER_IS_TRACED;
		  }
	      }
            ip4_reass_on_timeout (vm, rm, reass, &vec_drop_timeout);
            u32 after = vec_len (vec_drop_timeout);
            ASSERT (rt->buffers_n >= (after - before));
            rt->buffers_n -= (after - before);
            ip4_reass_free (rm, rt, reass);
          }
          /* *INDENT-ON* */

	  clib_spinlock_unlock (&rt->lock);
	}

      while (vec_len (vec_drop_timeout) > 0)
	{
	  vlib_frame_t *f = vlib_get_frame_to_node (vm, rm->ip4_drop_idx);
	  u32 *to_next = vlib_frame_vector_args (f);
	  u32 n_left_to_next = VLIB_FRAME_SIZE - f->n_vectors;
	  int trace_frame = 0;
	  while (vec_len (vec_drop_timeout) > 0 && n_left_to_next > 0)
	    {
	      u32 bi = vec_pop (vec_drop_timeout);
	      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	      if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
		{
		  if (pool_is_free_index (vm->trace_main.trace_buffer_pool,
					  b->trace_index))
		    {
		      /* the trace is gone, don't trace this buffer anymore */
		      b->flags &= ~VLIB_BUFFER_IS_TRACED;
		    }
		  else
		    {
		      trace_frame = 1;
		    }
		}
	      b->error = node->errors[IP4_ERROR_REASS_TIMEOUT];
	      to_next[0] = bi;
	      ++f->n_vectors;
	      to_next += 1;
	      n_left_to_next -= 1;
	      IP4_REASS_DEBUG_BUFFER (bi, enqueue_drop_timeout_walk);
	    }
	  f->frame_flags |= (trace_frame * VLIB_FRAME_TRACE);
	  vlib_put_frame_to_node (vm, rm->ip4_drop_idx, f);
	}

      vec_free (pool_indexes_to_free);
      vec_free (vec_drop_timeout);
      if (event_data)
	{
	  _vec_len (event_data) = 0;
	}
    }

  return 0;
}

static vlib_node_registration_t ip4_reass_expire_node;

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_reass_expire_node, static) = {
    .function = ip4_reass_walk_expired,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "ip4-reassembly-expire-walk",
    .format_trace = format_ip4_reass_trace,
    .n_errors = ARRAY_LEN (ip4_reassembly_error_strings),
    .error_strings = ip4_reassembly_error_strings,

};
/* *INDENT-ON* */

static u8 *
format_ip4_reass_key (u8 * s, va_list * args)
{
  ip4_reass_key_t *key = va_arg (*args, ip4_reass_key_t *);
  s = format (s, "xx_id: %u, src: %U, dst: %U, frag_id: %u, proto: %u",
	      key->xx_id, format_ip4_address, &key->src, format_ip4_address,
	      &key->dst, clib_net_to_host_u16 (key->frag_id), key->proto);
  return s;
}

static u8 *
format_ip4_reass (u8 * s, va_list * args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  ip4_reass_t *reass = va_arg (*args, ip4_reass_t *);

  s = format (s, "ID: %lu, key: %U\n  first_bi: %u, data_len: %u, "
	      "last_packet_octet: %u, trace_op_counter: %u\n",
	      reass->id, format_ip4_reass_key, &reass->key, reass->first_bi,
	      reass->data_len, reass->last_packet_octet,
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
		  ip4_reass_buffer_get_data_offset_no_check (b),
		  ip4_reass_buffer_get_data_len_no_check (b),
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
show_ip4_reass (vlib_main_t * vm, unformat_input_t * input,
		CLIB_UNUSED (vlib_cli_command_t * lmd))
{
  ip4_reass_main_t *rm = &ip4_reass_main;

  vlib_cli_output (vm, "---------------------");
  vlib_cli_output (vm, "IP4 reassembly status");
  vlib_cli_output (vm, "---------------------");
  bool details = false;
  if (unformat (input, "details"))
    {
      details = true;
    }

  u32 sum_reass_n = 0;
  u64 sum_buffers_n = 0;
  ip4_reass_t *reass;
  uword thread_index;
  const uword nthreads = vlib_num_workers () + 1;
  for (thread_index = 0; thread_index < nthreads; ++thread_index)
    {
      ip4_reass_per_thread_t *rt = &rm->per_thread_data[thread_index];
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
      sum_buffers_n += rt->buffers_n;
      clib_spinlock_unlock (&rt->lock);
    }
  vlib_cli_output (vm, "---------------------");
  vlib_cli_output (vm, "Current IP4 reassemblies count: %lu\n",
		   (long unsigned) sum_reass_n);
  vlib_cli_output (vm,
		   "Maximum configured concurrent IP4 reassemblies per worker-thread: %lu\n",
		   (long unsigned) rm->max_reass_n);
  vlib_cli_output (vm, "Buffers in use: %lu\n",
		   (long unsigned) sum_buffers_n);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip4_reassembly_cmd, static) = {
    .path = "show ip4-reassembly",
    .short_help = "show ip4-reassembly [details]",
    .function = show_ip4_reass,
};
/* *INDENT-ON* */

vnet_api_error_t
ip4_reass_enable_disable (u32 sw_if_index, u8 enable_disable)
{
  return vnet_feature_enable_disable ("ip4-unicast", "ip4-reassembly-feature",
				      sw_if_index, enable_disable, 0, 0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
