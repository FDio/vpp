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
 * @brief IPv6 Reassembly.
 *
 * This file contains the source code for IPv6 reassembly.
 */

#include <vppinfra/vec.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vppinfra/bihash_48_8.h>
#include <vnet/ip/ip6_reassembly.h>

#define MSEC_PER_SEC 1000
#define IP6_REASS_TIMEOUT_DEFAULT_MS 100
#define IP6_REASS_EXPIRE_WALK_INTERVAL_DEFAULT_MS 10000	// 10 seconds default
#define IP6_REASS_MAX_REASSEMBLIES_DEFAULT 1024
#define IP6_REASS_HT_LOAD_FACTOR (0.75)

static vlib_node_registration_t ip6_reass_node;

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
} ip6_reass_key_t;

always_inline u32
ip6_reass_buffer_get_data_offset_no_check (vlib_buffer_t * b)
{
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  return vnb->ip.reass.range_first - vnb->ip.reass.fragment_first;
}

always_inline u32
ip6_reass_buffer_get_data_offset (vlib_buffer_t * b)
{
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  ASSERT (vnb->ip.reass.range_first >= vnb->ip.reass.fragment_first);
  return ip6_reass_buffer_get_data_offset_no_check (b);
}

always_inline u16
ip6_reass_buffer_get_data_len_no_check (vlib_buffer_t * b)
{
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  return clib_min (vnb->ip.reass.range_last, vnb->ip.reass.fragment_last) -
    (vnb->ip.reass.fragment_first + ip6_reass_buffer_get_data_offset (b)) + 1;
}

always_inline u16
ip6_reass_buffer_get_data_len (vlib_buffer_t * b)
{
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  ASSERT (vnb->ip.reass.range_last > vnb->ip.reass.fragment_first);
  return ip6_reass_buffer_get_data_len_no_check (b);
}

typedef struct
{
  // hash table key
  ip6_reass_key_t key;
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
} ip6_reass_t;

typedef struct
{
  ip6_reass_t *pool;
  u32 reass_n;
  u32 buffers_n;
  u32 id_counter;
  clib_spinlock_t lock;
} ip6_reass_per_thread_t;

typedef struct
{
  // IPv6 config
  u32 timeout_ms;
  f64 timeout;
  u32 expire_walk_interval_ms;
  u32 max_reass_n;

  // IPv6 runtime
  clib_bihash_48_8_t hash;

  // per-thread data
  ip6_reass_per_thread_t *per_thread_data;

  // convenience
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  // node index of ip6-drop node
  u32 ip6_drop_idx;
  u32 ip6_icmp_error_idx;
  u32 ip6_reass_expire_node_idx;

} ip6_reass_main_t;

ip6_reass_main_t ip6_reass_main;

typedef enum
{
  IP6_REASSEMBLY_NEXT_INPUT,
  IP6_REASSEMBLY_NEXT_DROP,
  IP6_REASSEMBLY_NEXT_ICMP_ERROR,
  IP6_REASSEMBLY_N_NEXT,
} ip6_reass_next_t;

typedef enum
{
  RANGE_NEW,
  RANGE_OVERLAP,
  ICMP_ERROR_RT_EXCEEDED,
  ICMP_ERROR_FL_TOO_BIG,
  ICMP_ERROR_FL_NOT_MULT_8,
  FINALIZE,
} ip6_reass_trace_operation_e;

typedef struct
{
  u16 range_first;
  u16 range_last;
  u32 range_bi;
  i32 data_offset;
  u32 data_len;
  u32 first_bi;
} ip6_reass_range_trace_t;

typedef struct
{
  ip6_reass_trace_operation_e action;
  u32 reass_id;
  ip6_reass_range_trace_t trace_range;
  u32 size_diff;
  u32 op_id;
  u32 fragment_first;
  u32 fragment_last;
  u32 total_data_len;
} ip6_reass_trace_t;

static void
ip6_reass_trace_details (vlib_main_t * vm, u32 bi,
			 ip6_reass_range_trace_t * trace)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  trace->range_first = vnb->ip.reass.range_first;
  trace->range_last = vnb->ip.reass.range_last;
  trace->data_offset = ip6_reass_buffer_get_data_offset_no_check (b);
  trace->data_len = ip6_reass_buffer_get_data_len_no_check (b);
  trace->range_bi = bi;
}

static u8 *
format_ip6_reass_range_trace (u8 * s, va_list * args)
{
  ip6_reass_range_trace_t *trace = va_arg (*args, ip6_reass_range_trace_t *);
  s = format (s, "range: [%u, %u], off %d, len %u, bi %u", trace->range_first,
	      trace->range_last, trace->data_offset, trace->data_len,
	      trace->range_bi);
  return s;
}

static u8 *
format_ip6_reass_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_reass_trace_t *t = va_arg (*args, ip6_reass_trace_t *);
  s = format (s, "reass id: %u, op id: %u ", t->reass_id, t->op_id);
  u32 indent = format_get_indent (s);
  s = format (s, "first bi: %u, data len: %u, ip/fragment[%u, %u]",
	      t->trace_range.first_bi, t->total_data_len, t->fragment_first,
	      t->fragment_last);
  switch (t->action)
    {
    case RANGE_NEW:
      s = format (s, "\n%Unew %U", format_white_space, indent,
		  format_ip6_reass_range_trace, &t->trace_range);
      break;
    case RANGE_OVERLAP:
      s = format (s, "\n%Uoverlap %U", format_white_space, indent,
		  format_ip6_reass_range_trace, &t->trace_range);
      break;
    case ICMP_ERROR_FL_TOO_BIG:
      s = format (s, "\n%Uicmp-error - frag_len > 65535 %U",
		  format_white_space, indent, format_ip6_reass_range_trace,
		  &t->trace_range);
      break;
    case ICMP_ERROR_FL_NOT_MULT_8:
      s = format (s, "\n%Uicmp-error - frag_len mod 8 != 0 %U",
		  format_white_space, indent, format_ip6_reass_range_trace,
		  &t->trace_range);
      break;
    case ICMP_ERROR_RT_EXCEEDED:
      s = format (s, "\n%Uicmp-error - reassembly time exceeded",
		  format_white_space, indent);
      break;
    case FINALIZE:
      s = format (s, "\n%Ufinalize reassembly", format_white_space, indent);
      break;
    }
  return s;
}

static void
ip6_reass_add_trace (vlib_main_t * vm, vlib_node_runtime_t * node,
		     ip6_reass_main_t * rm, ip6_reass_t * reass,
		     u32 bi, ip6_reass_trace_operation_e action,
		     u32 size_diff)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vnet_buffer_opaque_t *vnb = vnet_buffer (b);
  if (pool_is_free_index (vm->trace_main.trace_buffer_pool, b->trace_index))
    {
      // this buffer's trace is gone
      b->flags &= ~VLIB_BUFFER_IS_TRACED;
      return;
    }
  ip6_reass_trace_t *t = vlib_add_trace (vm, node, b, sizeof (t[0]));
  t->reass_id = reass->id;
  t->action = action;
  ip6_reass_trace_details (vm, bi, &t->trace_range);
  t->size_diff = size_diff;
  t->op_id = reass->trace_op_counter;
  ++reass->trace_op_counter;
  t->fragment_first = vnb->ip.reass.fragment_first;
  t->fragment_last = vnb->ip.reass.fragment_last;
  t->trace_range.first_bi = reass->first_bi;
  t->total_data_len = reass->data_len;
#if 0
  static u8 *s = NULL;
  s = format (s, "%U", format_ip6_reass_trace, NULL, NULL, t);
  printf ("%.*s\n", vec_len (s), s);
  fflush (stdout);
  vec_reset_length (s);
#endif
}

always_inline void
ip6_reass_free (ip6_reass_main_t * rm, ip6_reass_per_thread_t * rt,
		ip6_reass_t * reass)
{
  clib_bihash_kv_48_8_t kv;
  kv.key[0] = reass->key.as_u64[0];
  kv.key[1] = reass->key.as_u64[1];
  kv.key[2] = reass->key.as_u64[2];
  kv.key[3] = reass->key.as_u64[3];
  kv.key[4] = reass->key.as_u64[4];
  kv.key[5] = reass->key.as_u64[5];
  clib_bihash_add_del_48_8 (&rm->hash, &kv, 0);
  pool_put (rt->pool, reass);
  --rt->reass_n;
}

always_inline void
ip6_reass_drop_all (vlib_main_t * vm, ip6_reass_main_t * rm,
		    ip6_reass_t * reass, u32 ** vec_drop_bi)
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
	  vec_add1 (*vec_drop_bi, bi);
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

always_inline void
ip6_reass_on_timeout (vlib_main_t * vm, vlib_node_runtime_t * node,
		      ip6_reass_main_t * rm, ip6_reass_t * reass,
		      u32 * icmp_bi, u32 ** vec_timeout)
{
  if (~0 == reass->first_bi)
    {
      return;
    }
  vlib_buffer_t *b = vlib_get_buffer (vm, reass->first_bi);
  if (0 == vnet_buffer (b)->ip.reass.fragment_first)
    {
      *icmp_bi = reass->first_bi;
      if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ip6_reass_add_trace (vm, node, rm, reass, reass->first_bi,
			       ICMP_ERROR_RT_EXCEEDED, 0);
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
  ip6_reass_drop_all (vm, rm, reass, vec_timeout);
}

always_inline ip6_reass_t *
ip6_reass_find_or_create (vlib_main_t * vm, vlib_node_runtime_t * node,
			  ip6_reass_main_t * rm, ip6_reass_per_thread_t * rt,
			  ip6_reass_key_t * k, u32 * icmp_bi,
			  u32 ** vec_timeout)
{
  ip6_reass_t *reass = NULL;
  f64 now = vlib_time_now (rm->vlib_main);
  clib_bihash_kv_48_8_t kv, value;
  kv.key[0] = k->as_u64[0];
  kv.key[1] = k->as_u64[1];
  kv.key[2] = k->as_u64[2];
  kv.key[3] = k->as_u64[3];
  kv.key[4] = k->as_u64[4];
  kv.key[5] = k->as_u64[5];

  if (!clib_bihash_search_48_8 (&rm->hash, &kv, &value))
    {
      reass = pool_elt_at_index (rt->pool, value.value);
      if (now > reass->last_heard + rm->timeout)
	{
	  ip6_reass_on_timeout (vm, node, rm, reass, icmp_bi, vec_timeout);
	  ip6_reass_free (rm, rt, reass);
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
      memset (reass, 0, sizeof (*reass));
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
  reass->key.as_u64[2] = kv.key[2] = k->as_u64[2];
  reass->key.as_u64[3] = kv.key[3] = k->as_u64[3];
  reass->key.as_u64[4] = kv.key[4] = k->as_u64[4];
  reass->key.as_u64[5] = kv.key[5] = k->as_u64[5];
  kv.value = reass - rt->pool;
  reass->last_heard = now;

  if (clib_bihash_add_del_48_8 (&rm->hash, &kv, 1))
    {
      ip6_reass_free (rm, rt, reass);
      reass = NULL;
    }

  return reass;
}

always_inline void
ip6_reass_finalize (vlib_main_t * vm, vlib_node_runtime_t * node,
		    ip6_reass_main_t * rm, ip6_reass_per_thread_t * rt,
		    ip6_reass_t * reass, u32 * bi0, u32 * next0,
		    u32 * error0, u32 ** vec_drop_compress, bool is_feature)
{
  ASSERT (~0 != reass->first_bi);
  *bi0 = reass->first_bi;
  *error0 = IP6_ERROR_NONE;
  ip6_frag_hdr_t *frag_hdr;
  vlib_buffer_t *last_b = NULL;
  u32 sub_chain_bi = reass->first_bi;
  u32 total_length = 0;
  u32 buf_cnt = 0;
  u32 dropped_cnt = 0;
  do
    {
      u32 tmp_bi = sub_chain_bi;
      vlib_buffer_t *tmp = vlib_get_buffer (vm, tmp_bi);
      u32 data_len = ip6_reass_buffer_get_data_len (tmp);
      u32 trim_front = vnet_buffer (tmp)->ip.reass.ip6_frag_hdr_offset +
	sizeof (*frag_hdr) + ip6_reass_buffer_get_data_offset (tmp);
      u32 trim_end =
	vlib_buffer_length_in_chain (vm, tmp) - trim_front - data_len;
      if (tmp_bi == reass->first_bi)
	{
	  /* first buffer - keep ip6 header */
	  ASSERT (0 == ip6_reass_buffer_get_data_offset (tmp));
	  trim_front = 0;
	  trim_end = vlib_buffer_length_in_chain (vm, tmp) - data_len -
	    (vnet_buffer (tmp)->ip.reass.ip6_frag_hdr_offset +
	     sizeof (*frag_hdr));
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
	      vec_add1 (*vec_drop_compress, tmp_bi);
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
  vlib_buffer_t *first_b = vlib_get_buffer (vm, reass->first_bi);
  ASSERT (total_length >= first_b->current_length);
  total_length -= first_b->current_length;
  first_b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  first_b->total_length_not_including_first_buffer = total_length;
  // drop fragment header
  vnet_buffer_opaque_t *first_b_vnb = vnet_buffer (first_b);
  ip6_header_t *ip = vlib_buffer_get_current (first_b);
  u16 ip6_frag_hdr_offset = first_b_vnb->ip.reass.ip6_frag_hdr_offset;
  ip6_ext_header_t *prev_hdr;
  ip6_ext_header_find_t (ip, prev_hdr, frag_hdr,
			 IP_PROTOCOL_IPV6_FRAGMENTATION);
  if (prev_hdr)
    {
      prev_hdr->next_hdr = frag_hdr->next_hdr;
    }
  else
    {
      ip->protocol = frag_hdr->next_hdr;
    }
  ASSERT ((u8 *) frag_hdr - (u8 *) ip == ip6_frag_hdr_offset);
  memmove (frag_hdr, (u8 *) frag_hdr + sizeof (*frag_hdr),
	   first_b->current_length - ip6_frag_hdr_offset -
	   sizeof (ip6_frag_hdr_t));
  first_b->current_length -= sizeof (*frag_hdr);
  ip->payload_length =
    clib_host_to_net_u16 (total_length + first_b->current_length -
			  sizeof (*ip));
  vlib_buffer_chain_compress (vm, first_b, vec_drop_compress);
  if (PREDICT_FALSE (first_b->flags & VLIB_BUFFER_IS_TRACED))
    {
      ip6_reass_add_trace (vm, node, rm, reass, reass->first_bi, FINALIZE, 0);
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
  if (is_feature)
    {
      *next0 = IP6_REASSEMBLY_NEXT_INPUT;
    }
  else
    {
      *next0 = reass->next_index;
    }
  vnet_buffer (first_b)->ip.reass.estimated_mtu = reass->min_fragment_length;
  ip6_reass_free (rm, rt, reass);
  reass = NULL;
}

always_inline u32
ip6_reass_get_buffer_chain_length (vlib_main_t * vm, vlib_buffer_t * b)
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
ip6_reass_insert_range_in_chain (vlib_main_t * vm, ip6_reass_main_t * rm,
				 ip6_reass_per_thread_t * rt,
				 ip6_reass_t * reass, u32 prev_range_bi,
				 u32 new_next_bi)
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
  reass->data_len += ip6_reass_buffer_get_data_len (new_next_b);
  rt->buffers_n += ip6_reass_get_buffer_chain_length (vm, new_next_b);
}

always_inline void
ip6_reass_update (vlib_main_t * vm, vlib_node_runtime_t * node,
		  ip6_reass_main_t * rm, ip6_reass_per_thread_t * rt,
		  ip6_reass_t * reass, u32 * bi0, u32 * next0,
		  u32 * error0, ip6_frag_hdr_t * frag_hdr,
		  u32 ** vec_drop_overlap, u32 ** vec_drop_compress,
		  bool is_feature)
{
  int consumed = 0;
  vlib_buffer_t *fb = vlib_get_buffer (vm, *bi0);
  vnet_buffer_opaque_t *fvnb = vnet_buffer (fb);
  reass->next_index = fvnb->ip.reass.next_index;	// store next_index before it's overwritten
  fvnb->ip.reass.ip6_frag_hdr_offset =
    (u8 *) frag_hdr - (u8 *) vlib_buffer_get_current (fb);
  ip6_header_t *fip = vlib_buffer_get_current (fb);
  ASSERT (fb->current_length > sizeof (*fip));
  ASSERT (fvnb->ip.reass.ip6_frag_hdr_offset > 0 &&
	  fvnb->ip.reass.ip6_frag_hdr_offset < fb->current_length);
  u32 fragment_first = fvnb->ip.reass.fragment_first =
    ip6_frag_hdr_offset_bytes (frag_hdr);
  u32 fragment_length =
    vlib_buffer_length_in_chain (vm, fb) -
    (fvnb->ip.reass.ip6_frag_hdr_offset + sizeof (*frag_hdr));
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
      ip6_reass_insert_range_in_chain (vm, rm, rt, reass, prev_range_bi,
				       *bi0);
      if (PREDICT_FALSE (fb->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ip6_reass_add_trace (vm, node, rm, reass, *bi0, RANGE_NEW, 0);
	}
      reass->min_fragment_length = clib_net_to_host_u16 (fip->payload_length);
      *bi0 = ~0;
      return;
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
	      ip6_reass_insert_range_in_chain (vm, rm, rt, reass,
					       prev_range_bi, *bi0);
	      consumed = 1;
	      break;
	    }
	  continue;
	}
      if (fragment_last < candidate_vnb->ip.reass.range_first)
	{
	  // this fragment ends before candidate range without any overlap
	  ip6_reass_insert_range_in_chain (vm, rm, rt, reass, prev_range_bi,
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
	  ip6_reass_drop_all (vm, rm, reass, vec_drop_overlap);
	  ip6_reass_free (rm, rt, reass);
	  if (PREDICT_FALSE (fb->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ip6_reass_add_trace (vm, node, rm, reass, *bi0, RANGE_OVERLAP,
				   0);
	    }
	  *next0 = IP6_REASSEMBLY_NEXT_DROP;
	  *error0 = IP6_ERROR_REASS_OVERLAPPING_FRAGMENT;
	}
      break;
    }
  if (consumed)
    {
      if (PREDICT_FALSE (fb->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ip6_reass_add_trace (vm, node, rm, reass, *bi0, RANGE_NEW, 0);
	}
    }
  if (~0 != reass->last_packet_octet &&
      reass->data_len == reass->last_packet_octet + 1)
    {
      ip6_reass_finalize (vm, node, rm, rt, reass, bi0, next0, error0,
			  vec_drop_compress, is_feature);
    }
  else
    {
      if (consumed)
	{
	  *bi0 = ~0;
	}
      else
	{
	  *next0 = IP6_REASSEMBLY_NEXT_DROP;
	  ;
	  *error0 = IP6_ERROR_REASS_DUPLICATE_FRAGMENT;
	}
    }
}

always_inline bool
ip6_reass_verify_upper_layer_present (vlib_node_runtime_t * node,
				      vlib_buffer_t * b,
				      ip6_frag_hdr_t * frag_hdr)
{
  ip6_ext_header_t *tmp = (ip6_ext_header_t *) frag_hdr;
  while (ip6_ext_hdr (tmp->next_hdr))
    {
      tmp = ip6_ext_next_header (tmp);
    }
  if (IP_PROTOCOL_IP6_NONXT == tmp->next_hdr)
    {
      icmp6_error_set_vnet_buffer (b, ICMP6_parameter_problem,
				   ICMP6_parameter_problem_first_fragment_has_incomplete_header_chain,
				   0);
      b->error = node->errors[IP6_ERROR_REASS_MISSING_UPPER];

      return false;
    }
  return true;
}

always_inline bool
ip6_reass_verify_fragment_multiple_8 (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
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
ip6_reass_verify_packet_size_lt_64k (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
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
ip6_reassembly_inline (vlib_main_t * vm,
		       vlib_node_runtime_t * node,
		       vlib_frame_t * frame, bool is_feature)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from, n_left_to_next, *to_next, next_index;
  ip6_reass_main_t *rm = &ip6_reass_main;
  ip6_reass_per_thread_t *rt = &rm->per_thread_data[os_get_thread_index ()];
  clib_spinlock_lock (&rt->lock);

  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  static u32 *vec_timeout = NULL;	// indexes of buffers which timed out
  static u32 *vec_drop_overlap = NULL;	// indexes of buffers dropped due to overlap
  static u32 *vec_drop_compress = NULL;	// indexes of buffers dropped due to buffer compression
  while (n_left_from > 0 || vec_len (vec_timeout) > 0 ||
	 vec_len (vec_drop_overlap) > 0 || vec_len (vec_drop_compress) > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (vec_len (vec_timeout) > 0 && n_left_to_next > 0)
	{
	  u32 bi = vec_pop (vec_timeout);
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	  b->error = node->errors[IP6_ERROR_REASS_TIMEOUT];
	  to_next[0] = bi;
	  to_next += 1;
	  n_left_to_next -= 1;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi,
					   IP6_REASSEMBLY_NEXT_DROP);
	  ASSERT (rt->buffers_n > 0);
	  --rt->buffers_n;
	}

      while (vec_len (vec_drop_overlap) > 0 && n_left_to_next > 0)
	{
	  u32 bi = vec_pop (vec_drop_overlap);
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	  b->error = node->errors[IP6_ERROR_REASS_OVERLAPPING_FRAGMENT];
	  to_next[0] = bi;
	  to_next += 1;
	  n_left_to_next -= 1;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi,
					   IP6_REASSEMBLY_NEXT_DROP);
	  ASSERT (rt->buffers_n > 0);
	  --rt->buffers_n;
	}

      while (vec_len (vec_drop_compress) > 0 && n_left_to_next > 0)
	{
	  u32 bi = vec_pop (vec_drop_compress);
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	  b->error = node->errors[IP6_ERROR_NONE];
	  to_next[0] = bi;
	  to_next += 1;
	  n_left_to_next -= 1;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi,
					   IP6_REASSEMBLY_NEXT_DROP);
	  ASSERT (rt->buffers_n > 0);
	  --rt->buffers_n;
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  u32 error0 = IP6_ERROR_NONE;
	  u32 icmp_bi = ~0;

	  bi0 = from[0];
	  b0 = vlib_get_buffer (vm, bi0);

	  ip6_header_t *ip0 = vlib_buffer_get_current (b0);
	  ip6_frag_hdr_t *frag_hdr = NULL;
	  ip6_ext_header_t *prev_hdr;
	  if (ip6_ext_hdr (ip0->protocol))
	    {
	      ip6_ext_header_find_t (ip0, prev_hdr, frag_hdr,
				     IP_PROTOCOL_IPV6_FRAGMENTATION);
	    }
	  if (!frag_hdr)
	    {
	      // this is a regular packet - no fragmentation
	      next0 = IP6_REASSEMBLY_NEXT_INPUT;
	      goto skip_reass;
	    }
	  if (0 == ip6_frag_hdr_offset (frag_hdr))
	    {
	      // first fragment - verify upper-layer is present
	      if (!ip6_reass_verify_upper_layer_present (node, b0, frag_hdr))
		{
		  next0 = IP6_REASSEMBLY_NEXT_ICMP_ERROR;
		  goto skip_reass;
		}
	    }
	  if (!ip6_reass_verify_fragment_multiple_8 (vm, node, b0, frag_hdr)
	      || !ip6_reass_verify_packet_size_lt_64k (vm, node, b0,
						       frag_hdr))
	    {
	      next0 = IP6_REASSEMBLY_NEXT_ICMP_ERROR;
	      goto skip_reass;
	    }
	  vnet_buffer (b0)->ip.reass.ip6_frag_hdr_offset =
	    (u8 *) frag_hdr - (u8 *) ip0;

	  ip6_reass_key_t k;
	  k.as_u64[0] = ip0->src_address.as_u64[0];
	  k.as_u64[1] = ip0->src_address.as_u64[1];
	  k.as_u64[2] = ip0->dst_address.as_u64[0];
	  k.as_u64[3] = ip0->dst_address.as_u64[1];
	  k.as_u64[4] =
	    (u64) vnet_buffer (b0)->
	    sw_if_index[VLIB_RX] << 32 | frag_hdr->identification;
	  k.as_u64[5] = ip0->protocol;
	  ip6_reass_t *reass =
	    ip6_reass_find_or_create (vm, node, rm, rt, &k, &icmp_bi,
				      &vec_timeout);

	  if (reass)
	    {
	      ip6_reass_update (vm, node, rm, rt, reass, &bi0, &next0,
				&error0, frag_hdr, &vec_drop_overlap,
				&vec_drop_compress, is_feature);
	    }
	  else
	    {
	      next0 = IP6_REASSEMBLY_NEXT_DROP;
	      error0 = IP6_ERROR_REASS_LIMIT_REACHED;
	    }

	  b0->error = node->errors[error0];

	  if (~0 != bi0)
	    {
	    skip_reass:
	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	      if (is_feature && IP6_ERROR_NONE == error0)
		{
		  b0 = vlib_get_buffer (vm, bi0);
		  vnet_feature_next (&next0, b0);
		}
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, bi0, next0);
	    }

	  if (~0 != icmp_bi)
	    {
	      next0 = IP6_REASSEMBLY_NEXT_ICMP_ERROR;
	      to_next[0] = icmp_bi;
	      to_next += 1;
	      n_left_to_next -= 1;
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, icmp_bi,
					       next0);
	    }
	  from += 1;
	  n_left_from -= 1;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  clib_spinlock_unlock (&rt->lock);
  return frame->n_vectors;
}

static char *ip6_reassembly_error_strings[] = {
#define _(sym, string) string,
  foreach_ip6_error
#undef _
};

static uword
ip6_reassembly (vlib_main_t * vm, vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{
  return ip6_reassembly_inline (vm, node, frame, false /* is_feature */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_reass_node, static) = {
    .function = ip6_reassembly,
    .name = "ip6-reassembly",
    .vector_size = sizeof (u32),
    .format_trace = format_ip6_reass_trace,
    .n_errors = ARRAY_LEN (ip6_reassembly_error_strings),
    .error_strings = ip6_reassembly_error_strings,
    .n_next_nodes = IP6_REASSEMBLY_N_NEXT,
    .next_nodes =
        {
                [IP6_REASSEMBLY_NEXT_INPUT] = "ip6-input",
                [IP6_REASSEMBLY_NEXT_DROP] = "ip6-drop",
                [IP6_REASSEMBLY_NEXT_ICMP_ERROR] = "ip6-icmp-error",
        },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (ip6_reass_node, ip6_reassembly);

static uword
ip6_reassembly_feature (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return ip6_reassembly_inline (vm, node, frame, true /* is_feature */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_reass_node_feature, static) = {
    .function = ip6_reassembly_feature,
    .name = "ip6-reassembly-feature",
    .vector_size = sizeof (u32),
    .format_trace = format_ip6_reass_trace,
    .n_errors = ARRAY_LEN (ip6_reassembly_error_strings),
    .error_strings = ip6_reassembly_error_strings,
    .n_next_nodes = IP6_REASSEMBLY_N_NEXT,
    .next_nodes =
        {
                [IP6_REASSEMBLY_NEXT_INPUT] = "ip6-input",
                [IP6_REASSEMBLY_NEXT_DROP] = "ip6-drop",
                [IP6_REASSEMBLY_NEXT_ICMP_ERROR] = "ip6-icmp-error",
        },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (ip6_reass_node_feature, ip6_reassembly_feature);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (ip6_reassembly_feature, static) = {
    .arc_name = "ip6-unicast",
    .node_name = "ip6-reassembly-feature",
    .runs_before = VNET_FEATURES ("ip6-lookup"),
    .runs_after = 0,
};
/* *INDENT-ON* */

static u32
ip6_reass_get_nbuckets ()
{
  ip6_reass_main_t *rm = &ip6_reass_main;
  u32 nbuckets;
  u8 i;

  nbuckets = (u32) (rm->max_reass_n / IP6_REASS_HT_LOAD_FACTOR);

  for (i = 0; i < 31; i++)
    if ((1 << i) >= nbuckets)
      break;
  nbuckets = 1 << i;

  return nbuckets;
}

typedef enum
{
  IP6_EVENT_CONFIG_CHANGED = 1,
} ip6_reass_event_t;

typedef struct
{
  int failure;
  clib_bihash_48_8_t *new_hash;
} ip6_rehash_cb_ctx;

static void
ip6_rehash_cb (clib_bihash_kv_48_8_t * kv, void *_ctx)
{
  ip6_rehash_cb_ctx *ctx = _ctx;
  if (clib_bihash_add_del_48_8 (ctx->new_hash, kv, 1))
    {
      ctx->failure = 1;
    }
}

static void
ip6_reass_set_params (u32 timeout_ms, u32 max_reassemblies,
		      u32 expire_walk_interval_ms)
{
  ip6_reass_main.timeout_ms = timeout_ms;
  ip6_reass_main.timeout = (f64) timeout_ms / (f64) MSEC_PER_SEC;
  ip6_reass_main.max_reass_n = max_reassemblies;
  ip6_reass_main.expire_walk_interval_ms = expire_walk_interval_ms;
}

vnet_api_error_t
ip6_reass_set (u32 timeout_ms, u32 max_reassemblies,
	       u32 expire_walk_interval_ms)
{
  u32 old_nbuckets = ip6_reass_get_nbuckets ();
  ip6_reass_set_params (timeout_ms, max_reassemblies,
			expire_walk_interval_ms);
  vlib_process_signal_event (ip6_reass_main.vlib_main,
			     ip6_reass_main.ip6_reass_expire_node_idx,
			     IP6_EVENT_CONFIG_CHANGED, 0);
  u32 new_nbuckets = ip6_reass_get_nbuckets ();
  if (ip6_reass_main.max_reass_n > 0 && new_nbuckets > old_nbuckets)
    {
      clib_bihash_48_8_t new_hash;
      memset (&new_hash, 0, sizeof (new_hash));
      ip6_rehash_cb_ctx ctx;
      ctx.failure = 0;
      ctx.new_hash = &new_hash;
      clib_bihash_init_48_8 (&new_hash, "ip6-reass", new_nbuckets,
			     new_nbuckets * 1024);
      clib_bihash_foreach_key_value_pair_48_8 (&ip6_reass_main.hash,
					       ip6_rehash_cb, &ctx);
      if (ctx.failure)
	{
	  clib_bihash_free_48_8 (&new_hash);
	  return -1;
	}
      else
	{
	  clib_bihash_free_48_8 (&ip6_reass_main.hash);
	  clib_memcpy (&ip6_reass_main.hash, &new_hash,
		       sizeof (ip6_reass_main.hash));
	}
    }
  return 0;
}

vnet_api_error_t
ip6_reass_get (u32 * timeout_ms, u32 * max_reassemblies,
	       u32 * expire_walk_interval_ms)
{
  *timeout_ms = ip6_reass_main.timeout_ms;
  *max_reassemblies = ip6_reass_main.max_reass_n;
  *expire_walk_interval_ms = ip6_reass_main.expire_walk_interval_ms;
  return 0;
}

static clib_error_t *
ip6_reass_init_function (vlib_main_t * vm)
{
  ip6_reass_main_t *rm = &ip6_reass_main;
  clib_error_t *error = 0;
  u32 nbuckets;
  vlib_node_t *node;

  rm->vlib_main = vm;
  rm->vnet_main = vnet_get_main ();

  vec_validate (rm->per_thread_data, vlib_num_workers ());
  ip6_reass_per_thread_t *rt;
  vec_foreach (rt, rm->per_thread_data)
  {
    clib_spinlock_init (&rt->lock);
    pool_alloc (rt->pool, rm->max_reass_n);
  }

  node = vlib_get_node_by_name (vm, (u8 *) "ip6-reassembly-expire-walk");
  ASSERT (node);
  rm->ip6_reass_expire_node_idx = node->index;

  ip6_reass_set_params (IP6_REASS_TIMEOUT_DEFAULT_MS,
			IP6_REASS_MAX_REASSEMBLIES_DEFAULT,
			IP6_REASS_EXPIRE_WALK_INTERVAL_DEFAULT_MS);

  nbuckets = ip6_reass_get_nbuckets ();
  clib_bihash_init_48_8 (&rm->hash, "ip6-reass", nbuckets, nbuckets * 1024);

  node = vlib_get_node_by_name (vm, (u8 *) "ip6-drop");
  ASSERT (node);
  rm->ip6_drop_idx = node->index;
  node = vlib_get_node_by_name (vm, (u8 *) "ip6-icmp-error");
  ASSERT (node);
  rm->ip6_icmp_error_idx = node->index;

  if ((error = vlib_call_init_function (vm, ip_main_init)))
    return error;
  ip6_register_protocol (IP_PROTOCOL_IPV6_FRAGMENTATION,
			 ip6_reass_node.index);

  return error;
}

VLIB_INIT_FUNCTION (ip6_reass_init_function);

static uword
ip6_reass_walk_expired (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * f)
{
  ip6_reass_main_t *rm = &ip6_reass_main;
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
	case IP6_EVENT_CONFIG_CHANGED:
	  break;
	default:
	  clib_warning ("BUG: event type 0x%wx", event_type);
	  break;
	}
      f64 now = vlib_time_now (vm);

      ip6_reass_t *reass;
      u32 *vec_timeout = NULL;
      int *pool_indexes_to_free = NULL;

      uword thread_index = 0;
      int index;
      const uword nthreads = vlib_num_workers () + 1;
      u32 *vec_icmp_bi = NULL;
      for (thread_index = 0; thread_index < nthreads; ++thread_index)
	{
	  ip6_reass_per_thread_t *rt = &rm->per_thread_data[thread_index];
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
            ip6_reass_t *reass = pool_elt_at_index (rt->pool, i[0]);
            u32 icmp_bi = ~0;
            u32 before = vec_len (vec_timeout);
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
            ip6_reass_on_timeout (vm, node, rm, reass, &icmp_bi, &vec_timeout);
            u32 after = vec_len (vec_timeout);
            ASSERT (rt->buffers_n >= (after - before));
            rt->buffers_n -= (after - before);
            if (~0 != icmp_bi)
              {
                vec_add1 (vec_icmp_bi, icmp_bi);
                ASSERT (rt->buffers_n > 0);
                --rt->buffers_n;
              }
            ip6_reass_free (rm, rt, reass);
          }
          /* *INDENT-ON* */

	  clib_spinlock_unlock (&rt->lock);
	}

      while (vec_len (vec_timeout) > 0)
	{
	  vlib_frame_t *f = vlib_get_frame_to_node (vm, rm->ip6_drop_idx);
	  u32 *to_next = vlib_frame_vector_args (f);
	  u32 n_left_to_next = VLIB_FRAME_SIZE - f->n_vectors;
	  int trace_frame = 0;
	  while (vec_len (vec_timeout) > 0 && n_left_to_next > 0)
	    {
	      u32 bi = vec_pop (vec_timeout);
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
	      b->error = node->errors[IP6_ERROR_REASS_TIMEOUT];
	      to_next[0] = bi;
	      ++f->n_vectors;
	      to_next += 1;
	      n_left_to_next -= 1;
	    }
	  f->frame_flags |= (trace_frame * VLIB_FRAME_TRACE);
	  vlib_put_frame_to_node (vm, rm->ip6_drop_idx, f);
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
      vec_free (vec_timeout);
      vec_free (vec_icmp_bi);
      if (event_data)
	{
	  _vec_len (event_data) = 0;
	}
    }

  return 0;
}

static vlib_node_registration_t ip6_reass_expire_node;

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_reass_expire_node, static) = {
    .function = ip6_reass_walk_expired,
    .format_trace = format_ip6_reass_trace,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "ip6-reassembly-expire-walk",

    .n_errors = ARRAY_LEN (ip6_reassembly_error_strings),
    .error_strings = ip6_reassembly_error_strings,

};
/* *INDENT-ON* */

static u8 *
format_ip6_reass_key (u8 * s, va_list * args)
{
  ip6_reass_key_t *key = va_arg (*args, ip6_reass_key_t *);
  s = format (s, "xx_id: %u, src: %U, dst: %U, frag_id: %u, proto: %u",
	      key->xx_id, format_ip6_address, &key->src, format_ip6_address,
	      &key->dst, clib_net_to_host_u16 (key->frag_id), key->proto);
  return s;
}

static u8 *
format_ip6_reass (u8 * s, va_list * args)
{
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  ip6_reass_t *reass = va_arg (*args, ip6_reass_t *);

  s = format (s, "ID: %lu, key: %U\n  first_bi: %u, data_len: %u, "
	      "last_packet_octet: %u, trace_op_counter: %u\n",
	      reass->id, format_ip6_reass_key, &reass->key, reass->first_bi,
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
		  ip6_reass_buffer_get_data_offset_no_check (b),
		  ip6_reass_buffer_get_data_len_no_check (b),
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
show_ip6_reass (vlib_main_t * vm, unformat_input_t * input,
		CLIB_UNUSED (vlib_cli_command_t * lmd))
{
  ip6_reass_main_t *rm = &ip6_reass_main;

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
  ip6_reass_t *reass;
  uword thread_index;
  const uword nthreads = vlib_num_workers () + 1;
  for (thread_index = 0; thread_index < nthreads; ++thread_index)
    {
      ip6_reass_per_thread_t *rt = &rm->per_thread_data[thread_index];
      clib_spinlock_lock (&rt->lock);
      if (details)
	{
          /* *INDENT-OFF* */
          pool_foreach (reass, rt->pool, {
            vlib_cli_output (vm, "%U", format_ip6_reass, vm, reass);
          });
          /* *INDENT-ON* */
	}
      sum_reass_n += rt->reass_n;
      sum_buffers_n += rt->buffers_n;
      clib_spinlock_unlock (&rt->lock);
    }
  vlib_cli_output (vm, "---------------------");
  vlib_cli_output (vm, "Current IP6 reassemblies count: %lu\n",
		   (long unsigned) sum_reass_n);
  vlib_cli_output (vm, "Maximum configured concurrent IP6 reassemblies per "
		   "worker-thread: %lu\n", (long unsigned) rm->max_reass_n);
  vlib_cli_output (vm, "Buffers in use: %lu\n",
		   (long unsigned) sum_buffers_n);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip6_reassembly_cmd, static) = {
    .path = "show ip6-reassembly",
    .short_help = "show ip6-reassembly [details]",
    .function = show_ip6_reass,
};
/* *INDENT-ON* */

vnet_api_error_t
ip6_reass_enable_disable (u32 sw_if_index, u8 enable_disable)
{
  return vnet_feature_enable_disable ("ip6-unicast", "ip6-reassembly-feature",
				      sw_if_index, enable_disable, 0, 0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
