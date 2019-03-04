/*
 * ct6_in2out.c - ip6 connection tracker, inside-to-outside path
 *
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <ct6/ct6.h>

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u32 session_index;
} ct6_in2out_trace_t;

#ifndef CLIB_MARCH_VARIANT

/* packet trace format function */
static u8 *
format_ct6_in2out_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ct6_in2out_trace_t *t = va_arg (*args, ct6_in2out_trace_t *);

  s = format (s, "CT6_IN2OUT: sw_if_index %d, next index %d session %d\n",
	      t->sw_if_index, t->next_index, t->session_index);
  return s;
}

vlib_node_registration_t ct6_in2out_node;

#endif /* CLIB_MARCH_VARIANT */

#define foreach_ct6_in2out_error                \
_(PROCESSED, "ct6 packets processed")           \
_(CREATED, "ct6 sessions created")              \
_(RECYCLED, "ct6 sessions recycled")

typedef enum
{
#define _(sym,str) CT6_IN2OUT_ERROR_##sym,
  foreach_ct6_in2out_error
#undef _
    CT6_IN2OUT_N_ERROR,
} ct6_in2out_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *ct6_in2out_error_strings[] = {
#define _(sym,string) string,
  foreach_ct6_in2out_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  CT6_IN2OUT_NEXT_DROP,
  CT6_IN2OUT_N_NEXT,
} ct6_next_t;

always_inline uword
ct6_in2out_inline (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame,
		   int is_trace)
{
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  ct6_main_t *cmp = &ct6_main;
  u32 my_thread_index = vm->thread_index;
  f64 now = vlib_time_now (vm);
  u32 created = 0;
  u32 recycled = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

#if 0
  while (n_left_from >= 4)
    {
      /* Prefetch next iteration. */
      if (PREDICT_TRUE (n_left_from >= 8))
	{
	  vlib_prefetch_buffer_header (b[4], STORE);
	  vlib_prefetch_buffer_header (b[5], STORE);
	  vlib_prefetch_buffer_header (b[6], STORE);
	  vlib_prefetch_buffer_header (b[7], STORE);
	  CLIB_PREFETCH (b[4]->data, CLIB_CACHE_LINE_BYTES, STORE);
	  CLIB_PREFETCH (b[5]->data, CLIB_CACHE_LINE_BYTES, STORE);
	  CLIB_PREFETCH (b[6]->data, CLIB_CACHE_LINE_BYTES, STORE);
	  CLIB_PREFETCH (b[7]->data, CLIB_CACHE_LINE_BYTES, STORE);
	}

      /* $$$$ process 4x pkts right here */
      next[0] = 0;
      next[1] = 0;
      next[2] = 0;
      next[3] = 0;

      if (is_trace)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      ct6_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->next_index = next[0];
	      t->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	    }
	  if (b[1]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      ct6_trace_t *t = vlib_add_trace (vm, node, b[1], sizeof (*t));
	      t->next_index = next[1];
	      t->sw_if_index = vnet_buffer (b[1])->sw_if_index[VLIB_RX];
	    }
	  if (b[2]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      ct6_trace_t *t = vlib_add_trace (vm, node, b[2], sizeof (*t));
	      t->next_index = next[2];
	      t->sw_if_index = vnet_buffer (b[2])->sw_if_index[VLIB_RX];
	    }
	  if (b[3]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      ct6_trace_t *t = vlib_add_trace (vm, node, b[3], sizeof (*t));
	      t->next_index = next[3];
	      t->sw_if_index = vnet_buffer (b[3])->sw_if_index[VLIB_RX];
	    }
	}

      b += 4;
      next += 4;
      n_left_from -= 4;
    }
#endif

  while (n_left_from > 0)
    {
      clib_bihash_kv_48_8_t kvp0;
      ct6_session_key_t *key0;
      ct6_session_t *s0, *next_s0, *prev_s0 __attribute__ ((unused));
      u32 session_index0 = ~0;
      u32 next0, delta0;
      ethernet_header_t *e0;

      ip6_header_t *ip0;
      udp_header_t *udp0;

      /* Are we having fun yet? */
      vnet_feature_next (&next0, b[0]);
      next[0] = next0;

      /*
       * This is an output feature which runs at the last possible
       * moment. Assume an ethernet header.
       */

      e0 = vlib_buffer_get_current (b[0]);
      delta0 = sizeof (*e0);
      delta0 += (e0->type == clib_net_to_host_u16 (ETHERNET_TYPE_VLAN))
	? 4 : 0;
      delta0 += (e0->type == clib_net_to_host_u16 (ETHERNET_TYPE_DOT1AD))
	? 8 : 0;

      ip0 = (ip6_header_t *) (vlib_buffer_get_current (b[0]) + delta0);

      /* Track (only) udp, tcp */
      if (PREDICT_FALSE (ip0->protocol != IP_PROTOCOL_TCP &&
			 ip0->protocol != IP_PROTOCOL_UDP))
	goto trace0;

      udp0 = ip6_next_header (ip0);

      /*
       * See if we know about this flow.
       * Key set up for the out2in path, the performant case
       */
      key0 = (ct6_session_key_t *) & kvp0;
      clib_memcpy_fast (&key0->src, &ip0->dst_address,
			sizeof (ip6_address_t));
      clib_memcpy_fast (&key0->dst, &ip0->src_address,
			sizeof (ip6_address_t));
      key0->as_u64[4] = 0;
      key0->as_u64[5] = 0;
      key0->sport = udp0->dst_port;
      key0->dport = udp0->src_port;
      key0->proto = ip0->protocol;

      /* Need to create a new session? */
      if (clib_bihash_search_48_8 (&cmp->session_hash, &kvp0, &kvp0) < 0)
	{
	  /* Recycle an old session? */
	  if (cmp->last_index[my_thread_index] == ~0)
	    goto alloc0;

	  s0 = pool_elt_at_index (cmp->sessions[my_thread_index],
				  cmp->last_index[my_thread_index]);
	  if (s0->expires > now
	      || vec_len (cmp->sessions[my_thread_index])
	      >= cmp->max_sessions_per_worker)
	    {
	      ct6_session_t *prev0;

	      if (clib_bihash_add_del_48_8 (&cmp->session_hash,
					    &kvp0, 0 /* is_add */ ) < 0)
		clib_warning ("session %d not found in hash?",
			      s0 - cmp->sessions[my_thread_index]);

	      if (s0->prev_index != ~0)
		{
		  prev0 = pool_elt_at_index (cmp->sessions[my_thread_index],
					     s0->prev_index);
		  prev0->next_index = ~0;
		  cmp->last_index[my_thread_index] = prev0 -
		    cmp->sessions[my_thread_index];
		}
	      else
		cmp->last_index[my_thread_index] = ~0;
	      recycled++;
	    }
	  else
	    {
	    alloc0:
	      pool_get (cmp->sessions[my_thread_index], s0);
	      created++;
	    }

	  memset (s0, 0, sizeof (*s0));

	  clib_memcpy_fast (s0, key0, sizeof (*key0));
	  s0->thread_index = my_thread_index;
	  s0->next_index = cmp->first_index[my_thread_index];
	  cmp->first_index[my_thread_index] =
	    s0 - cmp->sessions[my_thread_index];
	  if (s0->next_index == ~0)
	    cmp->last_index[my_thread_index] =
	      cmp->first_index[my_thread_index];
	  else
	    {
	      next_s0 = pool_elt_at_index (cmp->sessions[my_thread_index],
					   s0->next_index);
	      next_s0->prev_index = cmp->first_index[my_thread_index];
	    }

	  s0->prev_index = ~0;
	  s0->expires = now + cmp->session_timeout_interval;

	  kvp0.value = s0 - cmp->sessions[my_thread_index];
	  session_index0 = kvp0.value;
	  clib_bihash_add_del_48_8 (&cmp->session_hash, &kvp0,
				    1 /* is_add */ );
	}
      else
	{
	  s0 = pool_elt_at_index (cmp->sessions[my_thread_index], kvp0.value);
	  session_index0 = kvp0.value;
	  s0->expires = now + cmp->session_timeout_interval;
	  /* $$$$ remove and re-add item at the head of the list */
	}

    trace0:
      if (is_trace)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      ct6_in2out_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->next_index = next[0];
	      t->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	      t->session_index = session_index0;
	    }
	}

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  vlib_node_increment_counter (vm, node->node_index,
			       CT6_IN2OUT_ERROR_PROCESSED, frame->n_vectors);
  vlib_node_increment_counter (vm, node->node_index,
			       CT6_IN2OUT_ERROR_CREATED, created);
  vlib_node_increment_counter (vm, node->node_index,
			       CT6_IN2OUT_ERROR_RECYCLED, recycled);

  return frame->n_vectors;
}

VLIB_NODE_FN (ct6_in2out_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return ct6_in2out_inline (vm, node, frame, 1 /* is_trace */ );
  else
    return ct6_in2out_inline (vm, node, frame, 0 /* is_trace */ );
}

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (ct6_in2out_node) =
{
  .name = "ct6-in2out",
  .vector_size = sizeof (u32),
  .format_trace = format_ct6_in2out_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(ct6_in2out_error_strings),
  .error_strings = ct6_in2out_error_strings,

  .n_next_nodes = CT6_IN2OUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [CT6_IN2OUT_NEXT_DROP] = "error-drop",
  },
};
#endif /* CLIB_MARCH_VARIANT */
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
