/*
 * decap.c : L2TPv3 tunnel decapsulation
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/l2tp/l2tp.h>

/* Statistics (not really errors) */
#define foreach_l2t_decap_error                                 \
_(USER_TO_NETWORK, "L2TP user (ip6) to L2 network pkts")        \
_(SESSION_ID_MISMATCH, "l2tpv3 local session id mismatches")    \
_(COOKIE_MISMATCH, "l2tpv3 local cookie mismatches")            \
_(NO_SESSION, "l2tpv3 session not found")                       \
_(ADMIN_DOWN, "l2tpv3 tunnel is down")

static char *l2t_decap_error_strings[] = {
#define _(sym,string) string,
  foreach_l2t_decap_error
#undef _
};

typedef enum
{
#define _(sym,str) L2T_DECAP_ERROR_##sym,
  foreach_l2t_decap_error
#undef _
    L2T_DECAP_N_ERROR,
} l2t_DECAP_error_t;

typedef enum
{
  L2T_DECAP_NEXT_DROP,
  L2T_DECAP_NEXT_L2_INPUT,
  L2T_DECAP_N_NEXT,
  /* Pseudo next index */
  L2T_DECAP_NEXT_NO_INTERCEPT = L2T_DECAP_N_NEXT,
} l2t_decap_next_t;

#define NSTAGES 3

static inline void
stage0 (vlib_main_t * vm, vlib_node_runtime_t * node, u32 buffer_index)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, buffer_index);
  vlib_prefetch_buffer_header (b, STORE);
  /* l2tpv3 header is a long way away, need 2 cache lines */
  CLIB_PREFETCH (b->data, 2 * CLIB_CACHE_LINE_BYTES, STORE);
}

static inline void
stage1 (vlib_main_t * vm, vlib_node_runtime_t * node, u32 bi)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  l2t_main_t *lm = &l2t_main;
  ip6_header_t *ip6 = vlib_buffer_get_current (b);
  u32 session_index;
  uword *p = 0;
  l2tpv3_header_t *l2t;

  /* Not L2tpv3 (0x73, 0t115)? Use the normal path. */
  if (PREDICT_FALSE (ip6->protocol != IP_PROTOCOL_L2TP))
    {
      vnet_buffer (b)->l2t.next_index = L2T_DECAP_NEXT_NO_INTERCEPT;
      return;
    }

  /* Make up your minds, people... */
  switch (lm->lookup_type)
    {
    case L2T_LOOKUP_SRC_ADDRESS:
      p = hash_get_mem (lm->session_by_src_address, &ip6->src_address);
      break;
    case L2T_LOOKUP_DST_ADDRESS:
      p = hash_get_mem (lm->session_by_dst_address, &ip6->dst_address);
      break;
    case L2T_LOOKUP_SESSION_ID:
      l2t = (l2tpv3_header_t *) (ip6 + 1);
      p = hash_get (lm->session_by_session_id, l2t->session_id);
      break;
    default:
      ASSERT (0);
    }

  if (PREDICT_FALSE (p == 0))
    {
      vnet_buffer (b)->l2t.next_index = L2T_DECAP_NEXT_NO_INTERCEPT;
      return;
    }
  else
    {
      session_index = p[0];
    }

  /* Remember mapping index, prefetch the mini counter */
  vnet_buffer (b)->l2t.next_index = L2T_DECAP_NEXT_L2_INPUT;
  vnet_buffer (b)->l2t.session_index = session_index;

  /* $$$$$ prefetch counter */
}

static inline u32
last_stage (vlib_main_t * vm, vlib_node_runtime_t * node, u32 bi)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  l2t_main_t *lm = &l2t_main;
  ip6_header_t *ip6 = vlib_buffer_get_current (b);
  vlib_node_t *n = vlib_get_node (vm, node->node_index);
  u32 node_counter_base_index = n->error_heap_index;
  vlib_error_main_t *em = &vm->error_main;
  l2tpv3_header_t *l2tp;
  u32 counter_index;
  l2t_session_t *session = 0;
  u32 session_index;
  u32 next_index;
  u8 l2tp_decap_local = (l2t_decap_local_node.index == n->index);

  /* Other-than-output pkt? We're done... */
  if (vnet_buffer (b)->l2t.next_index != L2T_DECAP_NEXT_L2_INPUT)
    {
      next_index = vnet_buffer (b)->l2t.next_index;
      goto done;
    }

  em->counters[node_counter_base_index + L2T_DECAP_ERROR_USER_TO_NETWORK] +=
    1;

  session_index = vnet_buffer (b)->l2t.session_index;

  counter_index =
    session_index_to_counter_index (session_index,
				    SESSION_COUNTER_USER_TO_NETWORK);

  /* per-mapping byte stats include the ethernet header */
  vlib_increment_combined_counter (&lm->counter_main,
				   vlib_get_thread_index (),
				   counter_index, 1 /* packet_increment */ ,
				   vlib_buffer_length_in_chain (vm, b) +
				   sizeof (ethernet_header_t));

  session = pool_elt_at_index (lm->sessions, session_index);

  l2tp = vlib_buffer_get_current (b) + sizeof (*ip6);

  if (PREDICT_FALSE (l2tp->session_id != session->local_session_id))
    {
      /* Key matched but session id does not. Assume packet is not for us. */
      em->counters[node_counter_base_index +
		   L2T_DECAP_ERROR_SESSION_ID_MISMATCH] += 1;
      next_index = L2T_DECAP_NEXT_NO_INTERCEPT;
      goto done;
    }

  if (PREDICT_FALSE (l2tp->cookie != session->local_cookie[0]))
    {
      if (l2tp->cookie != session->local_cookie[1])
	{
	  /* Key and session ID matched, but cookie doesn't. Drop this packet. */
	  b->error = node->errors[L2T_DECAP_ERROR_COOKIE_MISMATCH];
	  next_index = L2T_DECAP_NEXT_DROP;
	  goto done;
	}
    }

  vnet_buffer (b)->sw_if_index[VLIB_RX] = session->sw_if_index;

  if (PREDICT_FALSE (!(session->admin_up)))
    {
      b->error = node->errors[L2T_DECAP_ERROR_ADMIN_DOWN];
      next_index = L2T_DECAP_NEXT_DROP;
      goto done;
    }

  /* strip the ip6 and L2TP header */
  vlib_buffer_advance (b, sizeof (*ip6) + session->l2tp_hdr_size);

  /* Required to make the l2 tag push / pop code work on l2 subifs */
  vnet_update_l2_len (b);

  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
    {
      l2t_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
      t->is_user_to_network = 1;
      t->our_address.as_u64[0] = ip6->dst_address.as_u64[0];
      t->our_address.as_u64[1] = ip6->dst_address.as_u64[1];
      t->client_address.as_u64[0] = ip6->src_address.as_u64[0];
      t->client_address.as_u64[1] = ip6->src_address.as_u64[1];
      t->session_index = session_index;
    }

  return L2T_DECAP_NEXT_L2_INPUT;

done:
  if (next_index == L2T_DECAP_NEXT_NO_INTERCEPT)
    {
      /* Small behavioral change between l2tp-decap and l2tp-decap-local */
      if (l2tp_decap_local)
	{
	  b->error = node->errors[L2T_DECAP_ERROR_NO_SESSION];
	  next_index = L2T_DECAP_NEXT_DROP;
	}
      else
	{
	  /* Go to next node on the ip6 configuration chain */
	  if (PREDICT_TRUE (session != 0))
	    vnet_feature_next (session->sw_if_index, &next_index, b);
	}
    }

  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
    {
      l2t_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
      t->is_user_to_network = 1;
      t->our_address.as_u64[0] = ip6->dst_address.as_u64[0];
      t->our_address.as_u64[1] = ip6->dst_address.as_u64[1];
      t->client_address.as_u64[0] = ip6->src_address.as_u64[0];
      t->client_address.as_u64[1] = ip6->src_address.as_u64[1];
      t->session_index = ~0;
    }
  return next_index;
}

#include <vnet/pipeline.h>

static uword
l2t_decap_node_fn (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return dispatch_pipeline (vm, node, frame);
}

/*
 * l2tp-decap and l2tp-decap-local have very slightly different behavior.
 * When a packet has no associated session l2tp-decap let it go to ip6 forward,
 * while l2tp-decap-local drops it.
 */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (l2t_decap_node) = {
  .function = l2t_decap_node_fn,
  .name = "l2tp-decap",
  .vector_size = sizeof (u32),
  .format_trace = format_l2t_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(l2t_decap_error_strings),
  .error_strings = l2t_decap_error_strings,

  .n_next_nodes = L2T_DECAP_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [L2T_DECAP_NEXT_L2_INPUT] = "l2-input",
        [L2T_DECAP_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (l2t_decap_node, l2t_decap_node_fn);
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (l2t_decap_local_node) = {
  .function = l2t_decap_node_fn,
  .name = "l2tp-decap-local",
  .vector_size = sizeof (u32),
  .format_trace = format_l2t_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(l2t_decap_error_strings),
  .error_strings = l2t_decap_error_strings,

  .n_next_nodes = L2T_DECAP_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [L2T_DECAP_NEXT_L2_INPUT] = "l2-input",
    [L2T_DECAP_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

void
l2tp_decap_init (void)
{
  ip6_register_protocol (IP_PROTOCOL_L2TP, l2t_decap_local_node.index);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
