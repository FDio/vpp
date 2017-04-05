/*
 * encap.c : L2TPv3 tunnel encapsulation
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
#define foreach_l2t_encap_error					\
_(NETWORK_TO_USER, "L2TP L2 network to user (ip6) pkts")	\
_(LOOKUP_FAIL_TO_L3, "L2TP L2 session lookup failed pkts")      \
_(ADMIN_DOWN, "L2TP tunnel is down")

static char *l2t_encap_error_strings[] = {
#define _(sym,string) string,
  foreach_l2t_encap_error
#undef _
};

typedef enum
{
#define _(sym,str) L2T_ENCAP_ERROR_##sym,
  foreach_l2t_encap_error
#undef _
    L2T_ENCAP_N_ERROR,
} l2t_encap_error_t;


typedef enum
{
  L2T_ENCAP_NEXT_DROP,
  L2T_ENCAP_NEXT_IP6_LOOKUP,
  L2T_ENCAP_N_NEXT,
} l2t_encap_next_t;

typedef struct
{
  u32 cached_session_index;
  u32 cached_sw_if_index;
  vnet_main_t *vnet_main;
} l2tp_encap_runtime_t;

vlib_node_registration_t l2t_encap_node;

#define NSTAGES 3

static inline void
stage0 (vlib_main_t * vm, vlib_node_runtime_t * node, u32 buffer_index)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, buffer_index);
  vlib_prefetch_buffer_header (b, STORE);
  CLIB_PREFETCH (b->data, 2 * CLIB_CACHE_LINE_BYTES, STORE);
}

static inline void
stage1 (vlib_main_t * vm, vlib_node_runtime_t * node, u32 bi)
{
  l2tp_encap_runtime_t *rt = (void *) node->runtime_data;
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vnet_hw_interface_t *hi;

  u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
  u32 session_index = rt->cached_session_index;

  if (PREDICT_FALSE (rt->cached_sw_if_index != sw_if_index))
    {
      hi = vnet_get_sup_hw_interface (rt->vnet_main, sw_if_index);
      session_index = rt->cached_session_index = hi->dev_instance;
      rt->cached_sw_if_index = sw_if_index;
    }

  /* Remember mapping index, prefetch the mini counter */
  vnet_buffer (b)->l2t.next_index = L2T_ENCAP_NEXT_IP6_LOOKUP;
  vnet_buffer (b)->l2t.session_index = session_index;

  /* $$$$ prefetch counter... */
}

static inline u32
last_stage (vlib_main_t * vm, vlib_node_runtime_t * node, u32 bi)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  l2t_main_t *lm = &l2t_main;
  vlib_node_t *n = vlib_get_node (vm, l2t_encap_node.index);
  u32 node_counter_base_index = n->error_heap_index;
  vlib_error_main_t *em = &vm->error_main;
  l2tpv3_header_t *l2tp;
  u32 session_index;
  u32 counter_index;
  l2t_session_t *s;
  ip6_header_t *ip6;
  u16 payload_length;
  u32 next_index = L2T_ENCAP_NEXT_IP6_LOOKUP;

  /* Other-than-output pkt? We're done... */
  if (vnet_buffer (b)->l2t.next_index != L2T_ENCAP_NEXT_IP6_LOOKUP)
    return vnet_buffer (b)->l2t.next_index;

  em->counters[node_counter_base_index + L2T_ENCAP_ERROR_NETWORK_TO_USER] +=
    1;

  session_index = vnet_buffer (b)->l2t.session_index;

  counter_index =
    session_index_to_counter_index (session_index,
				    SESSION_COUNTER_NETWORK_TO_USER);

  /* per-mapping byte stats include the ethernet header */
  vlib_increment_combined_counter (&lm->counter_main,
				   vlib_get_thread_index (),
				   counter_index, 1 /* packet_increment */ ,
				   vlib_buffer_length_in_chain (vm, b));

  s = pool_elt_at_index (lm->sessions, session_index);

  vnet_buffer (b)->sw_if_index[VLIB_TX] = s->encap_fib_index;

  /* Paint on an l2tpv3 hdr */
  vlib_buffer_advance (b, -(s->l2tp_hdr_size));
  l2tp = vlib_buffer_get_current (b);

  l2tp->session_id = s->remote_session_id;
  l2tp->cookie = s->remote_cookie;
  if (PREDICT_FALSE (s->l2_sublayer_present))
    {
      l2tp->l2_specific_sublayer = 0;
    }

  /* Paint on an ip6 header */
  vlib_buffer_advance (b, -(sizeof (*ip6)));
  ip6 = vlib_buffer_get_current (b);

  if (PREDICT_FALSE (!(s->admin_up)))
    {
      b->error = node->errors[L2T_ENCAP_ERROR_ADMIN_DOWN];
      next_index = L2T_ENCAP_NEXT_DROP;
      goto done;
    }

  ip6->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (0x6 << 28);

  /* calculate ip6 payload length */
  payload_length = vlib_buffer_length_in_chain (vm, b);
  payload_length -= sizeof (*ip6);

  ip6->payload_length = clib_host_to_net_u16 (payload_length);
  ip6->protocol = IP_PROTOCOL_L2TP;
  ip6->hop_limit = 0xff;
  ip6->src_address.as_u64[0] = s->our_address.as_u64[0];
  ip6->src_address.as_u64[1] = s->our_address.as_u64[1];
  ip6->dst_address.as_u64[0] = s->client_address.as_u64[0];
  ip6->dst_address.as_u64[1] = s->client_address.as_u64[1];


done:
  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
    {
      l2t_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
      t->is_user_to_network = 0;
      t->our_address.as_u64[0] = ip6->src_address.as_u64[0];
      t->our_address.as_u64[1] = ip6->src_address.as_u64[1];
      t->client_address.as_u64[0] = ip6->dst_address.as_u64[0];
      t->client_address.as_u64[1] = ip6->dst_address.as_u64[1];
      t->session_index = session_index;
    }

  return next_index;
}

#include <vnet/pipeline.h>

uword
l2t_encap_node_fn (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return dispatch_pipeline (vm, node, frame);
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (l2t_encap_node) = {
  .function = l2t_encap_node_fn,
  .name = "l2tp-encap",
  .vector_size = sizeof (u32),
  .format_trace = format_l2t_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .runtime_data_bytes = sizeof (l2tp_encap_runtime_t),

  .n_errors = ARRAY_LEN(l2t_encap_error_strings),
  .error_strings = l2t_encap_error_strings,

  .n_next_nodes = L2T_ENCAP_N_NEXT,

  /*  add dispositions here */
  .next_nodes = {
    [L2T_ENCAP_NEXT_IP6_LOOKUP] = "ip6-lookup",
    [L2T_ENCAP_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (l2t_encap_node, l2t_encap_node_fn);
void
l2tp_encap_init (vlib_main_t * vm)
{
  l2tp_encap_runtime_t *rt;

  rt = vlib_node_get_runtime_data (vm, l2t_encap_node.index);
  rt->vnet_main = vnet_get_main ();
  rt->cached_sw_if_index = (u32) ~ 0;
  rt->cached_session_index = (u32) ~ 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
