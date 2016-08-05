/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#if DPDK == 0
#include <vnet/devices/pci/ixgev.h>
#include <vnet/devices/pci/ixge.h>
#include <vnet/devices/pci/ige.h>
#include <vnet/devices/pci/vice.h>
#else
#include <vnet/devices/dpdk/dpdk.h>
#endif

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <app/l2t.h>

l2t_main_t l2t_main;

/* Statistics (not really errors) */
#define foreach_l2t_ip6_error                                   \
_(USER_TO_NETWORK, "User (v6) to L2 network pkts")              \
_(SESSION_ID_MISMATCH, "l2tpv3 local session id mismatches")    \
_(COOKIE_MISMATCH, "l2tpv3 local cookie mismatches")

static char *l2t_ip6_error_strings[] = {
#define _(sym,string) string,
  foreach_l2t_ip6_error
#undef _
};

typedef enum
{
#define _(sym,str) L2T_IP6_ERROR_##sym,
  foreach_l2t_ip6_error
#undef _
    L2T_IP6_N_ERROR,
} l2t_ip6_error_t;

/*
 * Packets go to ip6-input when they don't match a mapping,
 * example: v6 neighbor discovery. They go to ip4-input
 * when they do match, and are decapsulated.
 */
typedef enum
{
  L2T_IP6_NEXT_DROP,
  L2T_IP6_NEXT_IP6_INPUT,
  L2T_IP6_N_NEXT,
  /* Pseudo next, fixed in last_stage */
  L2T_IP6_NEXT_OUTPUT = L2T_IP6_N_NEXT,
} l2t_ip6_next_t;

vlib_node_registration_t l2t_ip6_node;

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
  uword *p;
  l2tpv3_header_t *l2t;

  /* Not L2tpv3 (0x73, 0t115)? Use the normal path. */
  if (PREDICT_FALSE (ip6->protocol != 0x73))
    {
      vnet_buffer (b)->l2t.next_index = L2T_IP6_NEXT_IP6_INPUT;
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
      vnet_buffer (b)->l2t.next_index = L2T_IP6_NEXT_IP6_INPUT;
      return;
    }
  else
    {
      session_index = p[0];
    }

  /* Remember mapping index, prefetch the mini counter */
  vnet_buffer (b)->l2t.next_index = L2T_IP6_NEXT_OUTPUT;
  vnet_buffer (b)->l2t.session_index = session_index;

  /* Each mapping has 2 x (pkt, byte) counters, hence the shift */
  CLIB_PREFETCH (lm->counter_main.mini + (p[0] << 1), CLIB_CACHE_LINE_BYTES,
		 STORE);
}

static inline u32
last_stage (vlib_main_t * vm, vlib_node_runtime_t * node, u32 bi)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  l2t_main_t *lm = &l2t_main;
  ip6_header_t *ip6 = vlib_buffer_get_current (b);
  vlib_node_t *n = vlib_get_node (vm, l2t_ip6_node.index);
  u32 node_counter_base_index = n->error_heap_index;
  vlib_error_main_t *em = &vm->error_main;
  ethernet_header_t *l2_payload;
  l2tpv3_header_t *l2t;		/* original l2 header */
  ethernet_vlan_header_t *vh;	/* synthesized 802.1q vlan header */
  u32 counter_index;
  l2t_session_t *session;
  u16 payload_ethertype;
  u8 dst_mac_address[6];
  u8 src_mac_address[6];
  u8 *vlan_header_pos;

  /* Other-than-output pkt? We're done... */
  if (vnet_buffer (b)->l2t.next_index != L2T_IP6_NEXT_OUTPUT)
    return vnet_buffer (b)->l2t.next_index;

  em->counters[node_counter_base_index + L2T_IP6_ERROR_USER_TO_NETWORK] += 1;

  counter_index =
    session_index_to_counter_index (vnet_buffer (b)->l2t.session_index,
				    SESSION_COUNTER_USER_TO_NETWORK);

  /* per-mapping byte stats include the ethernet header */
  vlib_increment_combined_counter (&lm->counter_main, counter_index,
				   1 /* packet_increment */ ,
				   vlib_buffer_length_in_chain (vm, b) +
				   sizeof (ethernet_header_t));

  session = pool_elt_at_index (lm->sessions,
			       vnet_buffer (b)->l2t.session_index);

  /* build the 802.1q encaps. Advance past ip6 and l2tpv3 hds */
  vlib_buffer_advance (b, sizeof (*ip6));
  l2t = vlib_buffer_get_current (b);

  /* $$$ wonder if we really need these checks... */
  if (PREDICT_FALSE (l2t->session_id != session->local_session_id))
    {
      b->error =
	lm->ip6_error_node->errors[L2T_IP6_ERROR_SESSION_ID_MISMATCH];
      return L2T_IP6_NEXT_DROP;
    }

  if (PREDICT_FALSE (!((l2t->cookie == session->local_cookie) ||
		       ((session->cookie_flags & L2TP_COOKIE_ROLLOVER_LOCAL)
			&& (l2t->cookie == session->lcl_ro_cookie)))))
    {
      b->error = lm->ip6_error_node->errors[L2T_IP6_ERROR_COOKIE_MISMATCH];
      return L2T_IP6_NEXT_DROP;
    }

  vnet_buffer (b)->sw_if_index[VLIB_TX] = session->l2_output_sw_if_index;

  vlib_buffer_advance (b, sizeof (*l2t));

  /* point at currrent l2 hdr */
  l2_payload = vlib_buffer_get_current (b);

  /* $$$$ rework for speed */

  /* Save type */
  payload_ethertype = l2_payload->type;

  /* Save src/dst MAC addresses */
#define _(i)  dst_mac_address[i] = l2_payload->dst_address[i];
  _(0) _(1) _(2) _(3) _(4) _(5);
#undef _
#define _(i)  src_mac_address[i] = l2_payload->src_address[i];
  _(0) _(1) _(2) _(3) _(4) _(5);
#undef _

  /* Punch in space for 802.1q tag */
  vlib_buffer_advance (b, -4);
  l2_payload = vlib_buffer_get_current (b);

  /* Restore MAC addresses */
#define _(i)  l2_payload->dst_address[i] = dst_mac_address[i];
  _(0) _(1) _(2) _(3) _(4) _(5);
#undef _
#define _(i)  l2_payload->src_address[i] = src_mac_address[i];
  _(0) _(1) _(2) _(3) _(4) _(5);
#undef _
  /* Set (outer) ethertype to 802.1q vlan */
  l2_payload->type = clib_host_to_net_u16 (0x8100);
  vlan_header_pos = (u8 *) (l2_payload + 1);
#if 0
  vlan_header_pos = session->l2_sublayer_present ?
    vlan_header_pos : vlan_header_pos - 4;
#endif
  vh = (ethernet_vlan_header_t *) vlan_header_pos;
  vh->priority_cfi_and_id = session->vlan_id;
  vh->type = payload_ethertype;

  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
    {
      l2t_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
      t->is_user_to_network = 1;
      t->our_address.as_u64[0] = ip6->dst_address.as_u64[0];
      t->our_address.as_u64[1] = ip6->dst_address.as_u64[1];
      t->client_address.as_u64[0] = ip6->src_address.as_u64[0];
      t->client_address.as_u64[1] = ip6->src_address.as_u64[1];
      t->session_index = vnet_buffer (b)->l2t.session_index;
      t->vlan_id_host_byte_order = clib_net_to_host_u16 (session->vlan_id);
    }

  return session->l2_output_next_index;
}

#include <vnet/pipeline.h>

static uword
ip6_l2t_node_fn (vlib_main_t * vm,
		 vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  l2t_main_t *lm = &l2t_main;
  lm->ip6_error_node = vlib_node_get_runtime (vm, l2t_ip6_node.index);

  return dispatch_pipeline (vm, node, frame);
}

/* *INDENT-OFF* */
static VLIB_REGISTER_NODE (sw6_ip6_node) = {
  .function = ip6_l2t_node_fn,
  .name = "ip6-l2t-input",
  .vector_size = sizeof (u32),
  .format_trace = format_l2t_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(l2t_ip6_error_strings),
  .error_strings = l2t_ip6_error_strings,

  .n_next_nodes = L2T_IP6_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [L2T_IP6_NEXT_IP6_INPUT] = "ip6-input",
    [L2T_IP6_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (sw6_ip6_node, ip6_l2t_node_fn);
static clib_error_t *
l2tp_config (vlib_main_t * vm, unformat_input_t * input)
{
  l2t_main_t *lm = &l2t_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "lookup-v6-src"))
	lm->lookup_type = L2T_LOOKUP_SRC_ADDRESS;
      else if (unformat (input, "lookup-v6-dst"))
	lm->lookup_type = L2T_LOOKUP_DST_ADDRESS;
      else if (unformat (input, "lookup-session-id"))
	lm->lookup_type = L2T_LOOKUP_SESSION_ID;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (l2tp_config, "l2tp");

clib_error_t *
l2t_ip6_init (vlib_main_t * vm)
{
  l2t_main_t *lm = &l2t_main;

  lm->vnet_main = vnet_get_main ();
  lm->vlib_main = vm;
  lm->lookup_type = L2T_LOOKUP_DST_ADDRESS;

  lm->session_by_src_address = hash_create_mem
    (0, sizeof (ip6_address_t) /* key bytes */ ,
     sizeof (u32) /* value bytes */ );
  lm->session_by_dst_address = hash_create_mem
    (0, sizeof (ip6_address_t) /* key bytes */ ,
     sizeof (u32) /* value bytes */ );
  lm->session_by_session_id = hash_create (0, sizeof (uword));

  lm->session_by_vlan_and_rx_sw_if_index = hash_create (0, sizeof (uword));

#if DPDK == 0
  vice_set_next_node (VICE_RX_NEXT_IP6_INPUT, "ip6-l2t-input");
  ixgev_set_next_node (IXGEV_RX_NEXT_IP6_INPUT, "ip6-l2t-input");
  ixge_set_next_node (IXGE_RX_NEXT_IP6_INPUT, "ip6-l2t-input");
  ige_set_next_node (IGE_RX_NEXT_IP6_INPUT, "ip6-l2t-input");
#else
  dpdk_set_next_node (DPDK_RX_NEXT_IP6_INPUT, "ip6-l2t-input");
#endif
  return 0;
}

VLIB_INIT_FUNCTION (l2t_ip6_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
