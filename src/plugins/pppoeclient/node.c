/* SPDX-License-Identifier: Apache-2.0 */
/*

 * node.c: pppoe client related packet logic.

 */

#include <vlib/vlib.h>

#include <ppp/packet.h>

#include <pppox/pppox.h>
#include <pppoeclient/pppoeclient.h>

/* PPP protocols not defined in newer VPP */

#ifndef PPP_PROTOCOL_ipcp
#define PPP_PROTOCOL_ipcp 0x8021
#endif

#ifndef PPP_PROTOCOL_ipv6cp
#define PPP_PROTOCOL_ipv6cp 0x8057
#endif

#ifndef PPP_PROTOCOL_lcp
#define PPP_PROTOCOL_lcp 0xc021
#endif

#ifndef PPP_PROTOCOL_pap
#define PPP_PROTOCOL_pap 0xc023
#endif

#ifndef PPP_PROTOCOL_chap
#define PPP_PROTOCOL_chap 0xc223
#endif

#ifndef PPP_PROTOCOL_ip4
#define PPP_PROTOCOL_ip4 0x0021
#endif

#ifndef PPP_PROTOCOL_ip6
#define PPP_PROTOCOL_ip6 0x0057
#endif

static char *pppoeclient_error_strings[] = {

#define pppoeclient_error(n, s) s,

#include <pppoeclient/pppoeclient_error.def>

#undef pppoeclient_error

#undef _

};

typedef struct
{

  u32 sw_if_index;

  u32 host_uniq;

  u16 session_id;

  u8 packet_code;

  u8 rsv;

  u32 error;

} pppoeclient_discovery_rx_trace_t;

static u8 *
format_pppoeclient_discovery_rx_trace (u8 *s, va_list *args)

{

  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);

  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  pppoeclient_discovery_rx_trace_t *t = va_arg (*args, pppoeclient_discovery_rx_trace_t *);

  s = format (s, "PPPoE discovery sw_if_index %d host_uniq %d session_id %d error %d",

	      t->sw_if_index, t->host_uniq, t->session_id, t->error);

  return s;
}

static uword

pppoeclient_discovery_input (vlib_main_t *vm,

			     vlib_node_runtime_t *node,

			     vlib_frame_t *from_frame)

{

  u32 n_left_from, next_index, *from, *to_next;

  u32 discovery_pkts = 0;

  from = vlib_frame_vector_args (from_frame);

  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)

    {

      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,

			   to_next, n_left_to_next);

      // Control packet use 1 batch is enough.

      while (n_left_from > 0 && n_left_to_next > 0)

	{

	  u32 bi0;

	  vlib_buffer_t *b0;

	  // The control packet will be dropped after processed.

	  u32 next0 = PPPOECLIENT_DISCOVERY_INPUT_NEXT_DROP;

	  pppoe_header_t *pppoe0;

	  u32 error0 = 0;

	  bi0 = from[0];

	  to_next[0] = bi0;

	  from += 1;

	  to_next += 1;

	  n_left_from -= 1;

	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  error0 = 0;

	  discovery_pkts++;

	  /* leaves current_data pointing at the pppoe header */

	  pppoe0 = vlib_buffer_get_current (b0);

	  switch (pppoe0->code)
	    {

	    case PPPOE_PADO:

	    case PPPOE_PADS:

	    case PPPOE_PADT:

	      break;

	    default:

	      error0 = PPPOECLIENT_ERROR_BAD_CODE_IN_DISCOVERY;

	      goto trace00;
	    }

	  (void) consume_pppoe_discovery_pkt (bi0, b0, pppoe0);

	trace00:

	  b0->error = error0 ? node->errors[error0] : 0;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))

	    {

	      pppoeclient_discovery_rx_trace_t *tr

		= vlib_add_trace (vm, node, b0, sizeof (*tr));

	      tr->error = error0;

	      // TODO: fill trace...
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,

					   to_next, n_left_to_next,

					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, pppoeclient_discovery_input_node.index,

			       PPPOECLIENT_ERROR_DISCOVERY_PKT_RCVED,

			       discovery_pkts);

  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (pppoeclient_discovery_input_node) = {

  .function = pppoeclient_discovery_input,

  .name = "pppoeclient-discovery-input",

  /* Takes a vector of packets. */

  .vector_size = sizeof (u32),



  .n_errors = PPPOECLIENT_N_ERROR,

  .error_strings = pppoeclient_error_strings,



  .n_next_nodes = PPPOECLIENT_DISCOVERY_INPUT_N_NEXT,

  .next_nodes = {

#define _(s, n) [PPPOECLIENT_DISCOVERY_INPUT_NEXT_##s] = n,

    foreach_pppoeclient_discovery_input_next

#undef _

  },



  .format_trace = format_pppoeclient_discovery_rx_trace,

};

/////// SESSION NODE /////

// ethernet II MTU(1500B) - pppoe overhead(8B) - IPv4(20B) - TCP(20B) = 1452
// ethernet II MTU(1500B) - pppoe overhead(8B) - IPv6(40B) - TCP(20B) = 1432
#define PPPOE_DEFAULT_TCP_MSS_V4 1452
#define PPPOE_DEFAULT_TCP_MSS_V6 1432

static_always_inline void
try_clamp_tcp_mss_in_syn (tcp_header_t *tcp0, u16 max_mss)
{
  if (!(tcp0->flags & TCP_FLAG_SYN))
    return;

  u8 opts_len = (tcp_doff (tcp0) << 2) - sizeof (tcp_header_t);
  u8 *data = (u8 *) (tcp0 + 1);

  /* MSS option: kind=2, length=4, value(2 bytes) */
  if (opts_len >= 4 && TCP_OPTION_MSS == data[0])
    {
      u16 mss = clib_net_to_host_u16 (*(u16 *) (data + 2));
      if (mss > max_mss)
	{
	  u16 new_mss_net = clib_host_to_net_u16 (max_mss);
	  ip_csum_t sum0 = tcp0->checksum;
	  sum0 = ip_csum_update (sum0, *(u16 *) (data + 2), new_mss_net, ip4_header_t, /* cheat */
				 length /* changed member */);
	  *(u16 *) (data + 2) = new_mss_net;
	  tcp0->checksum = ip_csum_fold (sum0);
	}
    }
}

static void
try_update_tcp_mss (vlib_buffer_t *b0)
{
  unsigned char *ppp0 = vlib_buffer_get_current (b0);
  u16 ppp_protocol = clib_net_to_host_u16 (*(u16 *) ppp0);

  if (PPP_PROTOCOL_ip4 == ppp_protocol)
    {
      ip4_header_t *ip0 = (ip4_header_t *) (ppp0 + 2); // skip ppp protocol.
      if (IP_PROTOCOL_TCP == ip0->protocol)
	{
	  tcp_header_t *tcp0 = ip4_next_header (ip0);
	  try_clamp_tcp_mss_in_syn (tcp0, PPPOE_DEFAULT_TCP_MSS_V4);
	}
    }
  else if (PPP_PROTOCOL_ip6 == ppp_protocol)
    {
      ip6_header_t *ip6_0 = (ip6_header_t *) (ppp0 + 2); // skip ppp protocol.
      if (IP_PROTOCOL_TCP == ip6_0->protocol)
	{
	  tcp_header_t *tcp0 = (tcp_header_t *) (ip6_0 + 1);
	  try_clamp_tcp_mss_in_syn (tcp0, PPPOE_DEFAULT_TCP_MSS_V6);
	}
    }

  return;
}

typedef struct
{

  u32 sw_if_index;

  u16 session_id;

  u16 rsv;

  u32 pppox_sw_if_index;

  u32 error;

} pppoeclient_session_rx_trace_t;

static u8 *
format_pppoeclient_session_rx_trace (u8 *s, va_list *args)

{

  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);

  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  pppoeclient_session_rx_trace_t *t = va_arg (*args, pppoeclient_session_rx_trace_t *);

  s = format (s, "PPPoE session sw_if_index %d session_id %d error %d pppox_sw_if_index %d",

	      t->sw_if_index, t->session_id, t->error, t->pppox_sw_if_index);

  return s;
}

static uword

pppoeclient_session_input (vlib_main_t *vm,

			   vlib_node_runtime_t *node,

			   vlib_frame_t *from_frame)

{

  pppoeclient_main_t *pem = &pppoeclient_main;

  u32 n_left_from, next_index, *from, *to_next;

  u32 session_pkts = 0;

  from = vlib_frame_vector_args (from_frame);

  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)

    {

      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,

			   to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)

	{

	  u32 bi0, bi1;

	  vlib_buffer_t *b0, *b1;

	  u32 next0, next1;

	  ethernet_header_t *h0, *h1;

	  pppoe_header_t *pppoe0, *pppoe1;

	  u16 ppp_proto0 = 0, ppp_proto1 = 0;

	  pppoe_client_t *c0 = 0, *c1 = 0;

	  u32 error0, error1;

	  pppoe_client_result_t result0, result1;

	  /* Prefetch next iteration. */

	  {

	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);

	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);

	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);

	    CLIB_PREFETCH (p3->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	  }

	  bi0 = from[0];

	  bi1 = from[1];

	  to_next[0] = bi0;

	  to_next[1] = bi1;

	  from += 2;

	  to_next += 2;

	  n_left_to_next -= 2;

	  n_left_from -= 2;

	  b0 = vlib_get_buffer (vm, bi0);

	  b1 = vlib_get_buffer (vm, bi1);

	  error0 = 0;

	  error1 = 0;

	  /* leaves current_data pointing at the pppoe header */

	  pppoe0 = vlib_buffer_get_current (b0);

	  pppoe1 = vlib_buffer_get_current (b1);

	  ppp_proto0 = clib_net_to_host_u16 (*(u16 *) (pppoe0 + 1));

	  ppp_proto1 = clib_net_to_host_u16 (*(u16 *) (pppoe1 + 1));

	  /* Manipulate packet 0 */

	  if (pppoe0->code != PPPOE_SESSION_DATA)

	    {

	      error0 = PPPOECLIENT_ERROR_BAD_CODE_IN_SESSION;

	      next0 = PPPOECLIENT_SESSION_INPUT_NEXT_DROP;

	      goto trace0;
	    }

	  pppoeclient_lookup_session_1 (&pem->session_table,

					clib_net_to_host_u16 (pppoe0->session_id),

					&result0);

	  if (PREDICT_FALSE (result0.fields.client_index == ~0))

	    {

	      error0 = PPPOECLIENT_ERROR_NO_SUCH_SESSION;

	      next0 = PPPOECLIENT_SESSION_INPUT_NEXT_DROP;

	      goto trace0;
	    }

	  /* client may be freed by interface type change */

	  if (pool_is_free_index (pem->clients, result0.fields.client_index))

	    {

	      error0 = PPPOECLIENT_ERROR_CLIENT_DELETED;

	      next0 = PPPOECLIENT_SESSION_INPUT_NEXT_DROP;

	      goto trace0;
	    }

	  c0 = pool_elt_at_index (pem->clients,

				  result0.fields.client_index);

	  /* Pop Eth and PPPPoE header */

	  vlib_buffer_reset (b0);

	  h0 = vlib_buffer_get_current (b0);

	  vlib_buffer_advance (b0, sizeof (*h0) + sizeof (*pppoe0));

	  // Update vlib rx to pppox virtual interface.

	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = c0->pppox_sw_if_index;

	  if (ppp_proto0 == PPP_PROTOCOL_ip4)

	    {

	      // do before skip ppp protocol.

	      try_update_tcp_mss (b0);

	      // give only ip4 packet for ip4-input.

	      vlib_buffer_advance (b0, sizeof (ppp_proto0));

	      next0 = PPPOECLIENT_SESSION_INPUT_NEXT_IP4_INPUT;
	    }

	  else if (ppp_proto0 == PPP_PROTOCOL_ip6)

	    {

	      // give only ip6 packet for ip6-input.

	      vlib_buffer_advance (b0, sizeof (ppp_proto0));

	      next0 = PPPOECLIENT_SESSION_INPUT_NEXT_IP6_INPUT;
	    }

	  else if ((ppp_proto0 == PPP_PROTOCOL_lcp) ||

		   (ppp_proto0 == PPP_PROTOCOL_pap) ||

		   (ppp_proto0 == PPP_PROTOCOL_ipcp) ||

		   (ppp_proto0 == PPP_PROTOCOL_ipv6cp) ||

		   (ppp_proto0 == PPP_PROTOCOL_chap))

	    {

	      // Set ppp length in order to help parsing ctrl packet (adapt oss pppd).

	      pppox_buffer (b0)->len = b0->current_length;

	      next0 = PPPOECLIENT_SESSION_INPUT_NEXT_PPPOX_INPUT;
	    }

	  else
	    {

	      error0 = PPPOECLIENT_ERROR_UNSUPPORTED_PPP_PROTOCOL;

	      next0 = PPPOECLIENT_SESSION_INPUT_NEXT_DROP;

	      goto trace0;
	    }

	trace0:

	  b0->error = error0 ? node->errors[error0] : 0;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))

	    {

	      pppoeclient_session_rx_trace_t *tr

		= vlib_add_trace (vm, node, b0, sizeof (*tr));

	      tr->error = error0;

	      tr->session_id = clib_net_to_host_u16 (pppoe0->session_id);

	      if (c0 != 0)

		{

		  tr->pppox_sw_if_index = c0->pppox_sw_if_index;
		}
	    }

	  /* Manipulate packet 1 */

	  if (pppoe1->code != PPPOE_SESSION_DATA)

	    {

	      error1 = PPPOECLIENT_ERROR_BAD_CODE_IN_SESSION;

	      next1 = PPPOECLIENT_SESSION_INPUT_NEXT_DROP;

	      goto trace1;
	    }

	  pppoeclient_lookup_session_1 (&pem->session_table,

					clib_net_to_host_u16 (pppoe1->session_id),

					&result1);

	  if (PREDICT_FALSE (result1.fields.client_index == ~0))

	    {

	      error1 = PPPOECLIENT_ERROR_NO_SUCH_SESSION;

	      next1 = PPPOECLIENT_SESSION_INPUT_NEXT_DROP;

	      goto trace1;
	    }

	  /* client may be freed by interface type change */

	  if (pool_is_free_index (pem->clients, result1.fields.client_index))

	    {

	      error1 = PPPOECLIENT_ERROR_CLIENT_DELETED;

	      next1 = PPPOECLIENT_SESSION_INPUT_NEXT_DROP;

	      goto trace1;
	    }

	  c1 = pool_elt_at_index (pem->clients,

				  result1.fields.client_index);

	  /* Pop Eth and PPPPoE header */

	  vlib_buffer_reset (b1);

	  h1 = vlib_buffer_get_current (b1);

	  vlib_buffer_advance (b1, sizeof (*h1) + sizeof (*pppoe1));

	  // Update vlib rx to pppox virtual interface.

	  vnet_buffer (b1)->sw_if_index[VLIB_RX] = c1->pppox_sw_if_index;

	  if (ppp_proto1 == PPP_PROTOCOL_ip4)

	    {

	      // do before skip ppp protocol.

	      try_update_tcp_mss (b1);

	      // give only ip4 packet for ip4-input.

	      vlib_buffer_advance (b1, sizeof (ppp_proto1));

	      next1 = PPPOECLIENT_SESSION_INPUT_NEXT_IP4_INPUT;
	    }

	  else if (ppp_proto1 == PPP_PROTOCOL_ip6)

	    {

	      // give only ip6 packet for ip6-input.

	      vlib_buffer_advance (b1, sizeof (ppp_proto1));

	      next1 = PPPOECLIENT_SESSION_INPUT_NEXT_IP6_INPUT;
	    }

	  else if ((ppp_proto1 == PPP_PROTOCOL_lcp) ||

		   (ppp_proto1 == PPP_PROTOCOL_pap) ||

		   (ppp_proto1 == PPP_PROTOCOL_ipcp) ||

		   (ppp_proto1 == PPP_PROTOCOL_ipv6cp) ||

		   (ppp_proto1 == PPP_PROTOCOL_chap))

	    {

	      // Set ppp length in order to help parsing ctrl packet (adapt oss pppd).

	      pppox_buffer (b1)->len = b1->current_length;

	      next1 = PPPOECLIENT_SESSION_INPUT_NEXT_PPPOX_INPUT;
	    }

	  else
	    {

	      error1 = PPPOECLIENT_ERROR_UNSUPPORTED_PPP_PROTOCOL;

	      next1 = PPPOECLIENT_SESSION_INPUT_NEXT_DROP;

	      goto trace1;
	    }

	trace1:

	  b1->error = error1 ? node->errors[error1] : 0;

	  if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))

	    {

	      pppoeclient_session_rx_trace_t *tr

		= vlib_add_trace (vm, node, b1, sizeof (*tr));

	      tr->error = error1;

	      tr->session_id = clib_net_to_host_u16 (pppoe1->session_id);

	      if (c1 != 0)

		{

		  tr->pppox_sw_if_index = c1->pppox_sw_if_index;
		}
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,

					   to_next, n_left_to_next,

					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)

	{

	  u32 bi0;

	  vlib_buffer_t *b0;

	  u32 next0;

	  ethernet_header_t *h0;

	  pppoe_header_t *pppoe0;

	  u16 ppp_proto0 = 0;

	  pppoe_client_t *c0 = 0;

	  u32 error0;

	  pppoe_client_result_t result0;

	  bi0 = from[0];

	  to_next[0] = bi0;

	  from += 1;

	  to_next += 1;

	  n_left_from -= 1;

	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  error0 = 0;

	  /* leaves current_data pointing at the pppoe header */

	  pppoe0 = vlib_buffer_get_current (b0);

	  ppp_proto0 = clib_net_to_host_u16 (*(u16 *) (pppoe0 + 1));

	  /* Manipulate packet 0 */

	  if (pppoe0->code != PPPOE_SESSION_DATA)

	    {

	      error0 = PPPOECLIENT_ERROR_BAD_CODE_IN_SESSION;

	      next0 = PPPOECLIENT_SESSION_INPUT_NEXT_DROP;

	      goto trace00;
	    }

	  pppoeclient_lookup_session_1 (&pem->session_table,

					clib_net_to_host_u16 (pppoe0->session_id),

					&result0);

	  if (PREDICT_FALSE (result0.fields.client_index == ~0))

	    {

	      error0 = PPPOECLIENT_ERROR_NO_SUCH_SESSION;

	      next0 = PPPOECLIENT_SESSION_INPUT_NEXT_DROP;

	      goto trace00;
	    }

	  /* client may be freed by interface type change */

	  if (pool_is_free_index (pem->clients, result0.fields.client_index))

	    {

	      error0 = PPPOECLIENT_ERROR_CLIENT_DELETED;

	      next0 = PPPOECLIENT_SESSION_INPUT_NEXT_DROP;

	      goto trace00;
	    }

	  c0 = pool_elt_at_index (pem->clients,

				  result0.fields.client_index);

	  /* Pop Eth and PPPPoE header */

	  vlib_buffer_reset (b0);

	  h0 = vlib_buffer_get_current (b0);

	  vlib_buffer_advance (b0, sizeof (*h0) + sizeof (*pppoe0));

	  // Update vlib rx to pppox virtual interface.

	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = c0->pppox_sw_if_index;

	  if (ppp_proto0 == PPP_PROTOCOL_ip4)

	    {

	      // do before skip ppp protocol.

	      try_update_tcp_mss (b0);

	      // give only ip4 packet for ip4-input.

	      vlib_buffer_advance (b0, sizeof (ppp_proto0));

	      next0 = PPPOECLIENT_SESSION_INPUT_NEXT_IP4_INPUT;
	    }

	  else if (ppp_proto0 == PPP_PROTOCOL_ip6)

	    {

	      // give only ip6 packet for ip6-input.

	      vlib_buffer_advance (b0, sizeof (ppp_proto0));

	      next0 = PPPOECLIENT_SESSION_INPUT_NEXT_IP6_INPUT;
	    }

	  else if ((ppp_proto0 == PPP_PROTOCOL_lcp) ||

		   (ppp_proto0 == PPP_PROTOCOL_pap) ||

		   (ppp_proto0 == PPP_PROTOCOL_ipcp) ||

		   (ppp_proto0 == PPP_PROTOCOL_ipv6cp) ||

		   (ppp_proto0 == PPP_PROTOCOL_chap))

	    {

	      // Set ppp length in order to help parsing ctrl packet (adapt oss pppd).

	      pppox_buffer (b0)->len = b0->current_length;

	      next0 = PPPOECLIENT_SESSION_INPUT_NEXT_PPPOX_INPUT;
	    }

	  else
	    {

	      error0 = PPPOECLIENT_ERROR_UNSUPPORTED_PPP_PROTOCOL;

	      next0 = PPPOECLIENT_SESSION_INPUT_NEXT_DROP;

	      goto trace00;
	    }

	trace00:

	  b0->error = error0 ? node->errors[error0] : 0;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))

	    {

	      pppoeclient_session_rx_trace_t *tr

		= vlib_add_trace (vm, node, b0, sizeof (*tr));

	      tr->error = error0;

	      tr->session_id = clib_net_to_host_u16 (pppoe0->session_id);

	      if (c0 != 0)

		{

		  tr->pppox_sw_if_index = c0->pppox_sw_if_index;
		}
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,

					   to_next, n_left_to_next,

					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, pppoeclient_session_input_node.index,

			       PPPOECLIENT_ERROR_SESSION_PKT_RCVED,

			       session_pkts);

  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (pppoeclient_session_input_node) = {

  .function = pppoeclient_session_input,

  .name = "pppoeclient-session-input",
.flags = VLIB_NODE_FLAG_ALLOW_LAZY_NEXT_NODES,

  /* Takes a vector of packets. */

  .vector_size = sizeof (u32),



  .n_errors = PPPOECLIENT_N_ERROR,

  .error_strings = pppoeclient_error_strings,



  .n_next_nodes = PPPOECLIENT_SESSION_INPUT_N_NEXT,

  .next_nodes = {

#define _(s, n) [PPPOECLIENT_SESSION_INPUT_NEXT_##s] = n,

    foreach_pppoeclient_session_input_next

#undef _

  },



  .format_trace = format_pppoeclient_session_rx_trace,

};

typedef struct
{

  u32 sw_if_index;

  u16 session_id;

  u16 rsv;

  u32 pppox_sw_if_index;

  u32 error;

} pppoeclient_session_tx_trace_t;

static u8 *
format_pppoeclient_session_tx_trace (u8 *s, va_list *args)

{

  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);

  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  pppoeclient_session_tx_trace_t *t = va_arg (*args, pppoeclient_session_tx_trace_t *);

  s = format (s, "PPPoE session sw_if_index %d session_id %d error %d",

	      t->sw_if_index, t->session_id, t->error);

  return s;
}

static uword

pppoeclient_session_output (vlib_main_t *vm,

			    vlib_node_runtime_t *node,

			    vlib_frame_t *from_frame)

{

  pppoeclient_main_t *pem = &pppoeclient_main;

  vnet_main_t *vnm = pem->vnet_main;

  u32 n_left_from, next_index, *from, *to_next;

  u32 session_out_pkts = 0;

  from = vlib_frame_vector_args (from_frame);

  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)

    {

      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,

			   to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)

	{

	  u32 bi0, bi1;

	  vlib_buffer_t *b0, *b1;

	  u32 next0, next1;

	  ethernet_header_t *h0, *h1;

	  pppoe_header_t *pppoe0, *pppoe1;

	  vnet_hw_interface_t *hw0, *hw1;

	  vnet_sw_interface_t *sup_sw0, *sw0, *sup_sw1, *sw1;

	  pppoe_client_t *c0 = 0, *c1 = 0;

	  u32 error0, error1;

	  u32 pppox_sw_if_index0, pppox_sw_if_index1;

	  /* Prefetch next iteration. */

	  {

	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);

	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);

	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);

	    CLIB_PREFETCH (p3->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	  }

	  bi0 = from[0];

	  bi1 = from[1];

	  to_next[0] = bi0;

	  to_next[1] = bi1;

	  from += 2;

	  to_next += 2;

	  n_left_to_next -= 2;

	  n_left_from -= 2;

	  b0 = vlib_get_buffer (vm, bi0);

	  b1 = vlib_get_buffer (vm, bi1);

	  pppox_sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];

	  pppox_sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_TX];

	  error0 = 0;

	  error1 = 0;

	  if (pem->client_index_by_pppox_sw_if_index[pppox_sw_if_index0] == ~0)

	    {

	      error0 = PPPOECLIENT_ERROR_CLIENT_DELETED;

	      next0 = PPPOECLIENT_SESSION_OUTPUT_NEXT_DROP;

	      goto trace0;
	    }

	  /* client may be freed by interface type change */

	  if (pool_is_free_index (pem->clients,
				  pem->client_index_by_pppox_sw_if_index[pppox_sw_if_index0]))

	    {

	      error0 = PPPOECLIENT_ERROR_CLIENT_DELETED;

	      next0 = PPPOECLIENT_SESSION_OUTPUT_NEXT_DROP;

	      goto trace0;
	    }

	  c0 = pool_elt_at_index (pem->clients,

				  pem->client_index_by_pppox_sw_if_index[pppox_sw_if_index0]);

	  hw0 = vnet_get_sup_hw_interface (vnm, c0->hw_if_index);

	  sup_sw0 = vnet_get_sup_sw_interface (vnm, c0->sw_if_index);

	  sw0 = vnet_get_sw_interface (vnm, c0->sw_if_index);

	  /* Interface(s) down? */

	  if ((hw0->flags & VNET_HW_INTERFACE_FLAG_LINK_UP) == 0)

	    {

	      error0 = PPPOECLIENT_ERROR_LINK_DOWN;

	      next0 = PPPOECLIENT_SESSION_OUTPUT_NEXT_DROP;

	      goto trace0;
	    }

	  if ((sup_sw0->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) == 0)

	    {

	      error0 = PPPOECLIENT_ERROR_LINK_DOWN;

	      next0 = PPPOECLIENT_SESSION_OUTPUT_NEXT_DROP;

	      goto trace0;
	    }

	  if ((sw0->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) == 0)

	    {

	      error0 = PPPOECLIENT_ERROR_LINK_DOWN;

	      next0 = PPPOECLIENT_SESSION_OUTPUT_NEXT_DROP;

	      goto trace0;
	    }

	  try_update_tcp_mss (b0);

	  vlib_buffer_advance (b0, -sizeof (pppoe_header_t));

	  pppoe0 = vlib_buffer_get_current (b0);

	  pppoe0->ver_type = PPPOE_VER_TYPE;

	  pppoe0->code = PPPOE_SESSION_DATA;

	  pppoe0->session_id = clib_host_to_net_u16 (c0->session_id);

	  pppoe0->length = clib_host_to_net_u16 (b0->current_length - sizeof (pppoe_header_t));

	  vlib_buffer_advance (b0, -sizeof (ethernet_header_t));

	  h0 = vlib_buffer_get_current (b0);

	  h0->type = clib_host_to_net_u16 (ETHERNET_TYPE_PPPOE_SESSION);

	  clib_memcpy (h0->src_address, hw0->hw_address,

		       sizeof (h0->src_address));

	  clib_memcpy (h0->dst_address, c0->ac_mac_address,

		       sizeof (h0->dst_address));

	  // buffer advance will have length adjusted, no need do again.

	  // b0->current_length += sizeof (pppoe_header_t) + sizeof (ethernet_header_t);

	  next0 = c0->hw_output_next_index;

	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = c0->sw_if_index;

	  session_out_pkts++;

	trace0:

	  b0->error = error0 ? node->errors[error0] : 0;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))

	    {

	      // todo: add trace.
	    }

	  if (pem->client_index_by_pppox_sw_if_index[pppox_sw_if_index1] == ~0)

	    {

	      error1 = PPPOECLIENT_ERROR_CLIENT_DELETED;

	      next1 = PPPOECLIENT_SESSION_OUTPUT_NEXT_DROP;

	      goto trace1;
	    }

	  /* client may be freed by interface type change */

	  if (pool_is_free_index (pem->clients,
				  pem->client_index_by_pppox_sw_if_index[pppox_sw_if_index1]))

	    {

	      error1 = PPPOECLIENT_ERROR_CLIENT_DELETED;

	      next1 = PPPOECLIENT_SESSION_OUTPUT_NEXT_DROP;

	      goto trace1;
	    }

	  c1 = pool_elt_at_index (pem->clients,

				  pem->client_index_by_pppox_sw_if_index[pppox_sw_if_index1]);

	  hw1 = vnet_get_sup_hw_interface (vnm, c1->hw_if_index);

	  sup_sw1 = vnet_get_sup_sw_interface (vnm, c1->sw_if_index);

	  sw1 = vnet_get_sw_interface (vnm, c1->sw_if_index);

	  /* Interface(s) down? */

	  if ((hw1->flags & VNET_HW_INTERFACE_FLAG_LINK_UP) == 0)

	    {

	      error1 = PPPOECLIENT_ERROR_LINK_DOWN;

	      next1 = PPPOECLIENT_SESSION_OUTPUT_NEXT_DROP;

	      goto trace1;
	    }

	  if ((sup_sw1->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) == 0)

	    {

	      error1 = PPPOECLIENT_ERROR_LINK_DOWN;

	      next1 = PPPOECLIENT_SESSION_OUTPUT_NEXT_DROP;

	      goto trace1;
	    }

	  if ((sw1->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) == 0)

	    {

	      error1 = PPPOECLIENT_ERROR_LINK_DOWN;

	      next1 = PPPOECLIENT_SESSION_OUTPUT_NEXT_DROP;

	      goto trace1;
	    }

	  try_update_tcp_mss (b1);

	  vlib_buffer_advance (b1, -sizeof (pppoe_header_t));

	  pppoe1 = vlib_buffer_get_current (b1);

	  pppoe1->ver_type = PPPOE_VER_TYPE;

	  pppoe1->code = PPPOE_SESSION_DATA;

	  pppoe1->session_id = clib_host_to_net_u16 (c1->session_id);

	  pppoe1->length = clib_host_to_net_u16 (b1->current_length - sizeof (pppoe_header_t));

	  vlib_buffer_advance (b1, -sizeof (ethernet_header_t));

	  h1 = vlib_buffer_get_current (b1);

	  h1->type = clib_host_to_net_u16 (ETHERNET_TYPE_PPPOE_SESSION);

	  clib_memcpy (h1->src_address, hw1->hw_address,

		       sizeof (h1->src_address));

	  clib_memcpy (h1->dst_address, c1->ac_mac_address,

		       sizeof (h1->dst_address));

	  // buffer advance will have length adjusted, no need do again.

	  //          b1->current_length += sizeof (pppoe_header_t) + sizeof (ethernet_header_t);

	  next1 = c1->hw_output_next_index;

	  vnet_buffer (b1)->sw_if_index[VLIB_TX] = c1->sw_if_index;

	  session_out_pkts++;

	trace1:

	  b1->error = error1 ? node->errors[error1] : 0;

	  if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))

	    {

	      // TODO: add trace.
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,

					   to_next, n_left_to_next,

					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)

	{

	  u32 bi0;

	  vlib_buffer_t *b0;

	  u32 next0;

	  ethernet_header_t *h0;

	  pppoe_header_t *pppoe0;

	  vnet_hw_interface_t *hw0;

	  vnet_sw_interface_t *sup_sw0, *sw0;

	  pppoe_client_t *c0 = 0;

	  u32 error0;

	  u32 pppox_sw_if_index0;

	  bi0 = from[0];

	  to_next[0] = bi0;

	  from += 1;

	  to_next += 1;

	  n_left_to_next -= 1;

	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  pppox_sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];

	  error0 = 0;

	  if (pem->client_index_by_pppox_sw_if_index[pppox_sw_if_index0] == ~0)

	    {

	      error0 = PPPOECLIENT_ERROR_CLIENT_DELETED;

	      next0 = PPPOECLIENT_SESSION_OUTPUT_NEXT_DROP;

	      goto trace00;
	    }

	  /* client may be freed by interface type change */

	  if (pool_is_free_index (pem->clients,
				  pem->client_index_by_pppox_sw_if_index[pppox_sw_if_index0]))

	    {

	      error0 = PPPOECLIENT_ERROR_CLIENT_DELETED;

	      next0 = PPPOECLIENT_SESSION_OUTPUT_NEXT_DROP;

	      goto trace00;
	    }

	  c0 = pool_elt_at_index (pem->clients,

				  pem->client_index_by_pppox_sw_if_index[pppox_sw_if_index0]);

	  hw0 = vnet_get_sup_hw_interface (vnm, c0->hw_if_index);

	  sup_sw0 = vnet_get_sup_sw_interface (vnm, c0->sw_if_index);

	  sw0 = vnet_get_sw_interface (vnm, c0->sw_if_index);

	  /* Interface(s) down? */

	  if ((hw0->flags & VNET_HW_INTERFACE_FLAG_LINK_UP) == 0)

	    {

	      error0 = PPPOECLIENT_ERROR_LINK_DOWN;

	      next0 = PPPOECLIENT_SESSION_OUTPUT_NEXT_DROP;

	      goto trace00;
	    }

	  if ((sup_sw0->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) == 0)

	    {

	      error0 = PPPOECLIENT_ERROR_LINK_DOWN;

	      next0 = PPPOECLIENT_SESSION_OUTPUT_NEXT_DROP;

	      goto trace00;
	    }

	  if ((sw0->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) == 0)

	    {

	      error0 = PPPOECLIENT_ERROR_LINK_DOWN;

	      next0 = PPPOECLIENT_SESSION_OUTPUT_NEXT_DROP;

	      goto trace00;
	    }

	  try_update_tcp_mss (b0);

	  vlib_buffer_advance (b0, -sizeof (pppoe_header_t));

	  pppoe0 = vlib_buffer_get_current (b0);

	  pppoe0->ver_type = PPPOE_VER_TYPE;

	  pppoe0->code = PPPOE_SESSION_DATA;

	  pppoe0->session_id = clib_host_to_net_u16 (c0->session_id);

	  pppoe0->length = clib_host_to_net_u16 (b0->current_length - sizeof (pppoe_header_t));

	  vlib_buffer_advance (b0, -sizeof (ethernet_header_t));

	  h0 = vlib_buffer_get_current (b0);

	  h0->type = clib_host_to_net_u16 (ETHERNET_TYPE_PPPOE_SESSION);

	  clib_memcpy (h0->src_address, hw0->hw_address,

		       sizeof (h0->src_address));

	  clib_memcpy (h0->dst_address, c0->ac_mac_address,

		       sizeof (h0->dst_address));

	  // buffer advance will have length adjusted, no need do again.

	  // b0->current_length += sizeof (pppoe_header_t) + sizeof (ethernet_header_t);

	  next0 = c0->hw_output_next_index;

	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = c0->sw_if_index;

	  session_out_pkts++;

	trace00:

	  b0->error = error0 ? node->errors[error0] : 0;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))

	    {

	      // TODO: add trace
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,

					   to_next, n_left_to_next,

					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, pppoeclient_session_output_node.index,

			       PPPOECLIENT_ERROR_SESSION_OUTPUT_PKTS,

			       session_out_pkts);

  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (pppoeclient_session_output_node) = {

  .function = pppoeclient_session_output,

  .name = "pppoeclient-session-output",

  /* Takes a vector of packets. */

  .vector_size = sizeof (u32),



  .n_errors = PPPOECLIENT_N_ERROR,

  .error_strings = pppoeclient_error_strings,



  .n_next_nodes = PPPOECLIENT_SESSION_OUTPUT_N_NEXT,

  .next_nodes = {

#define _(s, n) [PPPOECLIENT_SESSION_OUTPUT_NEXT_##s] = n,

    foreach_pppoeclient_session_output_next

#undef _

  },



  .format_trace = format_pppoeclient_session_tx_trace,

};

/////// DISPATCH FEATURE NODE /////
// This node runs on the "device-input" feature arc, before "ethernet-input".
// It inspects the Ethertype: if PPPoE Discovery (0x8863) or Session (0x8864),
// it advances past the Ethernet header and dispatches to the appropriate
// pppoeclient input node. Otherwise, it passes through to the next feature
// (e.g., the official pppoe plugin or ethernet-input).
// This avoids the Ethertype registration conflict with the pppoe plugin.

#define foreach_pppoeclient_dispatch_next                                     \
  _ (DROP, "error-drop")                                                      \
  _ (DISCOVERY_INPUT, "pppoeclient-discovery-input")                          \
  _ (SESSION_INPUT, "pppoeclient-session-input")                              \
  _ (ETHERNET_INPUT, "ethernet-input")

typedef enum
{
#define _(s, n) PPPOECLIENT_DISPATCH_NEXT_##s,
  foreach_pppoeclient_dispatch_next
#undef _
    PPPOECLIENT_DISPATCH_N_NEXT,
} pppoeclient_dispatch_next_t;

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u16 ethertype;
} pppoeclient_dispatch_trace_t;

static u8 *
format_pppoeclient_dispatch_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pppoeclient_dispatch_trace_t *t =
    va_arg (*args, pppoeclient_dispatch_trace_t *);
  s = format (s,
	      "pppoeclient-dispatch: sw_if_index %d ethertype 0x%04x next %d",
	      t->sw_if_index, t->ethertype, t->next_index);
  return s;
}

static uword
pppoeclient_dispatch (vlib_main_t *vm, vlib_node_runtime_t *node,
		      vlib_frame_t *from_frame)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  ethernet_header_t *h0;
	  u16 ethertype0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* Get the Ethernet header */
	  h0 = vlib_buffer_get_current (b0);
	  ethertype0 = clib_net_to_host_u16 (h0->type);

	  /* Handle VLAN-tagged frames */
	  if (ethertype0 == ETHERNET_TYPE_VLAN)
	    {
	      ethernet_vlan_header_t *vlan0 =
		(ethernet_vlan_header_t *) (h0 + 1);
	      ethertype0 = clib_net_to_host_u16 (vlan0->type);
	    }

	  if (ethertype0 == ETHERNET_TYPE_PPPOE_DISCOVERY)
	    {
	      /* Advance past Ethernet header so pppoeclient node sees PPPoE
	       * header */
	      vlib_buffer_advance (b0, sizeof (ethernet_header_t));
	      next0 = PPPOECLIENT_DISPATCH_NEXT_DISCOVERY_INPUT;
	    }
	  else if (ethertype0 == ETHERNET_TYPE_PPPOE_SESSION)
	    {
	      /* Advance past Ethernet header so pppoeclient node sees PPPoE
	       * header */
	      vlib_buffer_advance (b0, sizeof (ethernet_header_t));
	      next0 = PPPOECLIENT_DISPATCH_NEXT_SESSION_INPUT;
	    }
	  else
	    {
	      /* Not a PPPoE frame - pass through to ethernet-input */
	      next0 = PPPOECLIENT_DISPATCH_NEXT_ETHERNET_INPUT;
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      pppoeclient_dispatch_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->next_index = next0;
	      tr->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      tr->ethertype = ethertype0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (pppoeclient_dispatch_node) = {
  .function = pppoeclient_dispatch,
  .name = "pppoeclient-dispatch",
  .vector_size = sizeof (u32),
  .n_errors = PPPOECLIENT_N_ERROR,
  .error_strings = pppoeclient_error_strings,
  .n_next_nodes = PPPOECLIENT_DISPATCH_N_NEXT,
  .next_nodes = {
#define _(s, n) [PPPOECLIENT_DISPATCH_NEXT_##s] = n,
    foreach_pppoeclient_dispatch_next
#undef _
  },
  .format_trace = format_pppoeclient_dispatch_trace,
};

/* Register pppoeclient-dispatch as a feature on device-input arc.
 * It runs AFTER pppoe-input so the official pppoe plugin gets first dibs
 * on server-side sessions, while pppoeclient handles client-side traffic. */
VNET_FEATURE_INIT (pppoeclient_dispatch_feat, static) = {
  .arc_name = "device-input",
  .node_name = "pppoeclient-dispatch",
  .runs_after = VNET_FEATURES ("pppoe-input"),
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

/*

 *

 * Local Variables:

 * eval: (c-set-style "gnu")

 * End:

 */
