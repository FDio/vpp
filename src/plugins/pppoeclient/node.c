/* SPDX-License-Identifier: Apache-2.0 */
/*

 * node.c: pppoe client related packet logic.

 */

#include <vlib/vlib.h>

#include <ppp/packet.h>

#include <vnet/tcp/tcp_packet.h>
#include <pppoeclient/pppox/pppox.h>
#include <pppoeclient/pppoeclient.h>

/* PPP protocol numbers — canonical values in pppoeclient.h;
 * map the PPP_PROTOCOL_* names used by the session-input/output nodes. */
#define PPP_PROTOCOL_ipcp   PPP_IPCP
#define PPP_PROTOCOL_ipv6cp PPP_IPV6CP
#define PPP_PROTOCOL_lcp    PPP_LCP
#define PPP_PROTOCOL_pap    PPP_PAP
#define PPP_PROTOCOL_chap   PPP_CHAP
#define PPP_PROTOCOL_ip4    PPP_IP
#define PPP_PROTOCOL_ip6    PPP_IPV6

static char *pppoeclient_error_strings[] = {

#define pppoeclient_error(n, s) s,

#include <pppoeclient/pppoeclient_error.def>

#undef pppoeclient_error

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

  s = format (s, "PPPoE discovery sw_if_index %u host_uniq %u session_id %u error %u",

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

      /* Control packet use 1 batch is enough. */

      while (n_left_from > 0 && n_left_to_next > 0)

	{

	  u32 bi0;

	  vlib_buffer_t *b0;

	  /* The control packet will be dropped after processed. */

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

	  /* Guard against undersized buffers before we touch any header field.
	   * Without this, pppoe0->ver_type and every downstream
	   * b0->current_length - sizeof(*pppoe0) computation (used to bound
	   * the control-history raw-tag capture) could read out of bounds. */
	  if (PREDICT_FALSE (b0->current_length < sizeof (pppoe_header_t)))
	    {
	      error0 = PPPOECLIENT_ERROR_BAD_VER_TYPE;
	      goto trace00;
	    }

	  if (PREDICT_FALSE (pppoe0->ver_type != PPPOE_VER_TYPE))
	    {
	      error0 = PPPOECLIENT_ERROR_BAD_VER_TYPE;
	      goto trace00;
	    }

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

	  error0 = consume_pppoe_discovery_pkt (bi0, b0, pppoe0);

	trace00:

	  b0->error = error0 ? node->errors[error0] : 0;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))

	    {

	      pppoeclient_discovery_rx_trace_t *tr

		= vlib_add_trace (vm, node, b0, sizeof (*tr));

	      tr->error = error0;
	      tr->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      tr->session_id = b0->current_length >= sizeof (pppoe_header_t) ?
				 clib_net_to_host_u16 (pppoe0->session_id) :
				 0;
	      tr->packet_code = b0->current_length >= sizeof (pppoe_header_t) ? pppoe0->code : 0;
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

/* SESSION NODE */

static_always_inline u16
pppoeclient_get_tcp_mss_limit (u32 cached_mtu, u8 is_ip6)
{
  u32 headers = sizeof (tcp_header_t) + (is_ip6 ? sizeof (ip6_header_t) : sizeof (ip4_header_t));

  if (cached_mtu <= headers)
    return 0;

  return (u16) (cached_mtu - headers);
}

static_always_inline u32
pppoeclient_tcp_mss_fixup (tcp_header_t *tcp, u16 max_mss, u32 tcp_avail)
{
  ip_csum_t sum;

  if (max_mss == 0 || !tcp_syn (tcp))
    return 0;

  /* tcp_doff is the TCP data-offset field in 32-bit words; RFC 9293
   * requires it to be at least 5 (the fixed tcp_header_t is 20 bytes).
   * An attacker-supplied doff below 5 would make the subtraction below
   * underflow and walk off the buffer looking for options. */
  if (PREDICT_FALSE (tcp_doff (tcp) < 5))
    return 0;

  u32 tcp_hdr_len = (u32) (tcp_doff (tcp) << 2);
  if (PREDICT_FALSE (tcp_avail < tcp_hdr_len))
    return 0;

  u8 opts_len = tcp_hdr_len - sizeof (tcp_header_t);
  const u8 *data = (const u8 *) (tcp + 1);

  for (; opts_len > 0;)
    {
      u8 kind = data[0];
      u8 opt_len;

      if (kind == TCP_OPTION_EOL)
	break;
      if (kind == TCP_OPTION_NOOP)
	{
	  data++;
	  opts_len--;
	  continue;
	}

      if (opts_len < 2)
	return 0;
      opt_len = data[1];
      if (opt_len < 2 || opt_len > opts_len)
	return 0;

      if (kind == TCP_OPTION_MSS && opt_len == 4)
	{
	  /* The MSS option begins at an odd offset inside the TCP options
	   * block (kind + length precede it), so the u16 value is not
	   * guaranteed to land on a two-byte boundary. Use the unaligned
	   * helper so targets that trap on misaligned accesses stay safe. */
	  u16 old_mss = clib_mem_unaligned (data + 2, u16);
	  if (clib_net_to_host_u16 (old_mss) > max_mss)
	    {
	      u16 new_mss = clib_host_to_net_u16 (max_mss);
	      clib_mem_unaligned (data + 2, u16) = new_mss;
	      sum = tcp->checksum;
	      sum = ip_csum_update (sum, old_mss, new_mss, tcp_header_t, checksum);
	      tcp->checksum = ip_csum_fold (sum);
	      return 1;
	    }
	  break;
	}

      data += opt_len;
      opts_len -= opt_len;
    }

  return 0;
}

static_always_inline void
pppoeclient_try_update_tcp_mss (vlib_main_t *vm, vlib_buffer_t *b, u32 cached_mtu)
{
  u8 *ppp = vlib_buffer_get_current (b);

  /* Need at least 2 bytes for PPP protocol field */
  if (PREDICT_FALSE (b->current_length < 2))
    return;

  /* The PPP protocol field sits right after the ethertype-stripped frame;
   * it is not guaranteed to be two-byte aligned after VLAN tag handling,
   * so avoid a direct u16 load. */
  u16 ppp_protocol = clib_net_to_host_u16 (clib_mem_unaligned (ppp, u16));

  if (ppp_protocol == PPP_PROTOCOL_ip4)
    {
      /* Need PPP proto (2) + IP4 header (20) minimum */
      if (PREDICT_FALSE (b->current_length < 2 + sizeof (ip4_header_t)))
	return;
      ip4_header_t *ip4 = (ip4_header_t *) (ppp + 2);
      if (ip4->protocol == IP_PROTOCOL_TCP)
	{
	  /* Need PPP proto (2) + IP4 header + TCP header (20) minimum */
	  if (PREDICT_FALSE (b->current_length <
			     2 + ip4_header_bytes (ip4) + sizeof (tcp_header_t)))
	    return;
	  tcp_header_t *tcp = ip4_next_header (ip4);
	  u32 tcp_avail = b->current_length - 2 - ip4_header_bytes (ip4);
	  u16 max_mss = pppoeclient_get_tcp_mss_limit (cached_mtu, 0);
	  (void) pppoeclient_tcp_mss_fixup (tcp, max_mss, tcp_avail);
	}
    }
  else if (ppp_protocol == PPP_PROTOCOL_ip6)
    {
      /* Need PPP proto (2) + IP6 header (40) minimum */
      if (PREDICT_FALSE (b->current_length < 2 + sizeof (ip6_header_t)))
	return;
      ip6_header_t *ip6 = (ip6_header_t *) (ppp + 2);
      tcp_header_t *tcp = ip6_ext_header_find (vm, b, ip6, IP_PROTOCOL_TCP, NULL);
      if (tcp)
	{
	  u32 tcp_offset = (u8 *) tcp - (u8 *) vlib_buffer_get_current (b);
	  u32 tcp_avail = b->current_length > tcp_offset ? b->current_length - tcp_offset : 0;
	  u16 max_mss = pppoeclient_get_tcp_mss_limit (cached_mtu, 1);
	  (void) pppoeclient_tcp_mss_fixup (tcp, max_mss, tcp_avail);
	}
    }
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

  s = format (s, "PPPoE session sw_if_index %u session_id %u error %u pppox_sw_if_index %u",

	      t->sw_if_index, t->session_id, t->error, t->pppox_sw_if_index);

  return s;
}

/* Per-packet worker for pppoeclient_session_input.  Runs every session-data
 * packet through the same validation-lookup-rewrite pipeline so the x2 and
 * x1 loops below only need to differ in prefetch/enqueue bookkeeping.  All
 * outputs (next-node index, error, resolved client, original pppoe header,
 * original rx sw_if_index) are written via the out-struct so the caller can
 * fill tracing metadata without re-reading the buffer.  static_always_inline
 * keeps it folded into both callers, preserving the hand-rolled x2 throughput
 * characteristics. */
typedef struct
{
  u32 next;
  u32 error;
  pppoeclient_t *c;
  pppoe_header_t *pppoe;
  u32 rx_sw_if_index;
} pppoeclient_session_input_result_t;

static_always_inline void
pppoeclient_session_input_one (vlib_main_t *vm, pppoeclient_main_t *pem, vlib_buffer_t *b,
			       pppoeclient_session_input_result_t *r)
{
  ethernet_header_t *h;
  pppoe_header_t *pppoe = 0;
  u16 l2_hdr_len = sizeof (ethernet_header_t);
  u32 rx_sw_if_index;
  u32 error = 0;
  u32 next = PPPOECLIENT_SESSION_INPUT_NEXT_DROP;
  u16 ppp_proto;
  pppoeclient_result_t lookup;
  pppoeclient_t *c = 0;

  rx_sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
  vlib_buffer_reset (b);

  if (PREDICT_FALSE (!pppoeclient_get_l2_info (b, &h, &pppoe, 0, &l2_hdr_len)))
    {
      error = PPPOECLIENT_ERROR_BAD_VER_TYPE;
      goto out;
    }

  if (PREDICT_FALSE (pppoe->ver_type != PPPOE_VER_TYPE ||
		     b->current_length < l2_hdr_len + sizeof (*pppoe) + 2))
    {
      error = PPPOECLIENT_ERROR_BAD_VER_TYPE;
      goto out;
    }
  if (PREDICT_FALSE (clib_net_to_host_u16 (pppoe->length) >
		     b->current_length - l2_hdr_len - sizeof (*pppoe)))
    {
      error = PPPOECLIENT_ERROR_BAD_CODE_IN_SESSION;
      goto out;
    }

  ppp_proto = clib_net_to_host_u16 (clib_mem_unaligned (pppoe + 1, u16));

  if (pppoe->code != PPPOE_SESSION_DATA)
    {
      error = PPPOECLIENT_ERROR_BAD_CODE_IN_SESSION;
      goto out;
    }

  pppoeclient_lookup_session_1 (&pem->session_table, rx_sw_if_index, h->src_address,
				clib_net_to_host_u16 (pppoe->session_id), &lookup);
  if (PREDICT_FALSE (lookup.fields.client_index == ~0))
    {
      error = PPPOECLIENT_ERROR_NO_SUCH_SESSION;
      goto out;
    }
  if (pool_is_free_index (pem->clients, lookup.fields.client_index))
    {
      error = PPPOECLIENT_ERROR_CLIENT_DELETED;
      goto out;
    }

  c = pool_elt_at_index (pem->clients, lookup.fields.client_index);
  vlib_buffer_advance (b, l2_hdr_len + sizeof (*pppoe));
  /* Clamp current_length to the PPPoE declared payload.  Received Ethernet
   * frames are single-buffer (MTU 1500 << VPP buffer size), so overwriting
   * current_length is safe; total_length_not_including_first_buffer stays 0. */
  b->current_length = clib_net_to_host_u16 (pppoe->length);
  vnet_buffer (b)->sw_if_index[VLIB_RX] = c->pppox_sw_if_index;

  if (ppp_proto == PPP_PROTOCOL_ip4)
    {
      pppoeclient_try_update_tcp_mss (vm, b, c->cached_mtu);
      vlib_buffer_advance (b, sizeof (u16));
      next = PPPOECLIENT_SESSION_INPUT_NEXT_IP4_INPUT;
    }
  else if (ppp_proto == PPP_PROTOCOL_ip6)
    {
      pppoeclient_try_update_tcp_mss (vm, b, c->cached_mtu);
      vlib_buffer_advance (b, sizeof (u16));
      next = PPPOECLIENT_SESSION_INPUT_NEXT_IP6_INPUT;
    }
  else if (ppp_proto == PPP_PROTOCOL_lcp || ppp_proto == PPP_PROTOCOL_pap ||
	   ppp_proto == PPP_PROTOCOL_ipcp || ppp_proto == PPP_PROTOCOL_ipv6cp ||
	   ppp_proto == PPP_PROTOCOL_chap)
    {
      /* Set ppp length to help pppd-adapter parse the ctrl packet. */
      pppox_buffer (b)->len = b->current_length;
      next = PPPOECLIENT_SESSION_INPUT_NEXT_PPPOX_INPUT;
    }
  else
    {
      error = PPPOECLIENT_ERROR_UNSUPPORTED_PPP_PROTOCOL;
    }

out:
  r->next = next;
  r->error = error;
  r->c = c;
  r->pppoe = pppoe;
  r->rx_sw_if_index = rx_sw_if_index;
}

static_always_inline void
pppoeclient_session_input_trace (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
				 const pppoeclient_session_input_result_t *r)
{
  b->error = r->error ? node->errors[r->error] : 0;
  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
    {
      pppoeclient_session_rx_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));
      tr->error = r->error;
      tr->sw_if_index = r->rx_sw_if_index;
      tr->session_id = r->pppoe ? clib_net_to_host_u16 (r->pppoe->session_id) : 0;
      tr->pppox_sw_if_index = r->c ? r->c->pppox_sw_if_index : ~0;
    }
}

static uword

pppoeclient_session_input (vlib_main_t *vm,

			   vlib_node_runtime_t *node,

			   vlib_frame_t *from_frame)

{

  pppoeclient_main_t *pem = &pppoeclient_main;

  u32 n_left_from, next_index, *from, *to_next;

  u32 session_pkts = from_frame->n_vectors;

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
	  pppoeclient_session_input_result_t r0, r1;

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

	  pppoeclient_session_input_one (vm, pem, b0, &r0);
	  pppoeclient_session_input_one (vm, pem, b1, &r1);

	  pppoeclient_session_input_trace (vm, node, b0, &r0);
	  pppoeclient_session_input_trace (vm, node, b1, &r1);

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next, n_left_to_next, bi0, bi1,
					   r0.next, r1.next);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  pppoeclient_session_input_result_t r0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  pppoeclient_session_input_one (vm, pem, b0, &r0);
	  pppoeclient_session_input_trace (vm, node, b0, &r0);

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, n_left_to_next, bi0,
					   r0.next);
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

  s = format (s, "PPPoE session sw_if_index %u session_id %u pppox_sw_if_index %u error %u",
	      t->sw_if_index, t->session_id, t->pppox_sw_if_index, t->error);

  return s;
}

/* Per-packet worker for pppoeclient_session_output.  Applies the same
 * link-up checks, pppoe/L2 header push and next-node selection regardless
 * of whether the dual-packet or single-packet loop drives it.  The result
 * struct carries the counter-increment bit (forwarded) so callers can fold
 * it into session_out_pkts without re-inspecting the client pointer. */
typedef struct
{
  u32 next;
  u32 error;
  pppoeclient_t *c;
  u32 pppox_sw_if_index;
  u8 forwarded;
} pppoeclient_session_output_result_t;

static_always_inline void
pppoeclient_session_output_one (vlib_main_t *vm, pppoeclient_main_t *pem, vlib_buffer_t *b,
				pppoeclient_session_output_result_t *r)
{
  pppoe_header_t *pppoe;
  u32 error = 0;
  u32 next = PPPOECLIENT_SESSION_OUTPUT_NEXT_DROP;
  u32 pppox_sw_if_index;
  pppoeclient_t *c;
  u8 forwarded = 0;

  pppox_sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
  c = pppoeclient_get_client_by_pppox_sw_if_index (pem, pppox_sw_if_index, 0);
  if (c == 0)
    {
      error = PPPOECLIENT_ERROR_CLIENT_DELETED;
      goto out;
    }

  /* Use cached link status instead of per-packet interface lookups.
   * The cached values are set when the session enters SESSION state
   * and are valid until the session is torn down. */
  if (!c->cached_link_up)
    {
      error = PPPOECLIENT_ERROR_LINK_DOWN;
      goto out;
    }

  pppoeclient_try_update_tcp_mss (vm, b, c->cached_mtu);
  vlib_buffer_advance (b, -sizeof (pppoe_header_t));

  pppoe = vlib_buffer_get_current (b);
  pppoe->ver_type = PPPOE_VER_TYPE;
  pppoe->code = PPPOE_SESSION_DATA;
  pppoe->session_id = clib_host_to_net_u16 (c->session_id);
  pppoe->length = clib_host_to_net_u16 (b->current_length - sizeof (pppoe_header_t));

  pppoeclient_push_l2_header_cached (
    b, ETHERNET_TYPE_PPPOE_SESSION, c->cached_src_mac, c->ac_mac_address, c->cached_l2_encap_len,
    c->cached_one_tag, c->cached_two_tags, c->cached_outer_vlan_id, c->cached_inner_vlan_id);

  next = c->cached_hw_output_next_index;
  vnet_buffer (b)->sw_if_index[VLIB_TX] = c->sw_if_index;
  forwarded = 1;

out:
  r->next = next;
  r->error = error;
  r->c = c;
  r->pppox_sw_if_index = pppox_sw_if_index;
  r->forwarded = forwarded;
}

static_always_inline void
pppoeclient_session_output_trace (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
				  const pppoeclient_session_output_result_t *r)
{
  b->error = r->error ? node->errors[r->error] : 0;
  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
    {
      pppoeclient_session_tx_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));
      tr->sw_if_index = r->c ? r->c->sw_if_index : ~0;
      tr->session_id = r->c ? r->c->session_id : 0;
      tr->pppox_sw_if_index = r->pppox_sw_if_index;
      tr->error = r->error;
    }
}

static uword

pppoeclient_session_output (vlib_main_t *vm,

			    vlib_node_runtime_t *node,

			    vlib_frame_t *from_frame)

{

  pppoeclient_main_t *pem = &pppoeclient_main;

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
	  pppoeclient_session_output_result_t r0, r1;

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

	  pppoeclient_session_output_one (vm, pem, b0, &r0);
	  pppoeclient_session_output_one (vm, pem, b1, &r1);

	  session_out_pkts += r0.forwarded + r1.forwarded;

	  pppoeclient_session_output_trace (vm, node, b0, &r0);
	  pppoeclient_session_output_trace (vm, node, b1, &r1);

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next, n_left_to_next, bi0, bi1,
					   r0.next, r1.next);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  pppoeclient_session_output_result_t r0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  pppoeclient_session_output_one (vm, pem, b0, &r0);
	  session_out_pkts += r0.forwarded;
	  pppoeclient_session_output_trace (vm, node, b0, &r0);

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, n_left_to_next, bi0,
					   r0.next);
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

/* DISPATCH FEATURE NODE
 * This node runs on the "device-input" feature arc, before "ethernet-input".
 * It inspects the Ethertype: if PPPoE Discovery (0x8863) or Session (0x8864),
 * it advances past the Ethernet/VLAN header and dispatches to the appropriate
 * pppoeclient input node. Otherwise, it passes through to the next feature
 * in the device-input arc.
 * This avoids the Ethertype registration conflict with the pppoe plugin. */

#define foreach_pppoeclient_dispatch_next                                                          \
  _ (DROP, "error-drop")                                                                           \
  _ (DISCOVERY_INPUT, "pppoeclient-discovery-input")                                               \
  _ (SESSION_INPUT, "pppoeclient-session-input")

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
  pppoeclient_dispatch_trace_t *t = va_arg (*args, pppoeclient_dispatch_trace_t *);
  s = format (s, "pppoeclient-dispatch: sw_if_index %u ethertype 0x%04x next %u", t->sw_if_index,
	      t->ethertype, t->next_index);
  return s;
}

static uword
pppoeclient_dispatch (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
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

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 next0 = PPPOECLIENT_DISPATCH_NEXT_DROP;
	  u32 next1 = PPPOECLIENT_DISPATCH_NEXT_DROP;
	  u16 ethertype0 = 0, ethertype1 = 0;
	  u16 l2_hdr_len0 = sizeof (ethernet_header_t);
	  u16 l2_hdr_len1 = sizeof (ethernet_header_t);

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
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  (void) pppoeclient_get_l2_info (b0, 0, 0, &ethertype0, &l2_hdr_len0);
	  (void) pppoeclient_get_l2_info (b1, 0, 0, &ethertype1, &l2_hdr_len1);

	  if (ethertype0 == ETHERNET_TYPE_PPPOE_DISCOVERY)
	    {
	      vlib_buffer_advance (b0, l2_hdr_len0);
	      next0 = PPPOECLIENT_DISPATCH_NEXT_DISCOVERY_INPUT;
	    }
	  else if (ethertype0 == ETHERNET_TYPE_PPPOE_SESSION)
	    {
	      vlib_buffer_advance (b0, l2_hdr_len0);
	      next0 = PPPOECLIENT_DISPATCH_NEXT_SESSION_INPUT;
	    }
	  else
	    {
	      vnet_feature_next (&next0, b0);
	    }

	  if (ethertype1 == ETHERNET_TYPE_PPPOE_DISCOVERY)
	    {
	      vlib_buffer_advance (b1, l2_hdr_len1);
	      next1 = PPPOECLIENT_DISPATCH_NEXT_DISCOVERY_INPUT;
	    }
	  else if (ethertype1 == ETHERNET_TYPE_PPPOE_SESSION)
	    {
	      vlib_buffer_advance (b1, l2_hdr_len1);
	      next1 = PPPOECLIENT_DISPATCH_NEXT_SESSION_INPUT;
	    }
	  else
	    {
	      vnet_feature_next (&next1, b1);
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      pppoeclient_dispatch_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->next_index = next0;
	      tr->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      tr->ethertype = ethertype0;
	    }

	  if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      pppoeclient_dispatch_trace_t *tr = vlib_add_trace (vm, node, b1, sizeof (*tr));
	      tr->next_index = next1;
	      tr->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];
	      tr->ethertype = ethertype1;
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next, n_left_to_next, bi0, bi1,
					   next0, next1);
	}

      /* x1 tail loop */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = PPPOECLIENT_DISPATCH_NEXT_DROP;
	  u16 ethertype0 = 0;
	  u16 l2_hdr_len0 = sizeof (ethernet_header_t);

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  (void) pppoeclient_get_l2_info (b0, 0, 0, &ethertype0, &l2_hdr_len0);

	  if (ethertype0 == ETHERNET_TYPE_PPPOE_DISCOVERY)
	    {
	      vlib_buffer_advance (b0, l2_hdr_len0);
	      next0 = PPPOECLIENT_DISPATCH_NEXT_DISCOVERY_INPUT;
	    }
	  else if (ethertype0 == ETHERNET_TYPE_PPPOE_SESSION)
	    {
	      vlib_buffer_advance (b0, l2_hdr_len0);
	      next0 = PPPOECLIENT_DISPATCH_NEXT_SESSION_INPUT;
	    }
	  else
	    {
	      vnet_feature_next (&next0, b0);
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      pppoeclient_dispatch_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->next_index = next0;
	      tr->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      tr->ethertype = ethertype0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, n_left_to_next, bi0,
					   next0);
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
