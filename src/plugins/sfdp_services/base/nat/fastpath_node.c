/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <sfdp_services/base/nat/nat.h>
#include <vnet/sfdp/service.h>
#include <vnet/sfdp/sfdp_funcs.h>

#define foreach_sfdp_nat_fastpath_error _ (DROP, "drop")

#define foreach_sfdp_nat_terminal_next                                        \
  _ (DROP, "error-drop")                                                      \
  _ (IP4_LOOKUP, "ip4-lookup")

typedef enum
{
#define _(n, x) SFDP_NAT_TERMINAL_NEXT_##n,
  foreach_sfdp_nat_terminal_next
#undef _
    SFDP_NAT_TERMINAL_N_NEXT
} sfdp_nat_terminal_next_t;

typedef enum
{
#define _(sym, str) SFDP_NAT_FASTPATH_ERROR_##sym,
  foreach_sfdp_nat_fastpath_error
#undef _
    SFDP_NAT_FASTPATH_N_ERROR,
} sfdp_nat_fastpath_error_t;

static char *sfdp_nat_fastpath_error_strings[] = {
#define _(sym, string) string,
  foreach_sfdp_nat_fastpath_error
#undef _
};

typedef struct
{
  u32 thread_index;
  u32 flow_id;
} sfdp_nat_fastpath_trace_t;

static u8 *
format_sfdp_nat_fastpath_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  sfdp_nat_fastpath_trace_t *t = va_arg (*args, sfdp_nat_fastpath_trace_t *);
  nat_main_t *nm = &nat_main;
  nat_rewrite_data_t *rewrite = vec_elt_at_index (nm->flows, t->flow_id);
  s = format (
    s, "sfdp-nat-fastpath: flow-id %u (session %u, %s) rewrite: %U\n",
    t->flow_id, t->flow_id >> 1, t->flow_id & 0x1 ? "reverse" : "forward",
    format_sfdp_nat_rewrite, rewrite);

  return s;
}

SFDP_SERVICE_DECLARE (drop)

static_always_inline void
nat_fastpath_process_one (nat_rewrite_data_t *nat_session,
			  sfdp_session_t *session, u16 *to_next,
			  vlib_buffer_t **b, u8 is_terminal)
{
  u8 *data = vlib_buffer_get_current (b[0]);
  u8 proto = nat_session->rewrite.proto;
  u32 ops;
  ip4_header_t *ip4 = (void *) data;
  ip_csum_t ip_sum = 0, tcp_sum = 0, udp_sum = 0, icmp_sum = 0;
  tcp_header_t *tcp;
  udp_header_t *udp;
  icmp46_header_t *icmp;
  u16 *icmp_id;

  if (session->session_version != nat_session->version)
    {
      sfdp_buffer (b[0])->service_bitmap = SFDP_SERVICE_MASK (drop);
      goto end_of_packet;
    }

  ops = nat_session->ops;

  ip_sum = ip4->checksum;
  ip_sum = ip_csum_sub_even (ip_sum, nat_session->l3_csum_delta);
  ip_sum = ip_csum_fold (ip_sum);
  ip4->checksum = ip_sum;

  if (ops & NAT_REWRITE_OP_SADDR)
    ip4->src_address = nat_session->rewrite.saddr;

  if (ops & NAT_REWRITE_OP_DADDR)
    ip4->dst_address = nat_session->rewrite.daddr;

  if (proto == IP_PROTOCOL_TCP)
    {
      tcp = ip4_next_header (ip4);
      tcp_sum = tcp->checksum;
      tcp_sum = ip_csum_sub_even (tcp_sum, nat_session->l3_csum_delta);
      tcp_sum = ip_csum_sub_even (tcp_sum, nat_session->l4_csum_delta);
      tcp_sum = ip_csum_fold (tcp_sum);
      tcp->checksum = tcp_sum;

      if (ops & NAT_REWRITE_OP_SPORT)
	tcp->src_port = nat_session->rewrite.sport;

      if (ops & NAT_REWRITE_OP_DPORT)
	tcp->dst_port = nat_session->rewrite.dport;
    }
  else if (proto == IP_PROTOCOL_UDP)
    {
      udp = ip4_next_header (ip4);
      udp_sum = udp->checksum;
      udp_sum = ip_csum_sub_even (udp_sum, nat_session->l3_csum_delta);
      udp_sum = ip_csum_sub_even (udp_sum, nat_session->l4_csum_delta);
      udp_sum = ip_csum_fold (udp_sum);
      udp->checksum = udp_sum;

      if (ops & NAT_REWRITE_OP_SPORT)
	udp->src_port = nat_session->rewrite.sport;

      if (ops & NAT_REWRITE_OP_DPORT)
	udp->dst_port = nat_session->rewrite.dport;
    }
  else if (proto == IP_PROTOCOL_ICMP)
    {
      icmp = ip4_next_header (ip4);
      icmp_sum = icmp->checksum;
      icmp_id = (u16 *) (icmp + 1);
      icmp_sum = ip_csum_sub_even (icmp_sum, nat_session->l4_csum_delta);
      icmp_sum = ip_csum_fold (icmp_sum);
      icmp->checksum = icmp_sum;
      if (ops & NAT_REWRITE_OP_ICMP_ID)
	*icmp_id = nat_session->rewrite.icmp_id;
    }
  else
    {
      /*FIXME, must be done at the beginning!*/
      sfdp_buffer (b[0])->service_bitmap = SFDP_SERVICE_MASK (drop);
      goto end_of_packet;
    }

  if (ops & NAT_REWRITE_OP_TXFIB)
    vnet_buffer (b[0])->sw_if_index[VLIB_TX] = nat_session->rewrite.fib_index;

  if (is_terminal)
    {
      to_next[0] = SFDP_NAT_TERMINAL_NEXT_IP4_LOOKUP;
      return;
    }

end_of_packet:
  sfdp_next (b[0], to_next);
  return;
}

static_always_inline u16
sfdp_nat_fastpath_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_frame_t *frame, u8 is_terminal)
{

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  nat_main_t *nat = &nat_main;
  u32 thread_index = vlib_get_thread_index ();

  sfdp_session_t *session;
  u32 session_idx;
  nat_rewrite_data_t *nat_rewrite;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;

  vlib_get_buffers (vm, from, bufs, n_left);
  while (n_left > 0)
    {
      session_idx = sfdp_session_from_flow_index (b[0]->flow_id);
      session = sfdp_session_at_index (session_idx);
      nat_rewrite = vec_elt_at_index (nat->flows, b[0]->flow_id);

      nat_fastpath_process_one (nat_rewrite, session, to_next, b, is_terminal);
      n_left -= 1;
      b += 1;
      to_next += 1;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, next_indices, frame->n_vectors);
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      int i;
      b = bufs;
      n_left = frame->n_vectors;
      for (i = 0; i < n_left; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      sfdp_nat_fastpath_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->flow_id = b[0]->flow_id;
	      t->thread_index = thread_index;
	      b++;
	    }
	  else
	    break;
	}
    }
  return frame->n_vectors;
}

VLIB_NODE_FN (sfdp_nat_early_rewrite_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return sfdp_nat_fastpath_inline (vm, node, frame, 0);
}

VLIB_NODE_FN (sfdp_nat_late_rewrite_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return sfdp_nat_fastpath_inline (vm, node, frame, 1);
}

VLIB_REGISTER_NODE (sfdp_nat_early_rewrite_node) = {
  .name = "sfdp-nat-early-rewrite",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_nat_fastpath_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (sfdp_nat_fastpath_error_strings),
  .error_strings = sfdp_nat_fastpath_error_strings
};

VLIB_REGISTER_NODE (sfdp_nat_late_rewrite_node) = {
  .name = "sfdp-nat-late-rewrite",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_nat_fastpath_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (sfdp_nat_fastpath_error_strings),
  .error_strings = sfdp_nat_fastpath_error_strings,
  .n_next_nodes = SFDP_NAT_TERMINAL_N_NEXT,
  .next_nodes = {
#define _(n, x) [SFDP_NAT_TERMINAL_NEXT_##n] = x,
          foreach_sfdp_nat_terminal_next
#undef _
  }

};

SFDP_SERVICE_DEFINE (nat_late_rewrite) = {
  .node_name = "sfdp-nat-late-rewrite",
  .runs_before = SFDP_SERVICES (0),
  .runs_after = SFDP_SERVICES ("sfdp-drop", "sfdp-l4-lifecycle",
			       "sfdp-tcp-check", "sfdp-nat-output"),
  .is_terminal = 1
};

SFDP_SERVICE_DEFINE (nat_early_rewrite) = {
  .node_name = "sfdp-nat-early-rewrite",
  .runs_before = SFDP_SERVICES ("sfdp-geneve-output"),
  .runs_after = SFDP_SERVICES ("sfdp-drop", "sfdp-l4-lifecycle",
			       "sfdp-tcp-check"),
  .is_terminal = 0
};