/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <sfdp_services/base/tcp-check/tcp_check.h>
#include <vnet/sfdp/service.h>
#include <vnet/sfdp/timer/timer.h>

#define foreach_sfdp_tcp_check_error _ (DROP, "drop")

typedef enum
{
#define _(sym, str) SFDP_TCP_CHECK_ERROR_##sym,
  foreach_sfdp_tcp_check_error
#undef _
    SFDP_TCP_CHECK_N_ERROR,
} sfdp_tcp_check_error_t;

static char *sfdp_tcp_check_error_strings[] = {
#define _(sym, string) string,
  foreach_sfdp_tcp_check_error
#undef _
};

typedef struct
{
  u32 flow_id;
  u32 old_state_flags;
  u32 new_state_flags;
} sfdp_tcp_check_trace_t;

static u8 *
format_sfdp_tcp_check_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  sfdp_tcp_check_trace_t *t = va_arg (*args, sfdp_tcp_check_trace_t *);
  u32 indent = format_get_indent (s);
  indent += 2;
  s = format (s, "sfdp-tcp-check: flow-id %u (session %u, %s)\n", t->flow_id,
	      t->flow_id >> 1, t->flow_id & 0x1 ? "reverse" : "forward");
  s = format (s, "%Uold session flags: %U\n", format_white_space, indent,
	      format_sfdp_tcp_check_session_flags, t->old_state_flags);
  s = format (s, "%Unew session flags: %U\n", format_white_space, indent,
	      format_sfdp_tcp_check_session_flags, t->new_state_flags);
  return s;
}

SFDP_SERVICE_DECLARE (drop)
static_always_inline void
update_state_one_pkt (sfdp_tw_t *tw, sfdp_tenant_t *tenant,
		      sfdp_tcp_check_session_state_t *tcp_session,
		      sfdp_session_t *session, f64 current_time, u8 dir,
		      u16 *to_next, vlib_buffer_t **b, u32 *sf, u32 *nsf)
{
  /* Parse the packet */
  /* TODO: !!! Broken with IP options !!! */
  u8 *data = vlib_buffer_get_current (b[0]);
  tcp_header_t *tcph =
    (void *) (data + (session->type == SFDP_SESSION_TYPE_IP4 ?
			sizeof (ip4_header_t) :
			sizeof (ip6_header_t)));
  ip4_header_t *ip4 = (void *) data;
  ip6_header_t *ip6 = (void *) data;
  /* Ignore non first fragments */
  if (session->type == SFDP_SESSION_TYPE_IP4 &&
      ip4->flags_and_fragment_offset &
	clib_host_to_net_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS - 1))
    {
      sfdp_next (b[0], to_next);
      return;
    }

  if (session->type == SFDP_SESSION_TYPE_IP6 && ip6_ext_hdr (ip6->protocol))
    {
      ip6_ext_hdr_chain_t chain = { 0 };
      int res = ip6_ext_header_walk (b[0], ip6, IP_PROTOCOL_IPV6_FRAGMENTATION,
				     &chain);
      if (res >= 0 && chain.eh[res].protocol == IP_PROTOCOL_IPV6_FRAGMENTATION)
	{
	  ip6_frag_hdr_t *frag =
	    ip6_ext_next_header_offset (ip6, chain.eh[res].offset);
	  if (ip6_frag_hdr_offset (frag))
	    {
	      sfdp_next (b[0], to_next);
	      return;
	    }
	}
      tcph =
	ip6_ext_next_header_offset (ip6, chain.eh[chain.length - 1].offset);
    }

  u8 flags = tcph->flags & SFDP_TCP_CHECK_TCP_FLAGS_MASK;
  u32 acknum = clib_net_to_host_u32 (tcph->ack_number);
  u32 seqnum = clib_net_to_host_u32 (tcph->seq_number);
  u32 next_timeout = 0;
  u8 remove_session = 0;
  if (PREDICT_FALSE (tcp_session->version != session->session_version))
    {
      tcp_session->version = session->session_version;
      tcp_session->flags = 0;
      tcp_session->as_u64_0 = 0;
      if (flags != SFDP_TCP_CHECK_TCP_FLAGS_SYN)
	{
	  /* Abnormal, put the session in blocked state */
	  session->bitmaps[SFDP_FLOW_FORWARD] = SFDP_SERVICE_MASK (drop);
	  session->bitmaps[SFDP_FLOW_REVERSE] = SFDP_SERVICE_MASK (drop);
	  sfdp_buffer (b[0])->service_bitmap = SFDP_SERVICE_MASK (drop);
	  tcp_session->flags = SFDP_TCP_CHECK_SESSION_FLAG_BLOCKED;
	}
    }
  nsf[0] = (sf[0] = tcp_session->flags);
  if (dir == SFDP_FLOW_FORWARD)
    {
      if (sf[0] & SFDP_TCP_CHECK_SESSION_FLAG_BLOCKED)
	goto out;
      if (flags & SFDP_TCP_CHECK_TCP_FLAGS_SYN)
	{
	  /* New session, must be a SYN otherwise bad */
	  if (sf[0] == 0)
	    nsf[0] = SFDP_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_SYN |
		     SFDP_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_ACK_TO_SYN;
	  else
	    {
	      remove_session = 1;
	      goto out;
	    }
	}
      if (flags & SFDP_TCP_CHECK_TCP_FLAGS_ACK)
	{
	  /* Either ACK to SYN */
	  if (sf[0] & SFDP_TCP_CHECK_SESSION_FLAG_WAIT_FOR_INIT_ACK_TO_SYN)
	    nsf[0] &= ~SFDP_TCP_CHECK_SESSION_FLAG_WAIT_FOR_INIT_ACK_TO_SYN;
	  /* Or ACK to FIN */
	  if (sf[0] & SFDP_TCP_CHECK_SESSION_FLAG_SEEN_FIN_RESP &&
	      acknum == tcp_session->fin_num[SFDP_FLOW_REVERSE])
	    nsf[0] |= SFDP_TCP_CHECK_SESSION_FLAG_SEEN_ACK_TO_FIN_INIT;
	  /* Or regular ACK */
	}
      if (flags & SFDP_TCP_CHECK_TCP_FLAGS_FIN)
	{
	  /*If we were up, we are not anymore */
	  nsf[0] &= ~SFDP_TCP_CHECK_SESSION_FLAG_ESTABLISHED;
	  /*Seen our FIN, wait for the other FIN and for an ACK*/
	  tcp_session->fin_num[SFDP_FLOW_FORWARD] = seqnum + 1;
	  nsf[0] |= SFDP_TCP_CHECK_SESSION_FLAG_SEEN_FIN_INIT;
	}
      if (flags & SFDP_TCP_CHECK_TCP_FLAGS_RST)
	{
	  /* Reason to kill the connection */
	  remove_session = 1;
	  goto out;
	}
    }
  if (dir == SFDP_FLOW_REVERSE)
    {
      if (sf[0] & SFDP_TCP_CHECK_SESSION_FLAG_BLOCKED)
	goto out;
      if (flags & SFDP_TCP_CHECK_TCP_FLAGS_SYN)
	{
	  if (sf[0] & SFDP_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_SYN)
	    nsf[0] ^= SFDP_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_SYN |
		      SFDP_TCP_CHECK_SESSION_FLAG_WAIT_FOR_INIT_ACK_TO_SYN;
	}
      if (flags & SFDP_TCP_CHECK_TCP_FLAGS_ACK)
	{
	  /* Either ACK to SYN */
	  if (sf[0] & SFDP_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_ACK_TO_SYN)
	    nsf[0] &= ~SFDP_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_ACK_TO_SYN;
	  /* Or ACK to FIN */
	  if (sf[0] & SFDP_TCP_CHECK_SESSION_FLAG_SEEN_FIN_INIT &&
	      acknum == tcp_session->fin_num[SFDP_FLOW_FORWARD])
	    nsf[0] |= SFDP_TCP_CHECK_SESSION_FLAG_SEEN_ACK_TO_FIN_RESP;
	  /* Or regular ACK */
	}
      if (flags & SFDP_TCP_CHECK_TCP_FLAGS_FIN)
	{
	  /*If we were up, we are not anymore */
	  nsf[0] &= ~SFDP_TCP_CHECK_SESSION_FLAG_ESTABLISHED;
	  /* Seen our FIN, wait for the other FIN and for an ACK */
	  tcp_session->fin_num[SFDP_FLOW_REVERSE] = seqnum + 1;
	  nsf[0] |= SFDP_TCP_CHECK_SESSION_FLAG_SEEN_FIN_RESP;
	}
      if (flags & SFDP_TCP_CHECK_TCP_FLAGS_RST)
	{
	  /* Reason to kill the connection */
	  nsf[0] = SFDP_TCP_CHECK_SESSION_FLAG_REMOVING;
	  remove_session = 1;
	  goto out;
	}
    }
  /* If all flags are cleared connection is established! */
  if (nsf[0] == 0)
    {
      nsf[0] = SFDP_TCP_CHECK_SESSION_FLAG_ESTABLISHED;
      session->state = SFDP_SESSION_STATE_ESTABLISHED;
    }

  /* If all FINs are ACKED, game over */
  if ((nsf[0] & (SFDP_TCP_CHECK_SESSION_FLAG_SEEN_ACK_TO_FIN_INIT)) &&
      (nsf[0] & SFDP_TCP_CHECK_SESSION_FLAG_SEEN_ACK_TO_FIN_RESP))
    {
      nsf[0] = SFDP_TCP_CHECK_SESSION_FLAG_REMOVING;
      remove_session = 1;
    }
out:
  tcp_session->flags = nsf[0];
  if (remove_session)
    next_timeout = 0;
  else if (nsf[0] & SFDP_TCP_CHECK_SESSION_FLAG_ESTABLISHED)
    next_timeout = tenant->timeouts[SFDP_TIMEOUT_TCP_ESTABLISHED];
  else if (nsf[0] & SFDP_TCP_CHECK_SESSION_FLAG_BLOCKED)
    next_timeout = tenant->timeouts[SFDP_TIMEOUT_SECURITY];
  else
    next_timeout = tenant->timeouts[SFDP_TIMEOUT_EMBRYONIC];

  sfdp_session_timer_update_maybe_past (tw, SFDP_SESSION_TIMER (session),
					current_time, next_timeout);
  sfdp_next (b[0], to_next);
  return;
}

VLIB_NODE_FN (sfdp_tcp_check_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_timer_main_t *sfdpt = &sfdp_timer_main;
  sfdp_tcp_check_main_t *vtcm = &sfdp_tcp;
  u32 thread_index = vlib_get_thread_index ();
  sfdp_timer_per_thread_data_t *timer_ptd =
    vec_elt_at_index (sfdpt->per_thread_data, thread_index);

  sfdp_session_t *session;
  sfdp_tenant_t *tenant;
  u32 session_idx;
  sfdp_tcp_check_session_state_t *tcp_session;
  sfdp_tw_t *tw = &timer_ptd->wheel;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;
  u32 state_flags[VLIB_FRAME_SIZE], *sf = state_flags;
  u32 new_state_flags[VLIB_FRAME_SIZE], *nsf = new_state_flags;
  f64 current_time = timer_ptd->current_time;

  vlib_get_buffers (vm, from, bufs, n_left);
  while (n_left > 0)
    {
      session_idx = sfdp_session_from_flow_index (b[0]->flow_id);
      session = sfdp_session_at_index (session_idx);
      tcp_session = vec_elt_at_index (vtcm->state, session_idx);
      tenant = sfdp_tenant_at_index (sfdp, sfdp_buffer (b[0])->tenant_index);
      if (sfdp_direction_from_flow_index (b[0]->flow_id) == SFDP_FLOW_FORWARD)
	update_state_one_pkt (tw, tenant, tcp_session, session, current_time,
			      SFDP_FLOW_FORWARD, to_next, b, sf, nsf);
      else
	update_state_one_pkt (tw, tenant, tcp_session, session, current_time,
			      SFDP_FLOW_REVERSE, to_next, b, sf, nsf);
      n_left -= 1;
      b += 1;
      to_next += 1;
      sf += 1;
      nsf += 1;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, next_indices, frame->n_vectors);
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      int i;
      b = bufs;
      sf = state_flags;
      nsf = new_state_flags;
      n_left = frame->n_vectors;
      for (i = 0; i < n_left; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      sfdp_tcp_check_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->flow_id = b[0]->flow_id;
	      t->old_state_flags = sf[0];
	      t->new_state_flags = nsf[0];
	      b++;
	      sf++;
	      nsf++;
	    }
	  else
	    break;
	}
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (sfdp_tcp_check_node) = {
  .name = "sfdp-tcp-check",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_tcp_check_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (sfdp_tcp_check_error_strings),
  .error_strings = sfdp_tcp_check_error_strings
};

SFDP_SERVICE_DEFINE (tcp_check) = {
  .node_name = "sfdp-tcp-check",
  .runs_before = SFDP_SERVICES (0),
  .runs_after = SFDP_SERVICES ("sfdp-drop", "sfdp-l4-lifecycle"),
  .is_terminal = 0
};
