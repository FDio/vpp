/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

/* tcp_tamper.c - test-only TCP egress segment tampering node */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/tcp/tcp_inlines.h>
#include <unittest/tcp/tcp_tamper.h>

tcp_tamper_main_t tcp_tamper_main = {
  .out4_next = ~0,
  .out6_next = ~0,
};

#ifndef CLIB_MARCH_VARIANT
vlib_node_registration_t tcp_tamper_node;
#endif

typedef struct
{
  u32 seq;
  u8 flags;
  u8 dropped;
  u8 is_ip4;
} tcp_tamper_trace_t;

#ifndef CLIB_MARCH_VARIANT
static u8 *
format_tcp_tamper_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  tcp_tamper_trace_t *t = va_arg (*args, tcp_tamper_trace_t *);

  s = format (s, "TCP-TAMPER: ip%d seq %u flags 0x%x -> %s", t->is_ip4 ? 4 : 6, t->seq, t->flags,
	      t->dropped ? "drop" : "pass");
  return s;
}
#endif /* CLIB_MARCH_VARIANT */

#define foreach_tcp_tamper_error                                                                   \
  _ (PASSED, "segments passed through")                                                            \
  _ (DROPPED, "segments dropped")

typedef enum
{
#define _(sym, str) TCP_TAMPER_ERROR_##sym,
  foreach_tcp_tamper_error
#undef _
    TCP_TAMPER_N_ERROR,
} tcp_tamper_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *tcp_tamper_error_strings[] = {
#define _(sym, string) string,
  foreach_tcp_tamper_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  TCP_TAMPER_NEXT_DROP,
  TCP_TAMPER_NEXT_IP4_LOOKUP,
  TCP_TAMPER_NEXT_IP6_LOOKUP,
  TCP_TAMPER_N_NEXT,
} tcp_tamper_next_t;

/* Read the host-order seq and flags from an egress TCP segment. The node is
 * only ever a next node of tcp4/6-output, which records the TCP header location
 * in l4_hdr_offset when it pushes the header (before IP), so use that directly
 * rather than assuming a fixed IP header size. The IP version comes from the
 * buffer flag. */
static_always_inline void
tcp_tamper_parse (vlib_buffer_t *b, u32 *seq, u8 *flags, u8 *is_ip4)
{
  tcp_header_t *th;

  ASSERT (b->flags & VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
  th = (tcp_header_t *) (b->data + vnet_buffer (b)->l4_hdr_offset);
  *is_ip4 = (b->flags & VNET_BUFFER_F_IS_IP4) != 0;

  *seq = clib_net_to_host_u32 (th->seq_number);
  *flags = th->flags;
}

/* Decide whether this segment should be dropped, updating rule counters.
 * Connection indices are worker-local, so a connection-scoped rule must match
 * the worker too. */
static_always_inline int
tcp_tamper_should_drop (u32 thread_index, u32 conn_index, u32 seq, u8 flags)
{
  tcp_tamper_main_t *im = &tcp_tamper_main;
  /* The connection may be gone during teardown. */
  tcp_connection_t *tc = tcp_connection_get_if_valid (conn_index, thread_index);
  tcp_tamper_rule_t *r;

  vec_foreach (r, im->rules)
    {
      /* conn_index and thread_index are independent wildcards (~0 = any). */
      if (r->conn_index != ~0u && r->conn_index != conn_index)
	continue;
      if (r->thread_index != ~0u && r->thread_index != thread_index)
	continue;
      if ((flags & r->flags_mask) != r->flags_match)
	continue;
      if (r->above_rp_in_recovery)
	{
	  /* Only while in recovery and at/above the current recovery point. */
	  if (!tc || !tcp_in_cong_recovery (tc) || seq_lt (seq, tc->snd_congestion))
	    continue;
	}
      else if (r->seq_is_min)
	{
	  /* Wraparound-safe lower-bound match. */
	  if (seq_lt (seq, r->min_seq))
	    continue;
	}
      else if (r->seq != ~0u && r->seq != seq)
	continue;
      r->n_matched += 1;
      if (r->n_drop)
	{
	  /* Record sender state at the first drop. */
	  if (r->n_dropped == 0 && tc)
	    {
	      r->drop_in_recovery = tcp_in_cong_recovery (tc);
	      r->drop_snd_una = tc->snd_una;
	      r->drop_snd_congestion = tc->snd_congestion;
	    }
	  r->n_drop -= 1;
	  r->n_dropped += 1;
	  return 1;
	}
    }
  return 0;
}

VLIB_NODE_FN (tcp_tamper_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 n_dropped = 0, n_passed = 0;
  u8 is_trace = node->flags & VLIB_NODE_FLAG_TRACE;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from > 0)
    {
      u32 seq = 0, conn_index = vnet_buffer (b[0])->tcp.connection_index;
      u8 flags = 0, is_ip4 = 1, drop;

      tcp_tamper_parse (b[0], &seq, &flags, &is_ip4);
      drop = tcp_tamper_should_drop (vm->thread_index, conn_index, seq, flags);

      if (drop)
	{
	  next[0] = TCP_TAMPER_NEXT_DROP;
	  b[0]->error = node->errors[TCP_TAMPER_ERROR_DROPPED];
	  n_dropped += 1;
	}
      else
	{
	  next[0] = is_ip4 ? TCP_TAMPER_NEXT_IP4_LOOKUP : TCP_TAMPER_NEXT_IP6_LOOKUP;
	  n_passed += 1;
	}

      if (PREDICT_FALSE (is_trace && (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  tcp_tamper_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->seq = seq;
	  t->flags = flags;
	  t->dropped = drop;
	  t->is_ip4 = is_ip4;
	}

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  vlib_node_increment_counter (vm, node->node_index, TCP_TAMPER_ERROR_DROPPED, n_dropped);
  vlib_node_increment_counter (vm, node->node_index, TCP_TAMPER_ERROR_PASSED, n_passed);
  return frame->n_vectors;
}

#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (tcp_tamper_node) = {
  .name = "tcp-test-tamper",
  .vector_size = sizeof (u32),
  .format_trace = format_tcp_tamper_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = TCP_TAMPER_N_ERROR,
  .error_strings = tcp_tamper_error_strings,
  .n_next_nodes = TCP_TAMPER_N_NEXT,
  .next_nodes = {
    [TCP_TAMPER_NEXT_DROP] = "error-drop",
    [TCP_TAMPER_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [TCP_TAMPER_NEXT_IP6_LOOKUP] = "ip6-lookup",
  },
};

void
tcp_tamper_reset (void)
{
  tcp_tamper_main_t *im = &tcp_tamper_main;
  vec_free (im->rules);
}

tcp_tamper_rule_t *
tcp_tamper_add_rule (void)
{
  tcp_tamper_main_t *im = &tcp_tamper_main;
  tcp_tamper_rule_t *r;

  vec_add2 (im->rules, r, 1);
  clib_memset (r, 0, sizeof (*r));
  r->seq = ~0u;
  r->conn_index = ~0u;
  r->thread_index = ~0u;
  return r;
}

/* Scope a rule to a single connection (index is worker-local). */
static inline void
tcp_tamper_rule_set_conn (tcp_tamper_rule_t *r, tcp_connection_t *tc)
{
  r->conn_index = tc->c_c_index;
  r->thread_index = tc->c_thread_index;
}

tcp_tamper_rule_t *
tcp_tamper_drop_fin (tcp_connection_t *tc, u32 n_drop)
{
  tcp_tamper_rule_t *r = tcp_tamper_add_rule ();
  tcp_tamper_rule_set_conn (r, tc);
  r->flags_mask = TCP_FLAG_FIN;
  r->flags_match = TCP_FLAG_FIN;
  r->n_drop = n_drop;
  return r;
}

tcp_tamper_rule_t *
tcp_tamper_drop_seq (tcp_connection_t *tc, u32 seq, u32 n_drop)
{
  tcp_tamper_rule_t *r = tcp_tamper_add_rule ();
  tcp_tamper_rule_set_conn (r, tc);
  r->seq = seq;
  r->n_drop = n_drop;
  return r;
}

tcp_tamper_rule_t *
tcp_tamper_drop_from_seq (tcp_connection_t *tc, u32 min_seq, u32 n_drop)
{
  tcp_tamper_rule_t *r = tcp_tamper_add_rule ();
  tcp_tamper_rule_set_conn (r, tc);
  r->seq_is_min = 1;
  r->min_seq = min_seq;
  r->n_drop = n_drop;
  return r;
}

tcp_tamper_rule_t *
tcp_tamper_drop_above_rp (tcp_connection_t *tc, u32 n_drop)
{
  tcp_tamper_rule_t *r = tcp_tamper_add_rule ();
  tcp_tamper_rule_set_conn (r, tc);
  r->above_rp_in_recovery = 1;
  r->n_drop = n_drop;
  return r;
}

tcp_tamper_rule_t *
tcp_tamper_drop_pure_ack (tcp_connection_t *tc, u32 n_drop)
{
  tcp_tamper_rule_t *r = tcp_tamper_add_rule ();
  tcp_tamper_rule_set_conn (r, tc);
  /* ACK set, and FIN/SYN/RST all clear: a pure ack, not a control segment. */
  r->flags_mask = TCP_FLAG_ACK | TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST;
  r->flags_match = TCP_FLAG_ACK;
  r->n_drop = n_drop;
  return r;
}

void
tcp_tamper_enable (tcp_connection_t *tc)
{
  tcp_tamper_main_t *im = &tcp_tamper_main;
  vlib_main_t *vm = vlib_get_main ();

  if (im->out4_next == ~0u)
    {
      im->out4_next = vlib_node_add_next (vm, tcp4_output_node.index, tcp_tamper_node.index);
      im->out6_next = vlib_node_add_next (vm, tcp6_output_node.index, tcp_tamper_node.index);
    }

  tc->next_node_index = tc->c_is_ip4 ? im->out4_next : im->out6_next;
  tc->next_node_opaque = 0;
}

void
tcp_tamper_disable (tcp_connection_t *tc)
{
  tc->next_node_index = 0;
  tc->next_node_opaque = 0;
}

#endif /* CLIB_MARCH_VARIANT */
