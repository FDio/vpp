/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

/*
 * Test-only TCP segment tampering.
 *
 * A test connection points its output next node (tc->next_node_index) at the
 * tamper node, which parses each egress segment's sequence number and flags,
 * matches it against a small set of armed rules, and either drops the segment
 * or forwards it to ip lookup so it continues to the peer over the loopback
 * datapath.  This lets a unit test deterministically lose a specific control
 * or data segment (e.g. a FIN or the first retransmit of a byte range) while a
 * real connection makes progress, without external network emulation.
 */

#ifndef SRC_PLUGINS_UNITTEST_TCP_TCP_TAMPER_H_
#define SRC_PLUGINS_UNITTEST_TCP_TCP_TAMPER_H_

#include <vnet/tcp/tcp.h>

/* A single tampering rule.  A segment matches when its flags satisfy
 * (flags & flags_mask) == flags_match and, if seq is not ~0, its sequence
 * number equals seq.  Matching segments are dropped until n_drop have been
 * dropped; any further matches (and all non-matching segments) pass through. */
typedef struct
{
  u8 flags_mask;    /**< TCP flag bits to test (0 = ignore flags) */
  u8 flags_match;   /**< required value of the masked flag bits */
  u8 seq_is_min;    /**< if set, match seq >= min_seq instead of seq == exact */
  u8 above_rp_in_recovery; /**< match only in recovery and seq >= snd_congestion */
  u32 seq;	    /**< exact host-order seq to match, or ~0 for any */
  u32 min_seq;	    /**< lower bound (host order) when seq_is_min is set */
  u32 conn_index;   /**< only match this connection (c_c_index), or ~0 for any */
  u32 thread_index; /**< worker the conn_index is local to, or ~0 for any */
  u32 n_drop;	    /**< number of matching segments left to drop */
  u32 n_matched;    /**< total segments that matched this rule */
  u32 n_dropped;    /**< total segments dropped by this rule */
  /* Connection state sampled at the moment of the first drop by this rule.
   * Lets a test assert what the sender was doing when the segment was lost. */
  u8 drop_in_recovery;	   /**< in fast/rto recovery at first drop */
  u32 drop_snd_una;	   /**< snd_una at first drop */
  u32 drop_snd_congestion; /**< snd_congestion (recovery point) at first drop */
} tcp_tamper_rule_t;

typedef struct
{
  tcp_tamper_rule_t *rules; /**< armed rules */
  u32 out4_next;	    /**< tamper slot on tcp4-output, ~0 if unset */
  u32 out6_next;	    /**< tamper slot on tcp6-output, ~0 if unset */
} tcp_tamper_main_t;

extern tcp_tamper_main_t tcp_tamper_main;

/* Clear all rules and counters.  Does not detach connections. */
void tcp_tamper_reset (void);

/* Append a rule and return it so the caller can fill it in.  By default the
 * rule matches any connection; set conn_index to scope it to one. */
tcp_tamper_rule_t *tcp_tamper_add_rule (void);

/* Convenience: drop the first n_drop FIN segments on connection tc. */
tcp_tamper_rule_t *tcp_tamper_drop_fin (tcp_connection_t *tc, u32 n_drop);

/* Convenience: drop the first n_drop segments on connection tc whose seq
 * equals the given host-order sequence number (e.g. a specific retransmit). */
tcp_tamper_rule_t *tcp_tamper_drop_seq (tcp_connection_t *tc, u32 seq, u32 n_drop);

/* Convenience: drop the first n_drop segments on connection tc whose seq is at
 * or above min_seq (host order).  Matches the first segment sent beyond a
 * threshold, e.g. the first segment above a recovery point, regardless of exact
 * segmentation. */
tcp_tamper_rule_t *tcp_tamper_drop_from_seq (tcp_connection_t *tc, u32 min_seq, u32 n_drop);

/* Convenience: drop the first n_drop segments on connection tc that are sent
 * while it is in congestion recovery with a sequence at or above the current
 * recovery point (snd_congestion).  Deterministically targets the first fresh
 * segment above the recovery point during an ongoing recovery episode, the
 * loss needed to force a recovery-point exit and immediate re-entry. */
tcp_tamper_rule_t *tcp_tamper_drop_above_rp (tcp_connection_t *tc, u32 n_drop);

/* Convenience: drop the first n_drop pure-ACK segments (ACK set, FIN/SYN/RST
 * clear) on connection tc.  Used for the lost-final-ack teardown case. */
tcp_tamper_rule_t *tcp_tamper_drop_pure_ack (tcp_connection_t *tc, u32 n_drop);

/* Route this connection's egress through the tamper node, and back. */
void tcp_tamper_enable (tcp_connection_t *tc);
void tcp_tamper_disable (tcp_connection_t *tc);

#endif /* SRC_PLUGINS_UNITTEST_TCP_TCP_TAMPER_H_ */
