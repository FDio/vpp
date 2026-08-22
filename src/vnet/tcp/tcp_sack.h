/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#ifndef SRC_VNET_TCP_TCP_SACK_H_
#define SRC_VNET_TCP_TCP_SACK_H_

#include <vnet/tcp/tcp_types.h>

always_inline u32
scoreboard_hole_index (sack_scoreboard_t * sb, sack_scoreboard_hole_t * hole)
{
  ASSERT (!pool_is_free_index (sb->holes, hole - sb->holes));
  return hole - sb->holes;
}

always_inline u32
scoreboard_hole_bytes (sack_scoreboard_hole_t * hole)
{
  return hole->end - hole->start;
}

always_inline sack_scoreboard_hole_t *
scoreboard_get_hole (sack_scoreboard_t * sb, u32 index)
{
  if (index != TCP_INVALID_SACK_HOLE_INDEX)
    return pool_elt_at_index (sb->holes, index);
  return 0;
}

always_inline sack_scoreboard_hole_t *
scoreboard_next_hole (sack_scoreboard_t * sb, sack_scoreboard_hole_t * hole)
{
  if (hole->next != TCP_INVALID_SACK_HOLE_INDEX)
    return pool_elt_at_index (sb->holes, hole->next);
  return 0;
}

always_inline sack_scoreboard_hole_t *
scoreboard_prev_hole (sack_scoreboard_t * sb, sack_scoreboard_hole_t * hole)
{
  if (hole->prev != TCP_INVALID_SACK_HOLE_INDEX)
    return pool_elt_at_index (sb->holes, hole->prev);
  return 0;
}

always_inline sack_scoreboard_hole_t *
scoreboard_first_hole (sack_scoreboard_t * sb)
{
  if (sb->head != TCP_INVALID_SACK_HOLE_INDEX)
    return pool_elt_at_index (sb->holes, sb->head);
  return 0;
}

always_inline sack_scoreboard_hole_t *
scoreboard_last_hole (sack_scoreboard_t * sb)
{
  if (sb->tail != TCP_INVALID_SACK_HOLE_INDEX)
    return pool_elt_at_index (sb->holes, sb->tail);
  return 0;
}

#if TCP_SCOREBOARD_TRACE
#define tcp_scoreboard_trace_add(_tc, _ack)                                                        \
  {                                                                                                \
    static u64 _group = 0;                                                                         \
    sack_scoreboard_t *_sb = &_tc->sack_sb;                                                        \
    sack_block_t *_sack, *_sacks;                                                                  \
    scoreboard_trace_elt_t *_elt;                                                                  \
    int i;                                                                                         \
    _group++;                                                                                      \
    _sacks = _tc->rcv_opts.sacks;                                                                  \
    if (seq_gt (_ack, _tc->snd_una))                                                               \
      {                                                                                            \
	vec_add2 (_sb->trace, _elt, 1);                                                            \
	_elt->start = _tc->snd_una;                                                                \
	_elt->end = _ack;                                                                          \
	_elt->ack = _ack;                                                                          \
	_elt->snd_nxt = _tc->snd_nxt;                                                              \
	_elt->group = _group;                                                                      \
      }                                                                                            \
    for (i = 0; i < vec_len (_sacks); i++)                                                         \
      {                                                                                            \
	_sack = &_sacks[i];                                                                        \
	vec_add2 (_sb->trace, _elt, 1);                                                            \
	_elt->start = _sack->start;                                                                \
	_elt->end = _sack->end;                                                                    \
	_elt->ack = 0;                                                                             \
	_elt->snd_nxt = 0;                                                                         \
	_elt->group = _group;                                                                      \
      }                                                                                            \
  }

#define tcp_sack_trace(_tc, _ack)                                                                  \
  do                                                                                               \
    {                                                                                              \
      if (!((_tc)->cfg_flags & TCP_CFG_F_BYTE_TRACKER))                                            \
	tcp_scoreboard_trace_add (_tc, _ack);                                                      \
    }                                                                                              \
  while (0)
#else
#define tcp_scoreboard_trace_add(_tc, _ack)
#define tcp_sack_trace(_tc, _ack)
#endif

sack_scoreboard_hole_t *scoreboard_next_rxt_hole (sack_scoreboard_t *sb,
						  sack_scoreboard_hole_t *start,
						  u8 have_sent_1_smss, u8 *can_rescue,
						  u8 *snd_limited);
void scoreboard_clear (sack_scoreboard_t * sb);
void scoreboard_init (sack_scoreboard_t * sb);

format_function_t format_tcp_scoreboard;

void tcp_update_sack_list (tcp_connection_t * tc, u32 start, u32 end);
void tcp_dsack_cleanup (tcp_connection_t *tc);
void tcp_dsack_recovery_clear (tcp_connection_t *tc);
void tcp_dsack_recovery_init (tcp_connection_t *tc);
void tcp_sack_recovery_exit (tcp_connection_t *tc, tcp_ack_flag_t spurious_flags);
void tcp_dsack_track_retransmit (tcp_connection_t *tc, u32 start, u32 end);
u32 tcp_sack_list_bytes (tcp_connection_t * tc);
void tcp_rcv_dsack (tcp_connection_t *tc, u32 ack, tcp_ack_ctx_t *ac);
void tcp_loss_on_ack (tcp_connection_t *tc, tcp_ack_ctx_t *ac);
void tcp_ack_handle_full_feedback (tcp_connection_t *tc, u32 packet_ack, u32 ack,
				   tcp_ack_ctx_t *ac);

static_always_inline void
tcp_ack_handle_feedback (tcp_connection_t *tc, u32 packet_ack, tcp_ack_ctx_t *ac)
{
  sack_scoreboard_t *sb = &tc->sack_sb;
  u32 ack = seq_max (packet_ack, tc->snd_una);
  u8 has_ack_state, needs_full_feedback;

  ac->bytes_acked = ack - tc->snd_una;
  has_ack_state = ((sb->flags & TCP_DSACK_RXT_ACTIVE) != 0) | (sb->sacked_bytes != 0) |
		  (sb->head != TCP_INVALID_SACK_HOLE_INDEX);
  needs_full_feedback = ((tc->cfg_flags & TCP_CFG_F_BYTE_TRACKER) != 0) |
			(tcp_opts_sack (&tc->rcv_opts) != 0) |
			((ac->bytes_acked != 0) & has_ack_state);

  if (PREDICT_FALSE (needs_full_feedback))
    {
      tcp_ack_handle_full_feedback (tc, packet_ack, ack, ac);
      return;
    }

  ac->acked_and_sacked = ac->bytes_acked;
}

void tcp_sack_init_rxt (tcp_connection_t *tc, u32 snd_una);
void tcp_sack_recompute_loss (tcp_connection_t *tc);
void tcp_sack_rxt_mark_lost (tcp_connection_t *tc);
u8 tcp_sack_handle_reneging (tcp_connection_t *tc);
u8 *tcp_scoreboard_replay (u8 *s, tcp_connection_t *tc, u8 verbose);

#endif /* SRC_VNET_TCP_TCP_SACK_H_ */
