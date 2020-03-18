/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef SRC_VNET_TCP_TCP_SACK_H_
#define SRC_VNET_TCP_TCP_SACK_H_

#if TCP_SCOREBOARD_TRACE
#define tcp_scoreboard_trace_add(_tc, _ack) 				\
{									\
    static u64 _group = 0;						\
    sack_scoreboard_t *_sb = &_tc->sack_sb;				\
    sack_block_t *_sack, *_sacks;					\
    scoreboard_trace_elt_t *_elt;					\
    int i;								\
    _group++;								\
    _sacks = _tc->rcv_opts.sacks;					\
    for (i = 0; i < vec_len (_sacks); i++) 				\
      {									\
	_sack = &_sacks[i];						\
	vec_add2 (_sb->trace, _elt, 1);					\
	_elt->start = _sack->start;					\
	_elt->end = _sack->end;						\
	_elt->ack = _elt->end == _ack ? _ack : 0;			\
	_elt->snd_una_max = _elt->end == _ack ? _tc->snd_una_max : 0;	\
	_elt->group = _group;						\
      }									\
}
#else
#define tcp_scoreboard_trace_add(_tc, _ack)
#endif

sack_scoreboard_hole_t *scoreboard_next_rxt_hole (sack_scoreboard_t * sb,
						  sack_scoreboard_hole_t *
						  start, u8 have_sent_1_smss,
						  u8 * can_rescue,
						  u8 * snd_limited);
sack_scoreboard_hole_t *scoreboard_get_hole (sack_scoreboard_t * sb,
					     u32 index);

sack_scoreboard_hole_t *scoreboard_next_hole (sack_scoreboard_t * sb,
					      sack_scoreboard_hole_t * hole);
sack_scoreboard_hole_t *scoreboard_prev_hole (sack_scoreboard_t * sb,
					      sack_scoreboard_hole_t * hole);
sack_scoreboard_hole_t *scoreboard_first_hole (sack_scoreboard_t * sb);
sack_scoreboard_hole_t *scoreboard_last_hole (sack_scoreboard_t * sb);

void scoreboard_clear (sack_scoreboard_t * sb);
void scoreboard_clear_reneging (sack_scoreboard_t * sb, u32 start, u32 end);
void scoreboard_init (sack_scoreboard_t * sb);
void scoreboard_init_rxt (sack_scoreboard_t * sb, u32 snd_una);
u8 *format_tcp_scoreboard (u8 * s, va_list * args);


/* Made public for unit testing only */
void tcp_update_sack_list (tcp_connection_t * tc, u32 start, u32 end);
u32 tcp_sack_list_bytes (tcp_connection_t * tc);
void tcp_rcv_sacks (tcp_connection_t * tc, u32 ack);
u8 *tcp_scoreboard_replay (u8 * s, tcp_connection_t * tc, u8 verbose);

#endif /* SRC_VNET_TCP_TCP_SACK_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
