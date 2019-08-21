/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

#ifndef SRC_VNET_TCP_TCP_DEBUG_H_
#define SRC_VNET_TCP_TCP_DEBUG_H_

#include <vlib/vlib.h>

/**
 * Build debugging infra unconditionally. Debug components controlled via
 * debug configuration. Comes with some overhead so it's not recommended for
 * production/performance scenarios. Takes priority over TCP_DEBUG_ENABLE.
 */
#define TCP_DEBUG_ALWAYS (0)
/**
 * Build debugging infra only if enabled. Debug components controlled via
 * macros that follow.
 */
#define TCP_DEBUG_ENABLE (0)

#define TCP_DEBUG_SM (0)
#define TCP_DEBUG_CC (0)
#define TCP_DEBUG_CS (0)
#define TCP_DEBUG_LC (0 || TCP_DEBUG_SM || TCP_DEBUG_CC || TCP_DEBUG_CS)

#define TCP_DEBUG (TCP_DEBUG_ALWAYS || TCP_DEBUG_ENABLE)
#define TCP_DEBUG_BUF_ALLOC (0)

#if TCP_DEBUG > 0
#define TRANSPORT_DEBUG (1)
#endif

#define TCP_CONCAT_HELPER(_a, _b) _a##_b
#define TCP_CC(_a, _b) TCP_CONCAT_HELPER(_a, _b)

#define tcp_evt_lvl(_evt) TCP_CC(_evt, _LVL)
#define tcp_evt_grp(_evt) TCP_CC(_evt, _GRP)
#define tcp_evt_handler(_evt, _args...) TCP_CC(_evt, _HANDLER) (_args)
#define tcp_evt_grp_dbg_lvl(_evt) tcp_dbg_main.grp_dbg_lvl[tcp_evt_grp (_evt)]

#define foreach_tcp_evt_grp					\
  _(LC, "life cycle")						\
  _(SM, "state machine")					\
  _(CC, "congestion control")					\
  _(CS, "cc stats")						\

typedef enum tcp_evt_grp_
{
#define _(sym, str) TCP_EVT_GRP_ ## sym,
  foreach_tcp_evt_grp
#undef _
  TCP_EVT_N_GRP
} tcp_evt_grp_e;

typedef struct tcp_dbg_main_
{
  u8 grp_dbg_lvl[TCP_EVT_N_GRP];
  u32 *free_track_indices;
} tcp_dbg_main_t;

extern tcp_dbg_main_t tcp_dbg_main;

#define foreach_tcp_dbg_evt					\
  _(INIT, 		LC, 1, "init")				\
  _(DEALLOC, 		LC, 1, "dealloc")			\
  _(OPEN, 		LC, 1, "open")				\
  _(CLOSE, 		LC, 1, "close")				\
  _(BIND, 		LC, 1, "bind")				\
  _(UNBIND, 		LC, 1, "unbind")			\
  _(DELETE, 		LC, 1, "delete")			\
  _(SYN_RCVD, 		LC, 1, "SYN rcvd")			\
  _(STATE_CHANGE, 	LC, 1, "state change")			\
  _(SYN_SENT, 		SM, 1, "SYN sent")			\
  _(SYN_RXT, 		SM, 1, "SYN retransmit")		\
  _(SYNACK_SENT, 	SM, 1, "SYNACK sent")			\
  _(SYNACK_RCVD, 	SM, 1, "SYNACK rcvd")			\
  _(FIN_SENT, 		SM, 1, "FIN sent")			\
  _(FIN_RCVD, 		SM, 1, "FIN rcvd")			\
  _(RST_SENT, 		SM, 1, "RST sent")			\
  _(RST_RCVD, 		SM, 1, "RST rcvd")			\
  _(TIMER_POP, 		SM, 1, "timer pop")			\
  _(SEG_INVALID, 	SM, 2, "invalid segment")		\
  _(PAWS_FAIL, 		SM, 2, "failed paws check")		\
  _(ACK_RCV_ERR, 	SM, 2, "invalid ack")			\
  _(RCV_WND_SHRUNK, 	SM, 2, "shrunk rcv_wnd")		\
  _(ACK_SENT, 		SM, 3, "ACK sent")			\
  _(ACK_RCVD, 		SM, 3, "ACK rcvd")			\
  _(PKTIZE, 		SM, 3, "packetize")			\
  _(INPUT, 		SM, 3, "in")				\
  _(OUTPUT, 		SM, 4, "output")			\
  _(SND_WND, 		SM, 4, "snd_wnd update")		\
  _(CC_EVT, 		CC, 1, "cc event")			\
  _(CC_RTX, 		CC, 2, "retransmit")			\
  _(CC_PACK, 		CC, 2, "cc partial ack")		\
  _(DUPACK_SENT, 	CC, 2, "DUPACK sent")			\
  _(DUPACK_RCVD, 	CC, 2, "DUPACK rcvd")			\
  _(CC_SCOREBOARD, 	CC, 2, "scoreboard stats")		\
  _(CC_SACKS, 		CC, 2, "snd sacks stats")		\
  _(CC_INPUT, 		CC, 2, "ooo data delivered")		\
  _(CC_STAT, 		CS, 1, "cc stats")			\
  _(CC_RTO_STAT,	CS, 1, "cc rto stats")			\

typedef enum tcp_evt_types_
{
#define _(sym, grp, lvl, str) TCP_EVT_##sym,
  foreach_tcp_dbg_evt
#undef _
} tcp_evt_types_e;

typedef enum tcp_evt_lvl_
{
#define _(sym, grp, lvl, str) TCP_EVT_## sym ## _LVL = lvl,
  foreach_tcp_dbg_evt
#undef _
} tcp_evt_lvl_e;

typedef enum tcp_evt_to_grp_
{
#define _(sym, grp, lvl, str) TCP_EVT_ ## sym ## _GRP = TCP_EVT_GRP_ ## grp,
  foreach_tcp_dbg_evt
#undef _
} tcp_evt_to_grp_e;

#if TCP_DEBUG_ALWAYS > 0
#define TCP_EVT(_evt, _args...) 					\
  if (PREDICT_FALSE (tcp_evt_grp_dbg_lvl (_evt) >= tcp_evt_lvl (_evt)))	\
    tcp_evt_handler (_evt, _args)
#define TCP_DBG(_fmt, _args...) clib_warning (_fmt, ##_args)
#elif TCP_DEBUG_ENABLE > 0
#define TCP_EVT(_evt, _args...) tcp_evt_handler(_evt, _args)
#define TCP_DBG(_fmt, _args...) clib_warning (_fmt, ##_args)
#else
#define TCP_EVT(_evt, _args...)
#define TCP_DBG(_fmt, _args...)
#endif

void tcp_evt_track_register (elog_track_t * et);
void tcp_debug_init (void);

#define TCP_DECLARE_ETD(_tc, _e, _size)					\
struct									\
{									\
  u32 data[_size];							\
} * ed;									\
ed = ELOG_TRACK_DATA (&vlib_global_main.elog_main, _e, 			\
                      _tc->c_elog_track)				\

/*
 * Event handlers definitions
 */

#if TCP_DEBUG_LC || TCP_DEBUG_ALWAYS

/*
 * Infra and evt track setup
 */

#define TCP_DBG_IP_TAG_LCL(_tc)						\
{									\
  if (_tc->c_is_ip4)							\
    {									\
      ELOG_TYPE_DECLARE (_e) =						\
      {									\
        .format = "lcl: %d.%d.%d.%d:%d",				\
        .format_args = "i4i4i4i4i4",					\
      };								\
      TCP_DECLARE_ETD(_tc, _e, 5);					\
      ed->data[0] = _tc->c_lcl_ip.ip4.as_u8[0];				\
      ed->data[1] = _tc->c_lcl_ip.ip4.as_u8[1];				\
      ed->data[2] = _tc->c_lcl_ip.ip4.as_u8[2];				\
      ed->data[3] = _tc->c_lcl_ip.ip4.as_u8[3];				\
      ed->data[4] = clib_net_to_host_u16(_tc->c_lcl_port);		\
    }									\
}

#define TCP_DBG_IP_TAG_RMT(_tc)						\
{									\
  if (_tc->c_is_ip4)							\
    {									\
      ELOG_TYPE_DECLARE (_e) =						\
      {									\
        .format = "rmt: %d.%d.%d.%d:%d",				\
        .format_args = "i4i4i4i4i4",					\
      };								\
      TCP_DECLARE_ETD(_tc, _e, 5);					\
      ed->data[0] = _tc->c_rmt_ip.ip4.as_u8[0];				\
      ed->data[1] = _tc->c_rmt_ip.ip4.as_u8[1];				\
      ed->data[2] = _tc->c_rmt_ip.ip4.as_u8[2];				\
      ed->data[3] = _tc->c_rmt_ip.ip4.as_u8[3];				\
      ed->data[4] = clib_net_to_host_u16(_tc->c_rmt_port);		\
    }									\
}

#define TCP_EVT_INIT_HANDLER(_tc, _is_l, ...)				\
{									\
  char *_fmt = _is_l ? "l[%d].%d:%d%c" : "[%d].%d:%d->.%d:%d%c";	\
  if (_tc->c_is_ip4)							\
    {									\
      _tc->c_elog_track.name =						\
  	(char *) format (0, _fmt, _tc->c_thread_index, 			\
			 _tc->c_lcl_ip.ip4.as_u8[3],			\
			 clib_net_to_host_u16(_tc->c_lcl_port),		\
			 _tc->c_rmt_ip.ip4.as_u8[3], 			\
			 clib_net_to_host_u16(_tc->c_rmt_port), 0);	\
    }									\
  else									\
      _tc->c_elog_track.name =						\
	(char *) format (0, _fmt, _tc->c_thread_index, 			\
			 _tc->c_lcl_ip.ip6.as_u8[15],			\
			 clib_net_to_host_u16(_tc->c_lcl_port),		\
			 _tc->c_rmt_ip.ip6.as_u8[15], 			\
			 clib_net_to_host_u16(_tc->c_rmt_port), 0);	\
  tcp_evt_track_register (&_tc->c_elog_track);				\
  TCP_DBG_IP_TAG_LCL(_tc);						\
  TCP_DBG_IP_TAG_RMT(_tc);						\
}

#define TCP_EVT_DEALLOC_HANDLER(_tc, ...)				\
{									\
  vec_free (_tc->c_elog_track.name);					\
  vec_add1 (tcp_dbg_main.free_track_indices, 				\
            _tc->c_elog_track.track_index_plus_one - 1);		\
}

#define TCP_EVT_OPEN_HANDLER(_tc, ...)					\
{									\
  TCP_EVT_INIT_HANDLER(_tc, 0);						\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "open: index %d",						\
    .format_args = "i4",						\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 1);						\
  ed->data[0] = _tc->c_c_index;						\
}

#define TCP_EVT_CLOSE_HANDLER(_tc, ...)					\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "close: cidx %d",						\
    .format_args = "i4",						\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 1);						\
  ed->data[0] = _tc->c_c_index;						\
}

#define TCP_EVT_BIND_HANDLER(_tc, ...)					\
{									\
  TCP_EVT_INIT_HANDLER(_tc, 1);						\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "bind: listener %d",					\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 1);						\
  ed->data[0] = _tc->c_c_index;						\
}

#define TCP_EVT_SYN_RCVD_HANDLER(_tc,_init, ...)			\
{									\
  if (_init)								\
    TCP_EVT_INIT_HANDLER(_tc, 0);					\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "syn-rx: cidx %u sidx %u irs %u",				\
    .format_args = "i4i4i4",						\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 3);						\
  ed->data[0] = _tc->c_c_index;						\
  ed->data[1] = _tc->c_s_index;						\
  ed->data[2] = _tc->irs;						\
  TCP_EVT_STATE_CHANGE_HANDLER(_tc);					\
}

#define TCP_EVT_UNBIND_HANDLER(_tc, ...)				\
{									\
  TCP_EVT_DEALLOC_HANDLER(_tc);						\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "unbind: listener %d",					\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 1);						\
  ed->data[0] = _tc->c_c_index;						\
  TCP_EVT_DEALLOC_HANDLER(_tc);						\
}

#define TCP_EVT_DELETE_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "delete: cidx %d sidx %d",				\
    .format_args = "i4i4",						\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 2);						\
  ed->data[0] = _tc->c_c_index;						\
  ed->data[1] = _tc->c_s_index;						\
  TCP_EVT_DEALLOC_HANDLER(_tc);						\
}

#endif

/*
 * State machine
 */
#if TCP_DEBUG_SM > 0 || TCP_DEBUG_ALWAYS

#define TCP_EVT_STATE_CHANGE_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "state: %s",						\
    .format_args = "t4",						\
    .n_enum_strings = 11,						\
    .enum_strings = {                                           	\
      "closed",	                                             		\
      "listen",                                                 	\
      "syn-sent",                                                 	\
      "syn-rcvd",							\
      "established",							\
      "close_wait",							\
      "fin-wait-1",							\
      "last-ack",							\
      "closing",							\
      "fin-wait-2",							\
      "time-wait",							\
    },  								\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 1);						\
  ed->data[0] = _tc->state;						\
}

#define TCP_EVT_SYN_SENT_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "syn-tx: iss %u snd_una %u snd_una_max %u snd_nxt %u",	\
    .format_args = "i4i4i4i4",						\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 4);						\
  ed->data[0] = _tc->iss;						\
  ed->data[1] = _tc->snd_una - _tc->iss;				\
  ed->data[2] = _tc->snd_una_max - _tc->iss;				\
  ed->data[3] = _tc->snd_nxt - _tc->iss;				\
  TCP_EVT_STATE_CHANGE_HANDLER(_tc);					\
}

#define TCP_EVT_SYNACK_SENT_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "synack-tx: iss %u irs %u snd_una %u snd_nxt %u rcv_nxt %u",\
    .format_args = "i4i4i4i4i4",					\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _tc->iss;						\
  ed->data[1] = _tc->irs;						\
  ed->data[2] = _tc->snd_una - _tc->iss;				\
  ed->data[3] = _tc->snd_nxt - _tc->iss;				\
  ed->data[4] = _tc->rcv_nxt - _tc->irs;				\
}

#define TCP_EVT_SYNACK_RCVD_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "synack-rx: iss %u irs %u snd_una %u snd_nxt %u rcv_nxt %u",\
    .format_args = "i4i4i4i4i4",					\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _tc->iss;						\
  ed->data[1] = _tc->irs;						\
  ed->data[2] = _tc->snd_una - _tc->iss;				\
  ed->data[3] = _tc->snd_nxt - _tc->iss;				\
  ed->data[4] = _tc->rcv_nxt - _tc->irs;				\
  TCP_EVT_STATE_CHANGE_HANDLER(_tc);					\
}

#define TCP_EVT_FIN_SENT_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "fin-tx: snd_nxt %d rcv_nxt %d",				\
    .format_args = "i4i4",						\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 2);						\
  ed->data[0] = _tc->snd_nxt - _tc->iss;				\
  ed->data[1] = _tc->rcv_nxt - _tc->irs;				\
}

#define TCP_EVT_RST_SENT_HANDLER(_tc, ...)				\
{									\
if (_tc)								\
  {									\
    ELOG_TYPE_DECLARE (_e) =						\
    {									\
      .format = "rst-tx: snd_nxt %d rcv_nxt %d",			\
      .format_args = "i4i4",						\
    };									\
    TCP_DECLARE_ETD(_tc, _e, 2);					\
    ed->data[0] = _tc->snd_nxt - _tc->iss;				\
    ed->data[1] = _tc->rcv_nxt - _tc->irs;				\
    TCP_EVT_STATE_CHANGE_HANDLER(_tc);					\
  }									\
}

#define TCP_EVT_FIN_RCVD_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "fin-rx: snd_nxt %d rcv_nxt %d",				\
    .format_args = "i4i4",						\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 2);						\
  ed->data[0] = _tc->snd_nxt - _tc->iss;				\
  ed->data[1] = _tc->rcv_nxt - _tc->irs;				\
}

#define TCP_EVT_RST_RCVD_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "rst-rx: snd_nxt %d rcv_nxt %d",				\
    .format_args = "i4i4",						\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 2);						\
  ed->data[0] = _tc->snd_nxt - _tc->iss;				\
  ed->data[1] = _tc->rcv_nxt - _tc->irs;				\
}

#define TCP_EVT_SYN_RXT_HANDLER(_tc, _type, ...)			\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "%s-rxt: iss %u irs %u snd_nxt %u rcv_nxt %u",		\
    .format_args = "t4i4i4i4i4",					\
    .n_enum_strings = 2,						\
    .enum_strings = {                                           	\
	"syn",	                                             		\
        "synack",							\
    },  								\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _type;							\
  ed->data[1] = _tc->iss;						\
  ed->data[2] = _tc->irs;						\
  ed->data[3] = _tc->snd_nxt - _tc->iss;				\
  ed->data[4] = _tc->rcv_nxt - _tc->irs;				\
}

#define TCP_EVT_TIMER_POP_HANDLER(_tc_index, _timer_id, ...)            \
{                                                               	\
  tcp_connection_t *_tc;                                        	\
  if (_timer_id == TCP_TIMER_RETRANSMIT_SYN)                        	\
    {                                                           	\
      _tc = tcp_half_open_connection_get (_tc_index);           	\
    }                                                           	\
  else                                                          	\
    {                                                           	\
      u32 _thread_index = vlib_get_thread_index ();                 	\
      _tc = tcp_connection_get (_tc_index, _thread_index);      	\
    }                                                           	\
  ELOG_TYPE_DECLARE (_e) =                                      	\
  {                                                             	\
    .format = "timer-pop: %s cidx %u sidx %u",                  	\
    .format_args = "t4i4i4",                                      	\
    .n_enum_strings = 8,                                        	\
    .enum_strings = {                                           	\
      "retransmit",                                             	\
      "delack",                                                 	\
      "persist",                                                    	\
      "keep",                                                   	\
      "waitclose",                                              	\
      "retransmit syn",                                         	\
      "establish",                                              	\
      "establish-ao",                                              	\
    },                                                          	\
  };                                                            	\
  if (_tc)								\
    {									\
      TCP_DECLARE_ETD(_tc, _e, 3);                                      \
      ed->data[0] = _timer_id;                                      	\
      ed->data[1] = _tc->c_c_index;                                    	\
      ed->data[2] = _tc->c_s_index;                                    	\
    }									\
  else									\
    {									\
      clib_warning ("pop %d for unexisting connection %d", _timer_id,	\
		    _tc_index);						\
    }									\
}

#else
#define TCP_EVT_SYN_SENT_HANDLER(_tc, ...)
#define TCP_EVT_SYNACK_SENT_HANDLER(_tc, ...)
#define TCP_EVT_SYNACK_RCVD_HANDLER(_tc, ...)
#define TCP_EVT_SYN_RXT_HANDLER(_tc, ...)
#define TCP_EVT_FIN_SENT_HANDLER(_tc, ...)
#define TCP_EVT_RST_SENT_HANDLER(_tc, ...)
#define TCP_EVT_FIN_RCVD_HANDLER(_tc, ...)
#define TCP_EVT_RST_RCVD_HANDLER(_tc, ...)
#define TCP_EVT_STATE_CHANGE_HANDLER(_tc, ...)
#define TCP_EVT_TIMER_POP_HANDLER(_tc_index, _timer_id, ...)
#endif

#if TCP_DEBUG_SM > 1 || TCP_DEBUG_ALWAYS
#define TCP_EVT_SEG_INVALID_HANDLER(_tc, _btcp, ...)			\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "seg-inv: seq %u end %u rcv_las %u rcv_nxt %u rcv_wnd %u",\
    .format_args = "i4i4i4i4i4",					\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _btcp.seq_number - _tc->irs;				\
  ed->data[1] = _btcp.seq_end - _tc->irs;				\
  ed->data[2] = _tc->rcv_las - _tc->irs;				\
  ed->data[3] = _tc->rcv_nxt - _tc->irs;				\
  ed->data[4] = _tc->rcv_wnd;						\
}

#define TCP_EVT_PAWS_FAIL_HANDLER(_tc, _seq, _end, ...)			\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "paws-err: seq %u end %u tsval %u tsval_recent %u",	\
    .format_args = "i4i4i4i4",						\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 4);						\
  ed->data[0] = _seq - _tc->irs;					\
  ed->data[1] = _end - _tc->irs;					\
  ed->data[2] = _tc->rcv_opts.tsval;					\
  ed->data[3] = _tc->tsval_recent;					\
}

#define TCP_EVT_ACK_RCV_ERR_HANDLER(_tc, _type, _ack, ...)		\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "ack-err: %s ack %u snd_una %u snd_nxt %u una_max %u",	\
    .format_args = "t4i4i4i4i4",					\
    .n_enum_strings = 3,						\
    .enum_strings = {                                           	\
      "invalid",                                                 	\
      "old",                                                 		\
      "future",								\
    }, 									\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _type;							\
  ed->data[1] = _ack - _tc->iss;					\
  ed->data[2] = _tc->snd_una - _tc->iss;				\
  ed->data[3] = _tc->snd_nxt - _tc->iss;				\
  ed->data[4] = _tc->snd_una_max - _tc->iss;				\
}

#define TCP_EVT_RCV_WND_SHRUNK_HANDLER(_tc, _obs, _av, ...)		\
{									\
if (_av > 0) 								\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "huh?: rcv_wnd %u obsd %u av %u rcv_nxt %u rcv_las %u",	\
    .format_args = "i4i4i4i4i4",					\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _tc->rcv_wnd;						\
  ed->data[1] = _obs;							\
  ed->data[2] = _av;							\
  ed->data[3] = _tc->rcv_nxt - _tc->irs;				\
  ed->data[4] = _tc->rcv_las - _tc->irs;				\
}									\
}
#else
#define TCP_EVT_SEG_INVALID_HANDLER(_tc, _btcp, ...)
#define TCP_EVT_PAWS_FAIL_HANDLER(_tc, _seq, _end, ...)
#define TCP_EVT_ACK_RCV_ERR_HANDLER(_tc, _type, _ack, ...)
#define TCP_EVT_RCV_WND_SHRUNK_HANDLER(_tc, _obs, _av, ...)
#endif

#if TCP_DEBUG_SM > 2 || TCP_DEBUG_ALWAYS

#define TCP_EVT_ACK_SENT_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "ack-tx: acked %u rcv_nxt %u rcv_wnd %u snd_nxt %u snd_wnd %u",\
    .format_args = "i4i4i4i4i4",					\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _tc->rcv_nxt - _tc->rcv_las;				\
  ed->data[1] = _tc->rcv_nxt - _tc->irs;				\
  ed->data[2] = _tc->rcv_wnd;						\
  ed->data[3] = _tc->snd_nxt - _tc->iss;				\
  ed->data[4] = _tc->snd_wnd;						\
}

#define TCP_EVT_ACK_RCVD_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "ack-rx: %u snd_una %u snd_wnd %u cwnd %u inflight %u",	\
    .format_args = "i4i4i4i4i4",					\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _tc->bytes_acked;					\
  ed->data[1] = _tc->snd_una - _tc->iss;				\
  ed->data[2] = _tc->snd_wnd;						\
  ed->data[3] = _tc->cwnd;						\
  ed->data[4] = tcp_flight_size(_tc);					\
}

#define TCP_EVT_PKTIZE_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "tx: una %u snd_nxt %u space %u flight %u rcv_wnd %u",\
    .format_args = "i4i4i4i4i4",					\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _tc->snd_una - _tc->iss;				\
  ed->data[1] = _tc->snd_nxt - _tc->iss;				\
  ed->data[2] = tcp_available_output_snd_space (_tc);			\
  ed->data[3] = tcp_flight_size (_tc);					\
  ed->data[4] = _tc->rcv_wnd;						\
}

#define TCP_EVT_INPUT_HANDLER(_tc, _type, _len, _written, ...)		\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "in: %s len %u written %d rcv_nxt %u rcv_wnd(o) %d",	\
    .format_args = "t4i4i4i4i4",					\
    .n_enum_strings = 2,                                        	\
    .enum_strings = {                                           	\
      "order",   	                                        	\
      "ooo",   								\
    },									\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _type;							\
  ed->data[1] = _len;							\
  ed->data[2] = _written;						\
  ed->data[3] = (_tc->rcv_nxt - _tc->irs) + _written;			\
  ed->data[4] = _tc->rcv_wnd - (_tc->rcv_nxt - _tc->rcv_las);		\
}

#else
#define TCP_EVT_ACK_SENT_HANDLER(_tc, ...)
#define TCP_EVT_ACK_RCVD_HANDLER(_tc, ...)
#define TCP_EVT_PKTIZE_HANDLER(_tc, ...)
#define TCP_EVT_INPUT_HANDLER(_tc, _type, _len, _written, ...)
#endif

/*
 * State machine verbose
 */
#if TCP_DEBUG_SM > 3 || TCP_DEBUG_ALWAYS
#define TCP_EVT_SND_WND_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "snd-wnd update: %u ",					\
    .format_args = "i4",						\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 1);						\
  ed->data[0] = _tc->snd_wnd;						\
}

#define TCP_EVT_OUTPUT_HANDLER(_tc, flags, n_bytes,...)			\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "out: flags %x, bytes %u",				\
    .format_args = "i4i4",						\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 2);						\
  ed->data[0] = flags;							\
  ed->data[1] = n_bytes;						\
}
#else
#define TCP_EVT_SND_WND_HANDLER(_tc, ...)
#define TCP_EVT_OUTPUT_HANDLER(_tc, flags, n_bytes,...)
#endif

/*
 * Congestion Control
 */

#if TCP_DEBUG_CC || TCP_DEBUG_ALWAYS

#define TCP_EVT_CC_EVT_PRINT(_tc, _sub_evt)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "cc: %s snd_space %u snd_una %u out %u flight %u",	\
    .format_args = "t4i4i4i4i4",					\
    .n_enum_strings = 7,						\
    .enum_strings = {                                           	\
      "fast-rxt",	                                             	\
      "first-rxt",                                                 	\
      "rxt-timeout",                                                 	\
      "recovered",							\
      "congestion",							\
      "undo",								\
      "recovery",							\
    },  								\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _sub_evt;						\
  ed->data[1] = tcp_available_cc_snd_space (_tc);			\
  ed->data[2] = _tc->snd_una - _tc->iss;				\
  ed->data[3] = tcp_bytes_out(_tc);					\
  ed->data[4] = tcp_flight_size (_tc);					\
}

#define TCP_EVT_CC_EVT_HANDLER(_tc, _sub_evt, ...)			\
{									\
  if (_tc->snd_una != _tc->iss)						\
    TCP_EVT_CC_STAT_PRINT (_tc);					\
  if ((_sub_evt <= 1 && TCP_DEBUG_CC > 1)				\
      || (_sub_evt > 1 && TCP_DEBUG_CC > 0))				\
      TCP_EVT_CC_EVT_PRINT (_tc, _sub_evt);				\
}
#else
#define TCP_EVT_CC_EVT_HANDLER(_tc, _sub_evt, ...)			\

#endif

#if TCP_DEBUG_CC > 1 || TCP_DEBUG_ALWAYS
#define TCP_EVT_CC_RTX_HANDLER(_tc, offset, n_bytes, ...)		\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "rxt: snd_nxt %u offset %u snd %u rxt %u",		\
    .format_args = "i4i4i4i4",						\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 4);						\
  ed->data[0] = _tc->snd_nxt - _tc->iss;				\
  ed->data[1] = offset;							\
  ed->data[2] = n_bytes;						\
  ed->data[3] = _tc->snd_rxt_bytes;					\
}

#define TCP_EVT_DUPACK_SENT_HANDLER(_tc, _btcp, ...)			\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "dack-tx: rcv_nxt %u seq %u rcv_wnd %u snd_nxt %u av_wnd %u",\
    .format_args = "i4i4i4i4i4",					\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _tc->rcv_nxt - _tc->irs;				\
  ed->data[1] = _btcp.seq_number - _tc->irs;				\
  ed->data[2] = _tc->rcv_wnd;						\
  ed->data[3] = _tc->snd_nxt - _tc->iss;				\
  ed->data[4] = tcp_available_snd_wnd(_tc);				\
}

#define TCP_EVT_DUPACK_RCVD_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "dack-rx: snd_una %u cwnd %u snd_wnd %u flight %u rcv_wnd %u",\
    .format_args = "i4i4i4i4i4",					\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _tc->snd_una - _tc->iss;				\
  ed->data[1] = _tc->cwnd;						\
  ed->data[2] = _tc->snd_wnd;						\
  ed->data[3] = tcp_flight_size(_tc);					\
  ed->data[4] = _tc->rcv_wnd;						\
}

#define TCP_EVT_CC_PACK_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "pack: snd_una %u snd_una_max %u",			\
    .format_args = "i4i4",						\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 2);						\
  ed->data[0] = _tc->snd_una - _tc->iss;				\
  ed->data[1] = _tc->snd_una_max - _tc->iss;				\
}
#define TCP_EVT_CC_SCOREBOARD_HANDLER(_tc, ...)				\
{									\
if (TCP_DEBUG_CC > 1 && _tc->sack_sb.last_sacked_bytes)			\
  {									\
    ELOG_TYPE_DECLARE (_e) =						\
    {									\
      .format = "sb1: holes %u lost %u sacked %u high %u highrxt %u",	\
      .format_args = "i4i4i4i4i4",					\
    };									\
    TCP_DECLARE_ETD(_tc, _e, 5);					\
    ed->data[0] = pool_elts(_tc->sack_sb.holes);			\
    ed->data[1] = _tc->sack_sb.lost_bytes;				\
    ed->data[2] = _tc->sack_sb.sacked_bytes;				\
    ed->data[3] = _tc->sack_sb.high_sacked - _tc->iss;			\
    ed->data[4] = _tc->sack_sb.high_rxt - _tc->iss;			\
  }									\
if (TCP_DEBUG_CC > 1 && _tc->sack_sb.last_sacked_bytes)			\
  {									\
    sack_scoreboard_hole_t *hole;					\
    hole = scoreboard_first_hole (&_tc->sack_sb);			\
    ELOG_TYPE_DECLARE (_e) =						\
    {									\
      .format = "sb2: first start: %u end %u last start %u end %u",	\
      .format_args = "i4i4i4i4",					\
    };									\
    TCP_DECLARE_ETD(_tc, _e, 4);					\
    ed->data[0] = hole ? hole->start - _tc->iss : 0;			\
    ed->data[1] = hole ? hole->end - _tc->iss : 0;			\
    hole = scoreboard_last_hole (&_tc->sack_sb);			\
    ed->data[2] = hole ? hole->start - _tc->iss : 0;			\
    ed->data[3] = hole ? hole->end - _tc->iss : 0;			\
  }									\
}
#define TCP_EVT_CC_SACKS_HANDLER(_tc, ...)				\
{									\
if (TCP_DEBUG_CC > 1)							\
  {									\
    ELOG_TYPE_DECLARE (_e) =						\
    {									\
      .format = "sacks: blocks %u bytes %u",				\
      .format_args = "i4i4",						\
    };									\
    TCP_DECLARE_ETD(_tc, _e, 2);					\
    ed->data[0] = vec_len (_tc->snd_sacks);				\
    ed->data[1] = tcp_sack_list_bytes (_tc);				\
  }									\
}
#define TCP_EVT_CC_INPUT_HANDLER(_tc, _len, _written, ...)		\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "cc input: len %u written %d rcv_nxt %u rcv_wnd(o) %d",	\
    .format_args = "i4i4i4i4",						\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 4);						\
  ed->data[0] = _len;							\
  ed->data[1] = _written;						\
  ed->data[2] = _tc->rcv_nxt - _tc->irs;				\
  ed->data[3] = _tc->rcv_wnd - (_tc->rcv_nxt - _tc->rcv_las);		\
}
#else
#define TCP_EVT_CC_RTX_HANDLER(_tc, offset, n_bytes, ...)
#define TCP_EVT_DUPACK_SENT_HANDLER(_tc, _btcp, ...)
#define TCP_EVT_DUPACK_RCVD_HANDLER(_tc, ...)
#define TCP_EVT_CC_PACK_HANDLER(_tc, ...)
#define TCP_EVT_CC_SCOREBOARD_HANDLER(_tc, ...)
#define TCP_EVT_CC_SACKS_HANDLER(_tc, ...)
#define TCP_EVT_CC_INPUT_HANDLER(_tc, _len, _written, ...)
#endif

/*
 * Congestion control stats
 */
#if TCP_DEBUG_CS || TCP_DEBUG_ALWAYS

#define STATS_INTERVAL 1

#define tcp_cc_time_to_print_stats(_tc)					\
  _tc->c_cc_stat_tstamp + STATS_INTERVAL < tcp_time_now() 		\
  || tcp_in_fastrecovery (_tc)						\

#define TCP_EVT_CC_RTO_STAT_PRINT(_tc)					\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "rcv_stat: rto %u srtt %u mrtt-us %u rttvar %u",		\
    .format_args = "i4i4i4i4",						\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 4);						\
  ed->data[0] = _tc->rto;						\
  ed->data[1] = _tc->srtt;						\
  ed->data[2] = (u32) (_tc->mrtt_us * 1e6);				\
  ed->data[3] = _tc->rttvar;	 					\
}

#define TCP_EVT_CC_RTO_STAT_HANDLER(_tc, ...)				\
{									\
if (tcp_cc_time_to_print_stats (_tc))					\
{									\
  TCP_EVT_CC_RTO_STAT_PRINT (_tc);					\
  _tc->c_cc_stat_tstamp = tcp_time_now ();				\
}									\
}

#define TCP_EVT_CC_SND_STAT_PRINT(_tc)					\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "snd_stat: cc_space %u sacked %u lost %u out %u rxt %u",	\
    .format_args = "i4i4i4i4i4",					\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = tcp_available_cc_snd_space (_tc);			\
  ed->data[1] = _tc->sack_sb.sacked_bytes;				\
  ed->data[2] = _tc->sack_sb.lost_bytes;				\
  ed->data[3] = tcp_bytes_out (_tc);					\
  ed->data[3] = _tc->snd_rxt_bytes;					\
}

#define TCP_EVT_CC_SND_STAT_HANDLER(_tc, ...)				\
{									\
if (tcp_cc_time_to_print_stats (_tc))					\
{									\
    TCP_EVT_CC_SND_STAT_PRINT(_tc);					\
    _tc->c_cc_stat_tstamp = tcp_time_now ();				\
}									\
}

#define TCP_EVT_CC_STAT_PRINT(_tc)					\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "cc_stat: cwnd %u flight %u space %u ssthresh %u snd_wnd %u",\
    .format_args = "i4i4i4i4i4",					\
  };									\
  TCP_DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _tc->cwnd;						\
  ed->data[1] = tcp_flight_size (_tc);					\
  ed->data[2] = tcp_snd_space (_tc);					\
  ed->data[3] = _tc->ssthresh;						\
  ed->data[4] = _tc->snd_wnd;						\
  TCP_EVT_CC_RTO_STAT_PRINT (_tc);					\
  TCP_EVT_CC_SND_STAT_PRINT (_tc);					\
}

#define TCP_EVT_CC_STAT_HANDLER(_tc, ...)				\
{									\
if (tcp_cc_time_to_print_stats (_tc))					\
{									\
  TCP_EVT_CC_STAT_PRINT (_tc);						\
  _tc->c_cc_stat_tstamp = tcp_time_now();				\
}									\
}
#else
#define TCP_EVT_CC_STAT_HANDLER(_tc, ...)
#define TCP_EVT_CC_STAT_PRINT(_tc)
#endif

/*
 * Buffer allocation
 */
#if TCP_DEBUG_BUF_ALLOC

#define TCP_DBG_BUFFER_ALLOC_MAYBE_FAIL(thread_index)			\
{									\
  static u32 *buffer_fail_counters;					\
  if (PREDICT_FALSE (buffer_fail_counters == 0))			\
    {									\
      u32 num_threads;							\
      vlib_thread_main_t *vtm = vlib_get_thread_main ();		\
      num_threads = 1 /* main thread */  + vtm->n_threads;		\
      vec_validate (buffer_fail_counters, num_threads - 1);		\
    }									\
  if (PREDICT_FALSE (tcp_cfg.buffer_fail_fraction != 0.0))		\
    {									\
      if (PREDICT_TRUE (buffer_fail_counters[thread_index] > 0))	\
        {								\
          if ((1.0 / (f32) (buffer_fail_counters[thread_index]))	\
              < tcp_cfg.buffer_fail_fraction)				\
            {								\
              buffer_fail_counters[thread_index] = 0.0000001;		\
              return -1;						\
            }								\
        }								\
      buffer_fail_counters[thread_index] ++;				\
    }									\
}
#else
#define TCP_DBG_BUFFER_ALLOC_MAYBE_FAIL(thread_index)
#endif

#endif /* SRC_VNET_TCP_TCP_DEBUG_H_ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
