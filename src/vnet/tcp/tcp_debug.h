/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#define TCP_DEBUG (1)
#define TCP_DEBUG_CC (1)
#define TCP_DEBUG_VERBOSE (0)

#define foreach_tcp_dbg_evt		\
  _(INIT, "")				\
  _(DEALLOC, "")			\
  _(OPEN, "open")			\
  _(CLOSE, "close")			\
  _(BIND, "bind")			\
  _(UNBIND, "unbind")			\
  _(DELETE, "delete")			\
  _(SYN_SENT, "SYN sent")		\
  _(SYN_RTX, "SYN retransmit")		\
  _(FIN_SENT, "FIN sent")		\
  _(ACK_SENT, "ACK sent")		\
  _(DUPACK_SENT, "DUPACK sent")		\
  _(RST_SENT, "RST sent")		\
  _(SYN_RCVD, "SYN rcvd")		\
  _(ACK_RCVD, "ACK rcvd")		\
  _(DUPACK_RCVD, "DUPACK rcvd")		\
  _(FIN_RCVD, "FIN rcvd")		\
  _(RST_RCVD, "RST rcvd")		\
  _(PKTIZE, "packetize")		\
  _(INPUT, "in")			\
  _(SND_WND, "snd_wnd update")		\
  _(OUTPUT, "output")			\
  _(TIMER_POP, "timer pop")		\
  _(CC_RTX, "retransmit")		\
  _(CC_EVT, "cc event")			\
  _(CC_PACK, "cc partial ack")		\
  _(SEG_INVALID, "invalid segment")	\
  _(PAWS_FAIL, "failed paws check")	\
  _(ACK_RCV_ERR, "invalid ack")		\
  _(RCV_WND_SHRUNK, "shrunk rcv_wnd")	\

typedef enum _tcp_dbg
{
#define _(sym, str) TCP_DBG_##sym,
  foreach_tcp_dbg_evt
#undef _
} tcp_dbg_e;

typedef enum _tcp_dbg_evt
{
#define _(sym, str) TCP_EVT_##sym,
  foreach_tcp_dbg_evt
#undef _
} tcp_dbg_evt_e;

#if TCP_DEBUG

#define TRANSPORT_DEBUG (1)

#define TCP_DBG(_tc, _evt, _args...)					\
{   		            						\
    u8 *_tmp = 0;							\
    _tmp = format(_tmp, "%U", format_tcp_connection_verbose, _tc);	\
    clib_warning("%s", _tmp);						\
    vec_free(_tmp);							\
}

#define DECLARE_ETD(_tc, _e, _size)					\
  struct								\
  {									\
    u32 data[_size];							\
  } * ed;								\
  ed = ELOG_TRACK_DATA (&vlib_global_main.elog_main,			\
			_e, _tc->c_elog_track)

#define TCP_EVT_INIT_HANDLER(_tc, _fmt, ...)				\
{									\
  _tc->c_elog_track.name = 						\
	(char *) format (0, _fmt, _tc->c_c_index, 0);			\
  elog_track_register (&vlib_global_main.elog_main, &_tc->c_elog_track);\
}

#define TCP_EVT_DEALLOC_HANDLER(_tc, ...)				\
{									\
  vec_free (_tc->c_elog_track.name);					\
}

#define TCP_EVT_OPEN_HANDLER(_tc, ...)					\
{									\
  TCP_EVT_INIT_HANDLER(_tc, "s%d%c");					\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "open: index %d",						\
    .format_args = "i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 1);						\
  ed->data[0] = _tc->c_c_index;						\
}

#define TCP_EVT_CLOSE_HANDLER(_tc, ...)					\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "close: %d",						\
    .format_args = "i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 1);						\
  ed->data[0] = _tc->c_c_index;						\
}

#define TCP_EVT_BIND_HANDLER(_tc, ...)					\
{									\
  TCP_EVT_INIT_HANDLER(_tc, "l%d%c");					\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "bind: listener %d",					\
  };									\
  DECLARE_ETD(_tc, _e, 1);						\
  ed->data[0] = _tc->c_c_index;						\
}

#define TCP_EVT_UNBIND_HANDLER(_tc, ...)				\
{									\
  TCP_EVT_DEALLOC_HANDLER(_tc);						\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "unbind: listener %d",					\
  };									\
  DECLARE_ETD(_tc, _e, 1);						\
  ed->data[0] = _tc->c_c_index;						\
  TCP_EVT_DEALLOC_HANDLER(_tc);						\
}

#define TCP_EVT_DELETE_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "delete: %d",						\
    .format_args = "i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 1);						\
  ed->data[0] = _tc->c_c_index;						\
  TCP_EVT_DEALLOC_HANDLER(_tc);						\
}

#define TCP_EVT_ACK_SENT_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "ack_tx: acked %u rcv_nxt %u rcv_wnd %u snd_nxt %u snd_wnd %u",\
    .format_args = "i4i4i4i4i4",					\
  };									\
  DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _tc->rcv_nxt - _tc->rcv_las;				\
  ed->data[1] = _tc->rcv_nxt - _tc->irs;				\
  ed->data[2] = _tc->rcv_wnd;						\
  ed->data[3] = _tc->snd_nxt - _tc->iss;				\
  ed->data[4] = _tc->snd_wnd;						\
}

#define TCP_EVT_DUPACK_SENT_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "dack_tx: rcv_nxt %u rcv_wnd %u snd_nxt %u av_wnd %u snd_wnd %u",\
    .format_args = "i4i4i4i4i4",					\
  };									\
  DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _tc->rcv_nxt - _tc->irs;				\
  ed->data[1] = _tc->rcv_wnd;						\
  ed->data[2] = _tc->snd_nxt - _tc->iss;				\
  ed->data[3] = tcp_available_wnd(_tc);					\
  ed->data[4] = _tc->snd_wnd;						\
}

#define TCP_EVT_SYN_SENT_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "SYNtx: iss %u",						\
    .format_args = "i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 1);						\
  ed->data[0] = _tc->iss;						\
}

#define TCP_EVT_SYN_RTX_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "SYNrtx: iss %u",						\
    .format_args = "i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 1);						\
  ed->data[0] = _tc->iss;						\
}

#define TCP_EVT_FIN_SENT_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "FINtx: snd_nxt %d rcv_nxt %d",				\
    .format_args = "i4i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 2);						\
  ed->data[0] = _tc->snd_nxt - _tc->iss;				\
  ed->data[1] = _tc->rcv_nxt - _tc->irs;				\
}

#define TCP_EVT_RST_SENT_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "RSTtx: snd_nxt %d rcv_nxt %d",				\
    .format_args = "i4i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 2);						\
  ed->data[0] = _tc->snd_nxt - _tc->iss;				\
  ed->data[1] = _tc->rcv_nxt - _tc->irs;				\
}

#define TCP_EVT_SYN_RCVD_HANDLER(_tc, ...)				\
{									\
  TCP_EVT_INIT_HANDLER(_tc, "s%d%c");					\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "SYNrx: irs %u",						\
    .format_args = "i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 1);						\
  ed->data[0] = _tc->irs;						\
}

#define TCP_EVT_FIN_RCVD_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "FINrx: snd_nxt %d rcv_nxt %d",				\
    .format_args = "i4i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 2);						\
  ed->data[0] = _tc->snd_nxt - _tc->iss;				\
  ed->data[1] = _tc->rcv_nxt - _tc->irs;				\
}

#define TCP_EVT_RST_RCVD_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "RSTrx: snd_nxt %d rcv_nxt %d",				\
    .format_args = "i4i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 2);						\
  ed->data[0] = _tc->snd_nxt - _tc->iss;				\
  ed->data[1] = _tc->rcv_nxt - _tc->irs;				\
}

#define TCP_EVT_ACK_RCVD_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "acked: %u snd_una %u snd_wnd %u cwnd %u inflight %u",	\
    .format_args = "i4i4i4i4i4",					\
  };									\
  DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _tc->bytes_acked;					\
  ed->data[1] = _tc->snd_una - _tc->iss;				\
  ed->data[2] = _tc->snd_wnd;						\
  ed->data[3] = _tc->cwnd;						\
  ed->data[4] = tcp_flight_size(_tc);					\
}

#define TCP_EVT_DUPACK_RCVD_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "dack_rx: snd_una %u cwnd %u snd_wnd %u flight %u rcv_wnd %u",\
    .format_args = "i4i4i4i4i4",					\
  };									\
  DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _tc->snd_una - _tc->iss;				\
  ed->data[1] = _tc->cwnd;						\
  ed->data[2] = _tc->snd_wnd;						\
  ed->data[3] = tcp_flight_size(_tc);					\
  ed->data[4] = _tc->rcv_wnd;						\
}

#define TCP_EVT_PKTIZE_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "pktize: una %u snd_nxt %u space %u flight %u rcv_wnd %u",\
    .format_args = "i4i4i4i4i4",					\
  };									\
  DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _tc->snd_una - _tc->iss;				\
  ed->data[1] = _tc->snd_nxt - _tc->iss;				\
  ed->data[2] = tcp_available_snd_space (_tc);				\
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
  DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _type;							\
  ed->data[1] = _len;							\
  ed->data[2] = _written;						\
  ed->data[3] = (_tc->rcv_nxt - _tc->irs) + _written;			\
  ed->data[4] = _tc->rcv_wnd - (_tc->rcv_nxt - _tc->rcv_las);		\
}

#define TCP_EVT_TIMER_POP_HANDLER(_tc_index, _timer_id, ...)            \
{                                                               	\
  tcp_connection_t *_tc;                                        	\
  if (_timer_id == TCP_TIMER_RETRANSMIT_SYN                     	\
    || _timer_id == TCP_TIMER_ESTABLISH)                        	\
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
    .format = "TimerPop: %s (%d)",                              	\
    .format_args = "t4i4",                                      	\
    .n_enum_strings = 7,                                        	\
    .enum_strings = {                                           	\
      "retransmit",                                             	\
      "delack",                                                 	\
      "persist",                                                    	\
      "keep",                                                   	\
      "waitclose",                                              	\
      "retransmit syn",                                         	\
      "establish",                                              	\
    },                                                          	\
  };                                                            	\
  DECLARE_ETD(_tc, _e, 2);                                      	\
  ed->data[0] = _timer_id;                                      	\
  ed->data[1] = _timer_id;                                      	\
}

#define TCP_EVT_SEG_INVALID_HANDLER(_tc, _seq, _end, ...)		\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "seg-inv: seq %u end %u rcv_las %u rcv_nxt %u rcv_wnd %u",\
    .format_args = "i4i4i4i4i4",					\
  };									\
  DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _seq - _tc->irs;					\
  ed->data[1] = _end - _tc->irs;					\
  ed->data[2] = _tc->rcv_las - _tc->irs;				\
  ed->data[3] = _tc->rcv_nxt - _tc->irs;				\
  ed->data[4] = _tc->rcv_wnd;						\
}

#define TCP_EVT_PAWS_FAIL_HANDLER(_tc, _seq, _end, ...)			\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "paws fail: seq %u end %u tsval %u tsval_recent %u",	\
    .format_args = "i4i4i4i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 4);						\
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
  DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _type;							\
  ed->data[1] = _ack - _tc->iss;					\
  ed->data[2] = _tc->snd_una - _tc->iss;				\
  ed->data[3] = _tc->snd_nxt - _tc->iss;				\
  ed->data[4] = _tc->snd_una_max - _tc->iss;				\
}

/*
 * Congestion Control
 */

#if TCP_DEBUG_CC
#define TCP_EVT_CC_RTX_HANDLER(_tc, offset, n_bytes, ...)		\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "rxt: snd_nxt %u offset %u snd %u rxt %u",		\
    .format_args = "i4i4i4i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 4);						\
  ed->data[0] = _tc->snd_nxt - _tc->iss;				\
  ed->data[1] = offset;							\
  ed->data[2] = n_bytes;						\
  ed->data[3] = _tc->snd_rxt_bytes;					\
}

#define TCP_EVT_CC_EVT_HANDLER(_tc, _sub_evt, ...)			\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "cc: %s wnd %u snd_cong %u rxt_bytes %u",			\
    .format_args = "t4i4i4i4",						\
    .n_enum_strings = 5,						\
    .enum_strings = {                                           	\
      "fast-rxt",	                                             	\
      "rxt-timeout",                                                 	\
      "first-rxt",                                                 	\
      "recovered",							\
      "congestion",							\
    },  								\
  };									\
  DECLARE_ETD(_tc, _e, 4);						\
  ed->data[0] = _sub_evt;						\
  ed->data[1] = tcp_available_snd_space (_tc);				\
  ed->data[2] = _tc->snd_congestion - _tc->iss;				\
  ed->data[3] = _tc->snd_rxt_bytes;					\
}

#define TCP_EVT_CC_PACK_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "pack: snd_una %u snd_una_max %u",			\
    .format_args = "i4i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 2);						\
  ed->data[0] = _tc->snd_una - _tc->iss;				\
  ed->data[1] = _tc->snd_una_max - _tc->iss;				\
}

#else
#define TCP_EVT_CC_RTX_HANDLER(_tc, offset, n_bytes, ...)
#define TCP_EVT_CC_EVT_HANDLER(_tc, _sub_evt, _snd_space, ...)
#define TCP_EVT_CC_PACK_HANDLER(_tc, ...)
#endif

#define TCP_EVT_RCV_WND_SHRUNK_HANDLER(_tc, _obs, _av, ...)		\
{									\
if (_av > 0) 								\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "huh?: rcv_wnd %u obsd %u av %u rcv_nxt %u rcv_las %u",	\
    .format_args = "i4i4i4i4i4",					\
  };									\
  DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _tc->rcv_wnd;						\
  ed->data[1] = _obs;							\
  ed->data[2] = _av;							\
  ed->data[3] = _tc->rcv_nxt - _tc->irs;				\
  ed->data[4] = _tc->rcv_las - _tc->irs;				\
}									\
}

#if TCP_DBG_VERBOSE
#define TCP_EVT_SND_WND_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "snd_wnd update: %u ",					\
    .format_args = "i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 1);						\
  ed->data[0] = _tc->snd_wnd;						\
}

#define TCP_EVT_OUTPUT_HANDLER(_tc, flags, n_bytes,...)			\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "out: flags %x, bytes %u",				\
    .format_args = "i4i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 2);						\
  ed->data[0] = flags;							\
  ed->data[1] = n_bytes;						\
}
#else
#define TCP_EVT_SND_WND_HANDLER(_tc, ...)
#define TCP_EVT_OUTPUT_HANDLER(_tc, flags, n_bytes,...)
#endif

#define CONCAT_HELPER(_a, _b) _a##_b
#define CC(_a, _b) CONCAT_HELPER(_a, _b)
#define TCP_EVT_DBG(_evt, _args...) CC(_evt, _HANDLER)(_args)

#else
#define TCP_EVT_DBG(_evt, _args...)
#endif


#endif /* SRC_VNET_TCP_TCP_DEBUG_H_ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
