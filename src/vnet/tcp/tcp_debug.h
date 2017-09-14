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
#define TCP_DEBUG_SM (0)
#define TCP_DEBUG_CC (1)
#define TCP_DEBUG_CC_STAT (1)

#define foreach_tcp_dbg_evt		\
  _(INIT, "")				\
  _(DEALLOC, "")			\
  _(OPEN, "open")			\
  _(CLOSE, "close")			\
  _(BIND, "bind")			\
  _(UNBIND, "unbind")			\
  _(DELETE, "delete")			\
  _(SYN_SENT, "SYN sent")		\
  _(SYNACK_SENT, "SYNACK sent")		\
  _(SYNACK_RCVD, "SYNACK rcvd")		\
  _(SYN_RXT, "SYN retransmit")		\
  _(FIN_SENT, "FIN sent")		\
  _(ACK_SENT, "ACK sent")		\
  _(DUPACK_SENT, "DUPACK sent")		\
  _(RST_SENT, "RST sent")		\
  _(SYN_RCVD, "SYN rcvd")		\
  _(ACK_RCVD, "ACK rcvd")		\
  _(DUPACK_RCVD, "DUPACK rcvd")		\
  _(FIN_RCVD, "FIN rcvd")		\
  _(RST_RCVD, "RST rcvd")		\
  _(STATE_CHANGE, "state change")	\
  _(PKTIZE, "packetize")		\
  _(INPUT, "in")			\
  _(SND_WND, "snd_wnd update")		\
  _(OUTPUT, "output")			\
  _(TIMER_POP, "timer pop")		\
  _(CC_RTX, "retransmit")		\
  _(CC_EVT, "cc event")			\
  _(CC_PACK, "cc partial ack")		\
  _(CC_STAT, "cc stats")		\
  _(CC_RTO_STAT, "cc rto stats")	\
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

/*
 * Infra and evt track setup
 */

#define TCP_DBG(_fmt, _args...) clib_warning (_fmt, ##_args)

#define DECLARE_ETD(_tc, _e, _size)					\
  struct								\
  {									\
    u32 data[_size];							\
  } * ed;								\
  ed = ELOG_TRACK_DATA (&vlib_global_main.elog_main,			\
			_e, _tc->c_elog_track)

#define TCP_DBG_IP_TAG_LCL(_tc)						\
{									\
  if (_tc->c_is_ip4)							\
    {									\
      ELOG_TYPE_DECLARE (_e) =						\
      {									\
        .format = "lcl: %d.%d.%d.%d:%d",				\
        .format_args = "i4i4i4i4i4",					\
      };								\
      DECLARE_ETD(_tc, _e, 5);						\
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
      DECLARE_ETD(_tc, _e, 5);						\
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
  elog_track_register (&vlib_global_main.elog_main, &_tc->c_elog_track);\
  TCP_DBG_IP_TAG_LCL(_tc);						\
  TCP_DBG_IP_TAG_RMT(_tc);						\
}

#define TCP_EVT_DEALLOC_HANDLER(_tc, ...)				\
{									\
  vec_free (_tc->c_elog_track.name);					\
}

#define TCP_EVT_OPEN_HANDLER(_tc, ...)					\
{									\
  TCP_EVT_INIT_HANDLER(_tc, 0);						\
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
  TCP_EVT_INIT_HANDLER(_tc, 1);						\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "bind: listener %d",					\
  };									\
  DECLARE_ETD(_tc, _e, 1);						\
  ed->data[0] = _tc->c_c_index;						\
}

#define TCP_EVT_SYN_RCVD_HANDLER(_tc,_init, ...)				\
{									\
  if (_init)								\
    TCP_EVT_INIT_HANDLER(_tc, 0);					\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "syn-rx: irs %u",						\
    .format_args = "i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 1);						\
  ed->data[0] = _tc->irs;						\
  TCP_EVT_STATE_CHANGE_HANDLER(_tc);					\
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

#define CONCAT_HELPER(_a, _b) _a##_b
#define CC(_a, _b) CONCAT_HELPER(_a, _b)
#define TCP_EVT_DBG(_evt, _args...) CC(_evt, _HANDLER)(_args)
#else
#define TCP_EVT_DBG(_evt, _args...)
#define TCP_DBG(_fmt, _args...)
#endif

/*
 * State machine
 */
#if TCP_DEBUG_SM

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
  DECLARE_ETD(_tc, _e, 1);						\
  ed->data[0] = _tc->state;						\
}

#define TCP_EVT_SYN_SENT_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "syn-tx: iss %u snd_una %u snd_una_max %u snd_nxt %u",	\
    .format_args = "i4i4i4i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 4);						\
  ed->data[0] = _tc->iss;						\
  ed->data[1] = _tc->snd_una - _tc->iss;					\
  ed->data[2] = _tc->snd_una_max - _tc->iss;				\
  ed->data[3] = _tc->snd_nxt - _tc->iss;					\
  TCP_EVT_STATE_CHANGE_HANDLER(_tc);					\
}

#define TCP_EVT_SYNACK_SENT_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "synack-tx: iss %u irs %u snd_una %u snd_nxt %u rcv_nxt %u",\
    .format_args = "i4i4i4i4i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _tc->iss;						\
  ed->data[1] = _tc->irs;						\
  ed->data[2] = _tc->snd_una - _tc->iss;					\
  ed->data[3] = _tc->snd_nxt - _tc->iss;					\
  ed->data[4] = _tc->rcv_nxt - _tc->irs;					\
}

#define TCP_EVT_SYNACK_RCVD_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "synack-rx: iss %u irs %u snd_una %u snd_nxt %u rcv_nxt %u",\
    .format_args = "i4i4i4i4i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _tc->iss;						\
  ed->data[1] = _tc->irs;						\
  ed->data[2] = _tc->snd_una - _tc->iss;					\
  ed->data[3] = _tc->snd_nxt - _tc->iss;					\
  ed->data[4] = _tc->rcv_nxt - _tc->irs;					\
  TCP_EVT_STATE_CHANGE_HANDLER(_tc);					\
}

#define TCP_EVT_FIN_SENT_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "fin-tx: snd_nxt %d rcv_nxt %d",				\
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
    .format = "rst-tx: snd_nxt %d rcv_nxt %d",				\
    .format_args = "i4i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 2);						\
  ed->data[0] = _tc->snd_nxt - _tc->iss;				\
  ed->data[1] = _tc->rcv_nxt - _tc->irs;				\
  TCP_EVT_STATE_CHANGE_HANDLER(_tc);					\
}

#define TCP_EVT_FIN_RCVD_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "fin-rx: snd_nxt %d rcv_nxt %d",				\
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
    .format = "rst-rx: snd_nxt %d rcv_nxt %d",				\
    .format_args = "i4i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 2);						\
  ed->data[0] = _tc->snd_nxt - _tc->iss;				\
  ed->data[1] = _tc->rcv_nxt - _tc->irs;				\
}

#define TCP_EVT_SYN_RXT_HANDLER(_tc, _type, ...)			\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "%s-rxt: iss %u irs %u snd_nxt %u rcv_nxt %u",		\
    .format_args = "t4i4i4i4i4",						\
    .n_enum_strings = 2,						\
    .enum_strings = {                                           	\
	"syn",	                                             		\
        "syn-ack",							\
    },  								\
  };									\
  DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _type;							\
  ed->data[1] = _tc->iss;						\
  ed->data[2] = _tc->irs;						\
  ed->data[3] = _tc->snd_nxt - _tc->iss;					\
  ed->data[4] = _tc->rcv_nxt - _tc->irs;					\
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
#endif

#if TCP_DEBUG_SM > 1

#define TCP_EVT_ACK_SENT_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "ack-tx: acked %u rcv_nxt %u rcv_wnd %u snd_nxt %u snd_wnd %u",\
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
    .format = "dack-tx: rcv_nxt %u rcv_wnd %u snd_nxt %u av_wnd %u snd_wnd %u",\
    .format_args = "i4i4i4i4i4",					\
  };									\
  DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _tc->rcv_nxt - _tc->irs;				\
  ed->data[1] = _tc->rcv_wnd;						\
  ed->data[2] = _tc->snd_nxt - _tc->iss;				\
  ed->data[3] = tcp_available_snd_wnd(_tc);				\
  ed->data[4] = _tc->snd_wnd;						\
}

#define TCP_EVT_ACK_RCVD_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "ack-rx: %u snd_una %u snd_wnd %u cwnd %u inflight %u",	\
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
    .format = "dack-rx: snd_una %u cwnd %u snd_wnd %u flight %u rcv_wnd %u",\
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
    .format = "tx: una %u snd_nxt %u space %u flight %u rcv_wnd %u",\
    .format_args = "i4i4i4i4i4",					\
  };									\
  DECLARE_ETD(_tc, _e, 5);						\
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
    .format = "timer-pop: %s (%d)",                              	\
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
  if (_tc)								\
    {									\
      DECLARE_ETD(_tc, _e, 2);                                      	\
      ed->data[0] = _timer_id;                                      	\
      ed->data[1] = _timer_id;                                      	\
    }									\
  else									\
    {									\
      clib_warning ("pop %d for unexisting connection %d", _timer_id,	\
		    _tc_index);						\
    }									\
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
    .format = "paws-err: seq %u end %u tsval %u tsval_recent %u",	\
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
#else
#define TCP_EVT_ACK_SENT_HANDLER(_tc, ...)
#define TCP_EVT_DUPACK_SENT_HANDLER(_tc, ...)
#define TCP_EVT_ACK_RCVD_HANDLER(_tc, ...)
#define TCP_EVT_DUPACK_RCVD_HANDLER(_tc, ...)
#define TCP_EVT_PKTIZE_HANDLER(_tc, ...)
#define TCP_EVT_INPUT_HANDLER(_tc, _type, _len, _written, ...)
#define TCP_EVT_TIMER_POP_HANDLER(_tc_index, _timer_id, ...)
#define TCP_EVT_SEG_INVALID_HANDLER(_tc, _seq, _end, ...)
#define TCP_EVT_PAWS_FAIL_HANDLER(_tc, _seq, _end, ...)
#define TCP_EVT_ACK_RCV_ERR_HANDLER(_tc, _type, _ack, ...)
#define TCP_EVT_RCV_WND_SHRUNK_HANDLER(_tc, _obs, _av, ...)
#endif

/*
 * State machine verbose
 */
#if TCP_DEBUG_SM > 2
#define TCP_EVT_SND_WND_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "snd-wnd update: %u ",					\
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

/*
 * Congestion control stats
 */
#if TCP_DEBUG_CC_STAT

#define STATS_INTERVAL 1

#define TCP_EVT_CC_RTO_STAT_HANDLER(_tc, ...)				\
{									\
if (_tc->c_cc_stat_tstamp + STATS_INTERVAL < tcp_time_now())		\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "rto_stat: rto %u srtt %u rttvar %u ",			\
    .format_args = "i4i4i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 3);						\
  ed->data[0] = _tc->rto;						\
  ed->data[1] = _tc->srtt;						\
  ed->data[2] = _tc->rttvar;						\
}									\
}

#define TCP_EVT_CC_STAT_HANDLER(_tc, ...)				\
{									\
if (_tc->c_cc_stat_tstamp + STATS_INTERVAL < tcp_time_now())		\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "cc_stat: cwnd %u flight %u space %u ssthresh %u snd_wnd %u",\
    .format_args = "i4i4i4i4i4",					\
  };									\
  DECLARE_ETD(_tc, _e, 5);						\
  ed->data[0] = _tc->cwnd;						\
  ed->data[1] = tcp_flight_size (_tc);					\
  ed->data[2] = tcp_snd_space (_tc);					\
  ed->data[3] = _tc->ssthresh;						\
  ed->data[4] = _tc->snd_wnd;						\
  TCP_EVT_CC_RTO_STAT_HANDLER (_tc);					\
  _tc->c_cc_stat_tstamp = tcp_time_now();				\
}									\
}

#else
#define TCP_EVT_CC_STAT_HANDLER(_tc, ...)
#endif

#else
#define TCP_EVT_CC_RTX_HANDLER(_tc, offset, n_bytes, ...)
#define TCP_EVT_CC_EVT_HANDLER(_tc, _sub_evt, ...)
#define TCP_EVT_CC_PACK_HANDLER(_tc, ...)
#define TCP_EVT_CC_STAT_HANDLER(_tc, ...)
#endif

#endif /* SRC_VNET_TCP_TCP_DEBUG_H_ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
