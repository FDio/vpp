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

#define foreach_tcp_dbg_evt		\
  _(INIT, "")				\
  _(DEALLOC, "")			\
  _(OPEN, "open")			\
  _(CLOSE, "close")			\
  _(BIND, "bind")			\
  _(UNBIND, "unbind")			\
  _(DELETE, "delete")			\
  _(SYN_SENT, "SYN sent")		\
  _(FIN_SENT, "FIN sent")		\
  _(RST_SENT, "RST sent")		\
  _(SYN_RCVD, "SYN rcvd")		\
  _(ACK_RCVD, "ACK rcvd")		\
  _(FIN_RCVD, "FIN rcvd")		\
  _(RST_RCVD, "RST rcvd")		\
  _(PKTIZE, "packetize")		\
  _(INPUT, "in")			\
  _(TIMER_POP, "timer pop")

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

#define TCP_EVT_INIT_HANDLER(_tc, ...)					\
{									\
  _tc->c_elog_track.name = 						\
	(char *) format (0, "%d%c", _tc->c_c_index, 0);			\
  elog_track_register (&vlib_global_main.elog_main, &_tc->c_elog_track);\
}

#define TCP_EVT_DEALLOC_HANDLER(_tc, ...)				\
{									\
  vec_free (_tc->c_elog_track.name);					\
}

#define TCP_EVT_OPEN_HANDLER(_tc, ...)					\
{									\
  TCP_EVT_INIT_HANDLER(_tc);						\
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
  TCP_EVT_INIT_HANDLER(_tc);						\
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
  DECLARE_ETD(_tc, _e, 0);						\
  ed->data[0] = _tc->c_c_index;						\
  TCP_EVT_DEALLOC_HANDLER(_tc);						\
}

#define TCP_EVT_SYN_SENT_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "SYN: iss %d",						\
    .format_args = "i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 1);						\
  ed->data[0] = _tc->iss;						\
}

#define TCP_EVT_FIN_SENT_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "FIN: snd_nxt %d rcv_nxt %d",				\
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
    .format = "RST: snd_nxt %d rcv_nxt %d",				\
    .format_args = "i4i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 2);						\
  ed->data[0] = _tc->snd_nxt - _tc->iss;				\
  ed->data[1] = _tc->rcv_nxt - _tc->irs;				\
}

#define TCP_EVT_SYN_RCVD_HANDLER(_tc, ...)				\
{									\
  TCP_EVT_INIT_HANDLER(_tc);						\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "SYN rcvd: irs %d",					\
    .format_args = "i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 1);						\
  ed->data[0] = _tc->irs;						\
}

#define TCP_EVT_FIN_RCVD_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "FIN rcvd: snd_nxt %d rcv_nxt %d",			\
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
    .format = "RST rcvd: snd_nxt %d rcv_nxt %d",			\
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
    .format = "ACK: acked %u cwnd %u inflight %u",			\
    .format_args = "i4i4i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 3);						\
  ed->data[0] = _tc->bytes_acked;					\
  ed->data[1] = _tc->cwnd;						\
  ed->data[2] = tcp_flight_size(_tc);					\
}

#define TCP_EVT_PKTIZE_HANDLER(_tc, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "pktize: snd_una %u snd_nxt %u una_max %u",		\
    .format_args = "i4i4i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 3);						\
  ed->data[0] = _tc->snd_una - _tc->iss;				\
  ed->data[1] = _tc->snd_nxt - _tc->iss;				\
  ed->data[2] = _tc->snd_una_max - _tc->iss;				\
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

#define TCP_EVT_INPUT_HANDLER(_tc, n_bytes, ...)			\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "in: bytes %u rcv_nxt %u",				\
    .format_args = "i4i4",						\
  };									\
  DECLARE_ETD(_tc, _e, 2);						\
  ed->data[0] = n_bytes;						\
  ed->data[1] = _tc->rcv_nxt - _tc->irs;				\
}

#define TCP_EVT_TIMER_POP_HANDLER(_tc_index, _timer_id, ...)            \
{                                                               	\
  tcp_connection_t *_tc;                                        	\
  if (_timer_id == TCP_TIMER_RETRANSMIT_SYN)                           	\
    {                                                           	\
      _tc = tcp_half_open_connection_get (_tc_index);           	\
    }                                                           	\
  else                                                          	\
    {                                                           	\
      u32 _thread_index = os_get_cpu_number ();                 	\
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
      "BUG",                                                    	\
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
