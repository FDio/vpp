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
#ifndef SRC_VNET_SESSION_SESSION_DEBUG_H_
#define SRC_VNET_SESSION_SESSION_DEBUG_H_

#include <vnet/session/transport.h>
#include <vlib/vlib.h>

#define foreach_session_dbg_evt		\
  _(ENQ, "enqueue")			\
  _(DEQ, "dequeue")			\
  _(DEQ_NODE, "dequeue")		\
  _(POLL_GAP_TRACK, "poll gap track")	\
  _(POLL_DISPATCH_TIME, "dispatch time")\
  _(DISPATCH_END, "dispatch end")	\
  _(FREE, "session free")		\

typedef enum _session_evt_dbg
{
#define _(sym, str) SESSION_EVT_##sym,
  foreach_session_dbg_evt
#undef _
} session_evt_dbg_e;

#define SESSION_DEBUG 0 * (TRANSPORT_DEBUG > 0)
#define SESSION_DEQ_NODE_EVTS (0)
#define SESSION_EVT_POLL_DBG (0)
#define SESSION_SM (0)

#if SESSION_DEBUG

#define SESSION_DBG(_fmt, _args...) clib_warning (_fmt, ##_args)

#define DEC_SESSION_ETD(_s, _e, _size)					\
  struct								\
  {									\
    u32 data[_size];							\
  } * ed;								\
  transport_connection_t *_tc = session_get_transport (_s);		\
  ed = ELOG_TRACK_DATA (&vlib_global_main.elog_main,			\
			_e, _tc->elog_track)

#define DEC_SESSION_ED(_e, _size)					\
  struct								\
  {									\
    u32 data[_size];							\
  } * ed;								\
  ed = ELOG_DATA (&vlib_global_main.elog_main, _e)

#if SESSION_SM
#define SESSION_EVT_FREE_HANDLER(_s)					\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "free: idx %u",						\
    .format_args = "i4",						\
  };									\
  DEC_SESSION_ETD(_s, _e, 1);						\
  ed->data[0] =	_s->session_index;					\
}
#else
#define SESSION_EVT_FREE_HANDLER(_s)
#endif

#if SESSION_DEQ_NODE_EVTS && SESSION_DEBUG > 1
#define SESSION_EVT_DEQ_HANDLER(_s, _body)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "deq: id %d len %d rd %d wnd %d",				\
    .format_args = "i4i4i4i4",						\
  };									\
  DEC_SESSION_ETD(_s, _e, 4);						\
  do { _body; } while (0);						\
}

#define SESSION_EVT_ENQ_HANDLER(_s, _body)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "enq: id %d length %d",					\
    .format_args = "i4i4",						\
  };									\
  DEC_SESSION_ETD(_s, _e, 2);						\
  do { _body; } while (0);						\
}

#define SESSION_EVT_DEQ_NODE_HANDLER(_node_evt)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "deq-node: %s",						\
    .format_args = "t4",                                      		\
    .n_enum_strings = 2,                                        	\
    .enum_strings = {                                           	\
      "start",                                             		\
      "end",                                              		\
    },									\
  };									\
  DEC_SESSION_ED(_e, 1);						\
  ed->data[0] = _node_evt;						\
}
#else
#define SESSION_EVT_DEQ_HANDLER(_s, _body)
#define SESSION_EVT_ENQ_HANDLER(_s, _body)
#define SESSION_EVT_DEQ_NODE_HANDLER(_node_evt)
#endif /* SESSION_DEQ_NODE_EVTS */

#if SESSION_EVT_POLL_DBG && SESSION_DEBUG > 1
#define SESSION_EVT_POLL_GAP(_smm, _ti)					\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "nixon-gap: %d us",					\
    .format_args = "i4",						\
  };									\
  DEC_SESSION_ED(_e, 1);						\
  ed->data[0] =	(u32) ((now -						\
      _smm->last_event_poll_by_thread[_ti])*1000000.0);			\
}
#define SESSION_EVT_POLL_GAP_TRACK_HANDLER(_smm, _ti)			\
{									\
  if (PREDICT_TRUE (smm->last_event_poll_by_thread[_ti] != 0.0))	\
    if (now > smm->last_event_poll_by_thread[_ti] + 500e-6)		\
      SESSION_EVT_POLL_GAP(smm, _ti);					\
  _smm->last_event_poll_by_thread[_ti] = now;				\
}

#define SESSION_EVT_POLL_DISPATCH_TIME_HANDLER(_smm, _ti)		\
{									\
  f64 diff = vlib_time_now (vlib_get_main ()) -				\
	       _smm->last_event_poll_by_thread[_ti];			\
  if (diff > 5e-2)							\
    {									\
      ELOG_TYPE_DECLARE (_e) =						\
      {									\
        .format = "dispatch time: %d us",				\
        .format_args = "i4",						\
      };								\
      DEC_SESSION_ED(_e, 1);						\
      ed->data[0] = diff *1000000.0;					\
    }									\
}

#else
#define SESSION_EVT_POLL_GAP(_smm, _my_thread_index)
#define SESSION_EVT_POLL_GAP_TRACK_HANDLER(_smm, _my_thread_index)
#define SESSION_EVT_POLL_DISPATCH_TIME_HANDLER(_smm, _ti)
#endif /* SESSION_EVT_POLL_DBG */

#define SESSION_EVT_DISPATCH_END_HANDLER(_smm, _ti)			\
{									\
  SESSION_EVT_DEQ_NODE_HANDLER(1);					\
  SESSION_EVT_POLL_DISPATCH_TIME_HANDLER(_smm, _ti);			\
}

#define CONCAT_HELPER(_a, _b) _a##_b
#define CC(_a, _b) CONCAT_HELPER(_a, _b)
#define SESSION_EVT_DBG(_evt, _args...) CC(_evt, _HANDLER)(_args)

#else
#define SESSION_EVT_DBG(_evt, _args...)
#define SESSION_DBG(_fmt, _args...)
#endif /* SESSION_DEBUG */

#endif /* SRC_VNET_SESSION_SESSION_DEBUG_H_ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
