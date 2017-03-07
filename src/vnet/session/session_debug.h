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
#ifndef SRC_VNET_SESSION_SESSION_DEBUG_H_
#define SRC_VNET_SESSION_SESSION_DEBUG_H_

#include <vnet/session/transport.h>
#include <vnet/session/session.h>
#include <vlib/vlib.h>

#define foreach_session_dbg_evt		\
  _(ENQ, "enqueue")			\
  _(DEQ, "dequeue")

typedef enum _session_evt_dbg
{
#define _(sym, str) SESSION_EVT_##sym,
  foreach_session_dbg_evt
#undef _
} session_evt_dbg_e;

#if TRANSPORT_DEBUG

#define DEC_SESSION_ETD(_s, _e, _size)					\
  struct								\
  {									\
    u32 data[_size];							\
  } * ed;								\
  transport_proto_vft_t *vft = 						\
      session_get_transport_vft (_s->session_type);			\
  transport_connection_t *_tc = 					\
      vft->get_connection (_s->connection_index, _s->thread_index);	\
  ed = ELOG_TRACK_DATA (&vlib_global_main.elog_main,			\
			_e, _tc->elog_track)


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

#define CONCAT_HELPER(_a, _b) _a##_b
#define CC(_a, _b) CONCAT_HELPER(_a, _b)

#define SESSION_EVT_DBG(_s, _evt, _body) CC(_evt, _HANDLER)(_s, _body)

#else
#define SESSION_EVT_DBG(_s, _evt, _body)
#endif

#endif /* SRC_VNET_SESSION_SESSION_DEBUG_H_ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
