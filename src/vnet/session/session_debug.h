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
#include <vpp/vnet/config.h>

#define foreach_session_dbg_evt                                               \
  _ (ENQ, DEQ_EVTS, 1, "enqueue")                                             \
  _ (DEQ, DEQ_EVTS, 1, "dequeue")                                             \
  _ (DEQ_NODE, DISPATCH_DBG, 1, "dequeue")                                    \
  _ (POLL_GAP_TRACK, EVT_POLL_DBG, 1, "poll gap track")                       \
  _ (POLL_DISPATCH_TIME, EVT_POLL_DBG, 1, "dispatch time")                    \
  _ (DISPATCH_START, CLOCKS_EVT_DBG, 1, "dispatch start")                     \
  _ (DISPATCH_END, CLOCKS_EVT_DBG, 1, "dispatch end")                         \
  _ (DSP_CNTRS, CLOCKS_EVT_DBG, 1, "dispatch counters")                       \
  _ (STATE_CHANGE, SM, 1, "session state change")                             \
  _ (FREE, SM, 1, "session free")                                             \
  _ (IO_EVT_COUNTS, COUNTS_EVT_DBG, 1, "io evt counts")                       \
  _ (COUNTS, COUNTS_EVT_DBG, 1, "ctrl evt counts")

typedef enum _session_evt_dbg
{
#define _(sym, grp, lvl, str) SESSION_EVT_##sym,
  foreach_session_dbg_evt
#undef _
} session_evt_dbg_e;

typedef enum session_evt_lvl_
{
#define _(sym, grp, lvl, str) SESSION_EVT_##sym##_LVL = lvl,
  foreach_session_dbg_evt
#undef _
} session_evt_lvl_e;

#define foreach_session_evt_grp                                               \
  _ (DEQ_EVTS, "dequeue/enqueue events")                                      \
  _ (DISPATCH_DBG, "dispatch")                                                \
  _ (EVT_POLL_DBG, "event poll")                                              \
  _ (SM, "state machine")                                                     \
  _ (CLOCKS_EVT_DBG, "clocks events")                                         \
  _ (COUNTS_EVT_DBG, "counts events")

typedef enum session_evt_grp_
{
#define _(sym, str) SESSION_EVT_GRP_##sym,
  foreach_session_evt_grp
#undef _
    SESSION_EVT_N_GRP
} session_evt_grp_e;

typedef enum session_evt_to_grp_
{
#define _(sym, grp, lvl, str) SESSION_EVT_##sym##_GRP = SESSION_EVT_GRP_##grp,
  foreach_session_dbg_evt
#undef _
} session_evt_to_grp_e;

#define foreach_session_events                                                \
  _ (CLK_UPDATE_TIME, 1, 1, "Time Update Time")                               \
  _ (CLK_MQ_DEQ, 1, 1, "Time MQ Dequeue")                                     \
  _ (CLK_CTRL_EVTS, 1, 1, "Time Ctrl Events")                                 \
  _ (CLK_NEW_IO_EVTS, 1, 1, "Time New IO Events")                             \
  _ (CLK_OLD_IO_EVTS, 1, 1, "Time Old IO Events")                             \
  _ (CLK_TOTAL, 1, 1, "Time Total in Node")                                   \
  _ (CLK_START, 1, 1, "Time Since Last Reset")                                \
                                                                              \
  _ (CNT_MQ_EVTS, 1, 0, "# of MQ Events Processed")                           \
  _ (CNT_CTRL_EVTS, 1, 0, "# of Ctrl Events Processed")                       \
  _ (CNT_NEW_EVTS, 1, 0, "# of New Events Processed")                         \
  _ (CNT_OLD_EVTS, 1, 0, "# of Old Events Processed")                         \
  _ (CNT_IO_EVTS, 1, 0, "# of Events Processed")                              \
  _ (CNT_NODE_CALL, 1, 0, "# of Node Calls")                                  \
                                                                              \
  _ (BASE_OFFSET_IO_EVTS, 0, 0, "NULL")                                       \
  _ (SESSION_IO_EVT_RX, 1, 0, "# of IO Event RX")                             \
  _ (SESSION_IO_EVT_TX, 1, 0, "# of IO Event TX")                             \
  _ (SESSION_IO_EVT_TX_FLUSH, 1, 0, "# of IO Event TX Flush")                 \
  _ (SESSION_IO_EVT_BUILTIN_RX, 1, 0, "# of IO Event BuiltIn RX")             \
  _ (SESSION_IO_EVT_TX_MAIN, 1, 0, "# of IO Event TX Main")

typedef enum
{
#define _(sym, disp, type, str) SESS_Q_##sym,
  foreach_session_events
#undef _
  SESS_Q_MAX_EVT_TYPES
} sess_q_node_events_types_t;

typedef struct session_dbg_counter_
{
  union
  {
    f64 f64;
    u64 u64;
  };
} session_dbg_counter_t;

typedef struct session_dbg_evts_t
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  f64 last_time;
  f64 start_time;
  u64 prev_io;
  session_dbg_counter_t counters[SESS_Q_MAX_EVT_TYPES];
} session_dbg_evts_t;

typedef struct session_dbg_main_
{
  session_dbg_evts_t *wrk;
  u8 grp_dbg_lvl[SESSION_EVT_N_GRP];
} session_dbg_main_t;

extern session_dbg_main_t session_dbg_main;

#if defined VPP_SESSION_DEBUG && (TRANSPORT_DEBUG > 0)
#define SESSION_DEBUG	       (1)
#define SESSION_DEQ_EVTS       (1)
#define SESSION_DISPATCH_DBG   (1)
#define SESSION_EVT_POLL_DBG   (1)
#define SESSION_SM	       (1)
#define SESSION_CLOCKS_EVT_DBG (1)
#define SESSION_COUNTS_EVT_DBG (1)
#else
#define SESSION_DEBUG	       (0)
#define SESSION_DEQ_EVTS       (0)
#define SESSION_DISPATCH_DBG   (0)
#define SESSION_EVT_POLL_DBG   (0)
#define SESSION_SM	       (0)
#define SESSION_CLOCKS_EVT_DBG (0)
#define SESSION_COUNTS_EVT_DBG (0)
#endif

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
#define SESSION_EVT_STATE_CHANGE_HANDLER(_s)                                  \
  {                                                                           \
    ELOG_TYPE_DECLARE (_e) = {						      \
      .format = "%s: idx %u",                                                 \
      .format_args = "t4i4",                                                  \
      .n_enum_strings = 12,					     	      \
      .enum_strings = {                                           	      \
		       "created",					      \
		       "listening",					      \
		       "connecting",					      \
		       "accepting",					      \
		       "ready",						      \
		       "opened",					      \
		       "transport closing",				      \
		       "closing",					      \
		       "app closed",					      \
		       "transport closed",				      \
		       "closed",					      \
		       "transport deleted",				      \
		       },						      \
    };                                   \
    DEC_SESSION_ETD (_s, _e, 2);                                              \
    ed->data[0] = _s->session_state;                                          \
    ed->data[1] = _s->session_index;                                          \
  }

#define SESSION_EVT_FREE_HANDLER(_s)                                          \
  {                                                                           \
    ELOG_TYPE_DECLARE (_e) = {                                                \
      .format = "free: idx %u",                                               \
      .format_args = "i4",                                                    \
    };                                                                        \
    DEC_SESSION_ED (_e, 1);                                                   \
    ed->data[0] = _s->session_index;                                          \
  }
#else
#define SESSION_EVT_STATE_CHANGE_HANDLER(_s)
#define SESSION_EVT_FREE_HANDLER(_s)
#endif

#if SESSION_DEQ_EVTS
#define SESSION_EVT_DEQ_HANDLER(_s, _now, _max, _has_evt, _ts)		\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "deq: now %u max %d evt %u ts %d",			\
    .format_args = "i4i4i4i4",						\
  };									\
  DEC_SESSION_ETD(_s, _e, 4);						\
  ed->data[0] = _now;							\
  ed->data[1] = _max;							\
  ed->data[2] = _has_evt;						\
  ed->data[3] = _ts * 1000000.0;					\
}

#define SESSION_EVT_ENQ_HANDLER(_s, _len)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "enq: length %d",						\
    .format_args = "i4",						\
  };									\
  DEC_SESSION_ETD(_s, _e, 1);						\
  ed->data[0] = _len;							\
}
#else
#define SESSION_EVT_DEQ_HANDLER(_s, _now, _max, _has_evt, _ts)
#define SESSION_EVT_ENQ_HANDLER(_s, _body)
#endif /* SESSION_DEQ_NODE_EVTS */

#if SESSION_DISPATCH_DBG
#define SESSION_EVT_DEQ_NODE_HANDLER(_wrk, _node_evt, _ntx)		\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "dispatch: %s pkts %u re-entry: %u dispatch %u",		\
    .format_args = "t4i4i4i4",                                   	\
    .n_enum_strings = 2,                                        	\
    .enum_strings = {                                           	\
      "start",                                             		\
      "end",                                              		\
    },									\
  };									\
  DEC_SESSION_ED(_e, 4);						\
  ed->data[0] = _node_evt;						\
  ed->data[1] = _ntx;							\
  ed->data[2] = (_wrk->last_vlib_time - _wrk->last_event_poll) 		\
		* 1000000.0;						\
  ed->data[3] = (vlib_time_now (_wrk->vm) - _wrk->last_vlib_time)	\
                * 1000000.0;						\
}
#else
#define SESSION_EVT_DEQ_NODE_HANDLER(_wrk, _node_evt, _ntx)
#endif /* SESSION_DISPATCH_DBG */

#if SESSION_EVT_POLL_DBG && SESSION_DEBUG > 1
#define SESSION_EVT_POLL_GAP(_wrk)					\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "nixon-gap: %d us",					\
    .format_args = "i4",						\
  };									\
  DEC_SESSION_ED(_e, 1);						\
  ed->data[0] =	(u32) ((_wrk->last_vlib_time - _wrk->last_event_poll)	\
			*1000000.0);					\
}
#define SESSION_EVT_POLL_GAP_TRACK_HANDLER(_wrk)			\
{									\
  if (PREDICT_TRUE (_wrk->last_event_poll != 0.0))			\
    if (_wrk->last_vlib_time > _wrk->last_event_poll + 500e-6)		\
      SESSION_EVT_POLL_GAP(_wrk);					\
  _wrk->last_event_poll = _wrk->last_vlib_time;				\
}

#define SESSION_EVT_POLL_DISPATCH_TIME_HANDLER(_wrk)			\
{									\
  f64 diff = vlib_time_now (vlib_get_main ()) - _wrk->last_event_poll;  \
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
#define SESSION_EVT_POLL_GAP(_wrk)
#define SESSION_EVT_POLL_GAP_TRACK_HANDLER(_wrk)
#define SESSION_EVT_POLL_DISPATCH_TIME_HANDLER(_wrk)
#define SESSION_EVT_POLL_CLOCKS_TIME_HANDLER(_wrk)

#endif /* SESSION_EVT_POLL_DBG */

#if SESSION_CLOCKS_EVT_DBG

#define SESSION_EVT_DSP_CNTRS_UPDATE_TIME_HANDLER(_wrk, _diff, _args...)      \
  session_dbg_evts_t *sde = &session_dbg_main.wrk[_wrk->vm->thread_index];    \
  sde->counters[SESS_Q_CLK_UPDATE_TIME].f64 += _diff;

#define SESSION_EVT_DSP_CNTRS_MQ_DEQ_HANDLER(_wrk, _diff, _cnt, _args...)     \
  session_dbg_evts_t *sde = &session_dbg_main.wrk[_wrk->vm->thread_index];    \
  sde->counters[SESS_Q_CNT_MQ_EVTS].u64 += _cnt;                              \
  sde->counters[SESS_Q_CLK_MQ_DEQ].f64 += _diff;

#define SESSION_EVT_DSP_CNTRS_CTRL_EVTS_HANDLER(_wrk, _diff, _args...)		\
  session_dbg_evts_t *sde = &session_dbg_main.wrk[_wrk->vm->thread_index];	\
  sde->counters[SESS_Q_CLK_CTRL_EVTS].f64 += _diff;                  		\
  sde->prev_io = sde->counters[SESS_Q_CNT_IO_EVTS].u64;				\

#define SESSION_EVT_DSP_CNTRS_NEW_IO_EVTS_HANDLER(_wrk, _diff, _args...)	\
  session_dbg_evts_t *sde = &session_dbg_main.wrk[_wrk->vm->thread_index];	\
  sde->counters[SESS_Q_CLK_NEW_IO_EVTS].f64 += _diff;         			\
  sde->counters[SESS_Q_CNT_NEW_EVTS].u64 += 					\
    sde->counters[SESS_Q_CNT_IO_EVTS].u64 - sde->prev_io;			\
  sde->prev_io = sde->counters[SESS_Q_CNT_IO_EVTS].u64;				\

#define SESSION_EVT_DSP_CNTRS_OLD_IO_EVTS_HANDLER(_wrk, _diff, _args...)	\
  session_dbg_evts_t *sde = &session_dbg_main.wrk[_wrk->vm->thread_index];	\
  sde->counters[SESS_Q_CLK_OLD_IO_EVTS].f64 += _diff;                 		\
  sde->counters[SESS_Q_CNT_OLD_EVTS].u64 += 					\
    sde->counters[SESS_Q_CNT_IO_EVTS].u64 - sde->prev_io;			\

#define SESSION_EVT_DSP_CNTRS_HANDLER(_disp_evt, _wrk, _args...)              	\
{                                                                               \
  f64 time_now = vlib_time_now (_wrk->vm), diff;                                \
  diff = time_now - session_dbg_main.wrk[_wrk->vm->thread_index].last_time; 	\
  session_dbg_main.wrk[_wrk->vm->thread_index].last_time = time_now;            \
  CC(CC(SESSION_EVT_DSP_CNTRS_,_disp_evt),_HANDLER)(wrk, diff, _args);		\
}
#else
#define SESSION_EVT_DSP_CNTRS_HANDLER(_disp_evt, _wrk, _args...)
#endif /*SESSION_CLOCKS_EVT_DBG */

#if SESSION_COUNTS_EVT_DBG
#define SESSION_EVT_COUNTS_HANDLER(_node_evt, _cnt, _wrk)	\
{                                                            	\
  session_dbg_main.wrk[_wrk->vm->thread_index].              	\
	counters[SESS_Q_##_node_evt].u64 += _cnt;     		\
}

#define SESSION_EVT_IO_EVT_COUNTS_HANDLER(_node_evt, _cnt, _wrk)              \
  {                                                                           \
    u8 type = SESS_Q_BASE_OFFSET_IO_EVTS + _node_evt + 1;                     \
    session_dbg_evts_t *sde;                                                  \
    sde = &session_dbg_main.wrk[_wrk->vm->thread_index];                      \
    sde->counters[type].u64 += _cnt;                                          \
    sde->counters[SESS_Q_CNT_IO_EVTS].u64 += _cnt;                            \
  }
#else
#define SESSION_EVT_COUNTS_HANDLER(_node_evt, _cnt, _wrk)
#define SESSION_EVT_IO_EVT_COUNTS_HANDLER(_node_evt, _cnt, _wrk)
#endif /*SESSION_COUNTS_EVT_DBG */


#define SESSION_EVT_DISPATCH_START_HANDLER(_wrk)			\
{									\
  session_dbg_evts_t *sde;						\
  sde = &session_dbg_main.wrk[_wrk->vm->thread_index];			\
  if (SESSION_DEQ_EVTS > 1)						\
    SESSION_EVT_DEQ_NODE_HANDLER (_wrk, 0, 0);				\
  SESSION_EVT_POLL_GAP_TRACK_HANDLER (wrk);				\
  sde->counters[SESS_Q_##CNT_NODE_CALL].u64 +=1;              		\
  sde->last_time = vlib_time_now (_wrk->vm);				\
}

#define SESSION_EVT_DISPATCH_END_HANDLER(_wrk, _ntx)			\
{									\
  f64 now = vlib_time_now (_wrk->vm);					\
  session_dbg_evts_t *sde;						\
  sde = &session_dbg_main.wrk[_wrk->vm->thread_index];			\
  if (_ntx)								\
    SESSION_EVT_DEQ_NODE_HANDLER (_wrk, 1, _ntx);			\
  SESSION_EVT_POLL_DISPATCH_TIME_HANDLER(_wrk);				\
  _wrk->last_event_poll = now;						\
  sde->counters[SESS_Q_CLK_TOTAL].f64 += now - _wrk->last_vlib_time;	\
  sde->counters[SESS_Q_CLK_START].f64 = now - sde->start_time;		\
}

#define CONCAT_HELPER(_a, _b) _a##_b
#define CC(_a, _b) CONCAT_HELPER(_a, _b)
#define session_evt_lvl(_evt) CC (_evt, _LVL)
#define session_evt_grp(_evt) CC (_evt, _GRP)
#define session_evt_grp_dbg_lvl(_evt)                                         \
  session_dbg_main.grp_dbg_lvl[session_evt_grp (_evt)]
#define SESSION_EVT(_evt, _args...)                                           \
  if (PREDICT_FALSE (session_evt_grp_dbg_lvl (_evt) >=                        \
		     session_evt_lvl (_evt)))                                 \
  CC (_evt, _HANDLER) (_args)
#else
#define SESSION_EVT(_evt, _args...)
#define SESSION_DBG(_fmt, _args...)
#endif /* SESSION_DEBUG */

void session_debug_init (void);

#endif /* SRC_VNET_SESSION_SESSION_DEBUG_H_ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
