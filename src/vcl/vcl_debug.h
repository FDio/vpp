/*
 * Copyright (c) 2018-2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this
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

#ifndef SRC_VCL_VCL_DEBUG_H_
#define SRC_VCL_VCL_DEBUG_H_

#include <vppinfra/elog.h>

#ifdef VPP_VCL_ELOG
#define VCL_ELOG 1
#else
#define VCL_ELOG 0
#endif

#define VCL_DBG_ON	1

#define VDBG(_lvl, _fmt, _args...) 					\
  if (VCL_DBG_ON && vcm->debug > _lvl)					\
    clib_warning ("vcl<%d:%d>: " _fmt, 					\
		  vcm->workers[__vcl_worker_index].current_pid, 	\
		  __vcl_worker_index, ##_args)

#define VWRN(_fmt, _args...)						\
  clib_warning ("vcl<%d:%d>: " _fmt,		 			\
                vcm->workers[__vcl_worker_index].current_pid, 		\
                __vcl_worker_index, ##_args)

#define VERR(_fmt, _args...)						\
  clib_warning ("vcl<%d:%d>: ERROR " _fmt, 		 		\
                vcm->workers[__vcl_worker_index].current_pid, 		\
		__vcl_worker_index, ##_args)

#define VCFG_DBG(_lvl, _fmt, _args...)                                        \
  {                                                                           \
    if (vcm->debug > _lvl)                                                    \
      fprintf (stderr, _fmt "\n", ##_args);                                   \
  }

#define foreach_vcl_dbg_evt						\
  _(INIT, "vcl init track")						\
  _(TIMEOUT, "vcl timeout")						\
  _(DETACH, "vcl detach")						\
  _(SESSION_INIT, "init session track")					\
  _(SESSION_TIMEOUT, "session timeout")					\
  _(CREATE, "session create")						\
  _(CLOSE, "session close")						\
  _(BIND, "session bind")						\
  _(UNBIND, "session unbind")						\
  _(ACCEPT, "session accept")						\
  _(EPOLL_CREATE, "epoll session create")				\
  _(EPOLL_CTLADD, "epoll ctl add")					\
  _(EPOLL_CTLDEL, "epoll ctl del")					\

typedef enum vcl_dbg_evt_
{
#define _(sym, str) VCL_EVT_##sym,
  foreach_vcl_dbg_evt
#undef _
} vcl_dbg_evt_e;

#if (VCL_ELOG > 0)

#define VCL_DECLARE_ETD(_s, _e, _size)                                        \
  struct                                                                      \
  {                                                                           \
    u32 data[_size];                                                          \
  } *ed;                                                                      \
  ed = ELOG_TRACK_DATA (&vcm->elog_main, _e, _s->elog_track)

#define VCL_EVT_INIT_HANDLER(_vcm, ...)                                       \
  {                                                                           \
    _vcm->elog_track.name =                                                   \
      (char *) format (0, "P:%d:C:%d%c", getpid (), _vcm->app_index, 0);      \
    elog_track_register (&_vcm->elog_main, &_vcm->elog_track);                \
  }

#define VCL_EVT_SESSION_INIT_HANDLER(_s, _s_index, ...)                       \
  {                                                                           \
    _s->elog_track.name =                                                     \
      (char *) format (0, "CI:%d:S:%d%c", vcm->app_index, _s->_s_index, 0);   \
    elog_track_register (&vcm->elog_main, &_s->elog_track);                   \
  }

#define VCL_EVT_BIND_HANDLER(_s, ...)                                         \
  {                                                                           \
    if (_s->transport.is_ip4)                                                 \
      {                                                                       \
	ELOG_TYPE_DECLARE (_e) =						\
      {									\
	.format = "bind local:%s:%d.%d.%d.%d:%d ",			\
	.format_args = "t1i1i1i1i1i2",					\
	.n_enum_strings = 2,						\
	.enum_strings = {"TCP", "UDP",},				\
      };                                       \
	CLIB_PACKED (struct {                                                 \
	  u8 proto;                                                           \
	  u8 addr[4];                                                         \
	  u16 port;                                                           \
	}) *                                                                  \
	  ed;                                                                 \
	ed = ELOG_TRACK_DATA (&vcm->elog_main, _e, _s->elog_track);           \
	ed->proto = _s->session_type;                                         \
	ed->addr[0] = _s->transport.lcl_ip.ip4.as_u8[0];                      \
	ed->addr[1] = _s->transport.lcl_ip.ip4.as_u8[1];                      \
	ed->addr[2] = _s->transport.lcl_ip.ip4.as_u8[2];                      \
	ed->addr[3] = _s->transport.lcl_ip.ip4.as_u8[3];                      \
	ed->port = clib_net_to_host_u16 (_s->transport.lcl_port);             \
      }                                                                       \
    else                                                                      \
      {                                                                       \
	/* TBD */                                                             \
      }                                                                       \
  }

#define VCL_EVT_ACCEPT_HANDLER(_s, _ls, _s_idx, ...)                          \
  {                                                                           \
    VCL_EVT_SESSION_INIT_HANDLER (_s, _s_idx);                                \
    ELOG_TYPE_DECLARE (_e) = {                                                \
      .format = "accept: listen_handle:%x from_handle:%x",                    \
      .format_args = "i8i8",                                                  \
    };                                                                        \
    struct                                                                    \
    {                                                                         \
      u64 handle[2];                                                          \
    } *ed;                                                                    \
    ed = ELOG_TRACK_DATA (&vcm->elog_main, _e, _s->elog_track);               \
    ed->handle[0] = _ls->vpp_handle;                                          \
    ed->handle[1] = _s->vpp_handle;                                           \
    if (_s->transport.is_ip4)                                                 \
      {                                                                       \
	ELOG_TYPE_DECLARE (_e) = {                                            \
	  .format = "accept:S:%x addr:%d.%d.%d.%d:%d",                        \
	  .format_args = "i8i1i1i1i1i2",                                      \
	};                                                                    \
	CLIB_PACKED (struct {                                                 \
	  u32 s_idx;                                                          \
	  u8 addr[4];                                                         \
	  u16 port;                                                           \
	}) *                                                                  \
	  ed;                                                                 \
	ed = ELOG_TRACK_DATA (&vcm->elog_main, _e, _s->elog_track);           \
	ed->s_idx = _s->_s_idx;                                               \
	ed->addr[0] = _s->transport.rmt_ip.ip4.as_u8[0];                      \
	ed->addr[1] = _s->transport.rmt_ip.ip4.as_u8[1];                      \
	ed->addr[2] = _s->transport.rmt_ip.ip4.as_u8[2];                      \
	ed->addr[3] = _s->transport.rmt_ip.ip4.as_u8[3];                      \
	ed->port = clib_net_to_host_u16 (_s->transport.rmt_port);             \
      }                                                                       \
    else                                                                      \
      {                                                                       \
	/* TBD */                                                             \
      }                                                                       \
  }

#define VCL_EVT_CREATE_HANDLER(_s, _proto, _state, _is_nb, _s_idx, ...)       \
  {                                                                           \
    VCL_EVT_SESSION_INIT_HANDLER (_s, _s_idx);                                \
    ELOG_TYPE_DECLARE (_e) = {                                                \
      .format = "create:proto:%d state:%d is_nonblk:%d idx: %d",              \
      .format_args = "i4i4i4i4",                                              \
    };                                                                        \
    VCL_DECLARE_ETD (_s, _e, 4);                                              \
    ed->data[0] = _s->_proto;                                                 \
    ed->data[1] = _s->_state;                                                 \
    ed->data[2] = _is_nb;                                                     \
    ed->data[3] = _s->_s_idx;                                                 \
  }

#define VCL_EVT_CLOSE_HANDLER(_s, _rv, ...)				\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "session_close:rv:%d",					\
    .format_args = "i4",						\
  };									\
  VCL_DECLARE_ETD (_s, _e, 1);						\
  ed->data[0] = _rv;							\
}

#define VCL_EVT_SESSION_TIMEOUT_HANDLER(_s, _state, ...)                      \
  {                                                                           \
    ELOG_TYPE_DECLARE (_e) = {                                                \
      .format = "ERR: timeout state:%d",                                      \
      .format_args = "i4",                                                    \
    };                                                                        \
    VCL_DECLARE_ETD (_s, _e, 1);                                              \
    ed->data[0] = _s->_state;                                                 \
  }

#define VCL_EVT_TIMEOUT_HANDLER(_vcm, _state, ...)			\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "ERR: timeout state:%d",					\
    .format_args = "i4",						\
  };									\
  struct { u32 data; } * ed;						\
  ed = ELOG_TRACK_DATA (&_vcm->elog_main, _e, _vcm->elog_track);	\
  ed->data[0] = _state;							\
}

#define VCL_EVT_DETACH_HANDLER(_vcm, ...)                                     \
  {                                                                           \
    ELOG_TYPE_DECLARE (_e) = {                                                \
      .format = "app_detach:C:%d",                                            \
      .format_args = "i4",                                                    \
    };                                                                        \
    struct                                                                    \
    {                                                                         \
      u32 data;                                                               \
    } *ed;                                                                    \
    ed = ELOG_TRACK_DATA (&_vcm->elog_main, _e, _vcm->elog_track);            \
    ed->data = _vcm->app_index;                                               \
  }

#define VCL_EVT_UNBIND_HANDLER(_s, ...)					\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "unbind: handle:%x",					\
    .format_args = "i8",						\
  };									\
  struct { u64 data; } * ed;						\
  ed = ELOG_TRACK_DATA (&vcm->elog_main, _e, _s->elog_track);		\
  ed->data = _s->vpp_handle;						\
}

#define VCL_EVT_EPOLL_CREATE_HANDLER(_s, _s_idx, ...)                         \
  {                                                                           \
    VCL_EVT_SESSION_INIT_HANDLER (_s, _s_idx);                                \
    ELOG_TYPE_DECLARE (_e) = {                                                \
      .format = "create epoll vep_idx: %d",                                   \
      .format_args = "i4",                                                    \
    };                                                                        \
    VCL_DECLARE_ETD (_s, _e, 1);                                              \
    ed->data[0] = _s->_s_idx;                                                 \
  }

#define VCL_EVT_EPOLL_CTLADD_HANDLER(_s, _evts, _evt_data, ...)		\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "epoll_ctladd: events:%x data:%x",			\
    .format_args = "i4",						\
  };									\
  struct { 	    							\
    u32 events;								\
    u64 event_data;							\
  } * ed;								\
  ed = ELOG_TRACK_DATA (&vcm->elog_main, _e, _s->elog_track);		\
  ed->events = _evts;							\
  ed->event_data = _evt_data;						\
}

#define VCL_EVT_EPOLL_CTLDEL_HANDLER(_s, _vep_idx, ...)			\
{									\
  ELOG_TYPE_DECLARE (_e) =						\
  {									\
    .format = "epoll_ctldel: vep:%d",					\
    .format_args = "i4",						\
  };									\
  VCL_DECLARE_ETD (_s, _e, 1);						\
  ed->data[0] = _vep_idx;						\
}

#define vcl_elog_init(_vcm)                                                   \
  {                                                                           \
    _vcm->elog_main.lock =                                                    \
      clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES, CLIB_CACHE_LINE_BYTES);  \
    _vcm->elog_main.lock[0] = 0;                                              \
    _vcm->elog_main.event_ring_size = (128 << 10);                            \
    elog_init (&_vcm->elog_main, _vcm->elog_main.event_ring_size);            \
    elog_enable_disable (&_vcm->elog_main, 1);                                \
  }

#define vcl_elog_stop(_vcm)                                                   \
  {                                                                           \
    clib_error_t *error = 0;                                                  \
    char *chroot_file =                                                       \
      (char *) format (0, "%s/%d-%d-vcl-elog%c", _vcm->cfg.event_log_path,    \
		       _vcm->app_index, getpid (), 0);                        \
    error =                                                                   \
      elog_write_file (&_vcm->elog_main, chroot_file, 1 /* flush ring */);    \
    if (error)                                                                \
      clib_error_report (error);                                              \
    clib_warning ("[%d] Event Log:'%s' ", getpid (), chroot_file);            \
    vec_free (chroot_file);                                                   \
  }

#define CONCAT_HELPER(_a, _b) _a##_b
#define CC(_a, _b) CONCAT_HELPER(_a, _b)
#define vcl_evt(_evt, _args...) CC(_evt, _HANDLER)(_args)
#else
#define vcl_evt(_evt, _args...)
#define vcl_elog_init(_vcm)
#define vcl_elog_stop(_vcm)
#endif

#endif /* SRC_VCL_VCL_DEBUG_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
