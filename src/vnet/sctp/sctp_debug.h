/*
 * Copyright (c) 2017 SUSE LLC.
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
#ifndef included_sctp_debug_h__
#define included_sctp_debug_h__

#include <vlib/vlib.h>

typedef enum _sctp_dbg
{
#define _(sym, str) SCTP_DBG_##sym,
  foreach_sctp_dbg_evt
#undef _
} sctp_dbg_e;

#define SCTP_DEBUG_STATE_MACHINE (0)
#if SCTP_DEBUG_STATE_MACHINE
#define SCTP_DBG_STATE_MACHINE(_fmt, _args...) clib_warning (_fmt, ##_args)
#else
#define SCTP_DBG_STATE_MACHINE(_fmt, _args...)
#endif

#define SCTP_DEBUG (0)
#if SCTP_DEBUG
#define SCTP_DBG(_fmt, _args...) clib_warning (_fmt, ##_args)
#else
#define SCTP_DBG(_fmt, _args...)
#endif

#define SCTP_ADV_DEBUG (0)
#if SCTP_ADV_DEBUG
#define SCTP_ADV_DBG(_fmt, _args...) clib_warning (_fmt, ##_args)
#else
#define SCTP_ADV_DBG(_fmt, _args...)
#endif

#define SCTP_DEBUG_OUTPUT (0)
#if SCTP_DEBUG_OUTPUT
#define SCTP_DBG_OUTPUT(_fmt, _args...) clib_warning (_fmt, ##_args)
#else
#define SCTP_DBG_OUTPUT(_fmt, _args...)
#endif

#define SCTP_ADV_DEBUG_OUTPUT (0)
#if SCTP_ADV_DEBUG_OUTPUT
#define SCTP_ADV_DBG_OUTPUT(_fmt, _args...) clib_warning (_fmt, ##_args)
#else
#define SCTP_ADV_DBG_OUTPUT(_fmt, _args...)
#endif

#define SCTP_CONN_TRACKING_DEBUG (0)
#if SCTP_CONN_TRACKING_DEBUG
#define SCTP_CONN_TRACKING_DBG(_fmt, _args...) clib_warning (_fmt, ##_args)
#else
#define SCTP_CONN_TRACKING_DBG(_fmt, _args...)
#endif

#endif /* included_sctp_debug_h__ */
