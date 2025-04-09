/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2054 Cisco Systems, Inc.
 */

#ifndef __vlib_tw_h__
#define __vlib_tw_h__

#include <vlib/vlib.h>
#define VLIB_TW_TICKS_PER_SECOND 1e5 /* 10 us */

typedef enum
{
  VLIB_TW_EVENT_T_PROCESS_NODE = 1,
  VLIB_TW_EVENT_T_TIMED_EVENT = 2,
  VLIB_TW_EVENT_T_SCHED_NODE = 3,
} vlib_tw_event_type_t;

typedef union
{
  struct
  {
    u32 type : 2; /* vlib_tw_event_type_t */
    u32 index : 30;
  };
  u32 as_u32;
} vlib_tw_event_t;

#endif /* __vlib_tw_h__ */
