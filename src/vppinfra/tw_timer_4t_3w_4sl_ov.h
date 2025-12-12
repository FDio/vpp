/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

#ifndef __included_tw_timer_4t_3w_4sl_ov_h__
#define __included_tw_timer_4t_3w_4sl_ov_h__

/* ... So that a client app can create multiple wheel geometries */
#undef TW_TIMER_WHEELS
#undef TW_SLOTS_PER_RING
#undef TW_RING_SHIFT
#undef TW_RING_MASK
#undef TW_TIMERS_PER_OBJECT
#undef LOG2_TW_TIMERS_PER_OBJECT
#undef TW_SUFFIX
#undef TW_OVERFLOW_VECTOR
#undef TW_FAST_WHEEL_BITMAP
#undef TW_TIMER_ALLOW_DUPLICATE_STOP
#undef TW_START_STOP_TRACE_SIZE

#define TW_TIMER_WHEELS 3
#define TW_SLOTS_PER_RING 4
#define TW_RING_SHIFT 2
#define TW_RING_MASK (TW_SLOTS_PER_RING -1)
#define TW_TIMERS_PER_OBJECT 4
#define LOG2_TW_TIMERS_PER_OBJECT 2
#define TW_SUFFIX _4t_3w_4sl_ov
#define TW_OVERFLOW_VECTOR 1
#define TW_FAST_WHEEL_BITMAP 0
#define TW_TIMER_ALLOW_DUPLICATE_STOP 0

#include <vppinfra/tw_timer_template.h>

#endif /* __included_tw_timer_4t_3w_256sl_h__ */
