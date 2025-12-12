/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

#ifndef __included_tw_timer_1t_3w_1024sl_ov_h__
#define __included_tw_timer_1t_3w_1024sl_ov_h__

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
#define TW_SLOTS_PER_RING 1024
#define TW_RING_SHIFT 10
#define TW_RING_MASK (TW_SLOTS_PER_RING -1)
#define TW_TIMERS_PER_OBJECT 1
#define LOG2_TW_TIMERS_PER_OBJECT 0
#define TW_SUFFIX _1t_3w_1024sl_ov
#define TW_OVERFLOW_VECTOR 1
#define TW_FAST_WHEEL_BITMAP 1
#define TW_TIMER_ALLOW_DUPLICATE_STOP 1

#include <vppinfra/tw_timer_template.h>

#endif /* __included_tw_timer_1t_3w_1024sl_ov_h__ */
