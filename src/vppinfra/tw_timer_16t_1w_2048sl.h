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

#ifndef __included_tw_timer_16t_2w_512sl_h__
#define __included_tw_timer_16t_2w_512sl_h__

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

#define TW_TIMER_WHEELS 1
#define TW_SLOTS_PER_RING 2048
#define TW_RING_SHIFT 11
#define TW_RING_MASK (TW_SLOTS_PER_RING -1)
#define TW_TIMERS_PER_OBJECT 16
#define LOG2_TW_TIMERS_PER_OBJECT 4
#define TW_SUFFIX _16t_1w_2048sl
#define TW_FAST_WHEEL_BITMAP 0
#define TW_TIMER_ALLOW_DUPLICATE_STOP 0

#include <vppinfra/tw_timer_template.h>

#endif /* __included_tw_timer_16t_2w_512sl_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
