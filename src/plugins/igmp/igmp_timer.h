/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

#ifndef _IGMP_TIMER_H_
#define _IGMP_TIMER_H_

#include <vlib/vlib.h>

/**
 * The id of a running timer
 */
typedef u32 igmp_timer_id_t;

#define IGMP_TIMER_ID_INVALID (~0)

/**
 * A call-back function invoked when a timer expires;
 *  @param obj - the [pool] index of the object that scheduled the timer
 *  @param data - Data registered by the client at schedule time.
 */
typedef void (*igmp_timer_function_t) (u32 obj, void *data);

/**
 * @brief
 *  Schedule a timer to expire in 'when' seconds
 *
 */
extern igmp_timer_id_t igmp_timer_schedule (f64 when,
					    u32 obj,
					    igmp_timer_function_t fn,
					    void *data);

extern void igmp_timer_retire (igmp_timer_id_t * tid);
extern int igmp_timer_is_running (igmp_timer_id_t tid);

extern f64 igmp_timer_get_expiry_time (igmp_timer_id_t t);
extern void *igmp_timer_get_data (igmp_timer_id_t t);
extern void igmp_timer_set_data (igmp_timer_id_t t, void *data);

extern u8 *format_igmp_timer_id (u8 * s, va_list * args);

/**
 * IGMP timer types and their values
 *  QUERY - the general query timer
 *  SRC - source expiration
 *  LEAVE - leave latency
 */
#define foreach_igmp_timer_type \
  _ (0x1, QUERY)                \
  _ (0x2, SRC)                  \
  _ (0x3, LEAVE)                \
  _ (0x4, REPORT_INTERVAL)

typedef enum igmp_timer_type_t_
{
#define _(n,f) IGMP_TIMER_##f = n,
  foreach_igmp_timer_type
#undef _
} igmp_timer_type_t;

extern u32 igmp_timer_type_get (igmp_timer_type_t t);
extern void igmp_timer_type_set (igmp_timer_type_t t, u32 v);

#endif /* IGMP_TIMER_H_ */
