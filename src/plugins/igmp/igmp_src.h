/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef __IGMP_SOURCE_H__
#define __IGMP_SOURCE_H__

#include <igmp/igmp_types.h>

/**
 * IGMP Source timers
 */
typedef enum igmp_src_timer_t_
{
  /**
   * On expiry the source has not been refreshed by a query
   * and can now be reaped
   */
  IGMP_SRC_TIMER_EXP,
} igmp_src_timer_t;

#define IGMP_SRC_N_TIMERS (IGMP_SRC_TIMER_EXP + 1)

/**
 *  @brief IGMP source
 *  The representation of a specified source address with in multicast group.
 */
typedef struct igmp_src_t_
{
  /**
   * The source's key
   */
  igmp_key_t *key;

  /**
   * The liveness timer. Reset with each received report. on expiry
   * the source is removed from the group.
   */
  u32 exp_timer;

  /**
   * The group this source is on
   */
  u32 group;

  /**
   * the mode that provided this source
   */
  igmp_mode_t mode;

  /**
   * Timers
   */
  u32 timers[IGMP_SRC_N_TIMERS];

  /**
   * Tells us which configurations
   * have this source.
   */
  u8 *referance_by_config_index;
} igmp_src_t;

extern void igmp_src_free (igmp_src_t * src);

extern igmp_src_t *igmp_src_alloc (u32 group_index,
				   const igmp_key_t * skey, igmp_mode_t mode);

extern u32 igmp_src_index (igmp_src_t * src);

extern void igmp_src_refresh (igmp_src_t * src);
extern void igmp_src_blocked (igmp_src_t * src);
extern u8 *format_igmp_src (u8 * s, va_list * args);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
