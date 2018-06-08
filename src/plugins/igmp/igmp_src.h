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
   * The liveness timer. Reset with each recieved report. on expiry
   * the source is removed from the group.
   */
  u32 exp_timer;

  /**
   * the mode that provided this source
   */
  igmp_mode_t mode;
} igmp_src_t;

/**
 * @brief A list of sources maintain for a multicast group
 */
typedef struct imgp_src_list_t_
{
  /** stored as a hasd table against the source's address */
  uword *srcs;
} igmp_src_list_t;

/**
 * Forward declaration
 */
struct igmp_group_t_;

extern void igmp_src_free (igmp_src_t * src,
                           struct igmp_group_t_ * group);

extern igmp_src_t *igmp_src_alloc (struct igmp_group_t_ * group,
                                   const igmp_key_t * skey,
                                   igmp_mode_t mode);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
