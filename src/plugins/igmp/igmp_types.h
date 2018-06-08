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

#ifndef __IGMP_TYPES_H__
#define __IGMP_TYPES_H__

#include <vnet/ip/ip.h>

/** \brief IGMP source - where to the request for state arrive from
 *  host - from an API/CLI command to add the state
 *  network - from a received report
 * Each source could be mode from both modes, so these are flags.
 */
#define foreach_igmp_mode	\
  _ (1, HOST)			\
  _ (2, ROUTER)                 \

typedef enum igmp_mode_t_
{
#define _(n,f) IGMP_MODE_##f = n,
  foreach_igmp_mode
#undef _
} igmp_mode_t;

typedef enum igmp_msg_type_t_
{
  IGMP_MSG_REPORT,
  IGMP_MSG_QUERY,
} igmp_msg_type_t;

/**
 * @brief IGMP Key
 *  Used to index groups within an interface config and sources within a list
 */
typedef ip46_address_t igmp_key_t;

/**
 * @brief IGMP filter mode
 * Exclude all source address except this one
 * Include only this source address
 */
#define foreach_igmp_filter_mode	\
  _ (1, INCLUDE)			\
  _ (0, EXCLUDE)			\

typedef enum igmp_filter_mode_t_
{
#define _(n,f) IGMP_FILTER_MODE_##f = n,
  foreach_igmp_filter_mode
#undef _
} igmp_filter_mode_t;

#define IGMP_N_FILTER_MODES 2

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
