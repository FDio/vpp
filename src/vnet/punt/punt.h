/*
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
 */

#ifndef __PUNT_H__
#define __PUNT_H__

#include <vnet/vnet.h>

#define foreach_punt_reason                     \
  _(IP4_ACL_DENY, "ip4 ACL-deny", "ip4-drop")   \
  _(IP6_ACL_DENY, "ip6 ACL-deny", "ip6-drop")

typedef enum punt_reason_t_
{
#define _(v, s, d) PUNT_REASON_##v,
  foreach_punt_reason
#undef _
    PUNT_N_REASONS,
} __attribute__ ((packed)) punt_reason_t;

/**
 * defined as a u16 in buffer oqaque
 */
STATIC_ASSERT (sizeof (punt_reason_t) <= 2,
               "punt_reason_t must be no more than u16");

extern u8 *format_punt_reason (u8 * s, va_list * args);

typedef int punt_hdl_t;

punt_hdl_t punt_client_register (const char *who);

/**
 * Allocate a new punt reason
 */
extern punt_reason_t punt_reason_alloc (punt_hdl_t client,
                                        const char *reason_name,
                                        const char *default_node);

/**
 * @brief Register a node to receive particular punted buffers
 *
 */
extern int punt_register (punt_hdl_t client,
                          punt_reason_t pr,
                          const char *node);

/**
 * Arc[s] to follow for each reason
 */
extern u32 **punt_dp_db;

/**
 * Per-reason counters
 */
extern vlib_combined_counter_main_t punt_counters;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
