/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#ifndef __IGMP_PKT_H__
#define __IGMP_PKT_H__

#include <igmp/igmp.h>

typedef struct igmp_pkt_build_report_t_ {
  u32 *buffers;
  u32 sw_if_index;
  u32 n_avail;
  u32 n_bytes;
  u32 n_groups;
  u16 n_srcs;
} igmp_pkt_build_report_t;

#define IGMP_PKT_BUILD_REPORT_INIT { 0 }


/**
 * Send igmp membership general report.
 */
extern void igmp_pkt_send_general_report_v3 (const igmp_config_t *config);

extern void igmp_pkt_report_v3_add_report (igmp_pkt_build_report_t *br,
                                           const ip46_address_t *grp,
                                           const ip46_address_t *srcs,
                                           igmp_membership_group_v3_type_t type);

extern void igmp_pkt_report_v3_add_group (igmp_pkt_build_report_t *br,
                                          const igmp_group_t * group,
                                          igmp_membership_group_v3_type_t type);

extern void igmp_pkt_send_report_v3 (igmp_pkt_build_report_t *br);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
