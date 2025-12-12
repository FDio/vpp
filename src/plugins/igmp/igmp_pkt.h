/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

#ifndef __IGMP_PKT_H__
#define __IGMP_PKT_H__

#include <igmp/igmp.h>

typedef struct igmp_pkt_build_t_
{
  u32 *buffers;
  u32 sw_if_index;
  u32 n_avail;
  u32 n_bytes;
} igmp_pkt_build_t;

typedef struct igmp_pkt_build_report_t_
{
  igmp_pkt_build_t base;
  u32 n_groups;
  u16 n_srcs;
} igmp_pkt_build_report_t;

extern void igmp_pkt_build_report_init (igmp_pkt_build_report_t * br,
					u32 sw_if_index);

extern void igmp_pkt_report_v3_add_report (igmp_pkt_build_report_t * br,
					   const ip46_address_t * grp,
					   const ip46_address_t * srcs,
					   igmp_membership_group_v3_type_t
					   type);

extern void igmp_pkt_report_v3_add_group (igmp_pkt_build_report_t * br,
					  const igmp_group_t * group,
					  igmp_membership_group_v3_type_t
					  type);

extern void igmp_pkt_report_v3_send (igmp_pkt_build_report_t * br);


typedef struct igmp_pkt_build_query_t_
{
  igmp_pkt_build_t base;
  u32 n_srcs;
} igmp_pkt_build_query_t;

extern void igmp_pkt_build_query_init (igmp_pkt_build_query_t * bq,
				       u32 sw_if_index);

extern void igmp_pkt_query_v3_add_group (igmp_pkt_build_query_t * bq,
					 const igmp_group_t * group,
					 const ip46_address_t * srcs);

extern void igmp_pkt_query_v3_send (igmp_pkt_build_query_t * bq);

#endif
