/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include <igmp/igmp.h>

/**
 * A copy of the report message sent from the worker to the main thread
 */
typedef struct igmp_report_args_t_
{
  u32 sw_if_index;
  igmp_membership_report_v3_t report[0];
} igmp_report_args_t;

extern void igmp_handle_report (const igmp_report_args_t *args);
