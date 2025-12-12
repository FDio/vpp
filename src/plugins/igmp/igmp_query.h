/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include <igmp/igmp.h>

/**
 * A copy of the query message sent from the worker to the main thread
 */
typedef struct igmp_query_args_t_
{
  u32 sw_if_index;
  igmp_membership_query_v3_t query[0];
} igmp_query_args_t;

extern void igmp_handle_query (const igmp_query_args_t *args);
