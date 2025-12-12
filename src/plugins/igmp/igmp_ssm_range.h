/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

#ifndef __IGMP_SSM_RANGE_H__
#define __IGMP_SSM_RANGE_H__

#include <igmp/igmp.h>

/**
 * Make sure this remains in-sync with the .api enum definition
 */
#define foreach_igmp_group_prefix_type                  \
  _ (0x0, ASM)                                          \
  _ (0x1, SSM)

typedef enum igmp_group_prefix_type_t_
{
#define _(n,f) IGMP_GROUP_PREFIX_TYPE_##f = n,
  foreach_igmp_group_prefix_type
#undef _
} igmp_group_prefix_type_t;

extern igmp_group_prefix_type_t igmp_group_prefix_get_type (const
							    ip46_address_t *
							    gaddr);

extern void igmp_group_prefix_set (const fib_prefix_t * pfx,
				   igmp_group_prefix_type_t type);

typedef walk_rc_t (*igmp_ssm_range_walk_t) (const fib_prefix_t * pfx,
					    igmp_group_prefix_type_t type,
					    void *ctx);

extern void igmp_ssm_range_walk (igmp_ssm_range_walk_t fn, void *ctx);

#endif
