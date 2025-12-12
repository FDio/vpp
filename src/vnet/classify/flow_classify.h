/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#ifndef __included_vnet_flow_classify_h__
#define __included_vnet_flow_classify_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/classify/vnet_classify.h>

typedef enum
{
  FLOW_CLASSIFY_TABLE_IP4,
  FLOW_CLASSIFY_TABLE_IP6,
  FLOW_CLASSIFY_N_TABLES,
} flow_classify_table_id_t;

typedef enum
{
  FLOW_CLASSIFY_NEXT_INDEX_DROP,
  FLOW_CLASSIFY_NEXT_INDEX_N_NEXT,
} flow_classify_next_index_t;

typedef struct
{
  /* Classifier table vectors */
  u32 *classify_table_index_by_sw_if_index[FLOW_CLASSIFY_N_TABLES];

  /* Convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  vnet_classify_main_t *vnet_classify_main;
  vnet_config_main_t *vnet_config_main[FLOW_CLASSIFY_N_TABLES];
} flow_classify_main_t;

extern flow_classify_main_t flow_classify_main;

int vnet_set_flow_classify_intfc (vlib_main_t * vm, u32 sw_if_index,
				  u32 ip4_table_index, u32 ip6_table_index,
				  u32 is_add);

#endif /* __included_vnet_flow_classify_h__ */
