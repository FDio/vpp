/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco and/or its affiliates.
 */

#ifndef _TRACENODE_H_
#define _TRACENODE_H_
#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <stdbool.h>

typedef struct
{
  vnet_main_t *vnet_main;
  uword *feature_enabled_by_sw_if;
  u16 msg_id_base;
} tracenode_main_t;

extern tracenode_main_t tracenode_main;

clib_error_t *tracenode_plugin_api_hookup (vlib_main_t *vm);

int tracenode_feature_enable_disable (u32 sw_if_index, bool is_pcap,
				      bool enable);

#endif /* _TRACENODE_H_ */
