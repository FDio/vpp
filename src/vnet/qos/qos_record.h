/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#ifndef __QOS_RECORD_H__
#define __QOS_RECORD_H__

#include <vnet/qos/qos_types.h>

extern int qos_record_disable (u32 sw_if_index, qos_source_t input_source);
extern int qos_record_enable (u32 sw_if_index, qos_source_t input_source);

typedef walk_rc_t (*qos_record_walk_cb_t) (u32 sw_if_index,
					   qos_source_t input_source,
					   void *ctx);
void qos_record_walk (qos_record_walk_cb_t fn, void *c);

#endif
