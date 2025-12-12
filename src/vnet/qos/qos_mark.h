/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#ifndef __QOS_MARK_H__
#define __QOS_MARK_H__

#include <vnet/qos/qos_egress_map.h>

/**
 * enable QoS marking by associating a MAP with an interface.
 * The output_source specifies which protocol/header the QoS value
 * will be written into
 */
extern int qos_mark_enable (u32 sw_if_index,
			    qos_source_t output_source,
			    qos_egress_map_id_t tid);
extern int qos_mark_disable (u32 sw_if_index, qos_source_t output_source);

typedef walk_rc_t (*qos_mark_walk_cb_t) (u32 sw_if_index,
					 u32 map_id,
					 qos_source_t input_source,
					 void *ctx);
void qos_mark_walk (qos_mark_walk_cb_t fn, void *c);

#endif
