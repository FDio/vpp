/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

/**
 * A QOS egress map translates from the COS bits stored in the packet's
 * meta-data into a per-protocol COS value
 */

#ifndef __QOS_EGRESS_MAP_H__
#define __QOS_EGRESS_MAP_H__

#include <vnet/qos/qos_types.h>
#include <vnet/dpo/dpo.h>

/**
 * An attempt at type safety
 */
typedef u32 qos_egress_map_id_t;

/**
 * For a given output source a table maps each value of every input sorce.
 */
typedef struct qos_egress_map_t_
{
    /**
     * The array of output mapped values;
     *   output = eq_qos[input-source][input-value]
     */
  qos_bits_t qem_output[QOS_N_SOURCES][256];
} qos_egress_map_t;

extern u8 *format_qos_egress_map (u8 * s, va_list * args);

/**
 * Add a qos-egress map to an interface. If sw_if_index = ~0
 * then the configuration is for the 'default' table.
 * If the table is ~0, this is a removal.
 * the egress mapping is applied. For example, is output is MPLS then
 * the QoS markings will occur for MPLS pakcets.
 */
extern void qos_egress_map_update (qos_egress_map_id_t tid,
				   qos_source_t input_source,
				   qos_bits_t * values);
extern void qos_egress_map_delete (qos_egress_map_id_t tid);

/**
 * Get the VPP QoS map index from the user's map-ID
 */
extern index_t qos_egress_map_find (qos_egress_map_id_t tid);

/**
 * Data-plane functions
 */

/**
 * Pool from which to allocate map
 */
extern qos_egress_map_t *qem_pool;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
