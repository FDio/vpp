/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 * For a given output source a table maps each value of every input source.
 */
typedef struct qos_egress_map_t_
{
  /**
   * Required for pool_get_aligned
   */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

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
 * the QoS markings will occur for MPLS packets.
 */
extern void qos_egress_map_update (qos_egress_map_id_t tid,
				   qos_source_t input_source,
				   qos_bits_t * values);
extern void qos_egress_map_delete (qos_egress_map_id_t tid);

/**
 * Get the VPP QoS map index from the user's map-ID
 */
extern index_t qos_egress_map_find (qos_egress_map_id_t tid);
extern qos_egress_map_id_t qos_egress_map_get_id (index_t qemi);

/**
 * Walk each of the configured maps
 */
typedef walk_rc_t (*qos_egress_map_walk_cb_t) (qos_egress_map_id_t id,
					       const qos_egress_map_t * m,
					       void *c);
void qos_egress_map_walk (qos_egress_map_walk_cb_t fn, void *c);

/**
 * Data-plane functions
 */

/**
 * Pool from which to allocate map
 */
extern qos_egress_map_t *qem_pool;

#endif
