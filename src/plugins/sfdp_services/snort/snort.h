/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __SFDP_SNORT_H__
#define __SFDP_SNORT_H__

#include <snort/export.h>
#include <daq_common.h>

typedef struct
{
  union
  {
    struct
    {
      uint32_t flags; /* DAQ_PKT_FLAG_* */
      uint32_t flow_id;
      int32_t ingress_index;
      uint16_t address_space_id;
    };
    struct
    {
      uint8_t verdict; /* DAQ_Verdict */
    };
    uint32_t data[4];
  };
} daq_vpp_pkt_metadata_t;

_Static_assert(sizeof (daq_vpp_pkt_metadata_t) == 16,
	       "let it be 128-bits, so it fits into single load/store");

static_always_inline daq_vpp_pkt_metadata_t *
sfdp_snort_get_buffer_metadata (vlib_buffer_t *b)
{
  return vnet_buffer_get_opaque (b);
}

typedef struct
{
  snort_instance_index_t instance_index;
  u32 snort_dequeue_node_index;
  u32 snort_dequeue_node_next_index;

} sfdp_snort_main_t;

extern sfdp_snort_main_t sfdp_snort_main;

#endif /* __SFDP_SNORT_H__ */
