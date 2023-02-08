/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#ifndef _ENA_ACQ_DEFS_H_
#define _ENA_ACQ_DEFS_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>

typedef struct
{
  /* common desc */
  u16 command;
  u8 status;
  u8 flags;
  u16 extended_status;
  u16 sq_head_indx;

  union
  {
    u32 data[14];

    struct
    {
      u32 supported_groups;
      u32 enabled_groups;
    } aenq;

    struct
    {
      u32 tx;
      u32 rx_supported;
      u32 rx_enabled;
    } offload;

    struct
    {
      u32 impl_id;
      u32 device_version;
      u32 supported_features;
      u32 reserved3;
      u32 phys_addr_width;
      u32 virt_addr_width;
      u8 mac_addr[6];
      u8 reserved7[2];
      u32 max_mtu;
    } dev_attr;

    struct
    {
      u8 version;
      u8 reserved1[3];
      u32 max_tx_sq_num;
      u32 max_tx_cq_num;
      u32 max_rx_sq_num;
      u32 max_rx_cq_num;
      u32 max_tx_sq_depth;
      u32 max_tx_cq_depth;
      u32 max_rx_sq_depth;
      u32 max_rx_cq_depth;
      u32 max_tx_header_size;
      u16 max_per_packet_tx_descs;
      u16 max_per_packet_rx_descs;
    } max_queue_ext;

    struct
    {
      u16 sq_idx;
      u16 reserved;
      u32 sq_doorbell_offset;
      u32 llq_descriptors_offset;
      u32 llq_headers_offset;
    } create_sq_resp;

    struct
    {
      u16 cq_idx;
      u16 cq_actual_depth;
      u32 numa_node_register_offset;
      u32 cq_head_db_register_offset;
      u32 cq_interrupt_unmask_register_offset;
    } create_cq_resp;
  };
} ena_acq_entry_t;

STATIC_ASSERT_SIZEOF (ena_acq_entry_t, 64);

#endif /* _ENA_ACQ_DEFS_H_ */
