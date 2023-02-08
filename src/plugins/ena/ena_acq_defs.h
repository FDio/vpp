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
  union
  {
    struct
    {
      u8 phase : 1;
    };
    u8 flags;
  };
  u16 extended_status;
  u16 sq_head_indx;

  union
  {
    u32 data[14];

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
