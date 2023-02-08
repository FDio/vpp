/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#ifndef _ENA_AENQ_DEFS_H_
#define _ENA_AENQ_DEFS_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>

typedef struct
{
  u16 group;
  u16 syndrome;
  u8 flags;
  u8 reserved1[3];
  u32 timestamp_low;
  u32 timestamp_high;

  union
  {
    u32 data[12];
  };
} __clib_packed ena_aenq_entry_t;

STATIC_ASSERT_SIZEOF (ena_aenq_entry_t, 64);

#endif /* _ENA_AENQ_DEFS_H_ */
