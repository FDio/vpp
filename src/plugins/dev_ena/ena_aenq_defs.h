/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#ifndef _ENA_AENQ_DEFS_H_
#define _ENA_AENQ_DEFS_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>

#define foreach_aenq_group                                                    \
  _ (0, LINK_CHANGE)                                                          \
  _ (1, FATAL_ERROR)                                                          \
  _ (2, WARNING)                                                              \
  _ (3, NOTIFICATION)                                                         \
  _ (4, KEEP_ALIVE)

#define foreach_aenq_syndrome                                                 \
  _ (0, SUSPEND)                                                              \
  _ (1, RESUME)                                                               \
  _ (2, UPDATE_HINTS)

typedef enum
{
#define _(v, n) ENA_AENQ_GROUP_##n = (v),
  foreach_aenq_group
#undef _
} ena_aenq_group_t;

typedef enum
{
#define _(v, n) ENA_AENQ_SYNDROME_##n = (v),
  foreach_aenq_syndrome
#undef _
} ena_aenq_syndrome_t;

typedef struct
{
  ena_aenq_group_t group : 16;
  ena_aenq_syndrome_t syndrome : 16;

  union
  {
    struct
    {
      u8 phase : 1;
    };
    u8 flags;
  };
  u8 reserved1[3];

  union
  {
    u64 timestamp;
    struct
    {
      u32 timestamp_low;
      u32 timestamp_high;
    };
  };

  union
  {
    u32 data[12];

    struct
    {
      union
      {
	struct
	{
	  u32 link_status : 1;
	};
	u32 flags;
      };
    } link_change;

    struct
    {
      union
      {
	u64 rx_drops;
	struct
	{
	  u32 rx_drops_low;
	  u32 rx_drops_high;
	};
      };

      union
      {
	u64 tx_drops;
	struct
	{
	  u32 tx_drops_low;
	  u32 tx_drops_high;
	};
      };
    } keep_alive;
  };
} __clib_packed ena_aenq_entry_t;

STATIC_ASSERT_SIZEOF (ena_aenq_entry_t, 64);

#endif /* _ENA_AENQ_DEFS_H_ */
