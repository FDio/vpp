/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_inc_common_h
#define included_onp_drv_inc_common_h

#include <vlib/pci/pci.h>
#include <vnet/flow/flow.h>
#include <vnet/udp/udp.h>

#include <base/roc_api.h>
#include <base/roc_priv.h>
#include <util.h>
#include <onp/drv/inc/log.h>

typedef enum
{
  CNXK_PKTIO_LINK_CGX,
  CNXK_PKTIO_LINK_LBK,
  CNXK_PKTIO_LINK_PCI,
} cnxk_pktio_link_type_t;

#define foreach_cnxk_pktio_mode_flag                                          \
  _ (UNUSED, 0)                                                               \
  _ (TRACE_EN, 1)

typedef enum
{
#define _(name, bit) CNXK_PKTIO_FP_FLAG_##name = (1 << bit),
  foreach_cnxk_pktio_mode_flag
#undef _
} cnxk_pktio_mode_flag_t;

#define CNXK_FRAME_SIZE		   VLIB_FRAME_SIZE
#define CNXK_FRAME_CAPACITY	   ((CNXK_FRAME_SIZE) *4)
#define CNXK_UNSUPPORTED_OPERATION ~(0)

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (c0);
  u32 pktio_index;
  u32 flags;

  u32 out_flags;
  u32 out_user_nstats;
  u16 pktio_node_state;
  u8 buffer_pool_index;
  u8 buffer_start_index;

  i32 *refill_deplete_count_per_pool;
  i32 *default_refill_count_per_pool;
  i32 *default_deplete_count_per_pool;

  CLIB_CACHE_LINE_ALIGN_MARK (c1);
  vlib_buffer_t *buffers[CNXK_FRAME_CAPACITY];

  CLIB_CACHE_LINE_ALIGN_MARK (c2);
  u32 buffer_indices[CNXK_FRAME_CAPACITY];

  vlib_buffer_t buffer_template;
} cnxk_per_thread_data_t;

void cnxk_drv_per_thread_data_init (cnxk_per_thread_data_t *ptd,
				    i16 pktpool_refill_deplete_sz,
				    i32 max_vlib_buffer_pools);

#endif /* included_onp_drv_inc_common_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
