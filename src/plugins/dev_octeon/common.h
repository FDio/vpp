/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _OCT_COMMON_H_
#define _OCT_COMMON_H_

#include <vppinfra/clib.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <base/roc_api.h>

static_always_inline u32
oct_aura_free_all_buffers (vlib_main_t *vm, u64 aura_handle, u16 hdr_off,
			   u32 num_buffers)
{
  u32 n = 0;
  u64 iova;

  while ((iova = roc_npa_aura_op_alloc (aura_handle, 0)))
    {
      vlib_buffer_t *b = (void *) iova + hdr_off;
      vlib_buffer_free_one (vm, vlib_get_buffer_index (vm, b));
      n++;
      if (num_buffers && n == num_buffers)
	break;
    }
  return n;
}

#endif /* _OCT_COMMON_H_ */
