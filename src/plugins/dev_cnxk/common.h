/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _CNXK_COMMON_H_
#define _CNXK_COMMON_H_

#include <vppinfra/clib.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <roc/base/roc_api.h>

static_always_inline u32
cnxk_aura_fill_with_buffers (vlib_main_t *vm, u64 aura_handle,
			     u8 buffer_pool_index, u32 sz, u16 hdr_off)
{
  u32 buffer_indices[sz], n_alloc;
  n_alloc =
    vlib_buffer_alloc_from_pool (vm, buffer_indices, sz, buffer_pool_index);

  for (int i = 0; i < n_alloc; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, buffer_indices[i]);
      roc_npa_aura_op_free (aura_handle, 0, pointer_to_uword (b) - hdr_off);
    }
  return n_alloc;
}

static_always_inline u32
cnxk_aura_free_buffers (vlib_main_t *vm, u64 aura_handle, u32 sz, u16 hdr_off)
{
  u32 n = 0;
  u64 iova;

  while ((iova = roc_npa_aura_op_alloc (aura_handle, 0)))
    {
      vlib_buffer_t *b = (void *) iova + hdr_off;
      vlib_buffer_free_one (vm, vlib_get_buffer_index (vm, b));
      n++;
    }
  return n;
}

#endif /* _CNXK_COMMON_H_ */
