/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_modules_pool_pool_priv_h
#define included_onp_drv_modules_pool_pool_priv_h

#include <platform.h>
#include <base/roc_api.h>
#include <onp/drv/inc/log.h>
#include <onp/drv/inc/common.h>
#include <onp/drv/inc/pool.h>

#define CNXK_AURA(x) ((x & ROC_AURA_ID_MASK) << 20)

typedef struct cnxk_pool_ops
{
  i32 (*create) (const char *name, cnxk_drv_pool_params_t params, u32 *index);
  i32 (*destroy) (u32 index);
  i32 (*free) (u32 index, void *elem[], u32 n_elem);
  i32 (*alloc) (u32 index, void *elem[], u32 n_elem);
  i32 (*info_get) (u32 index, cnxk_pool_info_t *pool_info);
  i32 (*range_set) (u32 index, u64 start, u64 end);
  i32 (*setup) (vlib_main_t *vm, const char *name,
		cnxk_drv_pool_params_t params, u32 *index);
  i32 (*info_dump) (void);
} cnxk_pool_ops_t;

i32 cnxk_pool_create (const char *name, cnxk_drv_pool_params_t params,
		      u32 *index);
i32 cnxk_pool_destroy (u32 index);
i32 cnxk_pool_elem_free (u32 index, void *elem[], u32 n_elem);
i32 cnxk_pool_elem_alloc (u32 index, void *elem[], u32 n_elem);
i32 cnxk_pool_info_get (u32 index, cnxk_pool_info_t *pool_info);
i32 cnxk_pool_range_set (u32 index, u64 start, u64 end);
i32 cnxk_pool_setup (vlib_main_t *vm, const char *name,
		     cnxk_drv_pool_params_t params, u32 *pool_index);
i32 cnxk_pool_info_dump (void);
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (c0);
  u64 roc_aura_handle;
  u32 index;
  u32 n_elem;
  u32 elem_sz;
  u8 used;
  char name[CNXK_POOL_NAME_LEN];
} cnxk_pool_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  cnxk_pool_t pool_dev[CNXK_POOL_MAX_NUM];
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  vlib_simple_counter_main_t *refill_counter[CNXK_POOL_COUNTER_TYPE_MAX];
  vlib_simple_counter_main_t *deplete_counter[CNXK_POOL_COUNTER_TYPE_MAX];
  u32 meta_index;
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);
  cnxk_pool_ops_t *pool_ops;
} cnxk_pool_main_t;

extern cnxk_pool_main_t cnxk_pool_main;

static_always_inline cnxk_pool_main_t *
cnxk_pool_get_main (void)
{
  return &cnxk_pool_main;
}

static_always_inline u32
cnxk_pool_get_meta_index (void)
{
  cnxk_pool_main_t *pm = cnxk_pool_get_main ();

  return pm->meta_index;
}

static_always_inline void
cnxk_pool_set_meta_index (u32 meta_index)
{
  cnxk_pool_main_t *pm = cnxk_pool_get_main ();

  pm->meta_index = meta_index;
}

static_always_inline u64
cnxk_pool_get_aura_handle (u32 index)
{
  cnxk_pool_main_t *pm = cnxk_pool_get_main ();

  return pm->pool_dev[index].roc_aura_handle;
}

static_always_inline cnxk_pool_t *
cnxk_pool_get_dev (u32 pool_index)
{
  cnxk_pool_main_t *pm = cnxk_pool_get_main ();

  return &pm->pool_dev[pool_index];
}

static_always_inline u64
cnxk_pool_get_elem_sz (u32 index)
{
  cnxk_pool_main_t *pm = cnxk_pool_get_main ();

  return pm->pool_dev[index].elem_sz;
}

#endif /* included_onp_drv_modules_pool_pool_priv_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
