/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_inc_pool_h
#define included_onp_drv_inc_pool_h

#include <onp/drv/inc/common.h>

#define CNXK_POOL_MAX_REFILL_DEPLTE_COUNT 256
#define CNXK_POOL_MAX_NUM		  8 /* Max number of pools */
#define CNXK_POOL_NAME_LEN		  32

typedef enum
{
  CNXK_POOL_COUNTER_TYPE_DEFAULT,
} cnxk_pool_counter_type_t;

/* Total cnxk pool counter types */
#define CNXK_POOL_COUNTER_TYPE_MAX (CNXK_POOL_COUNTER_TYPE_DEFAULT + 1)

typedef struct
{
  /* Total elements used by pool */
  u64 elem_count;
  /* Total elements available in pool */
  u64 elem_available;
  /* Total elements in pool */
  u64 elem_limit;
  /* Each element size */
  u64 elem_size;
  char name[CNXK_POOL_NAME_LEN];
} cnxk_pool_info_t;

typedef struct
{
  u32 elem_size;
  u32 n_elem;
  bool is_pkt_pool;
  bool is_inl_meta_pool;
} cnxk_drv_pool_params_t;

i32 cnxk_drv_pool_init (void);
i32 cnxk_drv_pool_info_dump (void);
i32 cnxk_drv_pool_create (const char *name, cnxk_drv_pool_params_t params,
			  u32 *index);
i32 cnxk_drv_pool_destroy (u32 index);
i32 cnxk_drv_pool_elem_free (u32 index, void *elem[], u32 n_elem);
i32 cnxk_drv_pool_elem_alloc (u32 index, void *elem[], u32 n_elem);
i32 cnxk_drv_pool_info_get (u32 index, cnxk_pool_info_t *info);
i32 cnxk_drv_pool_range_set (u32 index, u64 start, u64 end);
i32 cnxk_drv_pool_setup (vlib_main_t *vm, const char *name,
			 const cnxk_drv_pool_params_t params, u32 *pool_index);
void cnxk_drv_pktpool_set_refill_deplete_counters (
  cnxk_pool_counter_type_t pool_type, vlib_simple_counter_main_t *refill,
  vlib_simple_counter_main_t *deplete);

#endif /* included_onp_drv_inc_pool_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
