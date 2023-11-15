/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP buffer pool interface.
 */

#ifndef included_onp_pool_buffer_h
#define included_onp_pool_buffer_h

#include <onp/drv/inc/pool.h>

#define ONP_MAX_VLIB_BUFFER_POOLS 256

clib_error_t *onp_buffer_pools_setup (vlib_main_t *vm);

clib_error_t *onp_pool_create (vlib_main_t *vm, u32 n_buffers, u8 bp_index,
			       u32 buffer_size, uword mem_start, uword mem_end,
			       u32 *pool_index);
clib_error_t *onp_buffer_create_vlib_pool (vlib_main_t *vm, u32 num_bufs,
					   u32 data_size, u8 *bp_index);
#endif /* included_onp_pool_buffer_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
