/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_inc_pool_fp_h
#define included_onp_drv_inc_pool_fp_h

#include <onp/drv/modules/pool/pool_priv.h>

static_always_inline u32
cnxk_drv_pool_alloc_inline (u32 cnxk_pool_index, void *buffers[],
			    u32 n_buffers)
{
  u64 roc_aura_handle;
  u32 n_alloc;

  roc_aura_handle = cnxk_pool_get_aura_handle (cnxk_pool_index);

  for (n_alloc = 0; n_alloc < n_buffers; n_alloc++)
    {
      buffers[n_alloc] = (void *) roc_npa_aura_op_alloc (roc_aura_handle, 0);
      if (PREDICT_FALSE (!buffers[n_alloc]))
	break;
    }
  return n_alloc;
}

static_always_inline u32
cnxk_drv_pool_free_inline (u32 cnxk_pool_index, void *buffers[], u32 n_buffers)
{
  u64 roc_aura_handle;
  u32 n_free;

  cnxk_wmb ();

  roc_aura_handle = cnxk_pool_get_aura_handle (cnxk_pool_index);

  for (n_free = 0; n_free < n_buffers; n_free++)
    {
      ASSERT (buffers[n_free]);
      roc_npa_aura_op_free (roc_aura_handle, 0, (u64) buffers[n_free]);
    }
  return n_free;
}

static_always_inline i32
cnxk_pktpool_refill (vlib_main_t *vm, u32 buffer_pool_index,
		     i16 n_buffers_to_refill, u32 *bi, void *buffers[],
		     const u64 mode, const u64 flags)
{
  cnxk_pool_main_t *pm;
  u32 n_alloc;

  ASSERT (n_buffers_to_refill <= CNXK_POOL_MAX_REFILL_DEPLTE_COUNT);

  pm = cnxk_pool_get_main ();
  if (PREDICT_FALSE (n_buffers_to_refill > CNXK_POOL_MAX_REFILL_DEPLTE_COUNT))
    n_buffers_to_refill = CNXK_POOL_MAX_REFILL_DEPLTE_COUNT;

  if (PREDICT_FALSE (n_buffers_to_refill <= 0))
    return 0;

  n_alloc = vlib_buffer_alloc_from_pool (vm, bi, n_buffers_to_refill,
					 buffer_pool_index);

  vlib_increment_simple_counter (pm->refill_counter[buffer_pool_index],
				 vm->thread_index, 0 /* Index */, 1);
  vlib_get_buffers (vm, bi, (vlib_buffer_t **) buffers, n_alloc);

  return cnxk_drv_pool_free_inline (buffer_pool_index, buffers, n_alloc);
}

static_always_inline i32
cnxk_pktpool_deplete (vlib_main_t *vm, vlib_buffer_pool_t *bp,
		      i16 n_buffers_to_deplete, u32 *bi, void *buffers[],
		      const u64 mode, const u64 flags)
{
  u32 buffer_pool_index;
  cnxk_pool_main_t *pm;

  ASSERT (n_buffers_to_deplete <= CNXK_POOL_MAX_REFILL_DEPLTE_COUNT);

  pm = cnxk_pool_get_main ();
  buffer_pool_index = bp->index;

  if (PREDICT_FALSE (n_buffers_to_deplete > CNXK_POOL_MAX_REFILL_DEPLTE_COUNT))
    n_buffers_to_deplete = CNXK_POOL_MAX_REFILL_DEPLTE_COUNT;

  if (PREDICT_FALSE (n_buffers_to_deplete <= 0))
    return 0;

  n_buffers_to_deplete = cnxk_drv_pool_alloc_inline (
    buffer_pool_index, buffers, n_buffers_to_deplete);

  vlib_increment_simple_counter (pm->deplete_counter[buffer_pool_index],
				 vm->thread_index, 0 /* Index */, 1);
  vlib_get_buffer_indices (vm, (vlib_buffer_t **) buffers, bi,
			   n_buffers_to_deplete);
  vlib_buffer_free (vm, bi, n_buffers_to_deplete);

  return n_buffers_to_deplete;
}

static_always_inline void
cnxk_pktpool_refill_single_aura (vlib_main_t *vm, vlib_node_runtime_t *node,
				 u8 buffer_pool_index,
				 cnxk_per_thread_data_t *ptd, i32 compare_val)
{
  vlib_buffer_pool_t *bp = vm->buffer_main->buffer_pools + buffer_pool_index;
  vlib_buffer_t *buffers[CNXK_POOL_MAX_REFILL_DEPLTE_COUNT];
  u32 bi[CNXK_POOL_MAX_REFILL_DEPLTE_COUNT];

  if (PREDICT_TRUE (ptd->refill_deplete_count_per_pool[bp->index] <
		    compare_val))
    return;

  ASSERT (bp->index < vec_len (ptd->default_refill_count_per_pool));
  ASSERT (bp->index < vec_len (ptd->refill_deplete_count_per_pool));

  ptd->refill_deplete_count_per_pool[bp->index] -= cnxk_pktpool_refill (
    vm, bp->index, ptd->default_refill_count_per_pool[bp->index], bi,
    (void **) buffers, 0, 0);
}

static_always_inline void
cnxk_pktpool_deplete_single_aura (vlib_main_t *vm, vlib_node_runtime_t *node,
				  u8 buffer_pool_index,
				  cnxk_per_thread_data_t *ptd, i32 compare_val)
{
  vlib_buffer_pool_t *bp = vm->buffer_main->buffer_pools + buffer_pool_index;
  vlib_buffer_t *buffers[CNXK_POOL_MAX_REFILL_DEPLTE_COUNT];
  u32 bi[CNXK_POOL_MAX_REFILL_DEPLTE_COUNT];

  if (PREDICT_TRUE (ptd->refill_deplete_count_per_pool[bp->index] >
		    compare_val))
    return;

  ASSERT (bp->index < vec_len (ptd->default_deplete_count_per_pool));
  ASSERT (bp->index < vec_len (ptd->refill_deplete_count_per_pool));

  ptd->refill_deplete_count_per_pool[bp->index] += cnxk_pktpool_deplete (
    vm, bp, ptd->default_refill_count_per_pool[bp->index], bi,
    (void **) buffers, 0, 0);
}

static_always_inline void
cnxk_pktpools_deplete_to_vlib (vlib_main_t *vm, vlib_node_runtime_t *node,
			       cnxk_per_thread_data_t *ptd, const u64 mode,
			       const u64 flags)
{
  vlib_buffer_t *buffers[CNXK_POOL_MAX_REFILL_DEPLTE_COUNT];
  u32 bi[CNXK_POOL_MAX_REFILL_DEPLTE_COUNT];
  vlib_buffer_pool_t *bp;

  vec_foreach (bp, vm->buffer_main->buffer_pools)
    {
      if (PREDICT_FALSE (ptd->refill_deplete_count_per_pool[bp->index] <
			 ptd->default_deplete_count_per_pool[bp->index]))
	{
	  ASSERT (bp->index < vec_len (ptd->default_deplete_count_per_pool));
	  ASSERT (bp->index < vec_len (ptd->refill_deplete_count_per_pool));

	  ptd->refill_deplete_count_per_pool[bp->index] +=
	    cnxk_pktpool_deplete (
	      vm, bp, ptd->default_refill_count_per_pool[bp->index], bi,
	      (void **) buffers, mode, flags);
	}
    }
}

static_always_inline void
cnxk_pktpool_update_refill_count (vlib_main_t *vm, cnxk_per_thread_data_t *ptd,
				  uword n_rx_packets, u8 buffer_pool_index)
{
  ASSERT (buffer_pool_index < vec_len (ptd->refill_deplete_count_per_pool));

  ptd->refill_deplete_count_per_pool[buffer_pool_index] += n_rx_packets;
}

static_always_inline void
cnxk_pktpool_update_deplete_count (vlib_main_t *vm,
				   cnxk_per_thread_data_t *ptd,
				   uword n_packets, u8 buffer_pool_index)
{
  ASSERT (buffer_pool_index < vec_len (ptd->refill_deplete_count_per_pool));

  ptd->refill_deplete_count_per_pool[buffer_pool_index] -= n_packets;
}

#endif /* included_onp_drv_inc_pool_fp_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
