/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP buffer pool implementation.
 */

#include <onp/onp.h>

clib_error_t *
onp_pool_create (vlib_main_t *vm, u32 n_buffers, u8 bp_index, u32 buffer_size,
		 uword mem_start, uword mem_end, u32 *pool_index)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  cnxk_drv_pool_params_t params = { 0 };
  vlib_buffer_pool_t *bp = NULL;
  u32 n_alloc, bi = 0, n_free;
  clib_error_t *error = NULL;
  vlib_buffer_t *b;
  u8 *name = NULL;
  u8 *buf = NULL;

  bp = vec_elt_at_index (bm->buffer_pools, bp_index);

  name = format (name, "buffer-pool-%d-numa-%d%c", bp_index, bp->numa_node, 0);
  params.elem_size = buffer_size;
  params.n_elem = n_buffers;
  params.is_pkt_pool = true;

  if (cnxk_drv_pool_create ((char *) name, params, pool_index))
    {
      error = clib_error_create ("cnxk_drv_pool_create failed");
      goto free_name;
    }

  if (cnxk_drv_pool_range_set (*pool_index, mem_start, mem_end))
    {
      error = clib_error_create ("cnxk_drv_pool_range_set failed");
      goto destroy_pool;
    }

  for (n_alloc = 0; n_alloc < n_buffers; n_alloc++)
    {
      if (vlib_buffer_alloc_from_pool (vm, &bi, 1, bp_index) != 1)
	{
	  error = clib_error_create ("vlib_buffer_alloc_from_pool failed");
	  goto free_buffers;
	}

      b = vlib_get_buffer (vm, bi);
      buf = ((u8 *) b - bm->ext_hdr_size);
      if (cnxk_drv_pool_elem_free (*pool_index, (void **) &buf, 1))
	{
	  error = clib_error_create ("cnxk_drv_pool_elem_free failed");
	  goto free_vlib;
	}
    }

  vec_free (name);

  return 0;

free_vlib:
  vlib_buffer_free (vm, &bi, 1);

free_buffers:
  for (n_free = 0; n_free < n_alloc; n_free++)
    {
      cnxk_drv_pool_elem_alloc (*pool_index, (void **) &b, 1);
      bi = vlib_get_buffer_index (vm, b);
      vlib_buffer_free (vm, &bi, 1);
    }

destroy_pool:
  cnxk_drv_pool_destroy (*pool_index);

free_name:
  vec_free (name);

  return error;
}

clib_error_t *
onp_buffer_pools_setup (vlib_main_t *vm)
{
  vlib_buffer_pool_t *bp = NULL;
  clib_error_t *error = NULL;
  vlib_physmem_map_t *pm;
  uword start, end;
  onp_main_t *om;
  u32 pool_index;

  om = onp_get_main ();

  cnxk_drv_pool_init ();

  vec_validate_init_empty (om->cnxk_pool_by_buffer_pool_index,
			   CNXK_POOL_MAX_NUM, ~0);

  vec_validate_init_empty (om->buffer_pool_by_cnxk_pool_index,
			   CNXK_POOL_MAX_NUM, ~0);

  vec_foreach (bp, vm->buffer_main->buffer_pools)
    {
      if (bp->start)
	{
	  pm = vlib_physmem_get_map (vm, bp->physmem_map_index);
	  start = bp->start;
	  end = start + (pm->n_pages << pm->log2_page_size);
	  error =
	    onp_pool_create (vm, om->onp_conf->onp_num_pkt_buf, bp->index,
			     bp->alloc_size, start, end, &pool_index);
	  if (error)
	    return clib_error_return (error, "onp_pool_create failed");

	  ASSERT (pool_index < CNXK_POOL_MAX_NUM);

	  /* Maintain both indexes differently, though they are same */
	  ASSERT (bp->index == pool_index);

	  om->cnxk_pool_by_buffer_pool_index[bp->index] = pool_index;
	  om->buffer_pool_by_cnxk_pool_index[pool_index] = bp->index;
	}
    }
  return NULL;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
