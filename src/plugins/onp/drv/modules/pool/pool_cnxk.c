/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <onp/drv/modules/pool/pool_priv.h>

extern cnxk_pool_ops_t pool_10k_ops;

cnxk_pool_main_t cnxk_pool_main;

static_always_inline cnxk_pool_t *
cnxk_pool_dev_alloc (void)
{
  cnxk_pool_t *pool = NULL;
  u32 i;

  for (i = 0; i < CNXK_POOL_MAX_NUM; i++)
    {
      pool = cnxk_pool_get_dev (i);
      if (pool->used)
	continue;

      clib_memset (pool, 0, sizeof (*pool));
      pool->used = 1;
      pool->index = i;

      return pool;
    }

  return 0;
}

i32
cnxk_pool_create (const char *name, cnxk_drv_pool_params_t params, u32 *index)
{
  u32 buf_size, total_buffers;
  struct npa_pool_s npapool;
  struct npa_aura_s aura;
  cnxk_pool_t *pool;
  u64 aura_handle;
  u32 flags = 0;
  int rv;

  clib_memset (&aura, 0, sizeof (struct npa_aura_s));
  clib_memset (&npapool, 0, sizeof (struct npa_pool_s));

  npapool.nat_align = 1;
  npapool.buf_offset = 0;
  buf_size = params.elem_size;
  total_buffers = params.n_elem;

  if (params.is_inl_meta_pool)
    flags = ROC_NPA_ZERO_AURA_F;

  rv = roc_npa_pool_create (&aura_handle, buf_size, total_buffers, &aura,
			    &npapool, flags);
  if (rv)
    {
      cnxk_pool_err ("roc_npa_pool_create failed with '%s' error",
		     roc_error_msg_get (rv));
      return -1;
    }
  pool = cnxk_pool_dev_alloc ();
  if (!pool)
    {
      cnxk_pool_err ("Failed to allocated memory for pool");
      return -1;
    }

  pool->roc_aura_handle = aura_handle;
  pool->n_elem = total_buffers;
  pool->elem_sz = buf_size;
  strncpy (pool->name, name, CNXK_POOL_NAME_LEN - 1);

  *index = pool->index;

  return 0;
}

i32
cnxk_pool_destroy (u32 index)
{
  cnxk_pool_t *pool = NULL;
  u64 roc_aura_handle;
  int rv;

  roc_aura_handle = cnxk_pool_get_aura_handle (index);
  if (roc_aura_handle == UINT64_MAX)
    {
      cnxk_pool_err ("Invalid AURA");
      return -1;
    }

  rv = roc_npa_pool_destroy (roc_aura_handle);
  if (rv)
    {
      cnxk_pool_err ("roc_npa_pool_destroy failed with '%s' error",
		     roc_error_msg_get (rv));
      return -1;
    }

  pool = cnxk_pool_get_dev (index);
  pool->used = 0;

  return 0;
}

i32
cnxk_pool_elem_alloc (u32 index, void *elem[], u32 n_elem)
{
  u64 roc_aura_handle;
  bool drop_ena = 0;
  u32 i;

  roc_aura_handle = cnxk_pool_get_aura_handle (index);
  if (roc_aura_handle == UINT64_MAX)
    {
      cnxk_pool_err ("Invalid AURA");
      return -1;
    }

  for (i = 0; i < n_elem; i++)
    {
      elem[i] = (void *) roc_npa_aura_op_alloc (roc_aura_handle, drop_ena);
      if (!elem[i])
	{
	  cnxk_pool_err ("roc_npa_aura_op_alloc failed");
	  return -1;
	}
    }

  return 0;
}

i32
cnxk_pool_elem_free (u32 index, void *elem[], u32 n_elem)
{
  u64 roc_aura_handle;
  u32 i;

  roc_aura_handle = cnxk_pool_get_aura_handle (index);
  if (roc_aura_handle == UINT64_MAX)
    {
      cnxk_pool_err ("Invalid AURA");
      return -1;
    }

  for (i = 0; i < n_elem; i++)
    roc_npa_aura_op_free (roc_aura_handle, 0, (u64) elem[i]);

  /* Read back to confirm pointers are freed */
  roc_npa_aura_op_available (roc_aura_handle);

  return 0;
}

i32
cnxk_pool_range_set (u32 index, u64 mem_start, u64 mem_end)
{
  u64 roc_aura_handle;

  roc_aura_handle = cnxk_pool_get_aura_handle (index);
  if (roc_aura_handle == UINT64_MAX)
    {
      cnxk_pool_err ("Invalid AURA");
      return -1;
    }

  roc_npa_aura_op_range_set (roc_aura_handle, mem_start, mem_end);

  return 0;
}

i32
cnxk_pool_info_get (u32 index, cnxk_pool_info_t *info)
{
  u64 roc_aura_handle;
  cnxk_pool_t *pool;

  roc_aura_handle = cnxk_pool_get_aura_handle (index);
  if (roc_aura_handle == UINT64_MAX)
    {
      cnxk_pool_err ("Invalid AURA");
      return -1;
    }

  pool = cnxk_pool_get_dev (index);
  if (!pool->used)
    return -1;

  info->elem_count = roc_npa_aura_op_cnt_get (roc_aura_handle);
  info->elem_limit = roc_npa_aura_op_limit_get (roc_aura_handle);
  info->elem_available = roc_npa_aura_op_available (roc_aura_handle);
  info->elem_size = pool->elem_sz;
  clib_strncpy (info->name, pool->name, CNXK_POOL_NAME_LEN - 1);

  return 0;
}

i32
cnxk_pool_setup (vlib_main_t *vm, const char *name,
		 cnxk_drv_pool_params_t params, u32 *index)
{
  u32 total_buffers, buf_size, total_sz;
  u64 mem_start, mem_end, elem_addr;
  u32 i, pool_index = ~0;

  if (!index)
    return -1;

  buf_size = CLIB_CACHE_LINE_ROUND (params.elem_size);
  total_buffers = params.n_elem;
  total_sz = total_buffers * buf_size;

  mem_start =
    (u64) cnxk_drv_physmem_alloc (vm, total_sz, CLIB_CACHE_LINE_BYTES);
  if (!mem_start)
    {
      cnxk_pool_err ("Failed to allocate physmem for pool %s", name);
      return -1;
    }

  if (cnxk_drv_pool_create (name, params, &pool_index))
    {
      cnxk_pool_err ("Failed to create %s pool", name);
      goto free_mem;
    }

  mem_end = mem_start + total_sz;

  if (cnxk_drv_pool_range_set (pool_index, mem_start, mem_end))
    {
      cnxk_pool_err ("Failed to set %s pool start/end range", name);
      goto pool_destroy;
    }

  elem_addr = mem_start;
  for (i = 0; i < total_buffers; i++)
    {
      if (cnxk_drv_pool_elem_free (pool_index, (void **) &elem_addr, 1))
	{
	  cnxk_pool_err ("Failed to free buffers to %s pool", name);
	  goto pool_destroy;
	}
      elem_addr += buf_size;
    }

  *index = pool_index;

  return 0;

pool_destroy:
  cnxk_drv_pool_destroy (pool_index);
free_mem:
  cnxk_drv_physmem_free (vm, (void *) mem_start);
  return -1;
}

i32
cnxk_drv_pool_init (void)
{
  cnxk_pool_main_t *pm;

  pm = cnxk_pool_get_main ();
  pm->meta_index = ~0;

  if (roc_model_is_cn10k ())
    pm->pool_ops = &pool_10k_ops;
  else
    ALWAYS_ASSERT (0);

  return 0;
}

i32
cnxk_pool_info_dump (void)
{
  roc_npa_dump ();

  /*
   * TODO:
   * Fix below function formatting and uncomment
   * roc_npa_ctx_dump ();
   */

  return 0;
}

void
cnxk_drv_per_thread_data_init (cnxk_per_thread_data_t *ptd,
			       i16 pktpool_refill_deplete_sz,
			       i32 max_vlib_buffer_pools)
{
  i16 refill_deplete_sz = max_pow2 (pktpool_refill_deplete_sz);

  vec_validate_init_empty_aligned (ptd->default_refill_count_per_pool,
				   max_vlib_buffer_pools, refill_deplete_sz,
				   CLIB_CACHE_LINE_BYTES);

  vec_validate_init_empty_aligned (ptd->default_deplete_count_per_pool,
				   max_vlib_buffer_pools, -refill_deplete_sz,
				   CLIB_CACHE_LINE_BYTES);

  vec_validate_init_empty_aligned (ptd->refill_deplete_count_per_pool,
				   max_vlib_buffer_pools, 0,
				   CLIB_CACHE_LINE_BYTES);
}

i32
cnxk_drv_pool_create (const char *name, cnxk_drv_pool_params_t params,
		      u32 *index)
{
  cnxk_pool_main_t *pm;

  pm = cnxk_pool_get_main ();
  return pm->pool_ops->create (name, params, index);
}

i32
cnxk_drv_pool_destroy (u32 index)
{
  cnxk_pool_main_t *pm;

  pm = cnxk_pool_get_main ();
  return pm->pool_ops->destroy (index);
}

i32
cnxk_drv_pool_elem_free (u32 index, void *elem[], u32 n_elem)
{
  cnxk_pool_main_t *pm;

  pm = cnxk_pool_get_main ();
  return pm->pool_ops->free (index, elem, n_elem);
}

i32
cnxk_drv_pool_elem_alloc (u32 index, void *elem[], u32 n_elem)
{
  cnxk_pool_main_t *pm;

  pm = cnxk_pool_get_main ();
  return pm->pool_ops->alloc (index, elem, n_elem);
}

i32
cnxk_drv_pool_info_get (u32 index, cnxk_pool_info_t *info)
{
  cnxk_pool_main_t *pm;

  pm = cnxk_pool_get_main ();
  return pm->pool_ops->info_get (index, info);
}

i32
cnxk_drv_pool_range_set (u32 index, u64 mem_start, u64 mem_end)
{
  cnxk_pool_main_t *pm;

  pm = cnxk_pool_get_main ();
  return pm->pool_ops->range_set (index, mem_start, mem_end);
}

i32
cnxk_drv_pool_setup (vlib_main_t *vm, const char *name,
		     cnxk_drv_pool_params_t params, u32 *pool_index)
{
  cnxk_pool_main_t *pm;

  pm = cnxk_pool_get_main ();
  return pm->pool_ops->setup (vm, name, params, pool_index);
}

i32
cnxk_drv_pool_info_dump (void)
{
  cnxk_pool_main_t *pm;

  pm = cnxk_pool_get_main ();
  return pm->pool_ops->info_dump ();
}

void
cnxk_drv_pktpool_set_refill_deplete_counters (
  cnxk_pool_counter_type_t pool_type, vlib_simple_counter_main_t *refill,
  vlib_simple_counter_main_t *deplete)
{
  cnxk_pool_main_t *pm;

  pm = cnxk_pool_get_main ();
  if (refill)
    pm->refill_counter[pool_type] = refill;

  if (deplete)
    pm->deplete_counter[pool_type] = deplete;
}

VLIB_REGISTER_LOG_CLASS (cnxk_pool_log) = {
  .class_name = "onp/pool",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
