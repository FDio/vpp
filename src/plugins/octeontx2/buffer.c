/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Copyright (c) 2019 Marvell International Ltd. */

#include <unistd.h>
#include <errno.h>

#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_vfio.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/vnet.h>
#include <octeontx2/device/octeontx2.h>
#include <octeontx2/buffer.h>
#include <octeontx2/device/mempool.h>

STATIC_ASSERT (VLIB_BUFFER_PRE_DATA_SIZE == RTE_PKTMBUF_HEADROOM,
	       "VLIB_BUFFER_PRE_DATA_SIZE must be equal to RTE_PKTMBUF_HEADROOM");

extern otx2_config_main_t otx2_config_main;

#ifndef CLIB_MARCH_VARIANT
struct rte_mempool **otx2_mempool_by_buffer_pool_index = 0;

clib_error_t *
otx2_buffer_pool_init (vlib_main_t * vm, vlib_buffer_pool_t * bp,
		       char *cached_pool_name)
{
  uword buffer_mem_start = vm->buffer_main->buffer_mem_start;
  struct rte_pktmbuf_pool_private priv;
  enum rte_iova_mode iova_mode;
  struct rte_mempool *mp;
  vlib_physmem_map_t *pm;
  struct rte_mbuf *mb;
  vlib_buffer_t *b;
  u32 buffer_index = 0, nmbufs;
  int do_vfio_map = 1;
  size_t page_sz;
  u8 *name = 0;
  uword i, pa;
  void *va;

  u32 elt_size =
    sizeof (struct rte_mbuf) + sizeof (vlib_buffer_t) + bp->data_size;

  ASSERT (bp->index < OTX2_MAX_NUM_MEMPOOLS);
  /* create empty mempools */
  vec_validate_aligned (otx2_mempool_by_buffer_pool_index, bp->index,
			CLIB_CACHE_LINE_BYTES);

  /* normal mempool */
  name = format (name, "%s pool %u%c", cached_pool_name, bp->index, 0);
  mp = rte_mempool_create_empty ((char *) name, bp->n_buffers,
				 elt_size, 512, sizeof (priv),
				 bp->numa_node, 0);
  if (!mp)
    {
      vec_free (name);
      return clib_error_return (0,
				"failed to create %s mempool for numa node %u",
				cached_pool_name, bp->index);
    }
  vec_free (name);

  otx2_mempool_by_buffer_pool_index[bp->index] = mp;

  mp->pool_id = bp->index;

  rte_mempool_set_ops_byname (mp, cached_pool_name, NULL);

  /* Call the mempool priv initializer */
  priv.mbuf_data_room_size = VLIB_BUFFER_PRE_DATA_SIZE +
    vlib_buffer_get_default_data_size (vm);
  priv.mbuf_priv_size = VLIB_BUFFER_HDR_SIZE;
  rte_pktmbuf_pool_init (mp, &priv);

  iova_mode = rte_eal_iova_mode ();
  pm = vlib_physmem_get_map (vm, bp->physmem_map_index);
  page_sz = 1ULL << pm->log2_page_size;

  if (rte_eth_dev_count_avail ())
    {
      /*Make sure that all buffers are intact */
      clib_spinlock_lock (&bp->lock);
      if (bp->n_buffers != vec_len (bp->buffers))
	{
	  clib_spinlock_unlock (&bp->lock);
	  clib_panic
	    ("Buffers of pool: %d are not intact(total: %lu, free: %lu)",
	     bp->index, bp->n_buffers, vec_len (bp->buffers));
	}
      /*Make buffers as 0 as we will populate them afresh */
      _vec_len (bp->buffers) = 0;
      clib_spinlock_unlock (&bp->lock);

      va = (void *) buffer_mem_start;
      /*Populate mempool */
      for (i = 0; i < pm->n_pages; i++)
	{
	  pa = (iova_mode == RTE_IOVA_VA) ?
	    pointer_to_uword (va) : pm->page_table[i];
	  if (rte_mempool_populate_iova (mp, va, pa, page_sz, 0, 0) < 0)
	    {
	      rte_mempool_free (mp);
	      return clib_error_return (0, "failed to populate %s",
					cached_pool_name);
	    }
	  if (do_vfio_map
	      && rte_vfio_dma_map (pointer_to_uword (va), pa, page_sz))
	    do_vfio_map = 0;
	}
      /* call the object initializers */
      rte_mempool_obj_iter (mp, rte_pktmbuf_init, 0);

      /*Now we have populated mempools, refill all buffers to bp to copy bt */
      for (i = 0; i < bp->n_buffers; i++)
	{
	  rte_mempool_get (mp, (void **) &mb);
	  b = vlib_buffer_from_rte_mbuf (mb);
	  vlib_buffer_copy_template (b, &bp->buffer_template);
	  vlib_get_buffer_indices_with_offset (vm, (void **) &b,
					       &buffer_index, 1, 0);
	  if (CLIB_DEBUG > 0)
	    {
	      vlib_buffer_validate_alloc_free (vm, &buffer_index, 1,
					       VLIB_BUFFER_KNOWN_FREE);
	    }
	  vlib_buffer_free (vm, &buffer_index, 1);
	}

      /*Number of buffers in mp is 0 so fill only required buffers from bp */
      nmbufs = otx2_config_main.num_mbufs;
      if (vec_len (bp->buffers) < otx2_config_main.num_mbufs)
	{
	  nmbufs = vec_len (bp->buffers);
	}

      for (i = 0; i < nmbufs; i++)
	{
	  vlib_buffer_alloc_from_pool (vm, &buffer_index, 1, bp->index);
	  b = vlib_buffer_ptr_from_index (buffer_mem_start, buffer_index, 0);
	  mb = rte_mbuf_from_vlib_buffer (b);
	  rte_mempool_put (mp, (void *) mb);
	}
    }
  return 0;
}

clib_error_t *
otx2_buffer_pools_create (vlib_main_t * vm)
{
  vlib_buffer_pool_t *bp;
  clib_error_t *err;
  /* *INDENT-OFF* */
  vec_foreach (bp, vm->buffer_main->buffer_pools)
    if (bp->start && (err = otx2_buffer_pool_init (vm, bp, "octeontx2_npa")))
      return err;
  /* *INDENT-ON* */

  return 0;
}

VLIB_BUFFER_SET_EXT_HDR_SIZE (sizeof (struct rte_mempool_objhdr) +
			      sizeof (struct rte_mbuf));
#endif
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
