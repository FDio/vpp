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

#include <unistd.h>
#include <errno.h>

#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_vfio.h>

#include <vlib/vlib.h>
#include <dpdk/buffer.h>

STATIC_ASSERT (VLIB_BUFFER_PRE_DATA_SIZE == RTE_PKTMBUF_HEADROOM,
	       "VLIB_BUFFER_PRE_DATA_SIZE must be equal to RTE_PKTMBUF_HEADROOM");

#ifndef CLIB_MARCH_VARIANT

typedef struct
{
  /* must be first */
  struct rte_pktmbuf_pool_private mbp_priv;
  u8 buffer_pool_index;
} dpdk_mempool_private_t;


#define ROUND_TO_CACHELINE(x) ((x + CLIB_CACHE_LINE_BYTES - 1) & ~(CLIB_CACHE_LINE_BYTES - 1))

clib_error_t *
dpdk_buffer_pool_init (vlib_main_t * vm, vlib_buffer_pool_t * bp)
{
  struct rte_mempool *mp;
  dpdk_mempool_private_t priv;
  enum rte_iova_mode iova_mode;
  u32 *bi;

  u32 elt_size = bp->buffer_size - sizeof (struct rte_mbuf) -
    sizeof (vlib_buffer_t) -
    ROUND_TO_CACHELINE (sizeof (struct rte_mempool_objhdr));

  /* create empty mempool */
  mp = rte_mempool_create_empty ((char *) bp->name, vec_len (bp->buffers),
				 elt_size, 0 /* 512 */ ,
				 sizeof (dpdk_mempool_private_t),
				 bp->numa_node, 0);

  rte_mempool_set_ops_byname (mp, "vpp", NULL);

  /* Call the mempool priv initializer */
  priv.mbp_priv.mbuf_data_room_size = VLIB_BUFFER_PRE_DATA_SIZE +
    VLIB_BUFFER_DATA_SIZE;
  priv.mbp_priv.mbuf_priv_size = VLIB_BUFFER_HDR_SIZE;
  priv.buffer_pool_index = bp->index;
  rte_pktmbuf_pool_init (mp, &priv);

  iova_mode = rte_eal_iova_mode ();

  /* populate mempool object buffer header */
  vec_foreach (bi, bp->buffers)
  {
    struct rte_mempool_objhdr *hdr;
    vlib_buffer_t *b = vlib_get_buffer (vm, *bi);
    struct rte_mbuf *mb = rte_mbuf_from_vlib_buffer (b);
    hdr = (struct rte_mempool_objhdr *) RTE_PTR_SUB (mb, sizeof (*hdr));
    hdr->mp = mp;
    hdr->iova = (iova_mode == RTE_IOVA_VA) ?
      pointer_to_uword (mb) : vlib_physmem_get_pa (vm, mb);
    STAILQ_INSERT_TAIL (&mp->elt_list, hdr, next);
    mp->populated_size++;
  }

  /* call the object initializers */
  rte_mempool_obj_iter (mp, rte_pktmbuf_init, 0);
  bp->external = mp;


  /* map DMA pages if at least one physical device exists */
  if (rte_eth_dev_count_avail ())
    {
      uword i;
      size_t page_sz;
      vlib_physmem_map_t *pm;

      pm = vlib_physmem_get_map (vm, bp->physmem_map_index);
      page_sz = 1ULL << pm->log2_page_size;

      for (i = 0; i < pm->n_pages; i++)
	{
	  char *va = ((char *) pm->base) + i * page_sz;
	  uword pa = (iova_mode == RTE_IOVA_VA) ?
	    pointer_to_uword (va) : pm->page_table[i];

	  if (rte_vfio_dma_map (pointer_to_uword (va), pa, page_sz))
	    break;
	}
    }

  return 0;
}

static int
dpdk_ops_vpp_alloc (struct rte_mempool *mp)
{
  clib_warning ("");
  return 0;
}

static void
dpdk_ops_vpp_free (struct rte_mempool *mp)
{
  clib_warning ("");
}

static int
dpdk_ops_vpp_enqueue (struct rte_mempool *mp, void *const *obj_table,
		      unsigned n)
{
  const int batch_size = 32;
  vlib_main_t *vm = vlib_get_main ();
  u32 bufs[batch_size];

  while (n >= batch_size)
    {
      vlib_get_buffer_indices_with_offset (vm, (void **) obj_table, bufs,
					   batch_size,
					   sizeof (struct rte_mbuf));
      vlib_buffer_free (vm, bufs, batch_size);
      n -= batch_size;
      obj_table += batch_size;
    }

  if (n)
    {
      vlib_get_buffer_indices_with_offset (vm, (void **) obj_table, bufs,
					   n, sizeof (struct rte_mbuf));
      vlib_buffer_free (vm, bufs, batch_size);
    }

  return 0;
}


static int
dpdk_ops_vpp_dequeue (struct rte_mempool *mp, void **obj_table, unsigned n)
{
  const int batch_size = 32;
  vlib_main_t *vm = vlib_get_main ();
  u32 bufs[batch_size], total = 0, n_alloc = 0;
  dpdk_mempool_private_t *privp = rte_mempool_get_priv (mp);
  u8 buffer_pool_index = privp->buffer_pool_index;

  while (n >= batch_size)
    {
      n_alloc = vlib_buffer_alloc_from_pool (vm, bufs, batch_size,
					     buffer_pool_index);
      if (n_alloc != batch_size)
	goto alloc_fail;

      vlib_get_buffers_with_offset (vm, bufs, obj_table, batch_size,
				    -(i32) sizeof (struct rte_mbuf));
      total += batch_size;
      obj_table += n_alloc;
    }

  if (n)
    {
      n_alloc = vlib_buffer_alloc_from_pool (vm, bufs, n, buffer_pool_index);

      if (n_alloc != n)
	goto alloc_fail;

      vlib_get_buffers_with_offset (vm, bufs, obj_table, n,
				    -(i32) sizeof (struct rte_mbuf));
    }

  return 0;

alloc_fail:
  if (n_alloc)
    vlib_buffer_free (vm, bufs, n_alloc);
  if (total)
    dpdk_ops_vpp_enqueue (mp, obj_table, total);
  return -ENOENT;
}

static unsigned
dpdk_ops_vpp_get_count (const struct rte_mempool *mp)
{
  clib_warning ("");
  return 0;
}

static const struct rte_mempool_ops ops_vpp = {
  .name = "vpp",
  .alloc = dpdk_ops_vpp_alloc,
  .free = dpdk_ops_vpp_free,
  .enqueue = dpdk_ops_vpp_enqueue,
  .dequeue = dpdk_ops_vpp_dequeue,
  .get_count = dpdk_ops_vpp_get_count,
};

MEMPOOL_REGISTER_OPS (ops_vpp);

clib_error_t *
dpdk_buffer_pools_create (vlib_main_t * vm, unsigned num_mbufs)
{
  clib_error_t *err;
  vlib_buffer_pool_t *bp;

  vec_foreach (bp, vm->buffer_main->buffer_pools)
    if ((err = dpdk_buffer_pool_init (vm, bp)))
    return err;
  return 0;
}

/* *INDENT-OFF* */
VLIB_BUFFER_REGISTER_CALLBACKS (dpdk, static) = {
  .external_header_size = sizeof (struct rte_mbuf) +
    ROUND_TO_CACHELINE (sizeof (struct rte_mempool_objhdr)),
};
/* *INDENT-ON* */
#endif

/** @endcond */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
