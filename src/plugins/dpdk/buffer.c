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
#include <rte_version.h>

#include <vlib/vlib.h>
#include <dpdk/buffer.h>

STATIC_ASSERT (VLIB_BUFFER_PRE_DATA_SIZE == RTE_PKTMBUF_HEADROOM,
	       "VLIB_BUFFER_PRE_DATA_SIZE must be equal to RTE_PKTMBUF_HEADROOM");

extern struct rte_mbuf *dpdk_mbuf_template_by_pool_index;
#ifndef CLIB_MARCH_VARIANT
struct rte_mempool **dpdk_mempool_by_buffer_pool_index = 0;
struct rte_mempool **dpdk_no_cache_mempool_by_buffer_pool_index = 0;
struct rte_mbuf *dpdk_mbuf_template_by_pool_index = 0;

clib_error_t *
dpdk_buffer_pool_init (vlib_main_t * vm, vlib_buffer_pool_t * bp)
{
  uword buffer_mem_start = vm->buffer_main->buffer_mem_start;
  struct rte_mempool *mp, *nmp;
  struct rte_pktmbuf_pool_private priv;
  enum rte_iova_mode iova_mode;
  u32 i;
  u8 *name = 0;

  u32 elt_size =
    sizeof (struct rte_mbuf) + sizeof (vlib_buffer_t) + bp->data_size;

  /* create empty mempools */
  vec_validate_aligned (dpdk_mempool_by_buffer_pool_index, bp->index,
			CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (dpdk_no_cache_mempool_by_buffer_pool_index, bp->index,
			CLIB_CACHE_LINE_BYTES);

  /* normal mempool */
  name = format (name, "vpp pool %u%c", bp->index, 0);
  mp = rte_mempool_create_empty ((char *) name, bp->n_buffers,
				 elt_size, 512, sizeof (priv),
				 bp->numa_node, 0);
  if (!mp)
    {
      vec_free (name);
      return clib_error_return (0,
				"failed to create normal mempool for numa node %u",
				bp->index);
    }
  vec_reset_length (name);

  /* non-cached mempool */
  name = format (name, "vpp pool %u (no cache)%c", bp->index, 0);
  nmp = rte_mempool_create_empty ((char *) name, bp->n_buffers,
				  elt_size, 0, sizeof (priv),
				  bp->numa_node, 0);
  if (!nmp)
    {
      rte_mempool_free (mp);
      vec_free (name);
      return clib_error_return (0,
				"failed to create non-cache mempool for numa nude %u",
				bp->index);
    }
  vec_free (name);

  dpdk_mempool_by_buffer_pool_index[bp->index] = mp;
  dpdk_no_cache_mempool_by_buffer_pool_index[bp->index] = nmp;

  mp->pool_id = nmp->pool_id = bp->index;

  rte_mempool_set_ops_byname (mp, "vpp", NULL);
  rte_mempool_set_ops_byname (nmp, "vpp-no-cache", NULL);

  /* Call the mempool priv initializer */
  memset (&priv, 0, sizeof (priv));
  priv.mbuf_data_room_size = VLIB_BUFFER_PRE_DATA_SIZE +
    vlib_buffer_get_default_data_size (vm);
  priv.mbuf_priv_size = VLIB_BUFFER_HDR_SIZE;
  rte_pktmbuf_pool_init (mp, &priv);
  rte_pktmbuf_pool_init (nmp, &priv);

  iova_mode = rte_eal_iova_mode ();

  /* populate mempool object buffer header */
  for (i = 0; i < bp->n_buffers; i++)
    {
      struct rte_mempool_objhdr *hdr;
      vlib_buffer_t *b = vlib_get_buffer (vm, bp->buffers[i]);
      struct rte_mbuf *mb = rte_mbuf_from_vlib_buffer (b);
      hdr = (struct rte_mempool_objhdr *) RTE_PTR_SUB (mb, sizeof (*hdr));
      hdr->mp = mp;
      hdr->iova = (iova_mode == RTE_IOVA_VA) ?
	pointer_to_uword (mb) : vlib_physmem_get_pa (vm, mb);
      STAILQ_INSERT_TAIL (&mp->elt_list, hdr, next);
      STAILQ_INSERT_TAIL (&nmp->elt_list, hdr, next);
      mp->populated_size++;
      nmp->populated_size++;
    }

  /* call the object initializers */
  rte_mempool_obj_iter (mp, rte_pktmbuf_init, 0);

  /* create mbuf header tempate from the first buffer in the pool */
  vec_validate_aligned (dpdk_mbuf_template_by_pool_index, bp->index,
			CLIB_CACHE_LINE_BYTES);
  clib_memcpy (vec_elt_at_index (dpdk_mbuf_template_by_pool_index, bp->index),
	       rte_mbuf_from_vlib_buffer (vlib_buffer_ptr_from_index
					  (buffer_mem_start, *bp->buffers,
					   0)), sizeof (struct rte_mbuf));

  for (i = 0; i < bp->n_buffers; i++)
    {
      vlib_buffer_t *b;
      b = vlib_buffer_ptr_from_index (buffer_mem_start, bp->buffers[i], 0);
      vlib_buffer_copy_template (b, &bp->buffer_template);
    }

  /* map DMA pages if at least one physical device exists */
  if (rte_eth_dev_count_avail ())
    {
      uword i;
      size_t page_sz;
      vlib_physmem_map_t *pm;
      int do_vfio_map = 1;

      pm = vlib_physmem_get_map (vm, bp->physmem_map_index);
      page_sz = 1ULL << pm->log2_page_size;

      for (i = 0; i < pm->n_pages; i++)
	{
	  char *va = ((char *) pm->base) + i * page_sz;
	  uword pa = (iova_mode == RTE_IOVA_VA) ?
	    pointer_to_uword (va) : pm->page_table[i];

	  if (do_vfio_map &&
#if RTE_VERSION < RTE_VERSION_NUM(19, 11, 0, 0)
	      rte_vfio_dma_map (pointer_to_uword (va), pa, page_sz))
#else
	      rte_vfio_container_dma_map (RTE_VFIO_DEFAULT_CONTAINER_FD,
					  pointer_to_uword (va), pa, page_sz))
#endif
	    do_vfio_map = 0;

	  struct rte_mempool_memhdr *memhdr;
	  memhdr = clib_mem_alloc (sizeof (*memhdr));
	  memhdr->mp = mp;
	  memhdr->addr = va;
	  memhdr->iova = pa;
	  memhdr->len = page_sz;
	  memhdr->free_cb = 0;
	  memhdr->opaque = 0;

	  STAILQ_INSERT_TAIL (&mp->mem_list, memhdr, next);
	  mp->nb_mem_chunks++;
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

#endif

static_always_inline void
dpdk_ops_vpp_enqueue_one (vlib_buffer_t * bt, void *obj)
{
  /* Only non-replicated packets (b->ref_count == 1) expected */

  struct rte_mbuf *mb = obj;
  vlib_buffer_t *b = vlib_buffer_from_rte_mbuf (mb);
  ASSERT (b->ref_count == 1);
  ASSERT (b->buffer_pool_index == bt->buffer_pool_index);
  vlib_buffer_copy_template (b, bt);
}

int
CLIB_MULTIARCH_FN (dpdk_ops_vpp_enqueue) (struct rte_mempool * mp,
					  void *const *obj_table, unsigned n)
{
  const int batch_size = 32;
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t bt;
  u8 buffer_pool_index = mp->pool_id;
  vlib_buffer_pool_t *bp = vlib_get_buffer_pool (vm, buffer_pool_index);
  u32 bufs[batch_size];
  u32 n_left = n;
  void *const *obj = obj_table;

  vlib_buffer_copy_template (&bt, &bp->buffer_template);

  while (n_left >= 4)
    {
      dpdk_ops_vpp_enqueue_one (&bt, obj[0]);
      dpdk_ops_vpp_enqueue_one (&bt, obj[1]);
      dpdk_ops_vpp_enqueue_one (&bt, obj[2]);
      dpdk_ops_vpp_enqueue_one (&bt, obj[3]);
      obj += 4;
      n_left -= 4;
    }

  while (n_left)
    {
      dpdk_ops_vpp_enqueue_one (&bt, obj[0]);
      obj += 1;
      n_left -= 1;
    }

  while (n >= batch_size)
    {
      vlib_get_buffer_indices_with_offset (vm, (void **) obj_table, bufs,
					   batch_size,
					   sizeof (struct rte_mbuf));
      vlib_buffer_pool_put (vm, buffer_pool_index, bufs, batch_size);
      n -= batch_size;
      obj_table += batch_size;
    }

  if (n)
    {
      vlib_get_buffer_indices_with_offset (vm, (void **) obj_table, bufs,
					   n, sizeof (struct rte_mbuf));
      vlib_buffer_pool_put (vm, buffer_pool_index, bufs, n);
    }

  return 0;
}

CLIB_MARCH_FN_REGISTRATION (dpdk_ops_vpp_enqueue);

static_always_inline void
dpdk_ops_vpp_enqueue_no_cache_one (vlib_main_t * vm, struct rte_mempool *old,
				   struct rte_mempool *new, void *obj,
				   vlib_buffer_t * bt)
{
  struct rte_mbuf *mb = obj;
  vlib_buffer_t *b = vlib_buffer_from_rte_mbuf (mb);

  if (clib_atomic_sub_fetch (&b->ref_count, 1) == 0)
    {
      u32 bi = vlib_get_buffer_index (vm, b);
      vlib_buffer_copy_template (b, bt);
      vlib_buffer_pool_put (vm, bt->buffer_pool_index, &bi, 1);
      return;
    }
}

int
CLIB_MULTIARCH_FN (dpdk_ops_vpp_enqueue_no_cache) (struct rte_mempool * cmp,
						   void *const *obj_table,
						   unsigned n)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t bt;
  struct rte_mempool *mp;
  mp = dpdk_mempool_by_buffer_pool_index[cmp->pool_id];
  u8 buffer_pool_index = cmp->pool_id;
  vlib_buffer_pool_t *bp = vlib_get_buffer_pool (vm, buffer_pool_index);
  vlib_buffer_copy_template (&bt, &bp->buffer_template);

  while (n >= 4)
    {
      dpdk_ops_vpp_enqueue_no_cache_one (vm, cmp, mp, obj_table[0], &bt);
      dpdk_ops_vpp_enqueue_no_cache_one (vm, cmp, mp, obj_table[1], &bt);
      dpdk_ops_vpp_enqueue_no_cache_one (vm, cmp, mp, obj_table[2], &bt);
      dpdk_ops_vpp_enqueue_no_cache_one (vm, cmp, mp, obj_table[3], &bt);
      obj_table += 4;
      n -= 4;
    }

  while (n)
    {
      dpdk_ops_vpp_enqueue_no_cache_one (vm, cmp, mp, obj_table[0], &bt);
      obj_table += 1;
      n -= 1;
    }

  return 0;
}

CLIB_MARCH_FN_REGISTRATION (dpdk_ops_vpp_enqueue_no_cache);

static_always_inline void
dpdk_mbuf_init_from_template (struct rte_mbuf **mba, struct rte_mbuf *mt,
			      int count)
{
  /* Assumptions about rte_mbuf layout */
  STATIC_ASSERT_OFFSET_OF (struct rte_mbuf, buf_addr, 0);
  STATIC_ASSERT_OFFSET_OF (struct rte_mbuf, buf_iova, 8);
  STATIC_ASSERT_SIZEOF_ELT (struct rte_mbuf, buf_iova, 8);
  STATIC_ASSERT_SIZEOF_ELT (struct rte_mbuf, buf_iova, 8);
  STATIC_ASSERT_SIZEOF (struct rte_mbuf, 128);

  while (count--)
    {
      struct rte_mbuf *mb = mba[0];
      int i;
      /* bytes 0 .. 15 hold buf_addr and buf_iova which we need to preserve */
      /* copy bytes 16 .. 31 */
      *((u8x16 *) mb + 1) = *((u8x16 *) mt + 1);

      /* copy bytes 32 .. 127 */
#ifdef CLIB_HAVE_VEC256
      for (i = 1; i < 4; i++)
	*((u8x32 *) mb + i) = *((u8x32 *) mt + i);
#else
      for (i = 2; i < 8; i++)
	*((u8x16 *) mb + i) = *((u8x16 *) mt + i);
#endif
      mba++;
    }
}

int
CLIB_MULTIARCH_FN (dpdk_ops_vpp_dequeue) (struct rte_mempool * mp,
					  void **obj_table, unsigned n)
{
  const int batch_size = 32;
  vlib_main_t *vm = vlib_get_main ();
  u32 bufs[batch_size], total = 0, n_alloc = 0;
  u8 buffer_pool_index = mp->pool_id;
  void **obj = obj_table;
  struct rte_mbuf t = dpdk_mbuf_template_by_pool_index[buffer_pool_index];

  while (n >= batch_size)
    {
      n_alloc = vlib_buffer_alloc_from_pool (vm, bufs, batch_size,
					     buffer_pool_index);
      if (n_alloc != batch_size)
	goto alloc_fail;

      vlib_get_buffers_with_offset (vm, bufs, obj, batch_size,
				    -(i32) sizeof (struct rte_mbuf));
      dpdk_mbuf_init_from_template ((struct rte_mbuf **) obj, &t, batch_size);
      total += batch_size;
      obj += batch_size;
      n -= batch_size;
    }

  if (n)
    {
      n_alloc = vlib_buffer_alloc_from_pool (vm, bufs, n, buffer_pool_index);

      if (n_alloc != n)
	goto alloc_fail;

      vlib_get_buffers_with_offset (vm, bufs, obj, n,
				    -(i32) sizeof (struct rte_mbuf));
      dpdk_mbuf_init_from_template ((struct rte_mbuf **) obj, &t, n);
    }

  return 0;

alloc_fail:
  /* dpdk doesn't support partial alloc, so we need to return what we
     already got */
  if (n_alloc)
    vlib_buffer_pool_put (vm, buffer_pool_index, bufs, n_alloc);
  obj = obj_table;
  while (total)
    {
      vlib_get_buffer_indices_with_offset (vm, obj, bufs, batch_size,
					   sizeof (struct rte_mbuf));
      vlib_buffer_pool_put (vm, buffer_pool_index, bufs, batch_size);

      obj += batch_size;
      total -= batch_size;
    }
  return -ENOENT;
}

CLIB_MARCH_FN_REGISTRATION (dpdk_ops_vpp_dequeue);

#ifndef CLIB_MARCH_VARIANT

static int
dpdk_ops_vpp_dequeue_no_cache (struct rte_mempool *mp, void **obj_table,
			       unsigned n)
{
  clib_error ("bug");
  return 0;
}

static unsigned
dpdk_ops_vpp_get_count (const struct rte_mempool *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  if (mp)
    {
      vlib_buffer_pool_t *pool = vlib_get_buffer_pool (vm, mp->pool_id);
      if (pool)
	{
	  return pool->n_avail;
	}
    }
  return 0;
}

static unsigned
dpdk_ops_vpp_get_count_no_cache (const struct rte_mempool *mp)
{
  struct rte_mempool *cmp;
  cmp = dpdk_no_cache_mempool_by_buffer_pool_index[mp->pool_id];
  return dpdk_ops_vpp_get_count (cmp);
}

clib_error_t *
dpdk_buffer_pools_create (vlib_main_t * vm)
{
  clib_error_t *err;
  vlib_buffer_pool_t *bp;
  char *vname = (char *) vm->node_main.cfg_node_variant;

  struct rte_mempool_ops ops = { };

  strncpy (ops.name, "vpp", 4);
  ops.alloc = dpdk_ops_vpp_alloc;
  ops.free = dpdk_ops_vpp_free;
  ops.get_count = dpdk_ops_vpp_get_count;
  ops.enqueue = CLIB_MARCH_FN_POINTER_BY_NAME (dpdk_ops_vpp_enqueue, vname);
  ops.dequeue = CLIB_MARCH_FN_POINTER_BY_NAME (dpdk_ops_vpp_dequeue, vname);
  rte_mempool_register_ops (&ops);

  strncpy (ops.name, "vpp-no-cache", 13);
  ops.get_count = dpdk_ops_vpp_get_count_no_cache;
  ops.enqueue =
    CLIB_MARCH_FN_POINTER_BY_NAME (dpdk_ops_vpp_enqueue_no_cache, vname);
  ops.dequeue = dpdk_ops_vpp_dequeue_no_cache;
  rte_mempool_register_ops (&ops);

  /* *INDENT-OFF* */
  vec_foreach (bp, vm->buffer_main->buffer_pools)
    if (bp->start && (err = dpdk_buffer_pool_init (vm, bp)))
      return err;
  /* *INDENT-ON* */
  return 0;
}

VLIB_BUFFER_SET_EXT_HDR_SIZE (sizeof (struct rte_mempool_objhdr) +
			      sizeof (struct rte_mbuf));

#endif

/** @endcond */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
