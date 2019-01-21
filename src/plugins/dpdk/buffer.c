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


typedef struct
{
  /* must be first */
  struct rte_pktmbuf_pool_private mbp_priv;
  u8 buffer_pool_index;
} dpdk_mempool_private_t;

#ifndef CLIB_MARCH_VARIANT
struct rte_mempool **dpdk_mempool_by_buffer_pool_index = 0;
struct rte_mempool **dpdk_no_cache_mempool_by_buffer_pool_index = 0;

clib_error_t *
dpdk_buffer_pool_init (vlib_main_t * vm, vlib_buffer_pool_t * bp)
{
  struct rte_mempool *mp, *nmp;
  dpdk_mempool_private_t priv;
  enum rte_iova_mode iova_mode;
  u32 *bi;
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
  mp = rte_mempool_create_empty ((char *) name, vec_len (bp->buffers),
				 elt_size, 512, sizeof (priv),
				 bp->numa_node, 0);
  vec_reset_length (name);

  /* non-cached mempool */
  name = format (name, "vpp pool %u (no cache)%c", bp->index, 0);
  nmp = rte_mempool_create_empty ((char *) name, vec_len (bp->buffers),
				  elt_size, 0, sizeof (priv),
				  bp->numa_node, 0);
  vec_free (name);

  dpdk_mempool_by_buffer_pool_index[bp->index] = mp;
  dpdk_no_cache_mempool_by_buffer_pool_index[bp->index] = nmp;

  rte_mempool_set_ops_byname (mp, "vpp", NULL);
  rte_mempool_set_ops_byname (nmp, "vpp-no-cache", NULL);

  /* Call the mempool priv initializer */
  priv.mbp_priv.mbuf_data_room_size = VLIB_BUFFER_PRE_DATA_SIZE +
    VLIB_BUFFER_DATA_SIZE;
  priv.mbp_priv.mbuf_priv_size = VLIB_BUFFER_HDR_SIZE;
  priv.buffer_pool_index = bp->index;
  rte_pktmbuf_pool_init (mp, &priv);
  rte_pktmbuf_pool_init (nmp, &priv);

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
    STAILQ_INSERT_TAIL (&nmp->elt_list, hdr, next);
    mp->populated_size++;
    nmp->populated_size++;
  }

  /* call the object initializers */
  rte_mempool_obj_iter (mp, rte_pktmbuf_init, 0);

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

#endif

static_always_inline void
dpdk_ops_vpp_enqueue_one (vlib_buffer_t * bt, void *obj)
{
  /* Only non-replicated packets (b->n_add_refs == 0) expected */

  struct rte_mbuf *mb = obj;
  vlib_buffer_t *b = vlib_buffer_from_rte_mbuf (mb);
  ASSERT (b->n_add_refs == 0);
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
  dpdk_mempool_private_t *privp = rte_mempool_get_priv (mp);
  u8 buffer_pool_index = privp->buffer_pool_index;
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
      vlib_buffer_pool_put (vm, buffer_pool_index, bufs, batch_size);
    }

  return 0;
}

static_always_inline void
dpdk_ops_vpp_enqueue_no_cache_one (struct rte_mempool *old,
				   struct rte_mempool *new, void *obj)
{
  /* Only replicated packets (b->n_add_refs > 0) should hit this function. We
     need to revvert pool on each buffer to cached mempool and
     decrement b->n_add_refs */

  struct rte_mbuf *mb = obj;
  vlib_buffer_t *b = vlib_buffer_from_rte_mbuf (mb);
  ASSERT (mb->pool == old);
  ASSERT (b->n_add_refs > 0);
  mb->pool = new;
  clib_atomic_fetch_sub (&b->n_add_refs, 1);
}

int
CLIB_MULTIARCH_FN (dpdk_ops_vpp_enqueue_no_cache) (struct rte_mempool * cmp,
						   void *const *obj_table,
						   unsigned n)
{
  dpdk_mempool_private_t *privp = rte_mempool_get_priv (cmp);
  struct rte_mempool *mp;
  mp = dpdk_no_cache_mempool_by_buffer_pool_index[privp->buffer_pool_index];

  while (n >= 4)
    {
      dpdk_ops_vpp_enqueue_no_cache_one (cmp, mp, obj_table[0]);
      dpdk_ops_vpp_enqueue_no_cache_one (cmp, mp, obj_table[1]);
      dpdk_ops_vpp_enqueue_no_cache_one (cmp, mp, obj_table[2]);
      dpdk_ops_vpp_enqueue_no_cache_one (cmp, mp, obj_table[3]);
      obj_table += 4;
      n -= 4;
    }

  while (n)
    {
      dpdk_ops_vpp_enqueue_no_cache_one (cmp, mp, obj_table[0]);
      obj_table += 1;
      n -= 1;
    }

  return 0;
}

int
CLIB_MULTIARCH_FN (dpdk_ops_vpp_dequeue) (struct rte_mempool * mp,
					  void **obj_table, unsigned n)
{
  const int batch_size = 32;
  vlib_main_t *vm = vlib_get_main ();
  u32 bufs[batch_size], total = 0, n_alloc = 0;
  dpdk_mempool_private_t *privp = rte_mempool_get_priv (mp);
  u8 buffer_pool_index = privp->buffer_pool_index;
  void **obj = obj_table;

  while (n >= batch_size)
    {
      n_alloc = vlib_buffer_alloc_from_pool (vm, bufs, batch_size,
					     buffer_pool_index);
      if (n_alloc != batch_size)
	goto alloc_fail;

      vlib_get_buffers_with_offset (vm, bufs, obj, batch_size,
				    -(i32) sizeof (struct rte_mbuf));
      total += batch_size;
      obj += batch_size;
      n -= batch_size;
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
  clib_warning ("");
  return 0;
}

static unsigned
dpdk_ops_vpp_get_count_no_cache (const struct rte_mempool *mp)
{
  dpdk_mempool_private_t *privp;
  struct rte_mempool *cmp;
  privp = rte_mempool_get_priv ((struct rte_mempool *) mp);
  cmp = dpdk_no_cache_mempool_by_buffer_pool_index[privp->buffer_pool_index];
  return dpdk_ops_vpp_get_count (cmp);
}

#define CLIB_GET_MARCH_FN_PTR(ptr, fn) \
{ \
  __typeof__(fn) __clib_weak fn##_avx2; \
  __typeof__(fn) __clib_weak fn##_avx512; \
  if (fn##_avx512 && clib_cpu_supports_avx512f()) \
    ptr = fn##_avx512; \
  else if (fn##_avx2 && clib_cpu_supports_avx2()) \
    ptr = fn##_avx2; \
  else \
    ptr = fn;\
}

clib_error_t *
dpdk_buffer_pools_create (vlib_main_t * vm, unsigned num_mbufs)
{
  clib_error_t *err;
  vlib_buffer_pool_t *bp;

  struct rte_mempool_ops ops = { };

  strncpy (ops.name, "vpp", 4);
  ops.alloc = dpdk_ops_vpp_alloc;
  ops.free = dpdk_ops_vpp_free;
  ops.get_count = dpdk_ops_vpp_get_count;
  CLIB_GET_MARCH_FN_PTR (ops.enqueue, dpdk_ops_vpp_enqueue);
  CLIB_GET_MARCH_FN_PTR (ops.dequeue, dpdk_ops_vpp_dequeue);
  rte_mempool_register_ops (&ops);

  strncpy (ops.name, "vpp-no-cache", 13);
  ops.get_count = dpdk_ops_vpp_get_count_no_cache;
  CLIB_GET_MARCH_FN_PTR (ops.enqueue, dpdk_ops_vpp_enqueue_no_cache);
  ops.dequeue = dpdk_ops_vpp_dequeue_no_cache;
  rte_mempool_register_ops (&ops);

  vec_foreach (bp, vm->buffer_main->buffer_pools)
    if (bp->start && (err = dpdk_buffer_pool_init (vm, bp)))
    return err;
  return 0;
}

/* *INDENT-OFF* */
VLIB_BUFFER_REGISTER_CALLBACKS (dpdk, static) = {
  .external_header_size = sizeof (struct rte_mbuf) +
    CLIB_CACHE_LINE_ROUND(sizeof (struct rte_mempool_objhdr)),
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
