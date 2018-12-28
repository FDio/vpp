/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
/*
 * buffer.c: allocate/free network buffers.
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file
 *
 * Allocate/free network buffers.
 */

#include <unistd.h>

#include <rte_config.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_vfio.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_version.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/vnet.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>

STATIC_ASSERT (VLIB_BUFFER_PRE_DATA_SIZE == RTE_PKTMBUF_HEADROOM,
	       "VLIB_BUFFER_PRE_DATA_SIZE must be equal to RTE_PKTMBUF_HEADROOM");

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  struct rte_mbuf **mbuf_alloc_list;
} dpdk_buffer_per_thread_data;

typedef struct
{
  int vfio_container_fd;
  dpdk_buffer_per_thread_data *ptd;
} dpdk_buffer_main_t;

dpdk_buffer_main_t dpdk_buffer_main;

static_always_inline void
dpdk_rte_pktmbuf_free (vlib_main_t * vm, u32 thread_index, vlib_buffer_t * b,
		       int maybe_next)
{
  struct rte_mbuf *mb;
  u32 next, flags;

next:
  flags = b->flags;
  next = b->next_buffer;
  mb = rte_mbuf_from_vlib_buffer (b);

  if (PREDICT_FALSE (b->n_add_refs))
    {
      rte_mbuf_refcnt_update (mb, b->n_add_refs);
      b->n_add_refs = 0;
    }

  if ((mb = rte_pktmbuf_prefree_seg (mb)))
    rte_mempool_put (mb->pool, mb);

  if (maybe_next && (flags & VLIB_BUFFER_NEXT_PRESENT))
    {
      b = vlib_get_buffer (vm, next);
      goto next;
    }
}

/* Make sure free list has at least given number of free buffers. */
uword
CLIB_MULTIARCH_FN (dpdk_buffer_fill_free_list) (vlib_main_t * vm,
						u8 buffer_pool_index,
						uword min_free_buffers)
{
  dpdk_main_t *dm = &dpdk_main;
  dpdk_buffer_main_t *dbm = &dpdk_buffer_main;
  vlib_buffer_pool_t *bp = vlib_buffer_pool_get (buffer_pool_index);
  vlib_buffer_pool_thread_t *bpt =
    vec_elt_at_index (bp->threads, vm->thread_index);
  struct rte_mbuf **mb;
  uword n_left, first;
  word n_alloc;
  unsigned socket_id = rte_socket_id ();
  u32 thread_index = vlib_get_thread_index ();
  dpdk_buffer_per_thread_data *d = vec_elt_at_index (dbm->ptd, thread_index);
  struct rte_mempool *rmp = dm->pktmbuf_pools[socket_id];
  dpdk_mempool_private_t *privp = rte_mempool_get_priv (rmp);
  vlib_buffer_t bt;
  u32 *bi;

  /* Too early? */
  if (PREDICT_FALSE (rmp == 0))
    return 0;

  /* Already have enough free buffers on free list? */
  n_alloc = min_free_buffers - vec_len (bpt->buffers);
  if (n_alloc <= 0)
    return min_free_buffers;

  /* Always allocate round number of buffers. */
  n_alloc = round_pow2 (n_alloc, CLIB_CACHE_LINE_BYTES / sizeof (u32));

  /* Always allocate new buffers in reasonably large sized chunks. */
  n_alloc = clib_max (n_alloc, VLIB_FRAME_SIZE);

  vec_validate_aligned (d->mbuf_alloc_list, n_alloc - 1,
			CLIB_CACHE_LINE_BYTES);

  if (rte_mempool_get_bulk (rmp, (void *) d->mbuf_alloc_list, n_alloc) < 0)
    return 0;

  clib_memset (&bt, 0, sizeof (vlib_buffer_t));
  bt.buffer_pool_index = privp->buffer_pool_index;

  _vec_len (d->mbuf_alloc_list) = n_alloc;

  first = vec_len (bpt->buffers);
  vec_resize_aligned (bpt->buffers, n_alloc, CLIB_CACHE_LINE_BYTES);

  n_left = n_alloc;
  mb = d->mbuf_alloc_list;
  bi = bpt->buffers + first;

  ASSERT (n_left % 8 == 0);

  while (n_left >= 8)
    {
      if (PREDICT_FALSE (n_left < 24))
	goto no_prefetch;

      vlib_prefetch_buffer_header (vlib_buffer_from_rte_mbuf (mb[16]), STORE);
      vlib_prefetch_buffer_header (vlib_buffer_from_rte_mbuf (mb[17]), STORE);
      vlib_prefetch_buffer_header (vlib_buffer_from_rte_mbuf (mb[18]), STORE);
      vlib_prefetch_buffer_header (vlib_buffer_from_rte_mbuf (mb[19]), STORE);
      vlib_prefetch_buffer_header (vlib_buffer_from_rte_mbuf (mb[20]), STORE);
      vlib_prefetch_buffer_header (vlib_buffer_from_rte_mbuf (mb[21]), STORE);
      vlib_prefetch_buffer_header (vlib_buffer_from_rte_mbuf (mb[22]), STORE);
      vlib_prefetch_buffer_header (vlib_buffer_from_rte_mbuf (mb[23]), STORE);

    no_prefetch:
      vlib_get_buffer_indices_with_offset (vm, (void **) mb, bi, 8,
					   sizeof (struct rte_mbuf));
      clib_memcpy64_x4 (vlib_buffer_from_rte_mbuf (mb[0]),
			vlib_buffer_from_rte_mbuf (mb[1]),
			vlib_buffer_from_rte_mbuf (mb[2]),
			vlib_buffer_from_rte_mbuf (mb[3]), &bt);
      clib_memcpy64_x4 (vlib_buffer_from_rte_mbuf (mb[4]),
			vlib_buffer_from_rte_mbuf (mb[5]),
			vlib_buffer_from_rte_mbuf (mb[6]),
			vlib_buffer_from_rte_mbuf (mb[7]), &bt);

      n_left -= 8;
      mb += 8;
      bi += 8;
    }

  bpt->n_alloc += n_alloc;

  return n_alloc;
}

static_always_inline void
dpdk_prefetch_buffer (vlib_buffer_t * b)
{
  struct rte_mbuf *mb;
  mb = rte_mbuf_from_vlib_buffer (b);
  CLIB_PREFETCH (mb, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
  CLIB_PREFETCH (b, CLIB_CACHE_LINE_BYTES, LOAD);
}

static_always_inline void
recycle_or_free (vlib_main_t * vm, vlib_buffer_main_t * bm, u32 bi,
		 vlib_buffer_t * b)
{
  u32 thread_index = vlib_get_thread_index ();

  dpdk_rte_pktmbuf_free (vm, thread_index, b, 1);
}

static_always_inline void
vlib_buffer_free_inline (vlib_main_t * vm,
			 u32 * buffers, u32 n_buffers, u32 follow_buffer_next)
{
  vlib_buffer_main_t *bm = &buffer_main;
  vlib_buffer_t *bufp[n_buffers], **b = bufp;
  u32 thread_index = vlib_get_thread_index ();
  int i = 0;
  u32 simple_mask = VLIB_BUFFER_NEXT_PRESENT;
  u32 n_left, *bi;
  u32 (*cb) (vlib_main_t * vm, u32 * buffers, u32 n_buffers,
	     u32 follow_buffer_next);

  cb = bm->buffer_free_callback;

  if (PREDICT_FALSE (cb != 0))
    n_buffers = (*cb) (vm, buffers, n_buffers, follow_buffer_next);

  if (!n_buffers)
    return;

  n_left = n_buffers;
  bi = buffers;
  b = bufp;
  vlib_get_buffers (vm, bi, b, n_buffers);

  while (n_left >= 4)
    {
      u32 or_flags;
      vlib_buffer_t **p;

      if (n_left < 16)
	goto no_prefetch;

      p = b + 12;
      dpdk_prefetch_buffer (p[0]);
      dpdk_prefetch_buffer (p[1]);
      dpdk_prefetch_buffer (p[2]);
      dpdk_prefetch_buffer (p[3]);
    no_prefetch:

      for (i = 0; i < 4; i++)
	VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[i]);

      or_flags = b[0]->flags | b[1]->flags | b[2]->flags | b[3]->flags;

      if (or_flags & simple_mask)
	{
	  recycle_or_free (vm, bm, bi[0], b[0]);
	  recycle_or_free (vm, bm, bi[1], b[1]);
	  recycle_or_free (vm, bm, bi[2], b[2]);
	  recycle_or_free (vm, bm, bi[3], b[3]);
	}
      else
	{
	  dpdk_rte_pktmbuf_free (vm, thread_index, b[0], 0);
	  dpdk_rte_pktmbuf_free (vm, thread_index, b[1], 0);
	  dpdk_rte_pktmbuf_free (vm, thread_index, b[2], 0);
	  dpdk_rte_pktmbuf_free (vm, thread_index, b[3], 0);
	}
      bi += 4;
      b += 4;
      n_left -= 4;
    }
  while (n_left)
    {
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);
      recycle_or_free (vm, bm, bi[0], b[0]);
      bi += 1;
      b += 1;
      n_left -= 1;
    }
}

void
CLIB_MULTIARCH_FN (dpdk_buffer_free) (vlib_main_t * vm, u32 * buffers,
				      u32 n_buffers)
{
  vlib_buffer_free_inline (vm, buffers, n_buffers,	/* follow_buffer_next */
			   1);
}

void
CLIB_MULTIARCH_FN (dpdk_buffer_free_no_next) (vlib_main_t * vm, u32 * buffers,
					      u32 n_buffers)
{
  vlib_buffer_free_inline (vm, buffers, n_buffers,	/* follow_buffer_next */
			   0);
}

#ifndef CLIB_MARCH_VARIANT
clib_error_t *
dpdk_pool_create (vlib_main_t * vm, u8 * pool_name, u32 elt_size,
		  u32 num_elts, u32 pool_priv_size, u16 cache_size, u8 numa,
		  struct rte_mempool **_mp, u32 * map_index)
{
  struct rte_mempool *mp;
  enum rte_iova_mode iova_mode;
  dpdk_mempool_private_t priv;
  vlib_physmem_map_t *pm;
  clib_error_t *error = 0;
  size_t min_chunk_size, align;
  int map_dma = 1;
  u32 size;
  i32 ret;
  uword i;

  mp = rte_mempool_create_empty ((char *) pool_name, num_elts, elt_size,
				 512, pool_priv_size, numa, 0);
  if (!mp)
    return clib_error_return (0, "failed to create %s", pool_name);

  rte_mempool_set_ops_byname (mp, RTE_MBUF_DEFAULT_MEMPOOL_OPS, NULL);

  size = rte_mempool_op_calc_mem_size_default (mp, num_elts, 21,
					       &min_chunk_size, &align);

  if ((error = vlib_physmem_shared_map_create (vm, (char *) pool_name, size,
					       0, numa, map_index)))
    {
      rte_mempool_free (mp);
      return error;
    }
  pm = vlib_physmem_get_map (vm, *map_index);

  /* Call the mempool priv initializer */
  priv.mbp_priv.mbuf_data_room_size = VLIB_BUFFER_PRE_DATA_SIZE +
    VLIB_BUFFER_DATA_SIZE;
  priv.mbp_priv.mbuf_priv_size = VLIB_BUFFER_HDR_SIZE;
  rte_pktmbuf_pool_init (mp, &priv);

  if (rte_eth_dev_count_avail () == 0)
    map_dma = 0;

  iova_mode = rte_eal_iova_mode ();
  for (i = 0; i < pm->n_pages; i++)
    {
      size_t page_sz = 1ULL << pm->log2_page_size;
      char *va = ((char *) pm->base) + i * page_sz;
      uword pa = iova_mode == RTE_IOVA_VA ?
	pointer_to_uword (va) : pm->page_table[i];
      ret = rte_mempool_populate_iova (mp, va, pa, page_sz, 0, 0);
      if (ret < 0)
	{
	  rte_mempool_free (mp);
	  return clib_error_return (0, "failed to populate %s", pool_name);
	}
      /* -1 likely means there is no PCI devices assigned to vfio
         container or noiommu mode is used  so we stop trying */
      if (map_dma && rte_vfio_dma_map (pointer_to_uword (va), pa, page_sz))
	map_dma = 0;
    }

  _mp[0] = mp;

  return 0;
}

clib_error_t *
dpdk_buffer_pool_create (vlib_main_t * vm, unsigned num_mbufs,
			 unsigned socket_id)
{
  dpdk_main_t *dm = &dpdk_main;
  struct rte_mempool *rmp;
  clib_error_t *error = 0;
  u8 *pool_name;
  u32 elt_size, i;
  u32 map_index;

  vec_validate_aligned (dm->pktmbuf_pools, socket_id, CLIB_CACHE_LINE_BYTES);

  /* pool already exists, nothing to do */
  if (dm->pktmbuf_pools[socket_id])
    return 0;

  pool_name = format (0, "dpdk_mbuf_pool_socket%u%c", socket_id, 0);

  elt_size = sizeof (struct rte_mbuf) +
    VLIB_BUFFER_HDR_SIZE /* priv size */  +
    VLIB_BUFFER_PRE_DATA_SIZE + VLIB_BUFFER_DATA_SIZE;	/*data room size */

  error = dpdk_pool_create (vm, pool_name, elt_size, num_mbufs,
			    sizeof (dpdk_mempool_private_t), 512, socket_id,
			    &rmp, &map_index);

  vec_free (pool_name);

  if (!error)
    {
      /* call the object initializers */
      rte_mempool_obj_iter (rmp, rte_pktmbuf_init, 0);

      dpdk_mempool_private_t *privp = rte_mempool_get_priv (rmp);
      privp->buffer_pool_index =
	vlib_buffer_register_physmem_map (vm, map_index);

      dm->pktmbuf_pools[socket_id] = rmp;

      return 0;
    }

  clib_error_report (error);

  /* no usable pool for this socket, try to use pool from another one */
  for (i = 0; i < vec_len (dm->pktmbuf_pools); i++)
    {
      if (dm->pktmbuf_pools[i])
	{
	  clib_warning ("WARNING: Failed to allocate mempool for CPU socket "
			"%u. Threads running on socket %u will use socket %u "
			"mempool.", socket_id, socket_id, i);
	  dm->pktmbuf_pools[socket_id] = dm->pktmbuf_pools[i];
	  return 0;
	}
    }

  return clib_error_return (0, "failed to allocate mempool on socket %u",
			    socket_id);
}

#if CLIB_DEBUG > 0

u32 *vlib_buffer_state_validation_lock;
uword *vlib_buffer_state_validation_hash;
void *vlib_buffer_state_heap;

static clib_error_t *
buffer_state_validation_init (vlib_main_t * vm)
{
  void *oldheap;

  vlib_buffer_state_heap =
    mheap_alloc_with_lock (0, 10 << 20, 0 /* locked */ );
  oldheap = clib_mem_set_heap (vlib_buffer_state_heap);

  vlib_buffer_state_validation_hash = hash_create (0, sizeof (uword));
  vec_validate_aligned (vlib_buffer_state_validation_lock, 0,
			CLIB_CACHE_LINE_BYTES);
  clib_mem_set_heap (oldheap);
  return 0;
}

VLIB_INIT_FUNCTION (buffer_state_validation_init);
#endif

#if CLI_DEBUG
struct dpdk_validate_buf_result
{
  u32 invalid;
  u32 uninitialized;
};

#define DPDK_TRAJECTORY_POISON 31

static void
dpdk_buffer_validate_trajectory (struct rte_mempool *mp, void *opaque,
				 void *obj, unsigned obj_idx)
{
  vlib_buffer_t *b;
  struct dpdk_validate_buf_result *counter = opaque;
  b = vlib_buffer_from_rte_mbuf ((struct rte_mbuf *) obj);
  if (b->pre_data[0] != 0)
    {
      if (b->pre_data[0] == DPDK_TRAJECTORY_POISON)
	counter->uninitialized++;
      else
	counter->invalid++;
    }
}

int
dpdk_buffer_validate_trajectory_all (u32 * uninitialized)
{
  dpdk_main_t *dm = &dpdk_main;
  struct dpdk_validate_buf_result counter = { 0 };
  int i;

  for (i = 0; i < vec_len (dm->pktmbuf_pools); i++)
    rte_mempool_obj_iter (dm->pktmbuf_pools[i],
			  dpdk_buffer_validate_trajectory, &counter);
  if (uninitialized)
    *uninitialized = counter.uninitialized;
  return counter.invalid;
}

static void
dpdk_buffer_poison_trajectory (struct rte_mempool *mp, void *opaque,
			       void *obj, unsigned obj_idx)
{
  vlib_buffer_t *b;
  b = vlib_buffer_from_rte_mbuf ((struct rte_mbuf *) obj);
  b->pre_data[0] = DPDK_TRAJECTORY_POISON;
}

void
dpdk_buffer_poison_trajectory_all (void)
{
  dpdk_main_t *dm = &dpdk_main;
  int i;

  for (i = 0; i < vec_len (dm->pktmbuf_pools); i++)
    rte_mempool_obj_iter (dm->pktmbuf_pools[i], dpdk_buffer_poison_trajectory,
			  0);
}
#endif

static clib_error_t *
dpdk_buffer_init (vlib_main_t * vm)
{
  dpdk_buffer_main_t *dbm = &dpdk_buffer_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  vec_validate_aligned (dbm->ptd, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  dbm->vfio_container_fd = -1;

  return 0;
}

VLIB_INIT_FUNCTION (dpdk_buffer_init);

/* *INDENT-OFF* */
VLIB_BUFFER_REGISTER_CALLBACKS (dpdk, static) = {
  .vlib_buffer_fill_free_list_cb = &dpdk_buffer_fill_free_list,
  .vlib_buffer_free_cb = &dpdk_buffer_free,
  .vlib_buffer_free_no_next_cb = &dpdk_buffer_free_no_next,
};
/* *INDENT-ON* */

#if __x86_64__
vlib_buffer_fill_free_list_cb_t __clib_weak dpdk_buffer_fill_free_list_avx512;
vlib_buffer_fill_free_list_cb_t __clib_weak dpdk_buffer_fill_free_list_avx2;
vlib_buffer_free_cb_t __clib_weak dpdk_buffer_free_avx512;
vlib_buffer_free_cb_t __clib_weak dpdk_buffer_free_avx2;
vlib_buffer_free_no_next_cb_t __clib_weak dpdk_buffer_free_no_next_avx512;
vlib_buffer_free_no_next_cb_t __clib_weak dpdk_buffer_free_no_next_avx2;

static void __clib_constructor
dpdk_input_multiarch_select (void)
{
  vlib_buffer_callbacks_t *cb = &__dpdk_buffer_callbacks;
  if (dpdk_buffer_fill_free_list_avx512 && clib_cpu_supports_avx512f ())
    {
      cb->vlib_buffer_fill_free_list_cb = dpdk_buffer_fill_free_list_avx512;
      cb->vlib_buffer_free_cb = dpdk_buffer_free_avx512;
      cb->vlib_buffer_free_no_next_cb = dpdk_buffer_free_no_next_avx512;
    }
  else if (dpdk_buffer_fill_free_list_avx2 && clib_cpu_supports_avx2 ())
    {
      cb->vlib_buffer_fill_free_list_cb = dpdk_buffer_fill_free_list_avx2;
      cb->vlib_buffer_free_cb = dpdk_buffer_free_avx2;
      cb->vlib_buffer_free_no_next_cb = dpdk_buffer_free_no_next_avx2;
    }
}
#endif
#endif

/** @endcond */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
