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
#include <linux/vfio.h>
#include <sys/ioctl.h>

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
#include <rte_pci.h>
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
#include <vlib/pci/pci.h>
#include <vlib/linux/vfio.h>
#include <vnet/vnet.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>

STATIC_ASSERT (VLIB_BUFFER_PRE_DATA_SIZE == RTE_PKTMBUF_HEADROOM,
	       "VLIB_BUFFER_PRE_DATA_SIZE must be equal to RTE_PKTMBUF_HEADROOM");

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  struct rte_mbuf **mbuf_alloc_list;
  struct rte_mbuf ***mbuf_pending_free_list;

  /* cached last pool */
  struct rte_mempool *last_pool;
  u8 last_buffer_pool_index;
} dpdk_buffer_per_thread_data;

typedef struct
{
  int vfio_container_fd;
  dpdk_buffer_per_thread_data *ptd;
} dpdk_buffer_main_t;

dpdk_buffer_main_t dpdk_buffer_main;

static_always_inline void
dpdk_rte_pktmbuf_free (vlib_main_t * vm, u32 thread_index, vlib_buffer_t * b)
{
  vlib_buffer_t *hb = b;
  dpdk_buffer_main_t *dbm = &dpdk_buffer_main;
  dpdk_buffer_per_thread_data *d = vec_elt_at_index (dbm->ptd, thread_index);
  struct rte_mbuf *mb;
  u32 next, flags;
  mb = rte_mbuf_from_vlib_buffer (hb);

next:
  flags = b->flags;
  next = b->next_buffer;
  mb = rte_mbuf_from_vlib_buffer (b);

  if (PREDICT_FALSE (b->n_add_refs))
    {
      rte_mbuf_refcnt_update (mb, b->n_add_refs);
      b->n_add_refs = 0;
    }

  mb = rte_pktmbuf_prefree_seg (mb);
  if (mb)
    {
      if (mb->pool != d->last_pool)
	{
	  d->last_pool = mb->pool;
	  dpdk_mempool_private_t *privp = rte_mempool_get_priv (d->last_pool);
	  d->last_buffer_pool_index = privp->buffer_pool_index;
	  vec_validate_aligned (d->mbuf_pending_free_list,
				d->last_buffer_pool_index,
				CLIB_CACHE_LINE_BYTES);
	}
      vec_add1 (d->mbuf_pending_free_list[d->last_buffer_pool_index], mb);
    }

  if (flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      b = vlib_get_buffer (vm, next);
      goto next;
    }
}

#ifndef CLIB_MARCH_VARIANT
static void
del_free_list (vlib_main_t * vm, vlib_buffer_free_list_t * f)
{
  u32 i;
  vlib_buffer_t *b;
  u32 thread_index = vlib_get_thread_index ();

  for (i = 0; i < vec_len (f->buffers); i++)
    {
      b = vlib_get_buffer (vm, f->buffers[i]);
      dpdk_rte_pktmbuf_free (vm, thread_index, b);
    }

  vec_free (f->name);
  vec_free (f->buffers);
  /* Poison it. */
  memset (f, 0xab, sizeof (f[0]));
}

/* Add buffer free list. */
static void
dpdk_buffer_delete_free_list (vlib_main_t * vm,
			      vlib_buffer_free_list_index_t free_list_index)
{
  vlib_buffer_free_list_t *f;
  int i;

  ASSERT (vlib_get_thread_index () == 0);

  f = vlib_buffer_get_free_list (vm, free_list_index);

  del_free_list (vm, f);

  pool_put (vm->buffer_free_list_pool, f);

  for (i = 1; i < vec_len (vlib_mains); i++)
    {
      vlib_main_t *wvm = vlib_mains[i];
      f = vlib_buffer_get_free_list (vlib_mains[i], free_list_index);
      del_free_list (wvm, f);
      pool_put (wvm->buffer_free_list_pool, f);
    }
}
#endif

/* Make sure free list has at least given number of free buffers. */
uword
CLIB_MULTIARCH_FN (dpdk_buffer_fill_free_list) (vlib_main_t * vm,
						vlib_buffer_free_list_t * fl,
						uword min_free_buffers)
{
  dpdk_main_t *dm = &dpdk_main;
  dpdk_buffer_main_t *dbm = &dpdk_buffer_main;
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
  n_alloc = min_free_buffers - vec_len (fl->buffers);
  if (n_alloc <= 0)
    return min_free_buffers;

  /* Always allocate round number of buffers. */
  n_alloc = round_pow2 (n_alloc, CLIB_CACHE_LINE_BYTES / sizeof (u32));

  /* Always allocate new buffers in reasonably large sized chunks. */
  n_alloc = clib_max (n_alloc, fl->min_n_buffers_each_alloc);

  vec_validate_aligned (d->mbuf_alloc_list, n_alloc - 1,
			CLIB_CACHE_LINE_BYTES);

  if (rte_mempool_get_bulk (rmp, (void *) d->mbuf_alloc_list, n_alloc) < 0)
    return 0;

  memset (&bt, 0, sizeof (vlib_buffer_t));
  vlib_buffer_init_for_free_list (&bt, fl);
  bt.buffer_pool_index = privp->buffer_pool_index;

  _vec_len (d->mbuf_alloc_list) = n_alloc;

  first = vec_len (fl->buffers);
  vec_resize_aligned (fl->buffers, n_alloc, CLIB_CACHE_LINE_BYTES);

  n_left = n_alloc;
  mb = d->mbuf_alloc_list;
  bi = fl->buffers + first;

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

  if (fl->buffer_init_function)
    fl->buffer_init_function (vm, fl, fl->buffers + first, n_alloc);

  fl->n_alloc += n_alloc;

  return n_alloc;
}

static_always_inline void
dpdk_prefetch_buffer_by_index (vlib_main_t * vm, u32 bi)
{
  vlib_buffer_t *b;
  struct rte_mbuf *mb;
  b = vlib_get_buffer (vm, bi);
  mb = rte_mbuf_from_vlib_buffer (b);
  CLIB_PREFETCH (mb, 2 * CLIB_CACHE_LINE_BYTES, STORE);
  CLIB_PREFETCH (b, CLIB_CACHE_LINE_BYTES, LOAD);
}

static_always_inline void
recycle_or_free (vlib_main_t * vm, vlib_buffer_main_t * bm, u32 bi,
		 vlib_buffer_t * b)
{
  vlib_buffer_free_list_t *fl;
  u32 thread_index = vlib_get_thread_index ();
  vlib_buffer_free_list_index_t fi;
  fl = vlib_buffer_get_buffer_free_list (vm, b, &fi);

  /* The only current use of this callback: multicast recycle */
  if (PREDICT_FALSE (fl->buffers_added_to_freelist_function != 0))
    {
      int j;

      vlib_buffer_add_to_free_list (vm, fl, bi,
				    (b->flags & VLIB_BUFFER_RECYCLE) == 0);

      for (j = 0; j < vec_len (vm->buffer_announce_list); j++)
	{
	  if (fl == vm->buffer_announce_list[j])
	    goto already_announced;
	}
      vec_add1 (vm->buffer_announce_list, fl);
    already_announced:
      ;
    }
  else
    {
      if (PREDICT_TRUE ((b->flags & VLIB_BUFFER_RECYCLE) == 0))
	dpdk_rte_pktmbuf_free (vm, thread_index, b);
    }
}

static_always_inline void
vlib_buffer_free_inline (vlib_main_t * vm,
			 u32 * buffers, u32 n_buffers, u32 follow_buffer_next)
{
  vlib_buffer_main_t *bm = &buffer_main;
  dpdk_buffer_main_t *dbm = &dpdk_buffer_main;
  vlib_buffer_t *b0, *b1, *b2, *b3;
  u32 thread_index = vlib_get_thread_index ();
  dpdk_buffer_per_thread_data *d = vec_elt_at_index (dbm->ptd, thread_index);
  int i = 0;
  u32 (*cb) (vlib_main_t * vm, u32 * buffers, u32 n_buffers,
	     u32 follow_buffer_next);

  cb = bm->buffer_free_callback;

  if (PREDICT_FALSE (cb != 0))
    n_buffers = (*cb) (vm, buffers, n_buffers, follow_buffer_next);

  if (!n_buffers)
    return;

  while (i + 7 < n_buffers)
    {
      dpdk_prefetch_buffer_by_index (vm, buffers[i + 4]);
      dpdk_prefetch_buffer_by_index (vm, buffers[i + 5]);
      dpdk_prefetch_buffer_by_index (vm, buffers[i + 6]);
      dpdk_prefetch_buffer_by_index (vm, buffers[i + 7]);

      b0 = vlib_get_buffer (vm, buffers[i]);
      b1 = vlib_get_buffer (vm, buffers[i + 1]);
      b2 = vlib_get_buffer (vm, buffers[i + 2]);
      b3 = vlib_get_buffer (vm, buffers[i + 3]);

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b1);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b2);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b3);

      recycle_or_free (vm, bm, buffers[i], b0);
      recycle_or_free (vm, bm, buffers[i + 1], b1);
      recycle_or_free (vm, bm, buffers[i + 2], b2);
      recycle_or_free (vm, bm, buffers[i + 3], b3);

      i += 4;
    }
  while (i < n_buffers)
    {
      b0 = vlib_get_buffer (vm, buffers[i]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
      recycle_or_free (vm, bm, buffers[i], b0);
      i++;
    }
  if (vec_len (vm->buffer_announce_list))
    {
      vlib_buffer_free_list_t *fl;
      for (i = 0; i < vec_len (vm->buffer_announce_list); i++)
	{
	  fl = vm->buffer_announce_list[i];
	  fl->buffers_added_to_freelist_function (vm, fl);
	}
      _vec_len (vm->buffer_announce_list) = 0;
    }

  vec_foreach_index (i, d->mbuf_pending_free_list)
  {
    int len = vec_len (d->mbuf_pending_free_list[i]);
    if (len)
      {
	rte_mempool_put_bulk (d->mbuf_pending_free_list[i][len - 1]->pool,
			      (void *) d->mbuf_pending_free_list[i], len);
	vec_reset_length (d->mbuf_pending_free_list[i]);
      }
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
static void
dpdk_packet_template_init (vlib_main_t * vm,
			   void *vt,
			   void *packet_data,
			   uword n_packet_data_bytes,
			   uword min_n_buffers_each_alloc, u8 * name)
{
  vlib_packet_template_t *t = (vlib_packet_template_t *) vt;

  vlib_worker_thread_barrier_sync (vm);
  memset (t, 0, sizeof (t[0]));

  vec_add (t->packet_data, packet_data, n_packet_data_bytes);

  vlib_worker_thread_barrier_release (vm);
}

static clib_error_t *
scan_vfio_fd (void *arg, u8 * path_name, u8 * file_name)
{
  dpdk_buffer_main_t *dbm = &dpdk_buffer_main;
  linux_vfio_main_t *lvm = &vfio_main;
  const char fn[] = "/dev/vfio/vfio";
  char buff[sizeof (fn)] = { 0 };
  int fd;
  u8 *path = format (0, "%v%c", path_name, 0);

  if (readlink ((char *) path, buff, sizeof (fn)) + 1 != sizeof (fn))
    goto done;

  if (strncmp (fn, buff, sizeof (fn)))
    goto done;

  fd = atoi ((char *) file_name);
  if (fd != lvm->container_fd)
    dbm->vfio_container_fd = fd;

done:
  vec_free (path);
  return 0;
}

clib_error_t *
dpdk_pool_create (vlib_main_t * vm, u8 * pool_name, u32 elt_size,
		  u32 num_elts, u32 pool_priv_size, u16 cache_size, u8 numa,
		  struct rte_mempool ** _mp,
		  vlib_physmem_region_index_t * pri)
{
  dpdk_buffer_main_t *dbm = &dpdk_buffer_main;
  struct rte_mempool *mp;
  vlib_physmem_region_t *pr;
  dpdk_mempool_private_t priv;
  clib_error_t *error = 0;
  u32 size, obj_size;
  i32 ret;

  obj_size = rte_mempool_calc_obj_size (elt_size, 0, 0);
  size = rte_mempool_xmem_size (num_elts, obj_size, 21, 0);

  error =
    vlib_physmem_region_alloc (vm, (char *) pool_name, size, numa,
			       VLIB_PHYSMEM_F_HUGETLB | VLIB_PHYSMEM_F_SHARED,
			       pri);
  if (error)
    return error;

  pr = vlib_physmem_get_region (vm, pri[0]);

  mp =
    rte_mempool_create_empty ((char *) pool_name, num_elts, elt_size,
			      512, pool_priv_size, numa, 0);
  if (!mp)
    return clib_error_return (0, "failed to create %s", pool_name);

  rte_mempool_set_ops_byname (mp, RTE_MBUF_DEFAULT_MEMPOOL_OPS, NULL);

  /* Call the mempool priv initializer */
  priv.mbp_priv.mbuf_data_room_size = VLIB_BUFFER_PRE_DATA_SIZE +
    VLIB_BUFFER_DATA_SIZE;
  priv.mbp_priv.mbuf_priv_size = VLIB_BUFFER_HDR_SIZE;
  rte_pktmbuf_pool_init (mp, &priv);

  ret =
    rte_mempool_populate_iova_tab (mp, pr->mem, pr->page_table, pr->n_pages,
				   pr->log2_page_size, NULL, NULL);
  if (ret != (i32) mp->size)
    {
      rte_mempool_free (mp);
      return clib_error_return (0, "failed to populate %s", pool_name);
    }

  _mp[0] = mp;

  /* DPDK currently doesn't provide API to map DMA memory for empty mempool
     so we are using this hack, will be nice to have at least API to get
     VFIO container FD */
  if (dbm->vfio_container_fd == -1)
    foreach_directory_file ("/proc/self/fd", scan_vfio_fd, 0, 0);

  if (dbm->vfio_container_fd != -1)
    {
      struct vfio_iommu_type1_dma_map dm = { 0 };
      int i, rv = 0;
      dm.argsz = sizeof (struct vfio_iommu_type1_dma_map);
      dm.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;

      /* *INDENT-OFF* */
      vec_foreach_index (i, pr->page_table)
	{
	  dm.vaddr = pointer_to_uword (pr->mem) + (i << pr->log2_page_size);
	  dm.size = 1 << pr->log2_page_size;
	  dm.iova = pr->page_table[i];
	  if ((rv = ioctl (dbm->vfio_container_fd, VFIO_IOMMU_MAP_DMA, &dm)))
	    break;
	}
      /* *INDENT-ON* */
      if (rv != 0 && errno != EINVAL)
	clib_unix_warning ("ioctl(VFIO_IOMMU_MAP_DMA) pool '%s'", pool_name);
    }

  return 0;
}

clib_error_t *
dpdk_buffer_pool_create (vlib_main_t * vm, unsigned num_mbufs,
			 unsigned socket_id)
{
  dpdk_main_t *dm = &dpdk_main;
  struct rte_mempool *rmp;
  vlib_physmem_region_index_t pri;
  clib_error_t *error = 0;
  u8 *pool_name;
  u32 elt_size, i;

  vec_validate_aligned (dm->pktmbuf_pools, socket_id, CLIB_CACHE_LINE_BYTES);

  /* pool already exists, nothing to do */
  if (dm->pktmbuf_pools[socket_id])
    return 0;

  pool_name = format (0, "dpdk_mbuf_pool_socket%u%c", socket_id, 0);

  elt_size = sizeof (struct rte_mbuf) +
    VLIB_BUFFER_HDR_SIZE /* priv size */  +
    VLIB_BUFFER_PRE_DATA_SIZE + VLIB_BUFFER_DATA_SIZE;	/*data room size */

  error =
    dpdk_pool_create (vm, pool_name, elt_size, num_mbufs,
		      sizeof (dpdk_mempool_private_t), 512, socket_id,
		      &rmp, &pri);

  vec_free (pool_name);

  if (!error)
    {
      /* call the object initializers */
      rte_mempool_obj_iter (rmp, rte_pktmbuf_init, 0);

      dpdk_mempool_private_t *privp = rte_mempool_get_priv (rmp);
      privp->buffer_pool_index = vlib_buffer_pool_create (vm, pri, 0);

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

  vlib_buffer_state_heap = mheap_alloc (0, 10 << 20);

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
  .vlib_packet_template_init_cb = &dpdk_packet_template_init,
  .vlib_buffer_delete_free_list_cb = &dpdk_buffer_delete_free_list,
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
