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
#include <vnet/vnet.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>


STATIC_ASSERT (VLIB_BUFFER_PRE_DATA_SIZE == RTE_PKTMBUF_HEADROOM,
	       "VLIB_BUFFER_PRE_DATA_SIZE must be equal to RTE_PKTMBUF_HEADROOM");

static_always_inline void
dpdk_rte_pktmbuf_free (vlib_main_t * vm, vlib_buffer_t * b)
{
  vlib_buffer_t *hb = b;
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

  rte_pktmbuf_free_seg (mb);

  if (flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      b = vlib_get_buffer (vm, next);
      goto next;
    }
}

static void
del_free_list (vlib_main_t * vm, vlib_buffer_free_list_t * f)
{
  u32 i;
  vlib_buffer_t *b;

  for (i = 0; i < vec_len (f->buffers); i++)
    {
      b = vlib_get_buffer (vm, f->buffers[i]);
      dpdk_rte_pktmbuf_free (vm, b);
    }

  vec_free (f->name);
  vec_free (f->buffers);
}

/* Add buffer free list. */
static void
dpdk_buffer_delete_free_list (vlib_main_t * vm, u32 free_list_index)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_free_list_t *f;
  u32 merge_index;
  int i;

  ASSERT (vlib_get_thread_index () == 0);

  f = vlib_buffer_get_free_list (vm, free_list_index);

  merge_index = vlib_buffer_get_free_list_with_size (vm, f->n_data_bytes);
  if (merge_index != ~0 && merge_index != free_list_index)
    {
      vlib_buffer_merge_free_lists (pool_elt_at_index
				    (bm->buffer_free_list_pool, merge_index),
				    f);
    }

  del_free_list (vm, f);

  /* Poison it. */
  memset (f, 0xab, sizeof (f[0]));

  pool_put (bm->buffer_free_list_pool, f);

  for (i = 1; i < vec_len (vlib_mains); i++)
    {
      bm = vlib_mains[i]->buffer_main;
      f = vlib_buffer_get_free_list (vlib_mains[i], free_list_index);;
      memset (f, 0xab, sizeof (f[0]));
      pool_put (bm->buffer_free_list_pool, f);
    }
}

/* Make sure free list has at least given number of free buffers. */
static uword
fill_free_list (vlib_main_t * vm,
		vlib_buffer_free_list_t * fl, uword min_free_buffers)
{
  dpdk_main_t *dm = &dpdk_main;
  vlib_buffer_t *b0, *b1, *b2, *b3;
  int n, i;
  u32 bi0, bi1, bi2, bi3;
  unsigned socket_id = rte_socket_id ();
  struct rte_mempool *rmp = dm->pktmbuf_pools[socket_id];
  struct rte_mbuf *mb0, *mb1, *mb2, *mb3;

  /* Too early? */
  if (PREDICT_FALSE (rmp == 0))
    return 0;

  /* Already have enough free buffers on free list? */
  n = min_free_buffers - vec_len (fl->buffers);
  if (n <= 0)
    return min_free_buffers;

  /* Always allocate round number of buffers. */
  n = round_pow2 (n, CLIB_CACHE_LINE_BYTES / sizeof (u32));

  /* Always allocate new buffers in reasonably large sized chunks. */
  n = clib_max (n, fl->min_n_buffers_each_physmem_alloc);

  vec_validate (vm->mbuf_alloc_list, n - 1);

  if (rte_mempool_get_bulk (rmp, vm->mbuf_alloc_list, n) < 0)
    return 0;

  _vec_len (vm->mbuf_alloc_list) = n;

  i = 0;

  while (i < (n - 7))
    {
      vlib_prefetch_buffer_header (vlib_buffer_from_rte_mbuf
				   (vm->mbuf_alloc_list[i + 4]), STORE);
      vlib_prefetch_buffer_header (vlib_buffer_from_rte_mbuf
				   (vm->mbuf_alloc_list[i + 5]), STORE);
      vlib_prefetch_buffer_header (vlib_buffer_from_rte_mbuf
				   (vm->mbuf_alloc_list[i + 6]), STORE);
      vlib_prefetch_buffer_header (vlib_buffer_from_rte_mbuf
				   (vm->mbuf_alloc_list[i + 7]), STORE);

      mb0 = vm->mbuf_alloc_list[i];
      mb1 = vm->mbuf_alloc_list[i + 1];
      mb2 = vm->mbuf_alloc_list[i + 2];
      mb3 = vm->mbuf_alloc_list[i + 3];

      b0 = vlib_buffer_from_rte_mbuf (mb0);
      b1 = vlib_buffer_from_rte_mbuf (mb1);
      b2 = vlib_buffer_from_rte_mbuf (mb2);
      b3 = vlib_buffer_from_rte_mbuf (mb3);

      bi0 = vlib_get_buffer_index (vm, b0);
      bi1 = vlib_get_buffer_index (vm, b1);
      bi2 = vlib_get_buffer_index (vm, b2);
      bi3 = vlib_get_buffer_index (vm, b3);

      vec_add1_aligned (fl->buffers, bi0, CLIB_CACHE_LINE_BYTES);
      vec_add1_aligned (fl->buffers, bi1, CLIB_CACHE_LINE_BYTES);
      vec_add1_aligned (fl->buffers, bi2, CLIB_CACHE_LINE_BYTES);
      vec_add1_aligned (fl->buffers, bi3, CLIB_CACHE_LINE_BYTES);

      vlib_buffer_init_for_free_list (b0, fl);
      vlib_buffer_init_for_free_list (b1, fl);
      vlib_buffer_init_for_free_list (b2, fl);
      vlib_buffer_init_for_free_list (b3, fl);

      if (fl->buffer_init_function)
	{
	  fl->buffer_init_function (vm, fl, &bi0, 1);
	  fl->buffer_init_function (vm, fl, &bi1, 1);
	  fl->buffer_init_function (vm, fl, &bi2, 1);
	  fl->buffer_init_function (vm, fl, &bi3, 1);
	}
      i += 4;
    }

  while (i < n)
    {
      mb0 = vm->mbuf_alloc_list[i];

      b0 = vlib_buffer_from_rte_mbuf (mb0);
      bi0 = vlib_get_buffer_index (vm, b0);

      vec_add1_aligned (fl->buffers, bi0, CLIB_CACHE_LINE_BYTES);

      vlib_buffer_init_for_free_list (b0, fl);

      if (fl->buffer_init_function)
	fl->buffer_init_function (vm, fl, &bi0, 1);
      i++;
    }

  fl->n_alloc += n;

  return n;
}

static u32
alloc_from_free_list (vlib_main_t * vm,
		      vlib_buffer_free_list_t * free_list,
		      u32 * alloc_buffers, u32 n_alloc_buffers)
{
  u32 *dst, *src;
  uword len, n_filled;

  dst = alloc_buffers;

  n_filled = fill_free_list (vm, free_list, n_alloc_buffers);
  if (n_filled == 0)
    return 0;

  len = vec_len (free_list->buffers);
  ASSERT (len >= n_alloc_buffers);

  src = free_list->buffers + len - n_alloc_buffers;
  clib_memcpy (dst, src, n_alloc_buffers * sizeof (u32));

  _vec_len (free_list->buffers) -= n_alloc_buffers;

  return n_alloc_buffers;
}

/* Allocate a given number of buffers into given array.
   Returns number actually allocated which will be either zero or
   number requested. */
u32
dpdk_buffer_alloc (vlib_main_t * vm, u32 * buffers, u32 n_buffers)
{
  vlib_buffer_main_t *bm = vm->buffer_main;

  return alloc_from_free_list
    (vm,
     pool_elt_at_index (bm->buffer_free_list_pool,
			VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX),
     buffers, n_buffers);
}


u32
dpdk_buffer_alloc_from_free_list (vlib_main_t * vm,
				  u32 * buffers,
				  u32 n_buffers, u32 free_list_index)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_free_list_t *f;
  f = pool_elt_at_index (bm->buffer_free_list_pool, free_list_index);
  return alloc_from_free_list (vm, f, buffers, n_buffers);
}

static_always_inline void
vlib_buffer_free_inline (vlib_main_t * vm,
			 u32 * buffers, u32 n_buffers, u32 follow_buffer_next)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_free_list_t *fl;
  u32 fi;
  int i;
  u32 (*cb) (vlib_main_t * vm, u32 * buffers, u32 n_buffers,
	     u32 follow_buffer_next);

  cb = bm->buffer_free_callback;

  if (PREDICT_FALSE (cb != 0))
    n_buffers = (*cb) (vm, buffers, n_buffers, follow_buffer_next);

  if (!n_buffers)
    return;

  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_t *b;

      b = vlib_get_buffer (vm, buffers[i]);

      fl = vlib_buffer_get_buffer_free_list (vm, b, &fi);

      /* The only current use of this callback: multicast recycle */
      if (PREDICT_FALSE (fl->buffers_added_to_freelist_function != 0))
	{
	  int j;

	  vlib_buffer_add_to_free_list
	    (vm, fl, buffers[i], (b->flags & VLIB_BUFFER_RECYCLE) == 0);

	  for (j = 0; j < vec_len (bm->announce_list); j++)
	    {
	      if (fl == bm->announce_list[j])
		goto already_announced;
	    }
	  vec_add1 (bm->announce_list, fl);
	already_announced:
	  ;
	}
      else
	{
	  if (PREDICT_TRUE ((b->flags & VLIB_BUFFER_RECYCLE) == 0))
	    dpdk_rte_pktmbuf_free (vm, b);
	}
    }
  if (vec_len (bm->announce_list))
    {
      vlib_buffer_free_list_t *fl;
      for (i = 0; i < vec_len (bm->announce_list); i++)
	{
	  fl = bm->announce_list[i];
	  fl->buffers_added_to_freelist_function (vm, fl);
	}
      _vec_len (bm->announce_list) = 0;
    }
}

static void
dpdk_buffer_free (vlib_main_t * vm, u32 * buffers, u32 n_buffers)
{
  vlib_buffer_free_inline (vm, buffers, n_buffers,	/* follow_buffer_next */
			   1);
}

static void
dpdk_buffer_free_no_next (vlib_main_t * vm, u32 * buffers, u32 n_buffers)
{
  vlib_buffer_free_inline (vm, buffers, n_buffers,	/* follow_buffer_next */
			   0);
}

static void
dpdk_packet_template_init (vlib_main_t * vm,
			   void *vt,
			   void *packet_data,
			   uword n_packet_data_bytes,
			   uword min_n_buffers_each_physmem_alloc, u8 * name)
{
  vlib_packet_template_t *t = (vlib_packet_template_t *) vt;

  vlib_worker_thread_barrier_sync (vm);
  memset (t, 0, sizeof (t[0]));

  vec_add (t->packet_data, packet_data, n_packet_data_bytes);

  vlib_worker_thread_barrier_release (vm);
}

clib_error_t *
dpdk_buffer_pool_create (vlib_main_t * vm, unsigned num_mbufs,
			 unsigned socket_id)
{
  dpdk_main_t *dm = &dpdk_main;
  struct rte_mempool *rmp;
  int i;

  vec_validate_aligned (dm->pktmbuf_pools, socket_id, CLIB_CACHE_LINE_BYTES);

  /* pool already exists, nothing to do */
  if (dm->pktmbuf_pools[socket_id])
    return 0;

  u8 *pool_name = format (0, "mbuf_pool_socket%u%c", socket_id, 0);

  rmp = rte_pktmbuf_pool_create ((char *) pool_name,	/* pool name */
				 num_mbufs,	/* number of mbufs */
				 512,	/* cache size */
				 VLIB_BUFFER_HDR_SIZE,	/* priv size */
				 VLIB_BUFFER_PRE_DATA_SIZE + VLIB_BUFFER_DATA_SIZE,	/* dataroom size */
				 socket_id);	/* cpu socket */

  if (rmp)
    {
      {
	struct rte_mempool_memhdr *memhdr;

	STAILQ_FOREACH (memhdr, &rmp->mem_list, next)
	  vlib_buffer_add_mem_range (vm, (uword) memhdr->addr, memhdr->len);
      }
      if (rmp)
	{
	  dm->pktmbuf_pools[socket_id] = rmp;
	  vec_free (pool_name);
	  return 0;
	}
    }

  vec_free (pool_name);

  /* no usable pool for this socket, try to use pool from another one */
  for (i = 0; i < vec_len (dm->pktmbuf_pools); i++)
    {
      if (dm->pktmbuf_pools[i])
	{
	  clib_warning
	    ("WARNING: Failed to allocate mempool for CPU socket %u. "
	     "Threads running on socket %u will use socket %u mempool.",
	     socket_id, socket_id, i);
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

void
dpdk_buffer_validate_trajectory (struct rte_mempool *mp, void *opaque, void *obj,
				  unsigned obj_idx)
{
  vlib_buffer_t *b;
  b = vlib_buffer_from_rte_mbuf ((struct rte_mbuf *)obj);
  if (b->pre_data[0] != 0)
    obj_idx++;
}

int
dpdk_buffer_validate_trajectory_all (void)
{
  dpdk_main_t *dm = &dpdk_main;
  int i, invalid = 0;

  for (i = 0; i < vec_len (dm->pktmbuf_pools); i++)
    {
      rte_mempool_obj_iter (dm->pktmbuf_pools[i], dpdk_buffer_validate_trajectory, &invalid);
    }
  return invalid;
}

/* *INDENT-OFF* */
VLIB_BUFFER_REGISTER_CALLBACKS (dpdk, static) = {
  .vlib_buffer_alloc_cb = &dpdk_buffer_alloc,
  .vlib_buffer_alloc_from_free_list_cb = &dpdk_buffer_alloc_from_free_list,
  .vlib_buffer_free_cb = &dpdk_buffer_free,
  .vlib_buffer_free_no_next_cb = &dpdk_buffer_free_no_next,
  .vlib_packet_template_init_cb = &dpdk_packet_template_init,
  .vlib_buffer_delete_free_list_cb = &dpdk_buffer_delete_free_list,
};
/* *INDENT-ON* */

/** @endcond */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
