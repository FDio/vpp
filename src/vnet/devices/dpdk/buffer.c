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
#include <vnet/devices/dpdk/dpdk.h>
#include <vnet/devices/dpdk/dpdk_priv.h>


STATIC_ASSERT (VLIB_BUFFER_PRE_DATA_SIZE == RTE_PKTMBUF_HEADROOM,
	       "VLIB_BUFFER_PRE_DATA_SIZE must be equal to RTE_PKTMBUF_HEADROOM");

#define BUFFERS_PER_COPY (sizeof (vlib_copy_unit_t) / sizeof (u32))

/* Make sure we have at least given number of unaligned buffers. */
static void
fill_unaligned (vlib_main_t * vm,
		vlib_buffer_free_list_t * free_list,
		uword n_unaligned_buffers)
{
  word la = vec_len (free_list->aligned_buffers);
  word lu = vec_len (free_list->unaligned_buffers);

  /* Aligned come in aligned copy-sized chunks. */
  ASSERT (la % BUFFERS_PER_COPY == 0);

  ASSERT (la >= n_unaligned_buffers);

  while (lu < n_unaligned_buffers)
    {
      /* Copy 4 buffers from end of aligned vector to unaligned vector. */
      vec_add (free_list->unaligned_buffers,
	       free_list->aligned_buffers + la - BUFFERS_PER_COPY,
	       BUFFERS_PER_COPY);
      la -= BUFFERS_PER_COPY;
      lu += BUFFERS_PER_COPY;
    }
  _vec_len (free_list->aligned_buffers) = la;
}

/* After free aligned buffers may not contain even sized chunks. */
static void
trim_aligned (vlib_buffer_free_list_t * f)
{
  uword l, n_trim;

  /* Add unaligned to aligned before trim. */
  l = vec_len (f->unaligned_buffers);
  if (l > 0)
    {
      vec_add_aligned (f->aligned_buffers, f->unaligned_buffers, l,
		       /* align */ sizeof (vlib_copy_unit_t));

      _vec_len (f->unaligned_buffers) = 0;
    }

  /* Remove unaligned buffers from end of aligned vector and save for next trim. */
  l = vec_len (f->aligned_buffers);
  n_trim = l % BUFFERS_PER_COPY;
  if (n_trim)
    {
      /* Trim aligned -> unaligned. */
      vec_add (f->unaligned_buffers, f->aligned_buffers + l - n_trim, n_trim);

      /* Remove from aligned. */
      _vec_len (f->aligned_buffers) = l - n_trim;
    }
}

static void
merge_free_lists (vlib_buffer_free_list_t * dst,
		  vlib_buffer_free_list_t * src)
{
  uword l;
  u32 *d;

  trim_aligned (src);
  trim_aligned (dst);

  l = vec_len (src->aligned_buffers);
  if (l > 0)
    {
      vec_add2_aligned (dst->aligned_buffers, d, l,
			/* align */ sizeof (vlib_copy_unit_t));
      clib_memcpy (d, src->aligned_buffers, l * sizeof (d[0]));
      vec_free (src->aligned_buffers);
    }

  l = vec_len (src->unaligned_buffers);
  if (l > 0)
    {
      vec_add (dst->unaligned_buffers, src->unaligned_buffers, l);
      vec_free (src->unaligned_buffers);
    }
}

always_inline u32
dpdk_buffer_get_free_list_with_size (vlib_main_t * vm, u32 size)
{
  vlib_buffer_main_t *bm = vm->buffer_main;

  size = vlib_buffer_round_size (size);
  uword *p = hash_get (bm->free_list_by_size, size);
  return p ? p[0] : ~0;
}

static void
del_free_list (vlib_main_t * vm, vlib_buffer_free_list_t * f)
{
  u32 i;
  struct rte_mbuf *mb;
  vlib_buffer_t *b;

  for (i = 0; i < vec_len (f->unaligned_buffers); i++)
    {
      b = vlib_get_buffer (vm, f->unaligned_buffers[i]);
      mb = rte_mbuf_from_vlib_buffer (b);
      ASSERT (rte_mbuf_refcnt_read (mb) == 1);
      rte_pktmbuf_free (mb);
    }
  for (i = 0; i < vec_len (f->aligned_buffers); i++)
    {
      b = vlib_get_buffer (vm, f->aligned_buffers[i]);
      mb = rte_mbuf_from_vlib_buffer (b);
      ASSERT (rte_mbuf_refcnt_read (mb) == 1);
      rte_pktmbuf_free (mb);
    }
  vec_free (f->name);
  vec_free (f->unaligned_buffers);
  vec_free (f->aligned_buffers);
}

/* Add buffer free list. */
static void
dpdk_buffer_delete_free_list (vlib_main_t * vm, u32 free_list_index)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_free_list_t *f;
  u32 merge_index;
  int i;

  ASSERT (os_get_cpu_number () == 0);

  f = vlib_buffer_get_free_list (vm, free_list_index);

  merge_index = dpdk_buffer_get_free_list_with_size (vm, f->n_data_bytes);
  if (merge_index != ~0 && merge_index != free_list_index)
    {
      merge_free_lists (pool_elt_at_index (bm->buffer_free_list_pool,
					   merge_index), f);
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
  vlib_buffer_t *b;
  int n, i;
  u32 bi;
  u32 n_remaining = 0, n_alloc = 0;
  unsigned socket_id = rte_socket_id ();
  struct rte_mempool *rmp = dm->pktmbuf_pools[socket_id];
  struct rte_mbuf *mb;

  /* Too early? */
  if (PREDICT_FALSE (rmp == 0))
    return 0;

  trim_aligned (fl);

  /* Already have enough free buffers on free list? */
  n = min_free_buffers - vec_len (fl->aligned_buffers);
  if (n <= 0)
    return min_free_buffers;

  /* Always allocate round number of buffers. */
  n = round_pow2 (n, BUFFERS_PER_COPY);

  /* Always allocate new buffers in reasonably large sized chunks. */
  n = clib_max (n, fl->min_n_buffers_each_physmem_alloc);

  vec_validate (vm->mbuf_alloc_list, n - 1);

  if (rte_mempool_get_bulk (rmp, vm->mbuf_alloc_list, n) < 0)
    return 0;

  _vec_len (vm->mbuf_alloc_list) = n;

  for (i = 0; i < n; i++)
    {
      mb = vm->mbuf_alloc_list[i];

      ASSERT (rte_mbuf_refcnt_read (mb) == 0);
      rte_mbuf_refcnt_set (mb, 1);

      b = vlib_buffer_from_rte_mbuf (mb);
      bi = vlib_get_buffer_index (vm, b);

      vec_add1_aligned (fl->aligned_buffers, bi, sizeof (vlib_copy_unit_t));
      n_alloc++;
      n_remaining--;

      vlib_buffer_init_for_free_list (b, fl);

      if (fl->buffer_init_function)
	fl->buffer_init_function (vm, fl, &bi, 1);
    }

  fl->n_alloc += n;

  return n;
}

always_inline uword
copy_alignment (u32 * x)
{
  return (pointer_to_uword (x) / sizeof (x[0])) % BUFFERS_PER_COPY;
}

static u32
alloc_from_free_list (vlib_main_t * vm,
		      vlib_buffer_free_list_t * free_list,
		      u32 * alloc_buffers, u32 n_alloc_buffers)
{
  u32 *dst, *u_src;
  uword u_len, n_left;
  uword n_unaligned_start, n_unaligned_end, n_filled;

  n_left = n_alloc_buffers;
  dst = alloc_buffers;
  n_unaligned_start = ((BUFFERS_PER_COPY - copy_alignment (dst))
		       & (BUFFERS_PER_COPY - 1));

  n_filled = fill_free_list (vm, free_list, n_alloc_buffers);
  if (n_filled == 0)
    return 0;

  n_left = n_filled < n_left ? n_filled : n_left;
  n_alloc_buffers = n_left;

  if (n_unaligned_start >= n_left)
    {
      n_unaligned_start = n_left;
      n_unaligned_end = 0;
    }
  else
    n_unaligned_end = copy_alignment (dst + n_alloc_buffers);

  fill_unaligned (vm, free_list, n_unaligned_start + n_unaligned_end);

  u_len = vec_len (free_list->unaligned_buffers);
  u_src = free_list->unaligned_buffers + u_len - 1;

  if (n_unaligned_start)
    {
      uword n_copy = n_unaligned_start;
      if (n_copy > n_left)
	n_copy = n_left;
      n_left -= n_copy;

      while (n_copy > 0)
	{
	  *dst++ = *u_src--;
	  n_copy--;
	  u_len--;
	}

      /* Now dst should be aligned. */
      if (n_left > 0)
	ASSERT (pointer_to_uword (dst) % sizeof (vlib_copy_unit_t) == 0);
    }

  /* Aligned copy. */
  {
    vlib_copy_unit_t *d, *s;
    uword n_copy;

    if (vec_len (free_list->aligned_buffers) <
	((n_left / BUFFERS_PER_COPY) * BUFFERS_PER_COPY))
      abort ();

    n_copy = n_left / BUFFERS_PER_COPY;
    n_left = n_left % BUFFERS_PER_COPY;

    /* Remove buffers from aligned free list. */
    _vec_len (free_list->aligned_buffers) -= n_copy * BUFFERS_PER_COPY;

    s = (vlib_copy_unit_t *) vec_end (free_list->aligned_buffers);
    d = (vlib_copy_unit_t *) dst;

    /* Fast path loop. */
    while (n_copy >= 4)
      {
	d[0] = s[0];
	d[1] = s[1];
	d[2] = s[2];
	d[3] = s[3];
	n_copy -= 4;
	s += 4;
	d += 4;
      }

    while (n_copy >= 1)
      {
	d[0] = s[0];
	n_copy -= 1;
	s += 1;
	d += 1;
      }

    dst = (void *) d;
  }

  /* Unaligned copy. */
  ASSERT (n_unaligned_end == n_left);
  while (n_left > 0)
    {
      *dst++ = *u_src--;
      n_left--;
      u_len--;
    }

  if (!free_list->unaligned_buffers)
    ASSERT (u_len == 0);
  else
    _vec_len (free_list->unaligned_buffers) = u_len;

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

always_inline void
add_buffer_to_free_list (vlib_main_t * vm,
			 vlib_buffer_free_list_t * f,
			 u32 buffer_index, u8 do_init)
{
  vlib_buffer_t *b;
  b = vlib_get_buffer (vm, buffer_index);
  if (PREDICT_TRUE (do_init))
    vlib_buffer_init_for_free_list (b, f);
  vec_add1_aligned (f->aligned_buffers, buffer_index,
		    sizeof (vlib_copy_unit_t));
}

always_inline vlib_buffer_free_list_t *
buffer_get_free_list (vlib_main_t * vm, vlib_buffer_t * b, u32 * index)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  u32 i;

  *index = i = b->free_list_index;
  return pool_elt_at_index (bm->buffer_free_list_pool, i);
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
      struct rte_mbuf *mb;

      b = vlib_get_buffer (vm, buffers[i]);

      fl = buffer_get_free_list (vm, b, &fi);

      /* The only current use of this callback: multicast recycle */
      if (PREDICT_FALSE (fl->buffers_added_to_freelist_function != 0))
	{
	  int j;

	  add_buffer_to_free_list
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
	    {
	      mb = rte_mbuf_from_vlib_buffer (b);
	      ASSERT (rte_mbuf_refcnt_read (mb) == 1);
	      rte_pktmbuf_free (mb);
	    }
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
vlib_buffer_pool_create (vlib_main_t * vm, unsigned num_mbufs,
			 unsigned socket_id)
{
  dpdk_main_t *dm = &dpdk_main;
  vlib_physmem_main_t *vpm = &vm->physmem_main;
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
	uword this_pool_end;
	uword this_pool_start;
	uword this_pool_size;
	uword save_vpm_start, save_vpm_end, save_vpm_size;
	struct rte_mempool_memhdr *memhdr;

	this_pool_start = ~0ULL;
	this_pool_end = 0LL;

	STAILQ_FOREACH (memhdr, &rmp->mem_list, next)
	{
	  if (((uword) (memhdr->addr + memhdr->len)) > this_pool_end)
	    this_pool_end = (uword) (memhdr->addr + memhdr->len);
	  if (((uword) memhdr->addr) < this_pool_start)
	    this_pool_start = (uword) (memhdr->addr);
	}
	ASSERT (this_pool_start < ~0ULL && this_pool_end > 0);
	this_pool_size = this_pool_end - this_pool_start;

	if (CLIB_DEBUG > 1)
	  {
	    clib_warning ("%s: pool start %llx pool end %llx pool size %lld",
			  pool_name, this_pool_start, this_pool_end,
			  this_pool_size);
	    clib_warning
	      ("before: virtual.start %llx virtual.end %llx virtual.size %lld",
	       vpm->virtual.start, vpm->virtual.end, vpm->virtual.size);
	  }

	save_vpm_start = vpm->virtual.start;
	save_vpm_end = vpm->virtual.end;
	save_vpm_size = vpm->virtual.size;

	if ((this_pool_start < vpm->virtual.start) || vpm->virtual.start == 0)
	  vpm->virtual.start = this_pool_start;
	if (this_pool_end > vpm->virtual.end)
	  vpm->virtual.end = this_pool_end;

	vpm->virtual.size = vpm->virtual.end - vpm->virtual.start;

	if (CLIB_DEBUG > 1)
	  {
	    clib_warning
	      ("after: virtual.start %llx virtual.end %llx virtual.size %lld",
	       vpm->virtual.start, vpm->virtual.end, vpm->virtual.size);
	  }

	/* check if fits into buffer index range */
	if ((u64) vpm->virtual.size >
	    ((u64) 1 << (32 + CLIB_LOG2_CACHE_LINE_BYTES)))
	  {
	    clib_warning ("physmem: virtual size out of range!");
	    vpm->virtual.start = save_vpm_start;
	    vpm->virtual.end = save_vpm_end;
	    vpm->virtual.size = save_vpm_size;
	    rmp = 0;
	  }
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

static vlib_buffer_callbacks_t callbacks = {
  .vlib_buffer_alloc_cb = &dpdk_buffer_alloc,
  .vlib_buffer_alloc_from_free_list_cb = &dpdk_buffer_alloc_from_free_list,
  .vlib_buffer_free_cb = &dpdk_buffer_free,
  .vlib_buffer_free_no_next_cb = &dpdk_buffer_free_no_next,
  .vlib_packet_template_init_cb = &dpdk_packet_template_init,
  .vlib_buffer_delete_free_list_cb = &dpdk_buffer_delete_free_list,
};

static clib_error_t *
dpdk_buffer_init (vlib_main_t * vm)
{
  vlib_buffer_cb_register (vm, &callbacks);
  return 0;
}

VLIB_INIT_FUNCTION (dpdk_buffer_init);

/** @endcond */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
