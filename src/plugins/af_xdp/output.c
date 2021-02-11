#include <errno.h>
#include <string.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <af_xdp/af_xdp.h>

#define AF_XDP_TX_RETRIES 5



static_always_inline void
af_xdp_add(u32 * lst, u32 len, vlib_buffer_t *bufs[VLIB_FRAME_SIZE], u64 start)
{
  af_xdp_main_t *rm = &af_xdp_main;
  clib_bihash_kv_8_8_t bkey, rkey;
  clib_bihash_kv_8_16_t bkey2;
  u32 th = vlib_get_thread_index();
  u64 offset, addr;
  int rv, dbs = 0;
  for (int i = 0; i < len; i++)
    {
      bkey.key = lst[i];
      rv = clib_bihash_search_8_8 (&rm->bhash, &bkey, &rkey);
      if (rv == 0)
	dbs++;
      bkey.key = lst[i];
      bkey.value = th;
      clib_bihash_add_del_8_8 (&rm->bhash, &bkey, 1 /* add */);
      offset =
	(sizeof (vlib_buffer_t) +
	 bufs[i]->current_data) << XSK_UNALIGNED_BUF_OFFSET_SHIFT;
      addr = pointer_to_uword (bufs[i]) - start;

      bkey2.key = lst[i];
      bkey2.value[0] = (offset | addr) >> CLIB_LOG2_CACHE_LINE_BYTES;
      bkey2.value[1] = bufs[i]->current_data;
      clib_bihash_add_del_8_16 (&rm->bhashlog, &bkey2, 1 /* add */);
    }
  if (dbs)
    clib_warning("Got dubs (add) : %d", dbs);
}

static_always_inline void
af_xdp_del(vlib_main_t *vm, u32 * lst, u32 len)
{
  af_xdp_main_t *rm = &af_xdp_main;
  clib_bihash_kv_8_8_t bkey, rkey;
  clib_bihash_kv_8_16_t bkey2, rkey2;
  u32 i, th = vlib_get_thread_index();
  int rv;
  for (i = 0; i < len; i++)
    {
      bkey.key = lst[i];
      rv = clib_bihash_search_8_8 (&rm->bhash, &bkey, &rkey);
      if (rv != 0)
	{
	  bkey2.key = lst[i];
	  // vlib_buffer_t * buf = vlib_get_buffer(vm, lst[i]);
	  rv = clib_bihash_search_8_16 (&rm->bhashlog, &bkey2, &rkey2);
	  clib_warning("Got dubs (del) %u [id:%u/%u]"
		       "(th:%u) log:%d [%lu %d]",
		       lst[i], i, len,
		       th, rv, rkey2.value[0], (int) rkey2.value[1]);
	}
      bkey.key = lst[i];
      clib_bihash_add_del_8_8 (&rm->bhash, &bkey, 0 /* delete */);
    }
}

static_always_inline void
af_xdp_device_output_free (vlib_main_t * vm, const vlib_node_runtime_t * node,
			   af_xdp_txq_t * txq)
{
  const __u64 *compl;
  const u32 size = txq->cq.size;
  const u32 mask = size - 1;
  u32 bis[VLIB_FRAME_SIZE], *bi = bis;
  u32 n_wrap, idx;
  u32 n = xsk_ring_cons__peek (&txq->cq, ARRAY_LEN (bis), &idx);
  if (n > 256)
    clib_panic ("af_xdp_device_output_free n %d > 256", n);
  u32 n_free = n;

  /* we rely on on casting addr (u64) -> bi (u32) to discard XSK offset below */
  STATIC_ASSERT (BITS (bi[0]) + CLIB_LOG2_CACHE_LINE_BYTES <=
		 XSK_UNALIGNED_BUF_OFFSET_SHIFT, "wrong size");
  ASSERT (mask == txq->cq.mask);

  if (!n_free)
    return;

  compl = xsk_ring_cons__comp_addr (&txq->cq, idx);
  n = clib_min (n_free, size - (idx & mask));
  n_wrap = n_free - n;

wrap_around:

  while (n >= 8)
    {
#ifdef CLIB_HAVE_VEC256
      u64x4 b0 = (*(u64x4u *) (compl + 0)) >> CLIB_LOG2_CACHE_LINE_BYTES;
      u64x4 b1 = (*(u64x4u *) (compl + 4)) >> CLIB_LOG2_CACHE_LINE_BYTES;
      /* permute 256-bit register so lower u32s of each buffer index are
       * placed into lower 128-bits */
      const u32x8 mask = { 0, 2, 4, 6, 1, 3, 5, 7 };
      u32x8 b2 = u32x8_permute ((u32x8) b0, mask);
      u32x8 b3 = u32x8_permute ((u32x8) b1, mask);
      /* extract lower 128-bits and save them to the array of buffer indices */
      *(u32x4u *) (bi + 0) = u32x8_extract_lo (b2);
      *(u32x4u *) (bi + 4) = u32x8_extract_lo (b3);
#else
      bi[0] = compl[0] >> CLIB_LOG2_CACHE_LINE_BYTES;
      bi[1] = compl[1] >> CLIB_LOG2_CACHE_LINE_BYTES;
      bi[2] = compl[2] >> CLIB_LOG2_CACHE_LINE_BYTES;
      bi[3] = compl[3] >> CLIB_LOG2_CACHE_LINE_BYTES;
      bi[4] = compl[4] >> CLIB_LOG2_CACHE_LINE_BYTES;
      bi[5] = compl[5] >> CLIB_LOG2_CACHE_LINE_BYTES;
      bi[6] = compl[6] >> CLIB_LOG2_CACHE_LINE_BYTES;
      bi[7] = compl[7] >> CLIB_LOG2_CACHE_LINE_BYTES;
#endif
      // if (compl[0] & 0xffff000000000000) clib_panic("AAA %p", compl[0]);
      // if (compl[1] & 0xffff000000000000) clib_panic("AAA %p", compl[1]);
      // if (compl[2] & 0xffff000000000000) clib_panic("AAA %p", compl[2]);
      // if (compl[3] & 0xffff000000000000) clib_panic("AAA %p", compl[3]);
      // if (compl[4] & 0xffff000000000000) clib_panic("AAA %p", compl[4]);
      // if (compl[5] & 0xffff000000000000) clib_panic("AAA %p", compl[5]);
      // if (compl[6] & 0xffff000000000000) clib_panic("AAA %p", compl[6]);
      // if (compl[7] & 0xffff000000000000) clib_panic("AAA %p", compl[7]);
      compl += 8;
      bi += 8;
      n -= 8;
    }

  while (n >= 1)
    {
      bi[0] = compl[0] >> CLIB_LOG2_CACHE_LINE_BYTES;
      // if (compl[0] & 0xffff000000000000) clib_panic("AAA %p", compl[0]);
      ASSERT (vlib_buffer_is_known (vm, bi[0]) ==
	      VLIB_BUFFER_KNOWN_ALLOCATED);
      compl += 1;
      bi += 1;
      n -= 1;
    }

  if (n_wrap)
    {
      compl = xsk_ring_cons__comp_addr (&txq->cq, 0);
      n = n_wrap;
      n_wrap = 0;
      goto wrap_around;
    }

  xsk_ring_cons__release (&txq->cq, n_free);
  af_xdp_del (vm, bis, n_free);

  vlib_buffer_free (vm, bis,  n_free);
}



static_always_inline void
af_xdp_device_output_tx_db (vlib_main_t * vm,
			    const vlib_node_runtime_t * node,
			    af_xdp_device_t * ad,
			    af_xdp_txq_t * txq, const u32 n_tx)
{
  int ret;

  xsk_ring_prod__submit (&txq->tx, n_tx);

  if (!xsk_ring_prod__needs_wakeup (&txq->tx))
    return;

  vlib_error_count (vm, node->node_index, AF_XDP_TX_ERROR_SENDTO_REQUIRED, 1);

  ret = sendto (txq->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
  if (PREDICT_TRUE (ret >= 0))
    return;

  /* those errors are fine */
  switch (errno)
    {
    case ENOBUFS:
    case EAGAIN:
    case EBUSY:
      return;
    }

  /* something bad is happening */
  vlib_error_count (vm, node->node_index, AF_XDP_TX_ERROR_SENDTO_FAILURES, 1);
  af_xdp_device_error (ad, "sendto() failed");
}

static_always_inline u32
af_xdp_device_output_tx_try (vlib_main_t * vm,
			     const vlib_node_runtime_t * node,
			     af_xdp_device_t * ad, af_xdp_txq_t * txq,
			     u32 n_tx, u32 * bi)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  const uword start = vm->buffer_main->buffer_mem_start;
  const u32 size = txq->tx.size;
  const u32 mask = size - 1;
  struct xdp_desc *desc;
  u64 offset, addr;
  u32 idx, n, n_wrap;

  ASSERT (mask == txq->cq.mask);

  n_tx = xsk_ring_prod__reserve (&txq->tx, n_tx, &idx);

  /* if ring is full, do nothing */
  if (PREDICT_FALSE (0 == n_tx))
    return 0;

  vlib_get_buffers (vm, bi, bufs, n_tx);

  desc = xsk_ring_prod__tx_desc (&txq->tx, idx);
  n = clib_min (n_tx, size - (idx & mask));
  n_wrap = n_tx - n;

  if (n > 256)
    clib_panic ("af_xdp_device_output_free n %d > 256", n);
  if (n > 256)
    clib_panic ("af_xdp_device_output_free n_tx %d > 256", n_tx);

wrap_around:

  while (n >= 8)
    {
      vlib_prefetch_buffer_header (b[4], LOAD);
      offset =
	(sizeof (vlib_buffer_t) +
	 b[0]->current_data) << XSK_UNALIGNED_BUF_OFFSET_SHIFT;
      addr = pointer_to_uword (b[0]) - start;
      desc[0].addr = offset | addr;
      desc[0].len = b[0]->current_length;

      vlib_prefetch_buffer_header (b[5], LOAD);
      offset =
	(sizeof (vlib_buffer_t) +
	 b[1]->current_data) << XSK_UNALIGNED_BUF_OFFSET_SHIFT;
      addr = pointer_to_uword (b[1]) - start;
      desc[1].addr = offset | addr;
      desc[1].len = b[1]->current_length;

      vlib_prefetch_buffer_header (b[6], LOAD);
      offset =
	(sizeof (vlib_buffer_t) +
	 b[2]->current_data) << XSK_UNALIGNED_BUF_OFFSET_SHIFT;
      addr = pointer_to_uword (b[2]) - start;
      desc[2].addr = offset | addr;
      desc[2].len = b[2]->current_length;

      vlib_prefetch_buffer_header (b[7], LOAD);
      offset =
	(sizeof (vlib_buffer_t) +
	 b[3]->current_data) << XSK_UNALIGNED_BUF_OFFSET_SHIFT;
      addr = pointer_to_uword (b[3]) - start;
      desc[3].addr = offset | addr;
      desc[3].len = b[3]->current_length;

      desc += 4;
      b += 4;
      n -= 4;
    }

  while (n >= 1)
    {
      offset =
	(sizeof (vlib_buffer_t) +
	 b[0]->current_data) << XSK_UNALIGNED_BUF_OFFSET_SHIFT;
      addr = pointer_to_uword (b[0]) - start;
      desc[0].addr = offset | addr;
      desc[0].len = b[0]->current_length;
      desc += 1;
      b += 1;
      n -= 1;
    }

  if (n_wrap)
    {
      desc = xsk_ring_prod__tx_desc (&txq->tx, 0);
      n = n_wrap;
      n_wrap = 0;
      goto wrap_around;
    }
  af_xdp_add(bi, n_tx, bufs, start);

  return n_tx;
}

VNET_DEVICE_CLASS_TX_FN (af_xdp_device_class) (vlib_main_t * vm,
					       vlib_node_runtime_t * node,
					       vlib_frame_t * frame)
{
  af_xdp_main_t *rm = &af_xdp_main;
  vnet_interface_output_runtime_t *ord = (void *) node->runtime_data;
  af_xdp_device_t *ad = pool_elt_at_index (rm->devices, ord->dev_instance);
  u32 thread_index = vm->thread_index;
  af_xdp_txq_t *txq = vec_elt_at_index (ad->txqs, thread_index % ad->txq_num);
  u32 *from;
  u32 n, n_tx;
  int i;

  from = vlib_frame_vector_args (frame);
  n_tx = frame->n_vectors;

  clib_spinlock_lock_if_init (&txq->lock);

  for (i = 0, n = 0; i < AF_XDP_TX_RETRIES && n < n_tx; i++)
    {
      u32 n_enq;
      af_xdp_device_output_free (vm, node, txq);
      n_enq = af_xdp_device_output_tx_try (vm, node, ad, txq, n_tx - n, from);
      n += n_enq;
      from += n_enq;
    }

  af_xdp_device_output_tx_db (vm, node, ad, txq, n);

  clib_spinlock_unlock_if_init (&txq->lock);

  if (PREDICT_FALSE (n != n_tx))
    {
      vlib_buffer_free (vm, from + n, n_tx - n);
      vlib_error_count (vm, node->node_index,
			AF_XDP_TX_ERROR_NO_FREE_SLOTS, n_tx - n);
    }

  return n;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
