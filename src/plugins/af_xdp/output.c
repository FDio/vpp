#include <poll.h>
#include <string.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <af_xdp/af_xdp.h>

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
  const u32 n_free = n;

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
      compl += 8;
      bi += 8;
      n -= 8;
    }

  while (n >= 1)
    {
      bi[0] = compl[0] >> CLIB_LOG2_CACHE_LINE_BYTES;
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
  vlib_buffer_free (vm, bis, n_free);
}

static_always_inline void
af_xdp_device_output_tx_db (vlib_main_t * vm,
			    const vlib_node_runtime_t * node,
			    af_xdp_device_t * ad,
			    af_xdp_txq_t * txq, const u32 n_tx)
{
  xsk_ring_prod__submit (&txq->tx, n_tx);

  if (!xsk_ring_prod__needs_wakeup (&txq->tx))
    return;

  vlib_error_count (vm, node->node_index, AF_XDP_TX_ERROR_SYSCALL_REQUIRED, 1);

  clib_spinlock_lock_if_init (&txq->syscall_lock);

  if (xsk_ring_prod__needs_wakeup (&txq->tx))
    {
      struct pollfd fd = { .fd = txq->xsk_fd, .events = POLLIN | POLLOUT };
      int ret = poll (&fd, 1, 0);
      if (PREDICT_FALSE (ret < 0))
	{
	  /* something bad is happening */
	  vlib_error_count (vm, node->node_index,
			    AF_XDP_TX_ERROR_SYSCALL_FAILURES, 1);
	  af_xdp_device_error (ad, "tx poll() failed");
	}
    }

  clib_spinlock_unlock_if_init (&txq->syscall_lock);
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

  /* if ring does not have enough space, do nothing */
  if (PREDICT_FALSE (xsk_ring_prod__reserve (&txq->tx, n_tx, &idx) < n_tx))
    return 0;

  vlib_get_buffers (vm, bi, bufs, n_tx);

  desc = xsk_ring_prod__tx_desc (&txq->tx, idx);
  n = clib_min (n_tx, size - (idx & mask));
  n_wrap = n_tx - n;

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

  return n_tx;
}

VNET_DEVICE_CLASS_TX_FN (af_xdp_device_class) (vlib_main_t * vm,
					       vlib_node_runtime_t * node,
					       vlib_frame_t * frame)
{
  af_xdp_main_t *rm = &af_xdp_main;
  vnet_interface_output_runtime_t *ord = (void *) node->runtime_data;
  af_xdp_device_t *ad = pool_elt_at_index (rm->devices, ord->dev_instance);
  const vnet_hw_if_tx_frame_t *tf = vlib_frame_scalar_args (frame);
  const int shared_queue = tf->shared_queue;
  af_xdp_txq_t *txq = vec_elt_at_index (ad->txqs, tf->queue_id);
  u32 *from;
  u32 n = 0, n_tx;
  f64 start;
  bool use_time = false;

  from = vlib_frame_vector_args (frame);
  n_tx = frame->n_vectors;

  if (shared_queue)
    clib_spinlock_lock (&txq->lock);

  while (n < n_tx)
    {
      f64 now;

      /* try to send packets */
      af_xdp_device_output_free (vm, node, txq);
      n = af_xdp_device_output_tx_try (vm, node, ad, txq, n_tx, from);
      if (n == n_tx)
	break;

      /* slow path, prevent kernel hang  */
      if (!use_time)
	{
	  start = vlib_time_now (vm);
	  use_time = true;
	}

      af_xdp_device_output_tx_db (vm, node, ad, txq, n);

      /* make sure we do not block for longer than 10ms */
      now = vlib_time_now (vm);
      if (PREDICT_FALSE (now - start > 0.01))
	break;
    }

  af_xdp_device_output_tx_db (vm, node, ad, txq, n);

  if (shared_queue)
    clib_spinlock_unlock (&txq->lock);

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
