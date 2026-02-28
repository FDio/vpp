#include <string.h>
#include <vppinfra/clib.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <af_xdp/af_xdp.h>

#define AF_XDP_TX_RETRIES 5

static_always_inline void
af_xdp_device_output_free (vlib_main_t *vm, const vlib_node_runtime_t *node, af_xdp_txq_t *txq)
{
  const __u64 * compl ;
  const u32 size = txq->cq.size;
  const u32 mask = size - 1;
  u32 bis[VLIB_FRAME_SIZE], *bi = bis;
  u32 n_wrap, idx;
  u32 n = xsk_ring_cons__peek (&txq->cq, ARRAY_LEN (bis), &idx);
  const u32 n_free = n;

  /* we rely on on casting addr (u64) -> bi (u32) to discard XSK offset below */
  STATIC_ASSERT (BITS (bi[0]) + CLIB_LOG2_CACHE_LINE_BYTES <= XSK_UNALIGNED_BUF_OFFSET_SHIFT,
		 "wrong size");
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
      u64x4 b0 = (*(u64x4u *) (compl +0)) >> CLIB_LOG2_CACHE_LINE_BYTES;
      u64x4 b1 = (*(u64x4u *) (compl +4)) >> CLIB_LOG2_CACHE_LINE_BYTES;
      /* permute 256-bit register so lower u32s of each buffer index are
       * placed into lower 128-bits */
      const u32x8 mask = { 0, 2, 4, 6, 1, 3, 5, 7 };
      u32x8 b2 = u32x8_permute ((u32x8) b0, mask);
      u32x8 b3 = u32x8_permute ((u32x8) b1, mask);
      /* extract lower 128-bits and save them to the array of buffer indices */
      *(u32x4u *) (bi + 0) = u32x8_extract_lo (b2);
      *(u32x4u *) (bi + 4) = u32x8_extract_lo (b3);
#else
      bi[0] = compl [0] >> CLIB_LOG2_CACHE_LINE_BYTES;
      bi[1] = compl [1] >> CLIB_LOG2_CACHE_LINE_BYTES;
      bi[2] = compl [2] >> CLIB_LOG2_CACHE_LINE_BYTES;
      bi[3] = compl [3] >> CLIB_LOG2_CACHE_LINE_BYTES;
      bi[4] = compl [4] >> CLIB_LOG2_CACHE_LINE_BYTES;
      bi[5] = compl [5] >> CLIB_LOG2_CACHE_LINE_BYTES;
      bi[6] = compl [6] >> CLIB_LOG2_CACHE_LINE_BYTES;
      bi[7] = compl [7] >> CLIB_LOG2_CACHE_LINE_BYTES;
#endif
      compl += 8;
      bi += 8;
      n -= 8;
    }

  while (n >= 1)
    {
      bi[0] = compl [0] >> CLIB_LOG2_CACHE_LINE_BYTES;
      ASSERT (vlib_buffer_is_known (vm, bi[0]) == VLIB_BUFFER_KNOWN_ALLOCATED);
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
af_xdp_device_output_tx_db (vlib_main_t *vm, const vlib_node_runtime_t *node, af_xdp_device_t *ad,
			    af_xdp_txq_t *txq, const u32 n_tx)
{
  /* For multi-buffer support, use n_tx_desc if set, otherwise n_tx */
  u32 n_desc = txq->n_tx_desc ? txq->n_tx_desc : n_tx;
  xsk_ring_prod__submit (&txq->tx, n_desc);
  txq->n_tx_desc = 0; /* Reset for next batch */

  if (!xsk_ring_prod__needs_wakeup (&txq->tx))
    return;

  vlib_error_count (vm, node->node_index, AF_XDP_TX_ERROR_SYSCALL_REQUIRED, 1);

  clib_spinlock_lock_if_init (&txq->syscall_lock);

  if (xsk_ring_prod__needs_wakeup (&txq->tx))
    {
      const struct msghdr msg = {};
      int ret;
      /* On tx, xsk socket will only tx up to TX_BATCH_SIZE, as defined in
       * kernel net/xdp/xsk.c. Unfortunately we do not know how much this is,
       * our only option is to retry until everything is sent... */
      do
	{
	  ret = sendmsg (txq->xsk_fd, &msg, MSG_DONTWAIT);
	}
      while (ret < 0 && EAGAIN == errno);
      if (PREDICT_FALSE (ret < 0))
	{
	  /* not EAGAIN: something bad is happening */
	  vlib_error_count (vm, node->node_index, AF_XDP_TX_ERROR_SYSCALL_FAILURES, 1);
	  af_xdp_device_error (ad, "tx poll() failed");
	}
    }

  clib_spinlock_unlock_if_init (&txq->syscall_lock);
}

static_always_inline u32
af_xdp_device_output_tx_try (vlib_main_t *vm, const vlib_node_runtime_t *node, af_xdp_device_t *ad,
			     af_xdp_txq_t *txq, u32 n_tx, u32 *bi)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  const uword start = vm->buffer_main->buffer_mem_start;
  const u32 size = txq->tx.size;
  const u32 mask = size - 1;
  struct xdp_desc *desc;
  u64 offset, addr;
  u32 idx, n_desc, n_sent;
  u32 i;

  ASSERT (mask == txq->cq.mask);

  vlib_get_buffers (vm, bi, bufs, n_tx);

  /* Count total number of descriptors needed (including chained buffers) */
  n_desc = 0;
  for (i = 0; i < n_tx; i++)
    {
      vlib_buffer_t *buf = bufs[i];
      n_desc++; /* Count first buffer */
      while (buf->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  buf = vlib_get_buffer (vm, buf->next_buffer);
	  n_desc++; /* Count each chained buffer */
	}
    }

  /* Reserve space for ALL descriptors (including fragments) */
  n_desc = xsk_ring_prod__reserve (&txq->tx, n_desc, &idx);

  /* If ring is full, do nothing */
  if (PREDICT_FALSE (0 == n_desc))
    return 0;

  /* Send each packet (and its fragments) */
  n_sent = 0;
  b = bufs;

  for (i = 0; i < n_tx && n_sent < n_desc; i++)
    {
      vlib_buffer_t *buf = b[i];

      /* Send packet fragments */
      while (1)
	{
	  desc = xsk_ring_prod__tx_desc (&txq->tx, (idx + n_sent) & mask);

	  offset = (sizeof (vlib_buffer_t) + buf->current_data) << XSK_UNALIGNED_BUF_OFFSET_SHIFT;
	  addr = pointer_to_uword (buf) - start;
	  desc->addr = offset | addr;
	  desc->len = buf->current_length;

	  /* Check if this buffer has more fragments */
	  if (buf->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      desc->options = XDP_PKT_CONTD; /* Mark as continued */
	      buf = vlib_get_buffer (vm, buf->next_buffer);
	      n_sent++;
	    }
	  else
	    {
	      desc->options = 0; /* Last fragment */
	      n_sent++;
	      break;
	    }
	}
    }

  /* Store number of descriptors submitted for later use in af_xdp_device_output_tx_db */
  txq->n_tx_desc = n_sent;

  return n_tx; /* Return number of packets, not descriptors */
}

VNET_DEVICE_CLASS_TX_FN (af_xdp_device_class)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  af_xdp_main_t *rm = &af_xdp_main;
  vnet_interface_output_runtime_t *ord = (void *) node->runtime_data;
  af_xdp_device_t *ad = pool_elt_at_index (rm->devices, ord->dev_instance);
  const vnet_hw_if_tx_frame_t *tf = vlib_frame_scalar_args (frame);
  const int shared_queue = tf->shared_queue;
  af_xdp_txq_t *txq = vec_elt_at_index (ad->txqs, tf->queue_id);
  u32 *from;
  u32 n, n_tx;
  int i;

  from = vlib_frame_vector_args (frame);
  n_tx = frame->n_vectors;

  if (shared_queue)
    clib_spinlock_lock (&txq->lock);

  for (i = 0, n = 0; i < AF_XDP_TX_RETRIES && n < n_tx; i++)
    {
      u32 n_enq;
      af_xdp_device_output_free (vm, node, txq);
      n_enq = af_xdp_device_output_tx_try (vm, node, ad, txq, n_tx - n, from + n);
      n += n_enq;
    }

  af_xdp_device_output_tx_db (vm, node, ad, txq, n);

  if (shared_queue)
    clib_spinlock_unlock (&txq->lock);

  if (PREDICT_FALSE (n != n_tx))
    {
      vlib_buffer_free (vm, from + n, n_tx - n);
      vlib_error_count (vm, node->node_index, AF_XDP_TX_ERROR_NO_FREE_SLOTS, n_tx - n);
    }

  return n;
}
