/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <ena/ena.h>
#include <ena/ena_inlines.h>

static_always_inline void
ena_tx_desc_write (ena_tx_desc_t *d, ena_tx_desc_t *t, u64 addr, u16 len)
{
  vec128_t r;
  const ena_tx_desc_t mask = {
    .req_id_lo = 0x3ff,
    .req_id_hi = 0x3, /* upper 4 bits used to store n desc in chain */
    .phase = 1
  };

  r.as_u32x4 = d->as_u32x4 & mask.as_u32x4; /* preserve req_id and phase */
  r.as_u32x4 ^= ((ena_tx_desc_t){ .phase = 1 }).as_u32x4; /* flip phase */
  r.as_u32x4 |= t->as_u32x4;				  /* add desc data */
  r.as_u64x2[1] = addr;
  r.as_u16x8[0] = len;
  d->as_u32x4 = r.as_u32x4;
}

VNET_DEVICE_CLASS_TX_FN (ena_device_class)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  ena_device_t *ad = ena_get_device (rd->dev_instance);
  vnet_hw_if_tx_frame_t *tf = vlib_frame_scalar_args (frame);
  u8 qid = tf->queue_id;
  ena_txq_t *txq = pool_elt_at_index (ad->txqs, qid);
  u32 mask = pow2_mask (txq->log2_n_desc);
  u32 next = txq->sq_next;
  u8 log2_n_desc = txq->log2_n_desc;
  u32 *from = vlib_frame_vector_args (frame);
  ena_tx_desc_t *d;
  u16 n_left, n_enq = 0;

  if (tf->shared_queue)
    {
      u8 free = 0;
      while (!__atomic_compare_exchange_n (&txq->lock, &free, 1, 0,
					   __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
	{
	  while (__atomic_load_n (&txq->lock, __ATOMIC_RELAXED))
	    CLIB_PAUSE ();
	  free = 0;
	}
    }

  if (txq->n_enq > 0)
    {
      ena_tx_cdesc_t *cd;
      u32 phase;

    cq_more:
      cd = txq->cqes + (txq->cq_next & mask);
      phase = 1 & ~(txq->cq_next >> log2_n_desc);
      if (cd->phase == phase)
	{
	  txq->cq_next++;
	  goto cq_more;
	}
    }

  n_left = frame->n_vectors;

  while (n_left)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[0]);

      d = txq->sqes + (next & mask);
      u64 pa = vlib_buffer_get_current_pa (vm, b);

      ena_tx_desc_t t = { .first = 1, .last = 1 };
      ena_tx_desc_write (d, &t, pa, b->current_length);
      next++;
      n_enq++;
      from++;
      n_left--;
    }

  if (next >= txq->sq_next)
    {
      txq->sq_next = next;
      txq->n_enq += n_enq;
      __atomic_store_n (txq->sq_db, next, __ATOMIC_RELEASE);
    }

  if (tf->shared_queue)
    __atomic_store_n (&txq->lock, 0, __ATOMIC_RELEASE);

  return frame->n_vectors - n_left;
}
