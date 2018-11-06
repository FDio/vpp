/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>

#include <marvell/pp2/pp2.h>

uword
mrvl_pp2_interface_tx (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  mrvl_pp2_main_t *ppm = &mrvl_pp2_main;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  mrvl_pp2_if_t *ppif = pool_elt_at_index (ppm->interfaces, rd->dev_instance);
  u32 thread_index = vm->thread_index;
  mrvl_pp2_per_thread_data_t *ptd =
    vec_elt_at_index (ppm->per_thread_data, thread_index);
  u8 qid = thread_index;
  mrvl_pp2_outq_t *outq = vec_elt_at_index (ppif->outqs, qid);
  u32 *buffers = vlib_frame_args (frame);
  u16 n_desc = frame->n_vectors, n_left = n_desc, n_sent = n_desc, n_done;
  struct pp2_ppio_desc *d;
  u16 mask = outq->size - 1;

  if (PREDICT_FALSE (pp2_ppio_get_num_outq_done (ppif->ppio, ptd->hif, qid,
						 &n_done)))
    {
      n_done = 0;
      vlib_error_count (vm, node->node_index,
			MRVL_PP2_TX_ERROR_PPIO_GET_NUM_OUTQ_DONE, 1);
    }

  if (n_done)
    {
      u16 n_free = clib_min (n_done, outq->size - (outq->tail & mask));
      vlib_buffer_free (vm, outq->buffers + (outq->tail & mask), n_free);
      if (PREDICT_FALSE (n_free < n_done))
	vlib_buffer_free (vm, outq->buffers, n_done - n_free);
      outq->tail += n_done;
    }

  vec_validate_aligned (ptd->descs, n_left, CLIB_CACHE_LINE_BYTES);
  d = ptd->descs;
  while (n_left)
    {
      u32 bi0 = buffers[0];
      vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
      u64 paddr = vlib_buffer_get_pa (vm, b0);

      pp2_ppio_outq_desc_reset (d);
      pp2_ppio_outq_desc_set_phys_addr (d, paddr + b0->current_data);
      pp2_ppio_outq_desc_set_pkt_offset (d, 0);
      pp2_ppio_outq_desc_set_pkt_len (d, b0->current_length);
      d++;
      buffers++;
      n_left--;
    }

  if (pp2_ppio_send (ppif->ppio, ptd->hif, qid, ptd->descs, &n_sent))
    {
      n_sent = 0;
      vlib_error_count (vm, node->node_index, MRVL_PP2_TX_ERROR_PPIO_SEND, 1);
    }

  /* free unsent buffers */
  if (PREDICT_FALSE (n_sent != n_desc))
    {
      vlib_buffer_free (vm, vlib_frame_args (frame) + n_sent,
			frame->n_vectors - n_sent);
      vlib_error_count (vm, node->node_index, MRVL_PP2_TX_ERROR_NO_FREE_SLOTS,
			frame->n_vectors - n_sent);
    }

  /* store buffer index for each enqueued packet into the ring
     so we can know what to free after packet is sent */
  if (n_sent)
    {
      u16 slot = outq->head & mask;
      buffers = vlib_frame_args (frame);
      u16 n_copy = clib_min (outq->size - slot, n_sent);

      clib_memcpy (outq->buffers + slot, buffers, n_copy * sizeof (u32));
      if (PREDICT_FALSE (n_copy < n_sent))
	clib_memcpy (outq->buffers, buffers + n_copy,
		     (n_sent - n_copy) * sizeof (u32));

      outq->head += n_sent;
    }

  return n_sent;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
