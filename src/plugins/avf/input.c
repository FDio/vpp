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

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>

#include <avf/avf.h>

#define foreach_avf_input_error \
  _(BUFFER_ALLOC, "buffer alloc error") \
  _(RX_PACKET_ERROR, "Rx packet errors")

typedef enum
{
#define _(f,s) AVF_INPUT_ERROR_##f,
  foreach_avf_input_error
#undef _
    AVF_INPUT_N_ERROR,
} avf_input_error_t;

static __clib_unused char *avf_input_error_strings[] = {
#define _(n,s) s,
  foreach_avf_input_error
#undef _
};

#define AVF_RX_DESC_STATUS(x)		(1 << x)
#define AVF_RX_DESC_STATUS_DD		AVF_RX_DESC_STATUS(0)
#define AVF_RX_DESC_STATUS_EOP		AVF_RX_DESC_STATUS(1)

#define AVF_INPUT_REFILL_TRESHOLD 32
static_always_inline void
avf_rxq_refill (vlib_main_t * vm, vlib_node_runtime_t * node, avf_rxq_t * rxq,
		int use_va_dma)
{
  u16 n_refill, mask, n_alloc, slot;
  u32 s0, s1, s2, s3;
  vlib_buffer_t *b[4];
  avf_rx_desc_t *d[4];

  n_refill = rxq->size - 1 - rxq->n_enqueued;
  if (PREDICT_TRUE (n_refill <= AVF_INPUT_REFILL_TRESHOLD))
    return;

  mask = rxq->size - 1;
  slot = (rxq->next - n_refill - 1) & mask;

  n_refill &= ~7;		/* round to 8 */
  n_alloc = vlib_buffer_alloc_to_ring (vm, rxq->bufs, slot, rxq->size,
				       n_refill);

  if (PREDICT_FALSE (n_alloc != n_refill))
    {
      vlib_error_count (vm, node->node_index,
			AVF_INPUT_ERROR_BUFFER_ALLOC, 1);
      if (n_alloc)
	vlib_buffer_free_from_ring (vm, rxq->bufs, slot, rxq->size, n_alloc);
      return;
    }

  rxq->n_enqueued += n_alloc;

  while (n_alloc >= 4)
    {
      if (PREDICT_TRUE (slot + 3 < rxq->size))
	{
	  s0 = slot;
	  s1 = slot + 1;
	  s2 = slot + 2;
	  s3 = slot + 3;
	}
      else
	{
	  s0 = slot;
	  s1 = (slot + 1) & mask;
	  s2 = (slot + 2) & mask;
	  s3 = (slot + 3) & mask;
	}

      d[0] = ((avf_rx_desc_t *) rxq->descs) + s0;
      d[1] = ((avf_rx_desc_t *) rxq->descs) + s1;
      d[2] = ((avf_rx_desc_t *) rxq->descs) + s2;
      d[3] = ((avf_rx_desc_t *) rxq->descs) + s3;
      b[0] = vlib_get_buffer (vm, rxq->bufs[s0]);
      b[1] = vlib_get_buffer (vm, rxq->bufs[s1]);
      b[2] = vlib_get_buffer (vm, rxq->bufs[s2]);
      b[3] = vlib_get_buffer (vm, rxq->bufs[s3]);

      if (use_va_dma)
	{
	  d[0]->qword[0] = vlib_buffer_get_va (b[0]);
	  d[1]->qword[0] = vlib_buffer_get_va (b[1]);
	  d[2]->qword[0] = vlib_buffer_get_va (b[2]);
	  d[3]->qword[0] = vlib_buffer_get_va (b[3]);
	}
      else
	{
	  d[0]->qword[0] = vlib_buffer_get_pa (vm, b[0]);
	  d[1]->qword[0] = vlib_buffer_get_pa (vm, b[1]);
	  d[2]->qword[0] = vlib_buffer_get_pa (vm, b[2]);
	  d[3]->qword[0] = vlib_buffer_get_pa (vm, b[3]);
	}

      d[0]->qword[1] = 0;
      d[1]->qword[1] = 0;
      d[2]->qword[1] = 0;
      d[3]->qword[1] = 0;

      /* next */
      slot = (slot + 4) & mask;
      n_alloc -= 4;
    }
  while (n_alloc)
    {
      s0 = slot;
      d[0] = ((avf_rx_desc_t *) rxq->descs) + s0;
      b[0] = vlib_get_buffer (vm, rxq->bufs[s0]);
      if (use_va_dma)
	d[0]->qword[0] = vlib_buffer_get_va (b[0]);
      else
	d[0]->qword[0] = vlib_buffer_get_pa (vm, b[0]);
      d[0]->qword[1] = 0;

      /* next */
      slot = (slot + 1) & mask;
      n_alloc -= 1;
    }

  CLIB_MEMORY_BARRIER ();
  *(rxq->qrx_tail) = slot;
}

static_always_inline uword
avf_process_rx_burst (vlib_main_t * vm, vlib_node_runtime_t * node,
		      vlib_buffer_t * bt, avf_rx_vector_entry_t * rxve,
		      vlib_buffer_t ** b, u32 n_rxv)
{
  uword n_rx_bytes = 0;

  while (n_rxv >= 4)
    {
      if (n_rxv >= 12)
	{
	  vlib_prefetch_buffer_header (b[8], LOAD);
	  vlib_prefetch_buffer_header (b[9], LOAD);
	  vlib_prefetch_buffer_header (b[10], LOAD);
	  vlib_prefetch_buffer_header (b[11], LOAD);
	}

      n_rx_bytes += b[0]->current_length = rxve[0].length;
      n_rx_bytes += b[1]->current_length = rxve[1].length;
      n_rx_bytes += b[2]->current_length = rxve[2].length;
      n_rx_bytes += b[3]->current_length = rxve[3].length;

      clib_memcpy_fast (vnet_buffer (b[0])->sw_if_index,
			vnet_buffer (bt)->sw_if_index, 2 * sizeof (u32));
      clib_memcpy_fast (vnet_buffer (b[1])->sw_if_index,
			vnet_buffer (bt)->sw_if_index, 2 * sizeof (u32));
      clib_memcpy_fast (vnet_buffer (b[2])->sw_if_index,
			vnet_buffer (bt)->sw_if_index, 2 * sizeof (u32));
      clib_memcpy_fast (vnet_buffer (b[3])->sw_if_index,
			vnet_buffer (bt)->sw_if_index, 2 * sizeof (u32));

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[1]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[2]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[3]);

      /* next */
      rxve += 4;
      b += 4;
      n_rxv -= 4;
    }
  while (n_rxv)
    {
      b[0]->current_length = rxve->length;
      n_rx_bytes += b[0]->current_length;

      clib_memcpy_fast (vnet_buffer (b[0])->sw_if_index,
			vnet_buffer (bt)->sw_if_index, 2 * sizeof (u32));

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);

      /* next */
      rxve += 1;
      b += 1;
      n_rxv -= 1;
    }
  return n_rx_bytes;
}

static_always_inline uword
avf_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			 vlib_frame_t * frame, avf_device_t * ad, u16 qid)
{
  avf_main_t *am = &avf_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 thr_idx = vlib_get_thread_index ();
  avf_per_thread_data_t *ptd =
    vec_elt_at_index (am->per_thread_data, thr_idx);
  avf_rxq_t *rxq = vec_elt_at_index (ad->rxqs, qid);
  avf_rx_vector_entry_t *rxve = 0;
  uword n_trace;
  avf_rx_desc_t *d;
  u32 n_rx_packets = 0, n_rx_bytes = 0;
  u16 mask = rxq->size - 1;
  u16 n_rxv = 0;
  u8 or_error = 0;
  u32 *bi;
  vlib_buffer_t *bufs[AVF_RX_VECTOR_SZ];
  vlib_buffer_t *bt = &ptd->buffer_template;
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;

  STATIC_ASSERT_SIZEOF (avf_rx_vector_entry_t, 8);
  STATIC_ASSERT_OFFSET_OF (avf_rx_vector_entry_t, status, 0);
  STATIC_ASSERT_OFFSET_OF (avf_rx_vector_entry_t, length, 4);
  STATIC_ASSERT_OFFSET_OF (avf_rx_vector_entry_t, ptype, 6);
  STATIC_ASSERT_OFFSET_OF (avf_rx_vector_entry_t, error, 7);

  /* is there anything on the ring */
  d = rxq->descs + rxq->next;
  if ((d->qword[1] & AVF_RX_DESC_STATUS_DD) == 0)
    goto done;

  u32 *to_next, n_left_to_next;
  if (PREDICT_FALSE (ad->per_interface_next_index != ~0))
    next_index = ad->per_interface_next_index;
  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

  /* fetch up to AVF_RX_VECTOR_SZ from the rx ring, unflatten them and
     copy needed data from descriptor to rx vector */
  bi = to_next;
  while (n_rxv < AVF_RX_VECTOR_SZ)
    {
      if (rxq->next + 11 < rxq->size)
	{
	  int stride = 8;
	  CLIB_PREFETCH ((void *) (rxq->descs + (rxq->next + stride)),
			 CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH ((void *) (rxq->descs + (rxq->next + stride + 1)),
			 CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH ((void *) (rxq->descs + (rxq->next + stride + 2)),
			 CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH ((void *) (rxq->descs + (rxq->next + stride + 3)),
			 CLIB_CACHE_LINE_BYTES, LOAD);
	}

#ifdef CLIB_HAVE_VEC256
      u64x4 q1x4, v, err4;
      u64x4 status_dd_eop_mask = u64x4_splat (0x3);

      if (n_rxv >= AVF_RX_VECTOR_SZ - 4)
	goto one_by_one;

      if (rxq->next >= rxq->size - 4)
	goto one_by_one;

      /* load 1st quadword of 4 dscriptors into 256-bit vector register */
      /* *INDENT-OFF* */
      q1x4 = (u64x4) {
	  d[0].qword[1],
	  d[1].qword[1],
	  d[2].qword[1],
	  d[3].qword[1]
      };
      /* *INDENT-ON* */

      /* not all packets are ready or at least one of them is chained */
      if (!u64x4_is_equal (q1x4 & status_dd_eop_mask, status_dd_eop_mask))
	goto one_by_one;

      /* shift and mask status, length, ptype and err */
      v = q1x4 & u64x4_splat ((u64) 0x3FFFFULL);
      v |= (q1x4 >> 6) & u64x4_splat ((u64) 0xFFFF << 32);
      v |= (q1x4 << 18) & u64x4_splat ((u64) 0xFF << 48);
      v |= err4 = (q1x4 << 37) & u64x4_splat ((u64) 0xFF << 56);

      u64x4_store_unaligned (v, ptd->rx_vector + n_rxv);

      if (!u64x4_is_all_zero (err4))
	or_error |= err4[0] | err4[1] | err4[2] | err4[3];

      clib_memcpy_fast (bi, rxq->bufs + rxq->next, 4 * sizeof (u32));

      /* next */
      rxq->next = (rxq->next + 4) & mask;
      d = rxq->descs + rxq->next;
      n_rxv += 4;
      rxq->n_enqueued -= 4;
      bi += 4;
      continue;
    one_by_one:
#endif
      CLIB_PREFETCH ((void *) (rxq->descs + ((rxq->next + 8) & mask)),
		     CLIB_CACHE_LINE_BYTES, LOAD);
      if ((d->qword[1] & AVF_RX_DESC_STATUS_DD) == 0)
	break;
      rxve = ptd->rx_vector + n_rxv;
      bi[0] = rxq->bufs[rxq->next];
      rxve->status = avf_get_u64_bits ((void *) d, 8, 18, 0);
      rxve->error = avf_get_u64_bits ((void *) d, 8, 26, 19);
      rxve->ptype = avf_get_u64_bits ((void *) d, 8, 37, 30);
      rxve->length = avf_get_u64_bits ((void *) d, 8, 63, 38);
      or_error |= rxve->error;

      /* deal with chained buffers */
      while (PREDICT_FALSE ((d->qword[1] & AVF_RX_DESC_STATUS_EOP) == 0))
	{
	  clib_error ("fixme");
	}

      /* next */
      rxq->next = (rxq->next + 1) & mask;
      d = rxq->descs + rxq->next;
      n_rxv++;
      rxq->n_enqueued--;
      bi++;
    }

  if (n_rxv == 0)
    goto done;

  /* refill rx ring */
  if (ad->flags & AVF_DEVICE_F_VA_DMA)
    avf_rxq_refill (vm, node, rxq, 1 /* use_va_dma */ );
  else
    avf_rxq_refill (vm, node, rxq, 0 /* use_va_dma */ );

  vlib_get_buffers (vm, to_next, bufs, n_rxv);
  n_rx_packets = n_rxv;

  vnet_buffer (bt)->sw_if_index[VLIB_RX] = ad->sw_if_index;
  vnet_buffer (bt)->sw_if_index[VLIB_TX] = ~0;

  n_rx_bytes = avf_process_rx_burst (vm, node, bt, ptd->rx_vector, bufs,
				     n_rxv);

  /* packet trace if enabled */
  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node))))
    {
      u32 n_left = n_rx_packets;
      bi = to_next;
      while (n_trace && n_left)
	{
	  vlib_buffer_t *b;
	  avf_input_trace_t *tr;
	  b = vlib_get_buffer (vm, bi[0]);
	  vlib_trace_buffer (vm, node, next_index, b, /* follow_chain */ 0);
	  tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	  tr->next_index = next_index;
	  tr->hw_if_index = ad->hw_if_index;
	  clib_memcpy_fast (&tr->rxve, rxve, sizeof (avf_rx_vector_entry_t));

	  /* next */
	  n_trace--;
	  n_left--;
	  bi++;
	}
      vlib_set_trace_count (vm, node, n_trace);
    }

  if (PREDICT_TRUE (next_index == VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT))
    {
      vlib_next_frame_t *nf;
      vlib_frame_t *f;
      ethernet_input_frame_t *ef;
      nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
      f = vlib_get_frame (vm, nf->frame_index);
      f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;

      ef = vlib_frame_scalar_args (f);
      ef->sw_if_index = ad->sw_if_index;
      ef->hw_if_index = ad->hw_if_index;

      if ((or_error & (1 << 3)) == 0)
	f->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK;
    }
  n_left_to_next -= n_rx_packets;
  vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters
				   + VNET_INTERFACE_COUNTER_RX, thr_idx,
				   ad->hw_if_index, n_rx_packets, n_rx_bytes);

done:
  return n_rx_packets;
}

VLIB_NODE_FN (avf_input_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  u32 n_rx = 0;
  avf_main_t *am = &avf_main;
  vnet_device_input_runtime_t *rt = (void *) node->runtime_data;
  vnet_device_and_queue_t *dq;

  foreach_device_and_queue (dq, rt->devices_and_queues)
  {
    avf_device_t *ad;
    ad = vec_elt_at_index (am->devices, dq->dev_instance);
    if ((ad->flags & AVF_DEVICE_F_ADMIN_UP) == 0)
      continue;
    n_rx += avf_device_input_inline (vm, node, frame, ad, dq->queue_id);
  }
  return n_rx;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (avf_input_node) = {
  .name = "avf-input",
  .sibling_of = "device-input",
  .format_trace = format_avf_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_errors = AVF_INPUT_N_ERROR,
  .error_strings = avf_input_error_strings,
};

/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
