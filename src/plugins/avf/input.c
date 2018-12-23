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

#if 0
#include </home/damarion/cisco/vpp-sandbox/include/tscmarks.h>
#else
#define tsc_mark(...)
#define tsc_print(...)
#endif

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

#define AVF_RX_DESC_STATUS(x)		(1ULL << x)
#define AVF_RX_DESC_STATUS_DD		AVF_RX_DESC_STATUS(0)
#define AVF_RX_DESC_STATUS_EOP		AVF_RX_DESC_STATUS(1)

#define AVF_RX_DESC_ERROR_IPE		(1ULL << (19 + 3))
#define AVF_RX_DESC_ERROR_L4E		(1ULL << (19 + 4))

#define AVF_INPUT_REFILL_TRESHOLD 32

static_always_inline void
avf_rx_desc_write (avf_rx_desc_t * d, u64 addr)
{
#ifdef CLIB_HAVE_VEC256
  u64x4 v = { addr, 0, 0, 0 };
  u64x4_store_unaligned (v, (void *) d);
#else
  d->qword[0] = addr;
  d->qword[1] = 0;
#endif
}

static_always_inline void
avf_rxq_refill (vlib_main_t * vm, vlib_node_runtime_t * node, avf_rxq_t * rxq,
		int use_va_dma)
{
  u16 n_refill, mask, n_alloc, slot, size;
  vlib_buffer_t *b[8];
  avf_rx_desc_t *d, *first_d;
  void *p[8];

  size = rxq->size;
  mask = size - 1;
  n_refill = mask - rxq->n_enqueued;
  if (PREDICT_TRUE (n_refill <= AVF_INPUT_REFILL_TRESHOLD))
    return;

  slot = (rxq->next - n_refill - 1) & mask;

  n_refill &= ~7;		/* round to 8 */
  n_alloc = vlib_buffer_alloc_to_ring (vm, rxq->bufs, slot, size, n_refill);

  if (PREDICT_FALSE (n_alloc != n_refill))
    {
      vlib_error_count (vm, node->node_index,
			AVF_INPUT_ERROR_BUFFER_ALLOC, 1);
      if (n_alloc)
	vlib_buffer_free_from_ring (vm, rxq->bufs, slot, size, n_alloc);
      return;
    }

  rxq->n_enqueued += n_alloc;
  first_d = rxq->descs;

  ASSERT (slot % 8 == 0);

  while (n_alloc >= 8)
    {
      d = first_d + slot;

      if (use_va_dma)
	{
	  vlib_get_buffers_with_offset (vm, rxq->bufs + slot, p, 8,
					sizeof (vlib_buffer_t));
	  avf_rx_desc_write (d + 0, pointer_to_uword (p[0]));
	  avf_rx_desc_write (d + 1, pointer_to_uword (p[1]));
	  avf_rx_desc_write (d + 2, pointer_to_uword (p[2]));
	  avf_rx_desc_write (d + 3, pointer_to_uword (p[3]));
	  avf_rx_desc_write (d + 4, pointer_to_uword (p[4]));
	  avf_rx_desc_write (d + 5, pointer_to_uword (p[5]));
	  avf_rx_desc_write (d + 6, pointer_to_uword (p[6]));
	  avf_rx_desc_write (d + 7, pointer_to_uword (p[7]));
	}
      else
	{
	  vlib_get_buffers (vm, rxq->bufs + slot, b, 8);
	  avf_rx_desc_write (d + 0, vlib_buffer_get_pa (vm, b[0]));
	  avf_rx_desc_write (d + 1, vlib_buffer_get_pa (vm, b[1]));
	  avf_rx_desc_write (d + 2, vlib_buffer_get_pa (vm, b[2]));
	  avf_rx_desc_write (d + 3, vlib_buffer_get_pa (vm, b[3]));
	  avf_rx_desc_write (d + 4, vlib_buffer_get_pa (vm, b[4]));
	  avf_rx_desc_write (d + 5, vlib_buffer_get_pa (vm, b[5]));
	  avf_rx_desc_write (d + 6, vlib_buffer_get_pa (vm, b[6]));
	  avf_rx_desc_write (d + 7, vlib_buffer_get_pa (vm, b[7]));
	}

      /* next */
      slot = (slot + 8) & mask;
      n_alloc -= 8;
    }

  CLIB_MEMORY_STORE_BARRIER ();
  *(rxq->qrx_tail) = slot;
}

static_always_inline uword
avf_process_rx_burst (vlib_main_t * vm, vlib_node_runtime_t * node,
		      vlib_buffer_t * bt, u64 * qw1,
		      vlib_buffer_t ** b, u32 n_left)
{
  uword n_rx_bytes = 0;

  while (n_left >= 4)
    {
      if (n_left >= 12)
	{
	  vlib_prefetch_buffer_header (b[8], LOAD);
	  vlib_prefetch_buffer_header (b[9], LOAD);
	  vlib_prefetch_buffer_header (b[10], LOAD);
	  vlib_prefetch_buffer_header (b[11], LOAD);
	}

      n_rx_bytes += b[0]->current_length = qw1[0] >> 38;
      n_rx_bytes += b[1]->current_length = qw1[1] >> 38;
      n_rx_bytes += b[2]->current_length = qw1[2] >> 38;
      n_rx_bytes += b[3]->current_length = qw1[3] >> 38;

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
      qw1 += 4;
      b += 4;
      n_left -= 4;
    }
  while (n_left)
    {
      n_rx_bytes += b[0]->current_length = qw1[0] >> 38;

      clib_memcpy_fast (vnet_buffer (b[0])->sw_if_index,
			vnet_buffer (bt)->sw_if_index, 2 * sizeof (u32));

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);

      /* next */
      qw1 += 1;
      b += 1;
      n_left -= 1;
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
  u32 n_trace, n_rx_packets = 0, n_rx_bytes = 0;
  u16 n_desc = 0;
  u64 or_qw1 = 0;
  u32 *bi, *to_next, n_left_to_next;
  vlib_buffer_t *bufs[AVF_RX_VECTOR_SZ];
  vlib_buffer_t *bt = &ptd->buffer_template;
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  u64 qw1s[AVF_RX_VECTOR_SZ];
  u16 next = rxq->next;
  u16 size = rxq->size;
  u16 mask = size - 1;
  avf_rx_desc_t *d, *fd = rxq->descs;
#ifdef CLIB_HAVE_VEC256
  u64x4 q1x4, or_q1x4 = { 0 };
  u64x4 dd_eop_mask4 = u64x4_splat (AVF_RX_DESC_STATUS_DD |
				    AVF_RX_DESC_STATUS_EOP);
#endif

  /* is there anything on the ring */
  d = fd + next;
  if ((d->qword[1] & AVF_RX_DESC_STATUS_DD) == 0)
    goto done;

  tsc_mark ("start");

  if (PREDICT_FALSE (ad->per_interface_next_index != ~0))
    next_index = ad->per_interface_next_index;
  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

  /* fetch up to AVF_RX_VECTOR_SZ from the rx ring, unflatten them and
     copy needed data from descriptor to rx vector */
  bi = to_next;

  tsc_mark ("desc");

  while (n_desc < AVF_RX_VECTOR_SZ)
    {
      if (next + 11 < size)
	{
	  int stride = 8;
	  CLIB_PREFETCH ((void *) (fd + (next + stride)),
			 CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH ((void *) (fd + (next + stride + 1)),
			 CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH ((void *) (fd + (next + stride + 2)),
			 CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH ((void *) (fd + (next + stride + 3)),
			 CLIB_CACHE_LINE_BYTES, LOAD);
	}

#ifdef CLIB_HAVE_VEC256
      if (n_desc >= AVF_RX_VECTOR_SZ - 4 || next >= size - 4)
	goto one_by_one;

      q1x4 = u64x4_gather ((void *) &d[0].qword[1], (void *) &d[1].qword[1],
			   (void *) &d[2].qword[1], (void *) &d[3].qword[1]);

      /* not all packets are ready or at least one of them is chained */
      if (!u64x4_is_equal (q1x4 & dd_eop_mask4, dd_eop_mask4))
	goto one_by_one;

      or_q1x4 |= q1x4;
      u64x4_store_unaligned (q1x4, qw1s + n_desc);
      clib_memcpy_fast (bi, rxq->bufs + next, 4 * sizeof (u32));

      /* next */
      next = (next + 4) & mask;
      d = fd + next;
      n_desc += 4;
      bi += 4;
      continue;
    one_by_one:
#endif
      CLIB_PREFETCH ((void *) (fd + ((next + 8) & mask)),
		     CLIB_CACHE_LINE_BYTES, LOAD);
      if ((d->qword[1] & AVF_RX_DESC_STATUS_DD) == 0)
	break;

      or_qw1 |= qw1s[n_desc] = d[0].qword[1];
      bi[0] = rxq->bufs[next];

      /* deal with chained buffers */
      while (PREDICT_FALSE ((d->qword[1] & AVF_RX_DESC_STATUS_EOP) == 0))
	{
	  clib_error ("fixme");
	}

      /* next */
      next = (next + 1) & mask;
      d = fd + next;
      n_desc++;
      bi++;
    }

  if (n_desc == 0)
    goto done;

  rxq->next = next;
  rxq->n_enqueued -= n_desc;

#ifdef CLIB_HAVE_VEC256
  or_qw1 |= or_q1x4[0] | or_q1x4[1] | or_q1x4[2] | or_q1x4[3];
#endif

  tsc_mark ("refill");
  /* refill rx ring */
  if (ad->flags & AVF_DEVICE_F_VA_DMA)
    avf_rxq_refill (vm, node, rxq, 1 /* use_va_dma */ );
  else
    avf_rxq_refill (vm, node, rxq, 0 /* use_va_dma */ );

  vlib_get_buffers (vm, to_next, bufs, n_desc);
  n_rx_packets = n_desc;

  vnet_buffer (bt)->sw_if_index[VLIB_RX] = ad->sw_if_index;
  vnet_buffer (bt)->sw_if_index[VLIB_TX] = ~0;

  tsc_mark ("burst");
  n_rx_bytes = avf_process_rx_burst (vm, node, bt, qw1s, bufs, n_desc);

  /* packet trace if enabled */
  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node))))
    {
      u32 n_left = n_rx_packets;
      bi = to_next;
      u64 *qw1 = qw1s;
      while (n_trace && n_left)
	{
	  vlib_buffer_t *b;
	  avf_input_trace_t *tr;
	  b = vlib_get_buffer (vm, bi[0]);
	  vlib_trace_buffer (vm, node, next_index, b, /* follow_chain */ 0);
	  tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	  tr->next_index = next_index;
	  tr->hw_if_index = ad->hw_if_index;
	  tr->qw1 = qw1[0];

	  /* next */
	  n_trace--;
	  n_left--;
	  bi++;
	  qw1++;
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

      if ((or_qw1 & AVF_RX_DESC_ERROR_IPE) == 0)
	f->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK;
    }
  tsc_mark ("enq");
  n_left_to_next -= n_rx_packets;
  vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters
				   + VNET_INTERFACE_COUNTER_RX, thr_idx,
				   ad->hw_if_index, n_rx_packets, n_rx_bytes);

done:
  tsc_mark (0);
  tsc_print (3, n_rx_packets);
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
