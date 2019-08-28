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

#include <af_xdp/af_xdp.h>
#include <af_xdp/xsk_common.h>

#define foreach_af_xdp_rx_func_error         \
_(_GET_NEXT_FRAME, "get next frame error")   \
_(_FQ_RESERVE,     "FQ reserve fatal error")

typedef enum
{
#define _(f,s) AF_XDP_RX_ERROR_##f,
  foreach_af_xdp_rx_func_error
#undef _
    AF_XDP_RX_N_ERROR,
} af_xdp_rx_func_error_t;

static char *af_xdp_rx_func_error_strings[] = {
#define _(n,s) s,
  foreach_af_xdp_rx_func_error
#undef _
};

static_always_inline void
add_trace (uword trace_cnt, vlib_main_t * vm, vlib_node_runtime_t * node,
	   vlib_buffer_t * buffer, u32 next_index, u32 hw_if_index)
{
  af_xdp_input_trace_t *tr;
  vlib_trace_buffer (vm, node, next_index, buffer, /* follow_chain */ 0);
  vlib_set_trace_count (vm, node, trace_cnt);
  tr = vlib_add_trace (vm, node, buffer, sizeof (*tr));
  tr->next_index = next_index;
  tr->hw_if_index = hw_if_index;
}

static_always_inline void
buffer_add_to_chain (vlib_main_t * vm, u32 bi, u32 first_bi, u32 prev_bi)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vlib_buffer_t *first_b = vlib_get_buffer (vm, first_bi);
  vlib_buffer_t *prev_b = vlib_get_buffer (vm, prev_bi);

  /* update first buffer */
  first_b->total_length_not_including_first_buffer += b->current_length;

  /* update previous buffer */
  prev_b->next_buffer = bi;
  prev_b->flags |= VLIB_BUFFER_NEXT_PRESENT;

  /* update current buffer */
  b->next_buffer = 0;
}

static_always_inline u32
refill_rx_buffer (vlib_main_t * vm, u32 thread_index)
{
  af_xdp_main_t *am = &af_xdp_main;
  u32 n_free_bufs = vec_len (am->rx_buffers[thread_index]);

  /* VLIB_FRAME_SIZE * 3 because maximum xdp frame size is 4 KB
   * // TODO is vpp buffer size always 1500 B ?
   *
   */
#define RX_BUFFERS_CNT (VLIB_FRAME_SIZE * 3)

  if (n_free_bufs < RX_BUFFERS_CNT)
    {
      vec_validate (am->rx_buffers[thread_index], RX_BUFFERS_CNT);

      n_free_bufs +=
	vlib_buffer_alloc (vm, &am->rx_buffers[thread_index][n_free_bufs],
			   RX_BUFFERS_CNT - n_free_bufs);

      _vec_len (am->rx_buffers[thread_index]) = n_free_bufs;
    }

  return n_free_bufs;

#undef RX_BUFFERS_CNT
}

static_always_inline void
refill_fq (vlib_main_t * vm, vlib_node_runtime_t * node,
	   struct xsk_socket_info *xsk)
{
  u32 stock_frames, i, idx_fq = 0;
  int rv;

  /* Stuff the ring with as much frames as possible */
  stock_frames = xsk_prod_nb_free (&xsk->umem->fq,
				   xsk_umem_free_rx_frames (xsk));

  if (stock_frames)
    {
      rv = xsk_ring_prod__reserve (&xsk->umem->fq, stock_frames, &idx_fq);

      if (rv != stock_frames)
	vlib_error_count (vm, node->node_index, AF_XDP_RX_ERROR__FQ_RESERVE,
			  1);

      for (i = 0; i < stock_frames; i++)
	*xsk_ring_prod__fill_addr (&xsk->umem->fq, idx_fq++) =
	  xsk_alloc_umem_rx_frame (xsk);

      xsk_ring_prod__submit (&xsk->umem->fq, stock_frames);
    }
}

static_always_inline uword
rxq_deq (vlib_main_t * vm, vlib_node_runtime_t * node,
	 struct xsk_socket_info *xsk, af_xdp_device_t * ad,
	 u32 rx_idx, u32 batch_size)
{
  af_xdp_main_t *am = &af_xdp_main;
  uword n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  u32 n_free_bufs;
  u32 *to_next = 0;
  uword n_trace = vlib_get_trace_count (vm, node);
  u32 thread_index = vm->thread_index;
  u32 n_buffer_bytes = vlib_buffer_get_default_data_size (vm);
  vlib_buffer_t *b0 = 0, *first_b0 = 0;
  u32 n_left_to_next, next0;

  if (ad->per_interface_next_index != ~0)
    next_index = ad->per_interface_next_index;

  n_free_bufs = refill_rx_buffer (vm, thread_index);

  vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

  while (PREDICT_TRUE (batch_size--))
    {
      if (PREDICT_FALSE (0 == n_left_to_next))
	{
	  vlib_put_next_frame (vm, node, next_index, n_left_to_next);
	  vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
	  if (PREDICT_FALSE (0 == n_left_to_next))
	    {
	      vlib_error_count (vm, node->node_index,
				AF_XDP_RX_ERROR__GET_NEXT_FRAME, 1);
	      break;
	    }
	}

      u64 addr = xsk_ring_cons__rx_desc (&xsk->rx, rx_idx)->addr;
      u32 pktdata_len = xsk_ring_cons__rx_desc (&xsk->rx, rx_idx)->len;
      u8 *pktdata = xsk_umem__get_data (xsk->umem->buffer, addr);

      u32 offset = 0;
      u32 bi0 = 0, first_bi0 = 0, prev_bi0;
      while (PREDICT_TRUE (pktdata_len))
	{
	  n_free_bufs--;
	  prev_bi0 = bi0;
	  bi0 = am->rx_buffers[thread_index][n_free_bufs];
	  b0 = vlib_get_buffer (vm, bi0);
	  _vec_len (am->rx_buffers[thread_index]) = n_free_bufs;

	  /* copy data */
	  u32 bytes_to_copy =
	    pktdata_len > n_buffer_bytes ? n_buffer_bytes : pktdata_len;
	  b0->current_data = 0;
	  clib_memcpy_fast (((u8 *) vlib_buffer_get_current (b0)),
			    pktdata + offset, bytes_to_copy);
	  b0->current_length = bytes_to_copy;

	  if (offset == 0)
	    {
	      b0->total_length_not_including_first_buffer = 0;
	      b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
	      vnet_buffer (b0)->sw_if_index[VLIB_RX] = ad->sw_if_index;
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	      first_bi0 = bi0;
	      first_b0 = vlib_get_buffer (vm, first_bi0);
	    }
	  else
	    buffer_add_to_chain (vm, bi0, first_bi0, prev_bi0);

	  offset += bytes_to_copy;
	  pktdata_len -= bytes_to_copy;
	}

      xsk_free_umem_rx_frame (xsk, addr);

      n_rx_packets++;
      n_rx_bytes += xsk_ring_cons__rx_desc (&xsk->rx, rx_idx)->len;
      to_next[0] = first_bi0;
      to_next++;
      n_left_to_next--;
      rx_idx++;

      next0 = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
      /* redirect if feature path enabled */
      vnet_feature_start_device_input_x1 (ad->sw_if_index, &next0, first_b0);

      /* trace */
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (first_b0);
      if (PREDICT_FALSE (n_trace > 0))
	add_trace (--n_trace, vm, node, first_b0, next0, ad->hw_if_index);

      /* enque and take next packet */
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
				       n_left_to_next, first_bi0, next0);
    }

  vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  vlib_increment_combined_counter
    (vnet_get_main ()->interface_main.combined_sw_if_counters
     + VNET_INTERFACE_COUNTER_RX,
     vlib_get_thread_index (), ad->hw_if_index, n_rx_packets, n_rx_bytes);

  return n_rx_packets;
}

static_always_inline uword
af_xdp_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			    af_xdp_device_t * ad)
{
  uword n_rx_packets = 0;
  u32 n_batch;
  u32 rx_idx;
  struct xsk_socket_info *xsk = ad->xsk;

  n_batch = xsk_ring_cons__peek (&xsk->rx, RX_BATCH_SIZE, &rx_idx);
  if (PREDICT_FALSE (!n_batch))
    return 0;

  n_rx_packets = rxq_deq (vm, node, xsk, ad, rx_idx, n_batch);

  refill_fq (vm, node, xsk);

  xsk_ring_cons__release (&xsk->rx, n_batch);

  vnet_device_increment_rx_packets (vm->thread_index, n_rx_packets);

  return n_rx_packets;
}

VLIB_NODE_FN (af_xdp_input_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  u32 n_rx = 0;
  af_xdp_main_t *am = &af_xdp_main;
  vnet_device_input_runtime_t *rt = (void *) node->runtime_data;
  vnet_device_and_queue_t *dq;

  foreach_device_and_queue (dq, rt->devices_and_queues)
  {
    af_xdp_device_t *ad;
    ad = vec_elt_at_index (am->devices, dq->dev_instance);
    if ((ad->flags & AF_XDP_DEVICE_F_ADMIN_UP) == 0)
      continue;
    n_rx += af_xdp_device_input_inline (vm, node, ad);
  }
  return n_rx;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (af_xdp_input_node) = {
  .name = "af-xdp-input",
  .sibling_of = "device-input",
  .format_trace = format_af_xdp_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_errors = AF_XDP_RX_N_ERROR,
  .error_strings = af_xdp_rx_func_error_strings,
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
