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

#include <rdma/rdma.h>

#define foreach_rdma_input_error \
  _(BUFFER_ALLOC, "buffer alloc error")

typedef enum
{
#define _(f,s) RDMA_INPUT_ERROR_##f,
  foreach_rdma_input_error
#undef _
    RDMA_INPUT_N_ERROR,
} rdma_input_error_t;

static __clib_unused char *rdma_input_error_strings[] = {
#define _(n,s) s,
  foreach_rdma_input_error
#undef _
};

static_always_inline void
rdma_device_input_refill (vlib_main_t * vm, rdma_device_t * rd,
			  rdma_rxq_t * rxq)
{
  u32 n_alloc, n;
  struct ibv_sge sg_entry;
  struct ibv_recv_wr wr, *bad_wr;
  u32 buffers[VLIB_FRAME_SIZE];

  if (rxq->n_enq >= rxq->size)
    return;

  n_alloc = clib_min (VLIB_FRAME_SIZE, rxq->size - rxq->n_enq);
  n_alloc = vlib_buffer_alloc (vm, buffers, n_alloc);

  sg_entry.length = vlib_buffer_get_default_data_size (vm);
  sg_entry.lkey = rd->mr->lkey;
  wr.num_sge = 1;
  wr.sg_list = &sg_entry;
  wr.next = NULL;
  for (n = 0; n < n_alloc; n++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, buffers[n]);
      sg_entry.addr = vlib_buffer_get_va (b);
      wr.wr_id = buffers[n];
      if (ibv_post_recv (rxq->qp, &wr, &bad_wr) != 0)
	vlib_buffer_free (vm, buffers + n, 1);
      else
	rxq->n_enq++;
    }
}

static_always_inline uword
rdma_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * frame, rdma_device_t * rd, u16 qid)
{
  vnet_main_t *vnm = vnet_get_main ();
  rdma_rxq_t *rxq = vec_elt_at_index (rd->rxqs, qid);
  u32 n_trace;
  struct ibv_wc wc[VLIB_FRAME_SIZE];
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  u32 *bi, *to_next, n_left_to_next;
  int i;
  u32 n_rx_packets = 0, n_rx_bytes = 0;

  n_rx_packets = ibv_poll_cq (rxq->cq, VLIB_FRAME_SIZE, wc);

  if (n_rx_packets <= 0)
    rdma_device_input_refill (vm, rd, rxq);

  if (PREDICT_FALSE (rd->per_interface_next_index != ~0))
    next_index = rd->per_interface_next_index;

  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

  for (i = 0; i < n_rx_packets; i++)
    {
      u32 bi = wc[i].wr_id;
      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
      b->current_length = wc[i].byte_len;
      vnet_buffer (b)->sw_if_index[VLIB_RX] = rd->sw_if_index;
      vnet_buffer (b)->sw_if_index[VLIB_TX] = ~0;
      to_next[i] = bi;
      n_rx_bytes += wc[i].byte_len;
    }

  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node))))
    {
      u32 n_left = n_rx_packets, i = 0;
      bi = to_next;

      while (n_trace && n_left)
	{
	  vlib_buffer_t *b;
	  rdma_input_trace_t *tr;
	  b = vlib_get_buffer (vm, bi[0]);
	  vlib_trace_buffer (vm, node, next_index, b, /* follow_chain */ 0);
	  tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	  tr->next_index = next_index;
	  tr->hw_if_index = rd->hw_if_index;

	  /* next */
	  n_trace--;
	  n_left--;
	  bi++;
	  i++;
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
      ef->sw_if_index = rd->sw_if_index;
      ef->hw_if_index = rd->hw_if_index;
      //f->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK;
    }

  n_left_to_next -= n_rx_packets;
  vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  vlib_increment_combined_counter
    (vnm->interface_main.combined_sw_if_counters +
     VNET_INTERFACE_COUNTER_RX, vm->thread_index,
     rd->hw_if_index, n_rx_packets, n_rx_bytes);

  rxq->n_enq -= n_rx_packets;
  rdma_device_input_refill (vm, rd, rxq);

  return n_rx_packets;
}

VLIB_NODE_FN (rdma_input_node) (vlib_main_t * vm,
				vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  u32 n_rx = 0;
  rdma_main_t *rm = &rdma_main;
  vnet_device_input_runtime_t *rt = (void *) node->runtime_data;
  vnet_device_and_queue_t *dq;

  foreach_device_and_queue (dq, rt->devices_and_queues)
  {
    rdma_device_t *rd;
    rd = vec_elt_at_index (rm->devices, dq->dev_instance);
    if ((rd->flags & RDMA_DEVICE_F_ADMIN_UP) == 0)
      continue;
    n_rx += rdma_device_input_inline (vm, node, frame, rd, dq->queue_id);
  }
  return n_rx;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (rdma_input_node) = {
  .name = "rdma-input",
  .sibling_of = "device-input",
  .format_trace = format_rdma_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_errors = RDMA_INPUT_N_ERROR,
  .error_strings = rdma_input_error_strings,
};

/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
