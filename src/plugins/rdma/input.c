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
  u32 buffers[VLIB_FRAME_SIZE], *bi = buffers;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  struct ibv_recv_wr wr[VLIB_FRAME_SIZE], *w = wr;
  struct ibv_sge sge[VLIB_FRAME_SIZE], *s = sge;

  if (PREDICT_FALSE (rxq->n_enq >= rxq->size))
    return;

  n_alloc = clib_min (VLIB_FRAME_SIZE, rxq->size - rxq->n_enq);
  n_alloc = n = vlib_buffer_alloc (vm, buffers, n_alloc);
  vlib_get_buffers (vm, buffers, bufs, n_alloc);

  while (n >= 4)
    {
      if (PREDICT_TRUE (n >= 8))
	{
	  CLIB_PREFETCH (&s[4 + 0], 4 * sizeof (s[0]), STORE);
	  CLIB_PREFETCH (&w[4 + 0], 4 * sizeof (w[0]), STORE);
	}

      s[0].addr = vlib_buffer_get_va (b[0]);
      s[0].length = vlib_buffer_get_default_data_size (vm);
      s[0].lkey = rd->mr->lkey;

      s[1].addr = vlib_buffer_get_va (b[1]);
      s[1].length = vlib_buffer_get_default_data_size (vm);
      s[1].lkey = rd->mr->lkey;

      s[2].addr = vlib_buffer_get_va (b[2]);
      s[2].length = vlib_buffer_get_default_data_size (vm);
      s[2].lkey = rd->mr->lkey;

      s[3].addr = vlib_buffer_get_va (b[3]);
      s[3].length = vlib_buffer_get_default_data_size (vm);
      s[3].lkey = rd->mr->lkey;

      w[0].wr_id = bi[0];
      w[0].next = &w[0] + 1;
      w[0].sg_list = &s[0];
      w[0].num_sge = 1;

      w[1].wr_id = bi[1];
      w[1].next = &w[1] + 1;
      w[1].sg_list = &s[1];
      w[1].num_sge = 1;

      w[2].wr_id = bi[2];
      w[2].next = &w[2] + 1;
      w[2].sg_list = &s[2];
      w[2].num_sge = 1;

      w[3].wr_id = bi[3];
      w[3].next = &w[3] + 1;
      w[3].sg_list = &s[3];
      w[3].num_sge = 1;

      s += 4;
      bi += 4;
      w += 4;
      b += 4;
      n -= 4;
    }

  while (n >= 1)
    {
      s[0].addr = vlib_buffer_get_va (b[0]);
      s[0].length = vlib_buffer_get_default_data_size (vm);
      s[0].lkey = rd->mr->lkey;

      w[0].wr_id = bi[0];
      w[0].next = &w[0] + 1;
      w[0].sg_list = &s[0];
      w[0].num_sge = 1;

      s += 1;
      bi += 1;
      w += 1;
      b += 1;
      n -= 1;
    }

  w[-1].next = 0;		/* fix next pointer in WR linked-list last item */

  w = wr;
  ibv_post_wq_recv (rxq->wq, wr, &w);
  n = wr == w ? n_alloc : (uintptr_t) (w - wr);

  if (PREDICT_FALSE (n != n_alloc))
    vlib_buffer_free (vm, buffers + n, n_alloc - n);

  rxq->n_enq += n;
}

static_always_inline void
rdma_device_input_trace (vlib_main_t * vm, vlib_node_runtime_t * node,
			 const rdma_device_t * rd, u32 n_left, const u32 * bi)
{
  u32 n_trace, i;

  if (PREDICT_TRUE (0 == (n_trace = vlib_get_trace_count (vm, node))))
    return;

  i = 0;
  while (n_trace && n_left)
    {
      vlib_buffer_t *b;
      rdma_input_trace_t *tr;
      b = vlib_get_buffer (vm, bi[0]);
      vlib_trace_buffer (vm, node, rd->per_interface_next_index, b,
			 /* follow_chain */ 0);
      tr = vlib_add_trace (vm, node, b, sizeof (*tr));
      tr->next_index = rd->per_interface_next_index;
      tr->hw_if_index = rd->hw_if_index;

      /* next */
      n_trace--;
      n_left--;
      bi++;
      i++;
    }
  vlib_set_trace_count (vm, node, n_trace);
}

static_always_inline void
rdma_device_input_ethernet (vlib_main_t * vm, vlib_node_runtime_t * node,
			    const rdma_device_t * rd)
{
  vlib_next_frame_t *nf;
  vlib_frame_t *f;
  ethernet_input_frame_t *ef;

  if (PREDICT_FALSE
      (VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT != rd->per_interface_next_index))
    return;

  nf =
    vlib_node_runtime_get_next_frame (vm, node, rd->per_interface_next_index);
  f = vlib_get_frame (vm, nf->frame_index);
  f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;
  /* FIXME: f->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK; */

  ef = vlib_frame_scalar_args (f);
  ef->sw_if_index = rd->sw_if_index;
  ef->hw_if_index = rd->hw_if_index;
}

static_always_inline u32
rdma_device_input_load_wc (u32 n_left_from, struct ibv_wc * wc, u32 * to_next,
			   u32 * bufsz)
{
  u32 n_rx_bytes[4] = { 0 };

  while (n_left_from >= 4)
    {
      if (PREDICT_TRUE (n_left_from >= 8))
	{
	  CLIB_PREFETCH (&wc[4 + 0], CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (&wc[4 + 1], CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (&wc[4 + 2], CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (&wc[4 + 3], CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (&bufsz[4 + 0], 4 * sizeof (bufsz[0]), STORE);
	  CLIB_PREFETCH (&to_next[4 + 0], 4 * sizeof (to_next[0]), STORE);
	}

      to_next[0] = wc[0].wr_id;
      to_next[1] = wc[1].wr_id;
      to_next[2] = wc[2].wr_id;
      to_next[3] = wc[3].wr_id;

      bufsz[0] = wc[0].byte_len;
      bufsz[1] = wc[1].byte_len;
      bufsz[2] = wc[2].byte_len;
      bufsz[3] = wc[3].byte_len;

      n_rx_bytes[0] += wc[0].byte_len;
      n_rx_bytes[1] += wc[1].byte_len;
      n_rx_bytes[2] += wc[2].byte_len;
      n_rx_bytes[3] += wc[3].byte_len;

      wc += 4;
      to_next += 4;
      bufsz += 4;
      n_left_from -= 4;
    }

  while (n_left_from >= 1)
    {
      to_next[0] = wc[0].wr_id;
      bufsz[0] = wc[0].byte_len;
      n_rx_bytes[0] += wc[0].byte_len;

      wc += 1;
      to_next += 1;
      bufsz += 1;
      n_left_from -= 1;
    }

  return n_rx_bytes[0] + n_rx_bytes[1] + n_rx_bytes[2] + n_rx_bytes[3];
}

static_always_inline void
rdma_device_input_bufs_init (u32 n_left_from, vlib_buffer_t ** bufs,
			     u32 * bufsz, u32 sw_if_index)
{
  while (n_left_from >= 4)
    {
      if (PREDICT_TRUE (n_left_from >= 8))
	{
	  vlib_prefetch_buffer_header (bufs[4 + 0], STORE);
	  vlib_prefetch_buffer_header (bufs[4 + 1], STORE);
	  vlib_prefetch_buffer_header (bufs[4 + 2], STORE);
	  vlib_prefetch_buffer_header (bufs[4 + 3], STORE);
	  CLIB_PREFETCH (&bufsz[4 + 0], 4 * sizeof (bufsz[0]), LOAD);
	}

      bufs[0]->current_length = bufsz[0];
      bufs[1]->current_length = bufsz[1];
      bufs[2]->current_length = bufsz[2];
      bufs[3]->current_length = bufsz[3];

      vnet_buffer (bufs[0])->sw_if_index[VLIB_RX] = sw_if_index;
      vnet_buffer (bufs[1])->sw_if_index[VLIB_RX] = sw_if_index;
      vnet_buffer (bufs[2])->sw_if_index[VLIB_RX] = sw_if_index;
      vnet_buffer (bufs[3])->sw_if_index[VLIB_RX] = sw_if_index;

      vnet_buffer (bufs[0])->sw_if_index[VLIB_TX] = ~0;
      vnet_buffer (bufs[1])->sw_if_index[VLIB_TX] = ~0;
      vnet_buffer (bufs[2])->sw_if_index[VLIB_TX] = ~0;
      vnet_buffer (bufs[3])->sw_if_index[VLIB_TX] = ~0;

      bufs += 4;
      bufsz += 4;
      n_left_from -= 4;
    }

  while (n_left_from >= 1)
    {
      bufs[0]->current_length = bufsz[0];
      vnet_buffer (bufs[0])->sw_if_index[VLIB_RX] = sw_if_index;
      vnet_buffer (bufs[0])->sw_if_index[VLIB_TX] = ~0;

      bufs += 1;
      bufsz += 1;
      n_left_from -= 1;
    }
}

static_always_inline uword
rdma_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * frame, rdma_device_t * rd, u16 qid)
{
  vnet_main_t *vnm = vnet_get_main ();
  rdma_rxq_t *rxq = vec_elt_at_index (rd->rxqs, qid);
  struct ibv_wc wc[VLIB_FRAME_SIZE];
  u32 bufsz[VLIB_FRAME_SIZE];
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u32 *to_next, n_left_to_next;
  u32 n_rx_packets, n_rx_bytes;

  n_rx_packets = ibv_poll_cq (rxq->cq, VLIB_FRAME_SIZE, wc);

  if (PREDICT_FALSE (n_rx_packets <= 0))
    {
      rdma_device_input_refill (vm, rd, rxq);
      return 0;
    }

  vlib_get_new_next_frame (vm, node, rd->per_interface_next_index, to_next,
			   n_left_to_next);
  n_rx_bytes = rdma_device_input_load_wc (n_rx_packets, wc, to_next, bufsz);
  vlib_get_buffers (vm, to_next, bufs, n_rx_packets);
  rdma_device_input_bufs_init (n_rx_packets, bufs, bufsz, rd->sw_if_index);
  rdma_device_input_trace (vm, node, rd, n_rx_packets, to_next);
  rdma_device_input_ethernet (vm, node, rd);

  vlib_put_next_frame (vm, node, rd->per_interface_next_index,
		       n_left_to_next - n_rx_packets);

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
    if (PREDICT_TRUE (rd->flags & RDMA_DEVICE_F_ADMIN_UP))
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
