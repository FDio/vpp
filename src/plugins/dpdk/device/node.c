/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
 */
#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/xxhash.h>

#include <vnet/ethernet/ethernet.h>
#include <dpdk/device/dpdk.h>
#include <vnet/classify/vnet_classify.h>
#include <vnet/mpls/packet.h>
#include <vnet/handoff.h>
#include <vnet/devices/devices.h>
#include <vnet/feature/feature.h>

#include <dpdk/device/dpdk_priv.h>

static char *dpdk_error_strings[] = {
#define _(n,s) s,
  foreach_dpdk_error
#undef _
};

/* make sure all flags we need are stored in lower 8 bits */
STATIC_ASSERT ((PKT_RX_IP_CKSUM_BAD | PKT_RX_FDIR) <
	       256, "dpdk flags not un lower byte, fix needed");

static_always_inline uword
dpdk_process_subseq_segs (vlib_main_t * vm, vlib_buffer_t * b,
			  struct rte_mbuf *mb)
{
  u8 nb_seg = 1;
  struct rte_mbuf *mb_seg = 0;
  vlib_buffer_t *b_seg, *b_chain = 0;
  mb_seg = mb->next;
  b_chain = b;

  if (mb->nb_segs < 2)
    return 0;

  b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  b->total_length_not_including_first_buffer = 0;

  while (nb_seg < mb->nb_segs)
    {
      ASSERT (mb_seg != 0);

      b_seg = vlib_buffer_from_rte_mbuf (mb_seg);
      vlib_buffer_init_for_pool (vm, b_seg, 0);

      /*
       * The driver (e.g. virtio) may not put the packet data at the start
       * of the segment, so don't assume b_seg->current_data == 0 is correct.
       */
      b_seg->current_data =
	(mb_seg->buf_addr + mb_seg->data_off) - (void *) b_seg->data;

      b_seg->current_length = mb_seg->data_len;
      b->total_length_not_including_first_buffer += mb_seg->data_len;

      b_chain->flags |= VLIB_BUFFER_NEXT_PRESENT;
      b_chain->next_buffer = vlib_get_buffer_index (vm, b_seg);

      b_chain = b_seg;
      mb_seg = mb_seg->next;
      nb_seg++;
    }
  return b->total_length_not_including_first_buffer;
}

static_always_inline void
dpdk_prefetch_mbuf_x4 (struct rte_mbuf *mb[])
{
  CLIB_PREFETCH (mb[0], CLIB_CACHE_LINE_BYTES, LOAD);
  CLIB_PREFETCH (mb[1], CLIB_CACHE_LINE_BYTES, LOAD);
  CLIB_PREFETCH (mb[2], CLIB_CACHE_LINE_BYTES, LOAD);
  CLIB_PREFETCH (mb[3], CLIB_CACHE_LINE_BYTES, LOAD);
}

static_always_inline void
dpdk_prefetch_buffer_x4 (struct rte_mbuf *mb[])
{
  vlib_buffer_t *b;
  b = vlib_buffer_from_rte_mbuf (mb[0]);
  CLIB_PREFETCH (b, CLIB_CACHE_LINE_BYTES, LOAD);
  b = vlib_buffer_from_rte_mbuf (mb[1]);
  CLIB_PREFETCH (b, CLIB_CACHE_LINE_BYTES, LOAD);
  b = vlib_buffer_from_rte_mbuf (mb[2]);
  CLIB_PREFETCH (b, CLIB_CACHE_LINE_BYTES, LOAD);
  b = vlib_buffer_from_rte_mbuf (mb[3]);
  CLIB_PREFETCH (b, CLIB_CACHE_LINE_BYTES, LOAD);
}

/** \brief Main DPDK input node
    @node dpdk-input

    This is the main DPDK input node: across each assigned interface,
    call rte_eth_rx_burst(...) or similar to obtain a vector of
    packets to process. Derive @c vlib_buffer_t metadata from
    <code>struct rte_mbuf</code> metadata,
    Depending on the resulting metadata: adjust <code>b->current_data,
    b->current_length </code> and dispatch directly to
    ip4-input-no-checksum, or ip6-input. Trace the packet if required.

    @param vm   vlib_main_t corresponding to the current thread
    @param node vlib_node_runtime_t
    @param f    vlib_frame_t input-node, not used.

    @par Graph mechanics: buffer metadata, next index usage

    @em Uses:
    - <code>struct rte_mbuf mb->ol_flags</code>
        - PKT_RX_IP_CKSUM_BAD

    @em Sets:
    - <code>b->error</code> if the packet is to be dropped immediately
    - <code>b->current_data, b->current_length</code>
        - adjusted as needed to skip the L2 header in  direct-dispatch cases
    - <code>vnet_buffer(b)->sw_if_index[VLIB_RX]</code>
        - rx interface sw_if_index
    - <code>vnet_buffer(b)->sw_if_index[VLIB_TX] = ~0</code>
        - required by ipX-lookup
    - <code>b->flags</code>
        - to indicate multi-segment pkts (VLIB_BUFFER_NEXT_PRESENT), etc.

    <em>Next Nodes:</em>
    - Static arcs to: error-drop, ethernet-input,
      ip4-input-no-checksum, ip6-input, mpls-input
    - per-interface redirection, controlled by
      <code>xd->per_interface_next_index</code>
*/

static_always_inline u8
dpdk_ol_flags_extract (struct rte_mbuf **mb, u8 * flags, int count)
{
  u8 rv = 0;
  int i;
  for (i = 0; i < count; i++)
    {
      /* all flags we are interested in are in lower 8 bits but
         that might change */
      flags[i] = (u8) mb[i]->ol_flags;
      rv |= flags[i];
    }
  return rv;
}

static_always_inline uword
dpdk_process_rx_burst (vlib_main_t * vm, dpdk_per_thread_data_t * ptd,
		       uword n_rx_packets, int maybe_multiseg, u8 * or_flagsp)
{
  u32 n_left = n_rx_packets;
  vlib_buffer_t *b[4];
  struct rte_mbuf **mb = ptd->mbufs;
  uword n_bytes = 0;
  u8 *flags, or_flags = 0;

  mb = ptd->mbufs;
  flags = ptd->flags;

  while (n_left >= 8)
    {
      dpdk_prefetch_buffer_x4 (mb + 4);

      b[0] = vlib_buffer_from_rte_mbuf (mb[0]);
      b[1] = vlib_buffer_from_rte_mbuf (mb[1]);
      b[2] = vlib_buffer_from_rte_mbuf (mb[2]);
      b[3] = vlib_buffer_from_rte_mbuf (mb[3]);

      clib_memcpy64_x4 (b[0], b[1], b[2], b[3], &ptd->buffer_template);

      dpdk_prefetch_mbuf_x4 (mb + 4);

      or_flags |= dpdk_ol_flags_extract (mb, flags, 4);
      flags += 4;

      b[0]->current_data = mb[0]->data_off - RTE_PKTMBUF_HEADROOM;
      n_bytes += b[0]->current_length = mb[0]->data_len;

      b[1]->current_data = mb[1]->data_off - RTE_PKTMBUF_HEADROOM;
      n_bytes += b[1]->current_length = mb[1]->data_len;

      b[2]->current_data = mb[2]->data_off - RTE_PKTMBUF_HEADROOM;
      n_bytes += b[2]->current_length = mb[2]->data_len;

      b[3]->current_data = mb[3]->data_off - RTE_PKTMBUF_HEADROOM;
      n_bytes += b[3]->current_length = mb[3]->data_len;

      if (maybe_multiseg)
	{
	  n_bytes += dpdk_process_subseq_segs (vm, b[0], mb[0]);
	  n_bytes += dpdk_process_subseq_segs (vm, b[1], mb[1]);
	  n_bytes += dpdk_process_subseq_segs (vm, b[2], mb[2]);
	  n_bytes += dpdk_process_subseq_segs (vm, b[3], mb[3]);
	}

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[1]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[2]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[3]);

      /* next */
      mb += 4;
      n_left -= 4;
    }

  while (n_left)
    {
      b[0] = vlib_buffer_from_rte_mbuf (mb[0]);
      clib_memcpy_fast (b[0], &ptd->buffer_template, 64);
      or_flags |= dpdk_ol_flags_extract (mb, flags, 1);
      flags += 1;

      b[0]->current_data = mb[0]->data_off - RTE_PKTMBUF_HEADROOM;
      n_bytes += b[0]->current_length = mb[0]->data_len;

      if (maybe_multiseg)
	n_bytes += dpdk_process_subseq_segs (vm, b[0], mb[0]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);

      /* next */
      mb += 1;
      n_left -= 1;
    }

  *or_flagsp = or_flags;
  return n_bytes;
}

static_always_inline void
dpdk_process_flow_offload (dpdk_device_t * xd, dpdk_per_thread_data_t * ptd,
			   uword n_rx_packets)
{
  uword n;
  dpdk_flow_lookup_entry_t *fle;
  vlib_buffer_t *b0;

  /* TODO prefetch and quad-loop */
  for (n = 0; n < n_rx_packets; n++)
    {
      if ((ptd->flags[n] & (1 << PKT_RX_FDIR)) == 0)
	continue;

      fle = pool_elt_at_index (xd->flow_lookup_entries,
			       ptd->mbufs[n]->hash.fdir.hi);

      if (fle->next_index != (u16) ~ 0)
	ptd->next[n] = fle->next_index;

      if (fle->flow_id != ~0)
	{
	  b0 = vlib_buffer_from_rte_mbuf (ptd->mbufs[n]);
	  b0->flow_id = fle->flow_id;
	}

      if (fle->buffer_advance != ~0)
	{
	  b0 = vlib_buffer_from_rte_mbuf (ptd->mbufs[n]);
	  vlib_buffer_advance (b0, fle->buffer_advance);
	}
    }
}

static_always_inline u32
dpdk_device_input (vlib_main_t * vm, dpdk_main_t * dm, dpdk_device_t * xd,
		   vlib_node_runtime_t * node, u32 thread_index, u16 queue_id)
{
  uword n_rx_packets = 0, n_rx_bytes;
  u32 n_left, n_trace;
  u32 *buffers;
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  struct rte_mbuf **mb;
  vlib_buffer_t *b0;
  u16 *next;
  u8 or_flags;
  u32 n;
  int single_next = 0;

  dpdk_per_thread_data_t *ptd = vec_elt_at_index (dm->per_thread_data,
						  thread_index);
  vlib_buffer_t *bt = &ptd->buffer_template;

  if ((xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP) == 0)
    return 0;

  /* get up to DPDK_RX_BURST_SZ buffers from PMD */
  while (n_rx_packets < DPDK_RX_BURST_SZ)
    {
      n = rte_eth_rx_burst (xd->port_id, queue_id,
			    ptd->mbufs + n_rx_packets,
			    DPDK_RX_BURST_SZ - n_rx_packets);
      n_rx_packets += n;

      if (n < 32)
	break;
    }

  if (n_rx_packets == 0)
    return 0;

  /* Update buffer template */
  vnet_buffer (bt)->sw_if_index[VLIB_RX] = xd->sw_if_index;
  bt->error = node->errors[DPDK_ERROR_NONE];
  /* as DPDK is allocating empty buffers from mempool provided before interface
     start for each queue, it is safe to store this in the template */
  bt->buffer_pool_index = xd->buffer_pool_for_queue[queue_id];
  vnet_buffer (bt)->feature_arc_index = 0;
  bt->current_config_index = 0;

  /* receive burst of packets from DPDK PMD */
  if (PREDICT_FALSE (xd->per_interface_next_index != ~0))
    next_index = xd->per_interface_next_index;

  /* as all packets belong to the same interface feature arc lookup
     can be don once and result stored in the buffer template */
  if (PREDICT_FALSE (vnet_device_input_have_features (xd->sw_if_index)))
    vnet_feature_start_device_input_x1 (xd->sw_if_index, &next_index, bt);

  if (xd->flags & DPDK_DEVICE_FLAG_MAYBE_MULTISEG)
    n_rx_bytes = dpdk_process_rx_burst (vm, ptd, n_rx_packets, 1, &or_flags);
  else
    n_rx_bytes = dpdk_process_rx_burst (vm, ptd, n_rx_packets, 0, &or_flags);

  if (PREDICT_FALSE (or_flags & PKT_RX_FDIR))
    {
      /* some packets will need to go to different next nodes */
      for (n = 0; n < n_rx_packets; n++)
	ptd->next[n] = next_index;

      /* flow offload - process if rx flow offload enabled and at least one
         packet is marked */
      if (PREDICT_FALSE ((xd->flags & DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD) &&
			 (or_flags & PKT_RX_FDIR)))
	dpdk_process_flow_offload (xd, ptd, n_rx_packets);

      /* enqueue buffers to the next node */
      vlib_get_buffer_indices_with_offset (vm, (void **) ptd->mbufs,
					   ptd->buffers, n_rx_packets,
					   sizeof (struct rte_mbuf));

      vlib_buffer_enqueue_to_next (vm, node, ptd->buffers, ptd->next,
				   n_rx_packets);
    }
  else
    {
      u32 *to_next, n_left_to_next;

      vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);
      vlib_get_buffer_indices_with_offset (vm, (void **) ptd->mbufs, to_next,
					   n_rx_packets,
					   sizeof (struct rte_mbuf));

      if (PREDICT_TRUE (next_index == VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT))
	{
	  vlib_next_frame_t *nf;
	  vlib_frame_t *f;
	  ethernet_input_frame_t *ef;
	  nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
	  f = vlib_get_frame (vm, nf->frame_index);
	  f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;

	  ef = vlib_frame_scalar_args (f);
	  ef->sw_if_index = xd->sw_if_index;
	  ef->hw_if_index = xd->hw_if_index;

	  /* if PMD supports ip4 checksum check and there are no packets
	     marked as ip4 checksum bad we can notify ethernet input so it
	     can send pacets to ip4-input-no-checksum node */
	  if (xd->flags & DPDK_DEVICE_FLAG_RX_IP4_CKSUM &&
	      (or_flags & PKT_RX_IP_CKSUM_BAD) == 0)
	    f->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK;
	}
      n_left_to_next -= n_rx_packets;
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
      single_next = 1;
    }

  /* packet trace if enabled */
  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node))))
    {
      if (single_next)
	vlib_get_buffer_indices_with_offset (vm, (void **) ptd->mbufs,
					     ptd->buffers, n_rx_packets,
					     sizeof (struct rte_mbuf));

      n_left = n_rx_packets;
      buffers = ptd->buffers;
      mb = ptd->mbufs;
      next = ptd->next;

      while (n_trace && n_left)
	{
	  b0 = vlib_get_buffer (vm, buffers[0]);
	  if (single_next == 0)
	    next_index = next[0];
	  vlib_trace_buffer (vm, node, next_index, b0, /* follow_chain */ 0);

	  dpdk_rx_trace_t *t0 = vlib_add_trace (vm, node, b0, sizeof t0[0]);
	  t0->queue_index = queue_id;
	  t0->device_index = xd->device_index;
	  t0->buffer_index = vlib_get_buffer_index (vm, b0);

	  clib_memcpy_fast (&t0->mb, mb[0], sizeof t0->mb);
	  clib_memcpy_fast (&t0->buffer, b0,
			    sizeof b0[0] - sizeof b0->pre_data);
	  clib_memcpy_fast (t0->buffer.pre_data, b0->data,
			    sizeof t0->buffer.pre_data);
	  clib_memcpy_fast (&t0->data, mb[0]->buf_addr + mb[0]->data_off,
			    sizeof t0->data);
	  n_trace--;
	  n_left--;
	  buffers++;
	  mb++;
	  next++;
	}
      vlib_set_trace_count (vm, node, n_trace);
    }

  /* rx pcap capture if enabled */
  if (PREDICT_FALSE (dm->pcap[VLIB_RX].pcap_enable))
    {
      u32 bi0;
      n_left = n_rx_packets;
      buffers = ptd->buffers;
      while (n_left)
	{
	  bi0 = buffers[0];
	  b0 = vlib_get_buffer (vm, bi0);
	  buffers++;

	  if (dm->pcap[VLIB_RX].pcap_sw_if_index == 0 ||
	      dm->pcap[VLIB_RX].pcap_sw_if_index
	      == vnet_buffer (b0)->sw_if_index[VLIB_RX])
	    {
	      struct rte_mbuf *mb;
	      i16 data_start;
	      i32 temp_advance;

	      /*
	       * Note: current_data will have advanced
	       * when we skip ethernet input.
	       * Temporarily back up to the original DMA
	       * target, so we capture a valid ethernet frame
	       */
	      mb = rte_mbuf_from_vlib_buffer (b0);

	      /* Figure out the original data_start */
	      data_start = (mb->buf_addr + mb->data_off) - (void *) b0->data;
	      /* Back up that far */
	      temp_advance = b0->current_data - data_start;
	      vlib_buffer_advance (b0, -temp_advance);
	      /* Trace the packet */
	      pcap_add_buffer (&dm->pcap[VLIB_RX].pcap_main, vm, bi0, 512);
	      /* and advance again */
	      vlib_buffer_advance (b0, temp_advance);
	    }
	  n_left--;
	}
    }

  vlib_increment_combined_counter
    (vnet_get_main ()->interface_main.combined_sw_if_counters
     + VNET_INTERFACE_COUNTER_RX, thread_index, xd->sw_if_index,
     n_rx_packets, n_rx_bytes);

  vnet_device_increment_rx_packets (thread_index, n_rx_packets);

  return n_rx_packets;
}

VLIB_NODE_FN (dpdk_input_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * f)
{
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;
  uword n_rx_packets = 0;
  vnet_device_input_runtime_t *rt = (void *) node->runtime_data;
  vnet_device_and_queue_t *dq;
  u32 thread_index = node->thread_index;

  /*
   * Poll all devices on this cpu for input/interrupts.
   */
  /* *INDENT-OFF* */
  foreach_device_and_queue (dq, rt->devices_and_queues)
    {
      xd = vec_elt_at_index(dm->devices, dq->dev_instance);
      if (PREDICT_FALSE (xd->flags & DPDK_DEVICE_FLAG_BOND_SLAVE))
	continue;	/* Do not poll slave to a bonded interface */
      n_rx_packets += dpdk_device_input (vm, dm, xd, node, thread_index,
					 dq->queue_id);
    }
  /* *INDENT-ON* */
  return n_rx_packets;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_input_node) = {
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "dpdk-input",
  .sibling_of = "device-input",

  /* Will be enabled if/when hardware is detected. */
  .state = VLIB_NODE_STATE_DISABLED,

  .format_buffer = format_ethernet_header_with_length,
  .format_trace = format_dpdk_rx_trace,

  .n_errors = DPDK_N_ERROR,
  .error_strings = dpdk_error_strings,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
