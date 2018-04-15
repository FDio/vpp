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

#ifndef CLIB_MULTIARCH_VARIANT
static char *dpdk_error_strings[] = {
#define _(n,s) s,
  foreach_dpdk_error
#undef _
};
#endif

STATIC_ASSERT (VNET_DEVICE_INPUT_NEXT_IP4_INPUT - 1 ==
	       VNET_DEVICE_INPUT_NEXT_IP4_NCS_INPUT,
	       "IP4_INPUT must follow IP4_NCS_INPUT");

always_inline u32
dpdk_rx_next (vlib_node_runtime_t * node, struct rte_mbuf *mb, int use_etype,
	      int maybe_bad, u32 next)
{
  ethernet_header_t *h = rte_pktmbuf_mtod (mb, ethernet_header_t *);

  if (maybe_bad && (mb->ol_flags & PKT_RX_IP_CKSUM_BAD))
    {
      vlib_buffer_t *b = vlib_buffer_from_rte_mbuf (mb);
      b->error = node->errors[DPDK_ERROR_IP_CHECKSUM_ERROR];
      return VNET_DEVICE_INPUT_NEXT_DROP;
    }

  if (use_etype == 0)
    return next;

  if (PREDICT_TRUE (h->type == clib_host_to_net_u16 (ETHERNET_TYPE_IP4)))
    {
      /* keep it branchless */
      u32 is_good = (mb->ol_flags >> min_log2 (PKT_RX_IP_CKSUM_GOOD)) & 1;
      return VNET_DEVICE_INPUT_NEXT_IP4_INPUT - is_good;
    }
  else if (PREDICT_TRUE (h->type == clib_host_to_net_u16 (ETHERNET_TYPE_IP6)))
    return VNET_DEVICE_INPUT_NEXT_IP6_INPUT;
  else
    if (PREDICT_TRUE (h->type == clib_host_to_net_u16 (ETHERNET_TYPE_MPLS)))
    return VNET_DEVICE_INPUT_NEXT_MPLS_INPUT;
  else
    return VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
}

static_always_inline uword
dpdk_process_subseq_segs (vlib_main_t * vm, vlib_buffer_t * b,
			  struct rte_mbuf * mb, vlib_buffer_free_list_t * fl)
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
      vlib_buffer_init_for_free_list (b_seg, fl);

      ASSERT ((b_seg->flags & VLIB_BUFFER_NEXT_PRESENT) == 0);
      ASSERT (b_seg->current_data == 0);

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
dpdk_prefetch_buffer (struct rte_mbuf *mb)
{
  vlib_buffer_t *b = vlib_buffer_from_rte_mbuf (mb);
  CLIB_PREFETCH (mb, CLIB_CACHE_LINE_BYTES, LOAD);
  CLIB_PREFETCH (b, CLIB_CACHE_LINE_BYTES, STORE);
  CLIB_PREFETCH (b->data, CLIB_CACHE_LINE_BYTES, LOAD);
}

static inline void
poll_rate_limit (dpdk_main_t * dm)
{
  /* Limit the poll rate by sleeping for N msec between polls */
  if (PREDICT_FALSE (dm->poll_sleep_usec != 0))
    {
      struct timespec ts, tsrem;

      ts.tv_sec = 0;
      ts.tv_nsec = 1000 * dm->poll_sleep_usec;

      while (nanosleep (&ts, &tsrem) < 0)
	{
	  ts = tsrem;
	}
    }
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

static_always_inline void
dpdk_process_rx_burst (vlib_main_t * vm, vlib_node_runtime_t * node,
		       dpdk_per_thread_data_t * ptd, uword n_rx_packets,
		       u32 next_index)
{
  u32 i = 0, *buffers = ptd->buffers;
  vlib_buffer_t *b[4];
  vlib_buffer_free_list_t *fl;
  struct rte_mbuf **mb = ptd->mbufs;
  u16 *next = ptd->next;
  i32x4 off = { 0 };
  i32x4 adv = { 0 };
  int use_etype = (next_index == ~0);
  u64 or_ol_flags = 0, ol_flags;
  uword n_segs = 0, n_bytes = 0;

  fl = vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);

  while (i + 8 < n_rx_packets)
    {
      buffers = ptd->buffers + i;
      mb = ptd->mbufs + i;
      next = ptd->next + i;

      dpdk_prefetch_buffer (mb[4]);
      dpdk_prefetch_buffer (mb[5]);

      b[0] = vlib_buffer_from_rte_mbuf (mb[0]);
      b[1] = vlib_buffer_from_rte_mbuf (mb[1]);
      b[2] = vlib_buffer_from_rte_mbuf (mb[2]);
      b[3] = vlib_buffer_from_rte_mbuf (mb[3]);

      buffers[0] = vlib_get_buffer_index (vm, b[0]);
      buffers[1] = vlib_get_buffer_index (vm, b[1]);
      buffers[2] = vlib_get_buffer_index (vm, b[2]);
      buffers[3] = vlib_get_buffer_index (vm, b[3]);

      clib_memcpy64_x4 (b[0], b[1], b[2], b[3], &ptd->buffer_template);

      dpdk_prefetch_buffer (mb[6]);
      dpdk_prefetch_buffer (mb[7]);

      ol_flags = 0;
      ol_flags |= mb[0]->ol_flags;
      ol_flags |= mb[1]->ol_flags;
      ol_flags |= mb[2]->ol_flags;
      ol_flags |= mb[3]->ol_flags;
      or_ol_flags |= ol_flags;

      if (PREDICT_FALSE (ol_flags & PKT_RX_IP_CKSUM_BAD))
	{
	  next[0] = dpdk_rx_next (node, mb[0], use_etype, 1, next_index);
	  next[1] = dpdk_rx_next (node, mb[1], use_etype, 1, next_index);
	  next[2] = dpdk_rx_next (node, mb[2], use_etype, 1, next_index);
	  next[3] = dpdk_rx_next (node, mb[3], use_etype, 1, next_index);
	}
      else
	{
	  next[0] = dpdk_rx_next (node, mb[0], use_etype, 0, next_index);
	  next[1] = dpdk_rx_next (node, mb[1], use_etype, 0, next_index);
	  next[2] = dpdk_rx_next (node, mb[2], use_etype, 0, next_index);
	  next[3] = dpdk_rx_next (node, mb[3], use_etype, 0, next_index);
	}

      adv[0] = use_etype ? device_input_next_node_advance[next[0]] : 0;
      adv[1] = use_etype ? device_input_next_node_advance[next[1]] : 0;
      adv[2] = use_etype ? device_input_next_node_advance[next[2]] : 0;
      adv[3] = use_etype ? device_input_next_node_advance[next[3]] : 0;

      off[0] = mb[0]->data_off;
      off[1] = mb[1]->data_off;
      off[2] = mb[2]->data_off;
      off[3] = mb[3]->data_off;

      off -= i32x4_splat (RTE_PKTMBUF_HEADROOM);

      vnet_buffer (b[0])->l2_hdr_offset = off[0];
      vnet_buffer (b[1])->l2_hdr_offset = off[1];
      vnet_buffer (b[2])->l2_hdr_offset = off[2];
      vnet_buffer (b[3])->l2_hdr_offset = off[3];

      off += adv;

      b[0]->current_data = off[0];
      b[1]->current_data = off[1];
      b[2]->current_data = off[2];
      b[3]->current_data = off[3];

      b[0]->current_length = mb[0]->data_len - adv[0];
      b[1]->current_length = mb[1]->data_len - adv[1];
      b[2]->current_length = mb[2]->data_len - adv[2];
      b[3]->current_length = mb[3]->data_len - adv[3];

      n_bytes += mb[0]->data_len;
      n_bytes += mb[1]->data_len;
      n_bytes += mb[2]->data_len;
      n_bytes += mb[3]->data_len;

      n_segs = 0;
      n_segs += mb[0]->nb_segs;
      n_segs += mb[1]->nb_segs;
      n_segs += mb[2]->nb_segs;
      n_segs += mb[3]->nb_segs;

      if (PREDICT_FALSE (n_segs > 4))
	{
	  n_bytes += dpdk_process_subseq_segs (vm, b[0], mb[0], fl);
	  n_bytes += dpdk_process_subseq_segs (vm, b[1], mb[1], fl);
	  n_bytes += dpdk_process_subseq_segs (vm, b[2], mb[2], fl);
	  n_bytes += dpdk_process_subseq_segs (vm, b[3], mb[3], fl);
	}

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b1);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b2);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b3);

      /* next */
      i += 4;
    }

  while (i < n_rx_packets)
    {
      buffers = ptd->buffers + i;
      mb = ptd->mbufs + i;
      next = ptd->next + i;
      b[0] = vlib_buffer_from_rte_mbuf (mb[0]);
      buffers[0] = vlib_get_buffer_index (vm, b[0]);
      clib_memcpy (b[0], &ptd->buffer_template, 64);
      next[0] = dpdk_rx_next (node, mb[0], use_etype, 1, next_index);
      adv[0] = use_etype ? device_input_next_node_advance[next[0]] : 0;
      off[0] = mb[0]->data_off - RTE_PKTMBUF_HEADROOM;
      vnet_buffer (b[0])->l2_hdr_offset = off[0];
      b[0]->current_data = off[0] + adv[0];
      b[0]->current_length = mb[0]->data_len - adv[0];
      n_bytes += mb[0]->data_len;
      n_bytes += dpdk_process_subseq_segs (vm, b[0], mb[0], fl);
      or_ol_flags |= mb[0]->ol_flags;
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);

      /* next */
      i += 1;
    }

  ptd->n_bytes = n_bytes;
  //ptd->n_segs = n_segs;
  ptd->or_ol_flags = or_ol_flags;
}

static_always_inline u32
dpdk_device_input (vlib_main_t * vm, dpdk_main_t * dm, dpdk_device_t * xd,
		   vlib_node_runtime_t * node, u32 thread_index, u16 queue_id)
{
  uword n_rx_packets = 0;
  u32 n_left, n_trace, i;
  u32 *buffers;
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  struct rte_mbuf *mb0;
  vlib_buffer_t *b0;
  u16 *next;

  dpdk_per_thread_data_t *ptd = vec_elt_at_index (dm->per_thread_data,
						  thread_index);
  vlib_buffer_t *bt = &ptd->buffer_template;

  /* Update buffer template */
  vnet_buffer (bt)->sw_if_index[VLIB_RX] = xd->sw_if_index;
  bt->error = node->errors[DPDK_ERROR_NONE];
  /* as DPDK is allocating empty buffers from mempool provided before interface
     start for each queue, it is safe to store this in the template */
  bt->buffer_pool_index = xd->buffer_pool_for_queue[queue_id];

  /* get up to DPDK_RX_BURST_SZ buffers from PMD */
  while (n_rx_packets < DPDK_RX_BURST_SZ)
    {
      u32 n = rte_eth_rx_burst (xd->device_index, queue_id,
				ptd->mbufs + n_rx_packets,
				DPDK_RX_BURST_SZ - n_rx_packets);
      n_rx_packets += n;

      if (n < 32)
	break;
    }

  if (n_rx_packets == 0)
    return 0;

  if (PREDICT_FALSE (xd->per_interface_next_index != ~0))
    dpdk_process_rx_burst (vm, node, ptd, n_rx_packets,
			   xd->per_interface_next_index);
  else if (vnet_device_input_have_features (xd->sw_if_index))
    {
      u32 n = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
      vnet_feature_start_device_input_x1 (xd->sw_if_index, &n, bt);
      dpdk_process_rx_burst (vm, node, ptd, n_rx_packets, n);
      bt->feature_arc_index = 0;
      bt->current_config_index = 0;
    }
  else
    dpdk_process_rx_burst (vm, node, ptd, n_rx_packets,	/* from ethertype */
			   ~0);

  /* dispatch packets */
  n_left = n_rx_packets;
  next = ptd->next;
  buffers = ptd->buffers;
  while (n_left)
    {
      u32 n_left_to_next;
      u32 *to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left >= 8 && n_left_to_next >= 4)
	{
	  to_next[0] = buffers[0];
	  to_next[1] = buffers[1];
	  to_next[2] = buffers[2];
	  to_next[3] = buffers[3];
	  to_next += 4;
	  n_left_to_next -= 4;

	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next,
					   n_left_to_next, buffers[0],
					   buffers[1], buffers[2], buffers[3],
					   next[0], next[1], next[2],
					   next[3]);
	  /* next */
	  buffers += 4;
	  n_left -= 4;
	  next += 4;
	}
      while (n_left && n_left_to_next)
	{
	  to_next[0] = buffers[0];
	  to_next += 1;
	  n_left_to_next -= 1;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, buffers[0],
					   next[0]);
	  /* next */
	  buffers += 1;
	  n_left -= 1;
	  next += 1;
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  if ((n_trace = vlib_get_trace_count (vm, node)))
    {
      n_left = clib_min (n_trace, n_rx_packets);
      i = 0;
      while (i < n_left)
	{
	  b0 = vlib_get_buffer (vm, ptd->buffers[i]);
	  mb0 = ptd->mbufs[i];
	  vlib_trace_buffer (vm, node, ptd->next[i],
			     b0, /* follow_chain */ 0);

	  dpdk_rx_trace_t *t0 = vlib_add_trace (vm, node, b0, sizeof t0[0]);
	  t0->queue_index = queue_id;
	  t0->device_index = xd->device_index;
	  t0->buffer_index = vlib_get_buffer_index (vm, b0);

	  clib_memcpy (&t0->mb, mb0, sizeof t0->mb);
	  clib_memcpy (&t0->buffer, b0, sizeof b0[0] - sizeof b0->pre_data);
	  clib_memcpy (t0->buffer.pre_data, b0->data,
		       sizeof t0->buffer.pre_data);
	  clib_memcpy (&t0->data, mb0->buf_addr + mb0->data_off,
		       sizeof t0->data);
	  i++;
	}
      vlib_set_trace_count (vm, node, n_trace - i);
    }

  vlib_increment_combined_counter
    (vnet_get_main ()->interface_main.combined_sw_if_counters
     + VNET_INTERFACE_COUNTER_RX,
     thread_index, xd->sw_if_index, n_rx_packets, ptd->n_bytes);

  vnet_device_increment_rx_packets (thread_index, n_rx_packets);

  return n_rx_packets;
}

uword
CLIB_MULTIARCH_FN (dpdk_input) (vlib_main_t * vm, vlib_node_runtime_t * node,
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

  poll_rate_limit (dm);

  return n_rx_packets;
}

#ifndef CLIB_MULTIARCH_VARIANT
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_input_node) = {
  .function = dpdk_input,
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

vlib_node_function_t __clib_weak dpdk_input_avx512;
vlib_node_function_t __clib_weak dpdk_input_avx2;

#if __x86_64__
static void __clib_constructor
dpdk_input_multiarch_select (void)
{
  if (dpdk_input_avx512 && clib_cpu_supports_avx512f ())
    dpdk_input_node.function = dpdk_input_avx512;
  else if (dpdk_input_avx2 && clib_cpu_supports_avx2 ())
    dpdk_input_node.function = dpdk_input_avx2;
}
#endif
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
