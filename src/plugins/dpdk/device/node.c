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

enum
{
  DPDK_RX_F_CKSUM_GOOD = 7,
  DPDK_RX_F_CKSUM_BAD = 4,
  DPDK_RX_F_FDIR = 2,
};

/* currently we are just copying bit positions from DPDK, but that
   might change in future, in case we strart to be interested in something
   stored in upper bytes. Curently we store only lower byte for perf reasons */
STATIC_ASSERT (1 << DPDK_RX_F_CKSUM_GOOD == PKT_RX_IP_CKSUM_GOOD, "");
STATIC_ASSERT (1 << DPDK_RX_F_CKSUM_BAD == PKT_RX_IP_CKSUM_BAD, "");
STATIC_ASSERT (1 << DPDK_RX_F_FDIR == PKT_RX_FDIR, "");
STATIC_ASSERT ((PKT_RX_IP_CKSUM_GOOD | PKT_RX_IP_CKSUM_BAD | PKT_RX_FDIR) <
	       256, "dpdk flags not un lower byte, fix needed");

always_inline u32
dpdk_rx_next (vlib_node_runtime_t * node, u16 etype, u8 flags)
{
  if (PREDICT_TRUE (etype == clib_host_to_net_u16 (ETHERNET_TYPE_IP4)))
    {
      /* keep it branchless */
      u32 is_good = (flags >> DPDK_RX_F_CKSUM_GOOD) & 1;
      return VNET_DEVICE_INPUT_NEXT_IP4_INPUT - is_good;
    }
  else if (PREDICT_TRUE (etype == clib_host_to_net_u16 (ETHERNET_TYPE_IP6)))
    return VNET_DEVICE_INPUT_NEXT_IP6_INPUT;
  else if (PREDICT_TRUE (etype == clib_host_to_net_u16 (ETHERNET_TYPE_MPLS)))
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

static_always_inline void
dpdk_prefetch_buffer_data_x4 (struct rte_mbuf *mb[])
{
  vlib_buffer_t *b;
  b = vlib_buffer_from_rte_mbuf (mb[0]);
  CLIB_PREFETCH (b->data, CLIB_CACHE_LINE_BYTES, LOAD);
  b = vlib_buffer_from_rte_mbuf (mb[1]);
  CLIB_PREFETCH (b->data, CLIB_CACHE_LINE_BYTES, LOAD);
  b = vlib_buffer_from_rte_mbuf (mb[2]);
  CLIB_PREFETCH (b->data, CLIB_CACHE_LINE_BYTES, LOAD);
  b = vlib_buffer_from_rte_mbuf (mb[3]);
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
  vlib_buffer_free_list_t *fl;
  struct rte_mbuf **mb = ptd->mbufs;
  uword n_bytes = 0;
  i16 off;
  u8 *flags, or_flags = 0;
  u16 *next;

  fl = vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);

  mb = ptd->mbufs;
  flags = ptd->flags;
  next = ptd->next;

  while (n_left >= 8)
    {
      CLIB_PREFETCH (mb + 8, CLIB_CACHE_LINE_BYTES, LOAD);

      dpdk_prefetch_buffer_x4 (mb + 4);

      b[0] = vlib_buffer_from_rte_mbuf (mb[0]);
      b[1] = vlib_buffer_from_rte_mbuf (mb[1]);
      b[2] = vlib_buffer_from_rte_mbuf (mb[2]);
      b[3] = vlib_buffer_from_rte_mbuf (mb[3]);

      clib_memcpy64_x4 (b[0], b[1], b[2], b[3], &ptd->buffer_template);

      dpdk_prefetch_mbuf_x4 (mb + 4);

      or_flags |= dpdk_ol_flags_extract (mb, flags, 4);
      flags += 4;

      /* we temporary store relative offset of ethertype into next[x]
         so we can prefetch and get it faster later */

      off = mb[0]->data_off;
      next[0] = off + STRUCT_OFFSET_OF (ethernet_header_t, type);
      off -= RTE_PKTMBUF_HEADROOM;
      vnet_buffer (b[0])->l2_hdr_offset = off;
      b[0]->current_data = off;

      off = mb[1]->data_off;
      next[1] = off + STRUCT_OFFSET_OF (ethernet_header_t, type);
      off -= RTE_PKTMBUF_HEADROOM;
      vnet_buffer (b[1])->l2_hdr_offset = off;
      b[1]->current_data = off;

      off = mb[2]->data_off;
      next[2] = off + STRUCT_OFFSET_OF (ethernet_header_t, type);
      off -= RTE_PKTMBUF_HEADROOM;
      vnet_buffer (b[2])->l2_hdr_offset = off;
      b[2]->current_data = off;

      off = mb[3]->data_off;
      next[3] = off + STRUCT_OFFSET_OF (ethernet_header_t, type);
      off -= RTE_PKTMBUF_HEADROOM;
      vnet_buffer (b[3])->l2_hdr_offset = off;
      b[3]->current_data = off;

      b[0]->current_length = mb[0]->data_len;
      b[1]->current_length = mb[1]->data_len;
      b[2]->current_length = mb[2]->data_len;
      b[3]->current_length = mb[3]->data_len;

      n_bytes += mb[0]->data_len;
      n_bytes += mb[1]->data_len;
      n_bytes += mb[2]->data_len;
      n_bytes += mb[3]->data_len;

      if (maybe_multiseg)
	{
	  n_bytes += dpdk_process_subseq_segs (vm, b[0], mb[0], fl);
	  n_bytes += dpdk_process_subseq_segs (vm, b[1], mb[1], fl);
	  n_bytes += dpdk_process_subseq_segs (vm, b[2], mb[2], fl);
	  n_bytes += dpdk_process_subseq_segs (vm, b[3], mb[3], fl);
	}

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[1]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[2]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[3]);

      /* next */
      mb += 4;
      n_left -= 4;
      next += 4;
    }

  while (n_left)
    {
      b[0] = vlib_buffer_from_rte_mbuf (mb[0]);
      clib_memcpy (b[0], &ptd->buffer_template, 64);
      or_flags |= dpdk_ol_flags_extract (mb, flags, 1);
      flags += 1;

      off = mb[0]->data_off;
      next[0] = off + STRUCT_OFFSET_OF (ethernet_header_t, type);
      off -= RTE_PKTMBUF_HEADROOM;
      vnet_buffer (b[0])->l2_hdr_offset = off;
      b[0]->current_data = off;
      b[0]->current_length = mb[0]->data_len;
      n_bytes += mb[0]->data_len;
      if (maybe_multiseg)
	n_bytes += dpdk_process_subseq_segs (vm, b[0], mb[0], fl);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);

      /* next */
      mb += 1;
      n_left -= 1;
      next += 1;
    }

  *or_flagsp = or_flags;
  return n_bytes;
}

static_always_inline void
dpdk_set_next_from_etype (vlib_main_t * vm, vlib_node_runtime_t * node,
			  dpdk_per_thread_data_t * ptd, uword n_rx_packets)
{
  vlib_buffer_t *b[4];
  i16 adv[4];
  u16 etype[4];
  struct rte_mbuf **mb = ptd->mbufs;
  u8 *flags = ptd->flags;
  u16 *next = ptd->next;
  u32 n_left = n_rx_packets;

  while (n_left >= 12)
    {
      dpdk_prefetch_buffer_data_x4 (mb + 8);
      dpdk_prefetch_buffer_x4 (mb + 8);

      b[0] = vlib_buffer_from_rte_mbuf (mb[0]);
      b[1] = vlib_buffer_from_rte_mbuf (mb[1]);
      b[2] = vlib_buffer_from_rte_mbuf (mb[2]);
      b[3] = vlib_buffer_from_rte_mbuf (mb[3]);
      etype[0] = *(u16 *) ((u8 *) mb[0] + next[0] + sizeof (vlib_buffer_t));
      etype[1] = *(u16 *) ((u8 *) mb[1] + next[1] + sizeof (vlib_buffer_t));
      etype[2] = *(u16 *) ((u8 *) mb[2] + next[2] + sizeof (vlib_buffer_t));
      etype[3] = *(u16 *) ((u8 *) mb[3] + next[3] + sizeof (vlib_buffer_t));
      next[0] = dpdk_rx_next (node, etype[0], flags[0]);
      next[1] = dpdk_rx_next (node, etype[1], flags[1]);
      next[2] = dpdk_rx_next (node, etype[2], flags[2]);
      next[3] = dpdk_rx_next (node, etype[3], flags[3]);
      adv[0] = device_input_next_node_advance[next[0]];
      adv[1] = device_input_next_node_advance[next[1]];
      adv[2] = device_input_next_node_advance[next[2]];
      adv[3] = device_input_next_node_advance[next[3]];
      b[0]->current_data += adv[0];
      b[1]->current_data += adv[1];
      b[2]->current_data += adv[2];
      b[3]->current_data += adv[3];
      b[0]->current_length -= adv[0];
      b[1]->current_length -= adv[1];
      b[2]->current_length -= adv[2];
      b[3]->current_length -= adv[3];

      /* next */
      next += 4;
      mb += 4;
      n_left -= 4;
      flags += 4;
    }

  while (n_left)
    {
      b[0] = vlib_buffer_from_rte_mbuf (mb[0]);
      next[0] = *(u16 *) ((u8 *) mb[0] + next[0] + sizeof (vlib_buffer_t));
      next[0] = dpdk_rx_next (node, next[0], flags[0]);
      adv[0] = device_input_next_node_advance[next[0]];
      b[0]->current_data += adv[0];
      b[0]->current_length -= adv[0];

      /* next */
      next += 1;
      mb += 1;
      n_left -= 1;
      flags += 1;
    }
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
      if ((ptd->flags[n] & (1 << DPDK_RX_F_FDIR)) == 0)
	continue;

      fle = vec_elt_at_index (xd->flow_lookup_entries,
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
  int known_next = 0;
  u16 *next;
  u8 or_flags;
  u32 n;

  dpdk_per_thread_data_t *ptd = vec_elt_at_index (dm->per_thread_data,
						  thread_index);
  vlib_buffer_t *bt = &ptd->buffer_template;

  if ((xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP) == 0)
    return 0;

  /* get up to DPDK_RX_BURST_SZ buffers from PMD */
  while (n_rx_packets < DPDK_RX_BURST_SZ)
    {
      n = rte_eth_rx_burst (xd->device_index, queue_id,
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

  /* receive burst of packets from DPDK PMD */
  if (PREDICT_FALSE (xd->per_interface_next_index != ~0))
    {
      known_next = 1;
      next_index = xd->per_interface_next_index;
    }

  /* as all packets belong to thr same interface feature arc lookup
     can be don once and result stored in the buffer template */
  if (PREDICT_FALSE (vnet_device_input_have_features (xd->sw_if_index)))
    {
      vnet_feature_start_device_input_x1 (xd->sw_if_index, &next_index, bt);
      known_next = 1;
    }

  if (xd->flags & DPDK_DEVICE_FLAG_MAYBE_MULTISEG)
    n_rx_bytes = dpdk_process_rx_burst (vm, ptd, n_rx_packets, 1, &or_flags);
  else
    n_rx_bytes = dpdk_process_rx_burst (vm, ptd, n_rx_packets, 0, &or_flags);

  if (PREDICT_FALSE (known_next))
    {
      for (n = 0; n < n_rx_packets; n++)
	ptd->next[n] = next_index;

      vnet_buffer (bt)->feature_arc_index = 0;
      bt->current_config_index = 0;
    }
  else
    dpdk_set_next_from_etype (vm, node, ptd, n_rx_packets);

  /* flow offload - process if rx flow offlaod enabled and at least one packet
     is marked */
  if (PREDICT_FALSE ((xd->flags & DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD) &&
		     (or_flags & (1 << DPDK_RX_F_FDIR))))
    dpdk_process_flow_offload (xd, ptd, n_rx_packets);

  /* is at least one packet marked as ip4 checksum bad? */
  if (PREDICT_FALSE (or_flags & (1 << DPDK_RX_F_CKSUM_BAD)))
    for (n = 0; n < n_rx_packets; n++)
      {
	if ((ptd->flags[n] & (1 << DPDK_RX_F_CKSUM_BAD)) == 0)
	  continue;
	if (ptd->next[n] != VNET_DEVICE_INPUT_NEXT_IP4_INPUT)
	  continue;

	b0 = vlib_buffer_from_rte_mbuf (ptd->mbufs[n]);
	b0->error = node->errors[DPDK_ERROR_IP_CHECKSUM_ERROR];
	ptd->next[n] = VNET_DEVICE_INPUT_NEXT_DROP;
      }

  /* enqueue buffers to the next node */
  vlib_get_buffer_indices_with_offset (vm, (void **) ptd->mbufs, ptd->buffers,
				       n_rx_packets,
				       sizeof (struct rte_mbuf));
  n_left = n_rx_packets;
  next = ptd->next;
  buffers = ptd->buffers;
  mb = ptd->mbufs;
  while (n_left)
    {
      u32 n_left_to_next;
      u32 *to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
#ifdef CLIB_HAVE_VEC256
      while (n_left >= 16 && n_left_to_next >= 16)
	{
	  u16x16 next16 = u16x16_load_unaligned (next);
	  if (u16x16_is_all_equal (next16, next_index))
	    {
	      clib_memcpy (to_next, buffers, 16 * sizeof (u32));
	      to_next += 16;
	      n_left_to_next -= 16;
	      buffers += 16;
	      n_left -= 16;
	      next += 16;
	      mb += 16;
	    }
	  else
	    {
	      clib_memcpy (to_next, buffers, 4 * sizeof (u32));
	      to_next += 4;
	      n_left_to_next -= 4;

	      vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next,
					       n_left_to_next, buffers[0],
					       buffers[1], buffers[2],
					       buffers[3], next[0], next[1],
					       next[2], next[3]);
	      /* next */
	      buffers += 4;
	      n_left -= 4;
	      next += 4;
	      mb += 4;
	    }
	}
#endif
      while (n_left >= 4 && n_left_to_next >= 4)
	{
	  clib_memcpy (to_next, buffers, 4 * sizeof (u32));
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
	  mb += 4;
	}
      while (n_left && n_left_to_next)
	{
	  clib_memcpy (to_next, buffers, 1 * sizeof (u32));
	  to_next += 1;
	  n_left_to_next -= 1;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, buffers[0],
					   next[0]);
	  /* next */
	  buffers += 1;
	  n_left -= 1;
	  next += 1;
	  mb += 1;
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* packet trace if enabled */
  if ((n_trace = vlib_get_trace_count (vm, node)))
    {
      n_left = n_rx_packets;
      buffers = ptd->buffers;
      mb = ptd->mbufs;
      next = ptd->next;
      while (n_trace && n_left)
	{
	  b0 = vlib_get_buffer (vm, buffers[0]);
	  vlib_trace_buffer (vm, node, next[0], b0, /* follow_chain */ 0);

	  dpdk_rx_trace_t *t0 = vlib_add_trace (vm, node, b0, sizeof t0[0]);
	  t0->queue_index = queue_id;
	  t0->device_index = xd->device_index;
	  t0->buffer_index = vlib_get_buffer_index (vm, b0);

	  clib_memcpy (&t0->mb, mb[0], sizeof t0->mb);
	  clib_memcpy (&t0->buffer, b0, sizeof b0[0] - sizeof b0->pre_data);
	  clib_memcpy (t0->buffer.pre_data, b0->data,
		       sizeof t0->buffer.pre_data);
	  clib_memcpy (&t0->data, mb[0]->buf_addr + mb[0]->data_off,
		       sizeof t0->data);
	  n_trace--;
	  n_left--;
	  buffers++;
	  mb++;
	  next++;
	}
      vlib_set_trace_count (vm, node, n_trace);
    }

  vlib_increment_combined_counter
    (vnet_get_main ()->interface_main.combined_sw_if_counters
     + VNET_INTERFACE_COUNTER_RX, thread_index, xd->sw_if_index,
     n_rx_packets, n_rx_bytes);

  vnet_device_increment_rx_packets (thread_index, n_rx_packets);

  return n_rx_packets;
}

uword CLIB_CPU_OPTIMIZED
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
