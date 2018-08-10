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
#include <vppinfra/format.h>
#include <vlib/unix/cj.h>
#include <assert.h>

#include <vnet/ethernet/ethernet.h>
#include <dpdk/device/dpdk.h>

#include <dpdk/device/dpdk_priv.h>
#include <vppinfra/error.h>

#define foreach_dpdk_tx_func_error			\
  _(BAD_RETVAL, "DPDK tx function returned an error")	\
  _(PKT_DROP, "Tx packet drops (dpdk tx failure)")	\
  _(REPL_FAIL, "Tx packet drops (replication failure)")

typedef enum
{
#define _(f,s) DPDK_TX_FUNC_ERROR_##f,
  foreach_dpdk_tx_func_error
#undef _
    DPDK_TX_FUNC_N_ERROR,
} dpdk_tx_func_error_t;

static char *dpdk_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_dpdk_tx_func_error
#undef _
};

static clib_error_t *
dpdk_set_mac_address (vnet_hw_interface_t * hi, char *address)
{
  int error;
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, hi->dev_instance);

  error = rte_eth_dev_default_mac_addr_set (xd->port_id,
					    (struct ether_addr *) address);

  if (error)
    {
      return clib_error_return (0, "mac address set failed: %d", error);
    }
  else
    {
      vec_reset_length (xd->default_mac_address);
      vec_add (xd->default_mac_address, address, sizeof (address));
      return NULL;
    }
}

static struct rte_mbuf *
dpdk_replicate_packet_mb (vlib_buffer_t * b)
{
  dpdk_main_t *dm = &dpdk_main;
  struct rte_mbuf **mbufs = 0, *s, *d;
  u8 nb_segs;
  unsigned socket_id = rte_socket_id ();
  int i;

  ASSERT (dm->pktmbuf_pools[socket_id]);
  s = rte_mbuf_from_vlib_buffer (b);
  nb_segs = s->nb_segs;
  vec_validate (mbufs, nb_segs - 1);

  if (rte_pktmbuf_alloc_bulk (dm->pktmbuf_pools[socket_id], mbufs, nb_segs))
    {
      vec_free (mbufs);
      return 0;
    }

  d = mbufs[0];
  d->nb_segs = s->nb_segs;
  d->data_len = s->data_len;
  d->pkt_len = s->pkt_len;
  d->data_off = s->data_off;
  clib_memcpy (d->buf_addr, s->buf_addr, RTE_PKTMBUF_HEADROOM + s->data_len);

  for (i = 1; i < nb_segs; i++)
    {
      d->next = mbufs[i];
      d = mbufs[i];
      s = s->next;
      d->data_len = s->data_len;
      clib_memcpy (d->buf_addr, s->buf_addr,
		   RTE_PKTMBUF_HEADROOM + s->data_len);
    }

  d = mbufs[0];
  vec_free (mbufs);
  return d;
}

static void
dpdk_tx_trace_buffer (dpdk_main_t * dm, vlib_node_runtime_t * node,
		      dpdk_device_t * xd, u16 queue_id,
		      vlib_buffer_t * buffer)
{
  vlib_main_t *vm = vlib_get_main ();
  dpdk_tx_trace_t *t0;
  struct rte_mbuf *mb;

  mb = rte_mbuf_from_vlib_buffer (buffer);

  t0 = vlib_add_trace (vm, node, buffer, sizeof (t0[0]));
  t0->queue_index = queue_id;
  t0->device_index = xd->device_index;
  t0->buffer_index = vlib_get_buffer_index (vm, buffer);
  clib_memcpy (&t0->mb, mb, sizeof (t0->mb));
  clib_memcpy (&t0->buffer, buffer,
	       sizeof (buffer[0]) - sizeof (buffer->pre_data));
  clib_memcpy (t0->buffer.pre_data, buffer->data + buffer->current_data,
	       sizeof (t0->buffer.pre_data));
  clib_memcpy (&t0->data, mb->buf_addr + mb->data_off, sizeof (t0->data));
}

static_always_inline void
dpdk_validate_rte_mbuf (vlib_main_t * vm, vlib_buffer_t * b,
			int maybe_multiseg)
{
  struct rte_mbuf *mb, *first_mb, *last_mb;

  /* buffer is coming from non-dpdk source so we need to init
     rte_mbuf header */
  if (PREDICT_FALSE ((b->flags & VLIB_BUFFER_EXT_HDR_VALID) == 0))
    {
      vlib_buffer_t *b2 = b;
      last_mb = mb = rte_mbuf_from_vlib_buffer (b2);
      rte_pktmbuf_reset (mb);
      while (maybe_multiseg && (b2->flags & VLIB_BUFFER_NEXT_PRESENT))
	{
	  b2 = vlib_get_buffer (vm, b2->next_buffer);
	  mb = rte_mbuf_from_vlib_buffer (b2);
	  rte_pktmbuf_reset (mb);
	}
    }

  last_mb = first_mb = mb = rte_mbuf_from_vlib_buffer (b);
  first_mb->nb_segs = 1;
  mb->data_len = b->current_length;
  mb->pkt_len = maybe_multiseg ? vlib_buffer_length_in_chain (vm, b) :
    b->current_length;
  mb->data_off = VLIB_BUFFER_PRE_DATA_SIZE + b->current_data;

  while (maybe_multiseg && (b->flags & VLIB_BUFFER_NEXT_PRESENT))
    {
      b = vlib_get_buffer (vm, b->next_buffer);
      mb = rte_mbuf_from_vlib_buffer (b);
      last_mb->next = mb;
      last_mb = mb;
      mb->data_len = b->current_length;
      mb->pkt_len = b->current_length;
      mb->data_off = VLIB_BUFFER_PRE_DATA_SIZE + b->current_data;
      first_mb->nb_segs++;
      if (PREDICT_FALSE (b->n_add_refs))
	{
	  rte_mbuf_refcnt_update (mb, b->n_add_refs);
	  b->n_add_refs = 0;
	}
    }
}

/*
 * This function calls the dpdk's tx_burst function to transmit the packets.
 * It manages a lock per-device if the device does not
 * support multiple queues. It returns the number of packets untransmitted
 * If all packets are transmitted (the normal case), the function returns 0.
 */
static_always_inline
  u32 tx_burst_vector_internal (vlib_main_t * vm,
				dpdk_device_t * xd,
				struct rte_mbuf **mb, u32 n_left)
{
  dpdk_main_t *dm = &dpdk_main;
  u32 n_retry;
  int n_sent = 0;
  int queue_id;

  n_retry = 16;
  queue_id = vm->thread_index;

  do
    {
      /*
       * This device only supports one TX queue,
       * and we're running multi-threaded...
       */
      if (PREDICT_FALSE (xd->lockp != 0))
	{
	  queue_id = queue_id % xd->tx_q_used;
	  while (__sync_lock_test_and_set (xd->lockp[queue_id], 1))
	    /* zzzz */
	    queue_id = (queue_id + 1) % xd->tx_q_used;
	}

      if (PREDICT_FALSE (xd->flags & DPDK_DEVICE_FLAG_HQOS))	/* HQoS ON */
	{
	  /* no wrap, transmit in one burst */
	  dpdk_device_hqos_per_worker_thread_t *hqos =
	    &xd->hqos_wt[vm->thread_index];

	  ASSERT (hqos->swq != NULL);

	  dpdk_hqos_metadata_set (hqos, mb, n_left);
	  n_sent = rte_ring_sp_enqueue_burst (hqos->swq, (void **) mb,
					      n_left, 0);
	}
      else if (PREDICT_TRUE (xd->flags & DPDK_DEVICE_FLAG_PMD))
	{
	  /* no wrap, transmit in one burst */
	  n_sent = rte_eth_tx_burst (xd->port_id, queue_id, mb, n_left);
	}
      else
	{
	  ASSERT (0);
	  n_sent = 0;
	}

      if (PREDICT_FALSE (xd->lockp != 0))
	*xd->lockp[queue_id] = 0;

      if (PREDICT_FALSE (n_sent < 0))
	{
	  // emit non-fatal message, bump counter
	  vnet_main_t *vnm = dm->vnet_main;
	  vnet_interface_main_t *im = &vnm->interface_main;
	  u32 node_index;

	  node_index = vec_elt_at_index (im->hw_interfaces,
					 xd->hw_if_index)->tx_node_index;

	  vlib_error_count (vm, node_index, DPDK_TX_FUNC_ERROR_BAD_RETVAL, 1);
	  clib_warning ("rte_eth_tx_burst[%d]: error %d",
			xd->port_id, n_sent);
	  return n_left;	// untransmitted packets
	}
      n_left -= n_sent;
      mb += n_sent;
    }
  while (n_sent && n_left && (n_retry > 0));

  return n_left;
}

static_always_inline void
dpdk_prefetch_buffer (vlib_main_t * vm, struct rte_mbuf *mb)
{
  vlib_buffer_t *b = vlib_buffer_from_rte_mbuf (mb);
  CLIB_PREFETCH (mb, 2 * CLIB_CACHE_LINE_BYTES, STORE);
  CLIB_PREFETCH (b, CLIB_CACHE_LINE_BYTES, LOAD);
}

static_always_inline void
dpdk_buffer_recycle (vlib_main_t * vm, vlib_node_runtime_t * node,
		     vlib_buffer_t * b, u32 bi, struct rte_mbuf **mbp)
{
  dpdk_main_t *dm = &dpdk_main;
  struct rte_mbuf *mb_new;

  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_RECYCLE) == 0)
    return;

  mb_new = dpdk_replicate_packet_mb (b);
  if (PREDICT_FALSE (mb_new == 0))
    {
      vlib_error_count (vm, node->node_index,
			DPDK_TX_FUNC_ERROR_REPL_FAIL, 1);
      b->flags |= VLIB_BUFFER_REPL_FAIL;
    }
  else
    *mbp = mb_new;

  vec_add1 (dm->recycle[vm->thread_index], bi);
}

static_always_inline void
dpdk_buffer_tx_offload (dpdk_device_t * xd, vlib_buffer_t * b,
			struct rte_mbuf *mb)
{
  u32 ip_cksum = b->flags & VNET_BUFFER_F_OFFLOAD_IP_CKSUM;
  u32 tcp_cksum = b->flags & VNET_BUFFER_F_OFFLOAD_TCP_CKSUM;
  u32 udp_cksum = b->flags & VNET_BUFFER_F_OFFLOAD_UDP_CKSUM;
  int is_ip4 = b->flags & VNET_BUFFER_F_IS_IP4;
  u64 ol_flags;

  /* Is there any work for us? */
  if (PREDICT_TRUE ((ip_cksum | tcp_cksum | udp_cksum) == 0))
    return;

  mb->l2_len = vnet_buffer (b)->l3_hdr_offset - b->current_data;
  mb->l3_len = vnet_buffer (b)->l4_hdr_offset -
    vnet_buffer (b)->l3_hdr_offset;
  mb->outer_l3_len = 0;
  mb->outer_l2_len = 0;
  ol_flags = is_ip4 ? PKT_TX_IPV4 : PKT_TX_IPV6;
  ol_flags |= ip_cksum ? PKT_TX_IP_CKSUM : 0;
  ol_flags |= tcp_cksum ? PKT_TX_TCP_CKSUM : 0;
  ol_flags |= udp_cksum ? PKT_TX_UDP_CKSUM : 0;
  mb->ol_flags |= ol_flags;

  /* we are trying to help compiler here by using local ol_flags with known
     state of all flags */
  if (xd->flags & DPDK_DEVICE_FLAG_INTEL_PHDR_CKSUM)
    rte_net_intel_cksum_flags_prepare (mb, ol_flags);
}

/*
 * Transmits the packets on the frame to the interface associated with the
 * node. It first copies packets on the frame to a per-thread arrays
 * containing the rte_mbuf pointers.
 */
VNET_DEVICE_CLASS_TX_FN (dpdk_device_class) (vlib_main_t * vm,
					     vlib_node_runtime_t * node,
					     vlib_frame_t * f)
{
  dpdk_main_t *dm = &dpdk_main;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, rd->dev_instance);
  u32 n_packets = f->n_vectors;
  u32 n_left;
  u32 *from;
  u32 thread_index = vm->thread_index;
  int queue_id = thread_index;
  u32 tx_pkts = 0, all_or_flags = 0;
  dpdk_per_thread_data_t *ptd = vec_elt_at_index (dm->per_thread_data,
						  thread_index);
  struct rte_mbuf **mb;
  vlib_buffer_t *b[4];

  from = vlib_frame_vector_args (f);

  ASSERT (n_packets <= VLIB_FRAME_SIZE);

  /* TX PCAP tracing */
  if (PREDICT_FALSE (dm->pcap[VLIB_TX].pcap_enable))
    {
      n_left = n_packets;
      while (n_left > 0)
	{
	  u32 bi0 = from[0];
	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
	  if (dm->pcap[VLIB_TX].pcap_sw_if_index == 0 ||
	      dm->pcap[VLIB_TX].pcap_sw_if_index
	      == vnet_buffer (b0)->sw_if_index[VLIB_TX])
	    pcap_add_buffer (&dm->pcap[VLIB_TX].pcap_main, vm, bi0, 512);
	  from++;
	  n_left--;
	}
    }

  /* calculate rte_mbuf pointers out of buffer indices */
  vlib_get_buffers_with_offset (vm, vlib_frame_vector_args (f),
				(void **) ptd->mbufs, n_packets,
				-(i32) sizeof (struct rte_mbuf));

  from = vlib_frame_vector_args (f);
  n_left = n_packets;
  mb = ptd->mbufs;

  while (n_left >= 8)
    {
      u32 or_flags;

      dpdk_prefetch_buffer (vm, mb[4]);
      dpdk_prefetch_buffer (vm, mb[5]);
      dpdk_prefetch_buffer (vm, mb[6]);
      dpdk_prefetch_buffer (vm, mb[7]);

      b[0] = vlib_buffer_from_rte_mbuf (mb[0]);
      b[1] = vlib_buffer_from_rte_mbuf (mb[1]);
      b[2] = vlib_buffer_from_rte_mbuf (mb[2]);
      b[3] = vlib_buffer_from_rte_mbuf (mb[3]);

      or_flags = b[0]->flags | b[1]->flags | b[2]->flags | b[3]->flags;
      all_or_flags |= or_flags;

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[1]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[2]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[3]);

      if (or_flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  dpdk_validate_rte_mbuf (vm, b[0], 1);
	  dpdk_validate_rte_mbuf (vm, b[1], 1);
	  dpdk_validate_rte_mbuf (vm, b[2], 1);
	  dpdk_validate_rte_mbuf (vm, b[3], 1);
	}
      else
	{
	  dpdk_validate_rte_mbuf (vm, b[0], 0);
	  dpdk_validate_rte_mbuf (vm, b[1], 0);
	  dpdk_validate_rte_mbuf (vm, b[2], 0);
	  dpdk_validate_rte_mbuf (vm, b[3], 0);
	}

      if (PREDICT_FALSE ((xd->flags & DPDK_DEVICE_FLAG_TX_OFFLOAD) &&
			 (or_flags &
			  (VNET_BUFFER_F_OFFLOAD_TCP_CKSUM
			   | VNET_BUFFER_F_OFFLOAD_IP_CKSUM
			   | VNET_BUFFER_F_OFFLOAD_UDP_CKSUM))))
	{
	  dpdk_buffer_tx_offload (xd, b[0], mb[0]);
	  dpdk_buffer_tx_offload (xd, b[1], mb[1]);
	  dpdk_buffer_tx_offload (xd, b[2], mb[2]);
	  dpdk_buffer_tx_offload (xd, b[3], mb[3]);
	}

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    dpdk_tx_trace_buffer (dm, node, xd, queue_id, b[0]);
	  if (b[1]->flags & VLIB_BUFFER_IS_TRACED)
	    dpdk_tx_trace_buffer (dm, node, xd, queue_id, b[1]);
	  if (b[2]->flags & VLIB_BUFFER_IS_TRACED)
	    dpdk_tx_trace_buffer (dm, node, xd, queue_id, b[2]);
	  if (b[3]->flags & VLIB_BUFFER_IS_TRACED)
	    dpdk_tx_trace_buffer (dm, node, xd, queue_id, b[3]);
	}

      mb += 4;
      n_left -= 4;
    }
  while (n_left > 0)
    {
      b[0] = vlib_buffer_from_rte_mbuf (mb[0]);
      all_or_flags |= b[0]->flags;
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);

      dpdk_validate_rte_mbuf (vm, b[0], 1);
      dpdk_buffer_tx_offload (xd, b[0], mb[0]);

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	  dpdk_tx_trace_buffer (dm, node, xd, queue_id, b[0]);

      mb++;
      n_left--;
    }

  /* run inly if we have buffers to recycle */
  if (PREDICT_FALSE (all_or_flags & VLIB_BUFFER_RECYCLE))
    {
      struct rte_mbuf **mb_old;
      from = vlib_frame_vector_args (f);
      n_left = n_packets;
      mb_old = mb = ptd->mbufs;
      while (n_left > 0)
	{
	  b[0] = vlib_buffer_from_rte_mbuf (mb[0]);
	  dpdk_buffer_recycle (vm, node, b[0], from[0], &mb_old[0]);

	  /* in case of REPL_FAIL we need to shift data */
	  mb[0] = mb_old[0];

	  if (PREDICT_TRUE ((b[0]->flags & VLIB_BUFFER_REPL_FAIL) == 0))
	    mb++;
	  mb_old++;
	  from++;
	  n_left--;
	}
    }

  /* transmit as many packets as possible */
  tx_pkts = n_packets = mb - ptd->mbufs;
  n_left = tx_burst_vector_internal (vm, xd, ptd->mbufs, n_packets);

  {
    /* If there is no callback then drop any non-transmitted packets */
    if (PREDICT_FALSE (n_left))
      {
	tx_pkts -= n_left;
	vlib_simple_counter_main_t *cm;
	vnet_main_t *vnm = vnet_get_main ();

	cm = vec_elt_at_index (vnm->interface_main.sw_if_counters,
			       VNET_INTERFACE_COUNTER_TX_ERROR);

	vlib_increment_simple_counter (cm, thread_index, xd->sw_if_index,
				       n_left);

	vlib_error_count (vm, node->node_index, DPDK_TX_FUNC_ERROR_PKT_DROP,
			  n_left);

	while (n_left--)
	  rte_pktmbuf_free (ptd->mbufs[n_packets - n_left - 1]);
      }
  }

  /* Recycle replicated buffers */
  if (PREDICT_FALSE (vec_len (dm->recycle[thread_index])))
    {
      vlib_buffer_free (vm, dm->recycle[thread_index],
			vec_len (dm->recycle[thread_index]));
      _vec_len (dm->recycle[thread_index]) = 0;
    }

  return tx_pkts;
}

static void
dpdk_clear_hw_interface_counters (u32 instance)
{
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, instance);

  /*
   * Set the "last_cleared_stats" to the current stats, so that
   * things appear to clear from a display perspective.
   */
  dpdk_update_counters (xd, vlib_time_now (dm->vlib_main));

  clib_memcpy (&xd->last_cleared_stats, &xd->stats, sizeof (xd->stats));
  clib_memcpy (xd->last_cleared_xstats, xd->xstats,
	       vec_len (xd->last_cleared_xstats) *
	       sizeof (xd->last_cleared_xstats[0]));

}

static clib_error_t *
dpdk_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hif = vnet_get_hw_interface (vnm, hw_if_index);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, hif->dev_instance);

  if (xd->flags & DPDK_DEVICE_FLAG_PMD_INIT_FAIL)
    return clib_error_return (0, "Interface not initialized");

  if (is_up)
    {
      vnet_hw_interface_set_flags (vnm, xd->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      if ((xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP) == 0)
	dpdk_device_start (xd);
      xd->flags |= DPDK_DEVICE_FLAG_ADMIN_UP;
      f64 now = vlib_time_now (dm->vlib_main);
      dpdk_update_counters (xd, now);
      dpdk_update_link_state (xd, now);
    }
  else
    {
      vnet_hw_interface_set_flags (vnm, xd->hw_if_index, 0);
      if ((xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP) != 0)
	dpdk_device_stop (xd);
      xd->flags &= ~DPDK_DEVICE_FLAG_ADMIN_UP;
    }

  return /* no error */ 0;
}

/*
 * Dynamically redirect all pkts from a specific interface
 * to the specified node
 */
static void
dpdk_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
			      u32 node_index)
{
  dpdk_main_t *xm = &dpdk_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  dpdk_device_t *xd = vec_elt_at_index (xm->devices, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      xd->per_interface_next_index = node_index;
      return;
    }

  xd->per_interface_next_index =
    vlib_node_add_next (xm->vlib_main, dpdk_input_node.index, node_index);
}


static clib_error_t *
dpdk_subif_add_del_function (vnet_main_t * vnm,
			     u32 hw_if_index,
			     struct vnet_sw_interface_t *st, int is_add)
{
  dpdk_main_t *xm = &dpdk_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  dpdk_device_t *xd = vec_elt_at_index (xm->devices, hw->dev_instance);
  vnet_sw_interface_t *t = (vnet_sw_interface_t *) st;
  int r, vlan_offload;
  u32 prev_subifs = xd->num_subifs;
  clib_error_t *err = 0;

  if (is_add)
    xd->num_subifs++;
  else if (xd->num_subifs)
    xd->num_subifs--;

  if ((xd->flags & DPDK_DEVICE_FLAG_PMD) == 0)
    goto done;

  /* currently we program VLANS only for IXGBE VF and I40E VF */
  if ((xd->pmd != VNET_DPDK_PMD_IXGBEVF) && (xd->pmd != VNET_DPDK_PMD_I40EVF))
    goto done;

  if (t->sub.eth.flags.no_tags == 1)
    goto done;

  if ((t->sub.eth.flags.one_tag != 1) || (t->sub.eth.flags.exact_match != 1))
    {
      xd->num_subifs = prev_subifs;
      err = clib_error_return (0, "unsupported VLAN setup");
      goto done;
    }

  vlan_offload = rte_eth_dev_get_vlan_offload (xd->port_id);
  vlan_offload |= ETH_VLAN_FILTER_OFFLOAD;

  if ((r = rte_eth_dev_set_vlan_offload (xd->port_id, vlan_offload)))
    {
      xd->num_subifs = prev_subifs;
      err = clib_error_return (0, "rte_eth_dev_set_vlan_offload[%d]: err %d",
			       xd->port_id, r);
      goto done;
    }


  if ((r =
       rte_eth_dev_vlan_filter (xd->port_id,
				t->sub.eth.outer_vlan_id, is_add)))
    {
      xd->num_subifs = prev_subifs;
      err = clib_error_return (0, "rte_eth_dev_vlan_filter[%d]: err %d",
			       xd->port_id, r);
      goto done;
    }

done:
  if (xd->num_subifs)
    xd->flags |= DPDK_DEVICE_FLAG_HAVE_SUBIF;
  else
    xd->flags &= ~DPDK_DEVICE_FLAG_HAVE_SUBIF;

  return err;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (dpdk_device_class) = {
  .name = "dpdk",
  .tx_function_n_errors = DPDK_TX_FUNC_N_ERROR,
  .tx_function_error_strings = dpdk_tx_func_error_strings,
  .format_device_name = format_dpdk_device_name,
  .format_device = format_dpdk_device,
  .format_tx_trace = format_dpdk_tx_trace,
  .clear_counters = dpdk_clear_hw_interface_counters,
  .admin_up_down_function = dpdk_interface_admin_up_down,
  .subif_add_del_function = dpdk_subif_add_del_function,
  .rx_redirect_to_node = dpdk_set_interface_next_node,
  .mac_addr_change_function = dpdk_set_mac_address,
  .format_flow = format_dpdk_flow,
  .flow_ops_function = dpdk_flow_ops_fn,
};
/* *INDENT-ON* */

#define UP_DOWN_FLAG_EVENT 1

static uword
admin_up_down_process (vlib_main_t * vm,
		       vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  clib_error_t *error = 0;
  uword event_type;
  uword *event_data = 0;
  u32 sw_if_index;
  u32 flags;

  while (1)
    {
      vlib_process_wait_for_event (vm);

      event_type = vlib_process_get_events (vm, &event_data);

      dpdk_main.admin_up_down_in_progress = 1;

      switch (event_type)
	{
	case UP_DOWN_FLAG_EVENT:
	  {
	    if (vec_len (event_data) == 2)
	      {
		sw_if_index = event_data[0];
		flags = event_data[1];
		error =
		  vnet_sw_interface_set_flags (vnet_get_main (), sw_if_index,
					       flags);
		clib_error_report (error);
	      }
	  }
	  break;
	}

      vec_reset_length (event_data);

      dpdk_main.admin_up_down_in_progress = 0;

    }
  return 0;			/* or not */
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (admin_up_down_process_node) = {
    .function = admin_up_down_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "admin-up-down-process",
    .process_log2_n_stack_bytes = 17,  // 256KB
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
