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
  _(RING_FULL, "Tx packet drops (ring full)")	        \
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

  error = rte_eth_dev_default_mac_addr_set (xd->device_index,
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

struct rte_mbuf *
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
dpdk_tx_trace_buffer (dpdk_main_t * dm,
		      vlib_node_runtime_t * node,
		      dpdk_device_t * xd,
		      u16 queue_id, u32 buffer_index, vlib_buffer_t * buffer)
{
  vlib_main_t *vm = vlib_get_main ();
  dpdk_tx_dma_trace_t *t0;
  struct rte_mbuf *mb;

  mb = rte_mbuf_from_vlib_buffer (buffer);

  t0 = vlib_add_trace (vm, node, buffer, sizeof (t0[0]));
  t0->queue_index = queue_id;
  t0->device_index = xd->device_index;
  t0->buffer_index = buffer_index;
  clib_memcpy (&t0->mb, mb, sizeof (t0->mb));
  clib_memcpy (&t0->buffer, buffer,
	       sizeof (buffer[0]) - sizeof (buffer->pre_data));
  clib_memcpy (t0->buffer.pre_data, buffer->data + buffer->current_data,
	       sizeof (t0->buffer.pre_data));
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
 * This function calls the dpdk's tx_burst function to transmit the packets
 * on the tx_vector. It manages a lock per-device if the device does not
 * support multiple queues. It returns the number of packets untransmitted
 * on the tx_vector. If all packets are transmitted (the normal case), the
 * function returns 0.
 *
 * The function assumes there is at least one packet on the tx_vector.
 */
static_always_inline
  u32 tx_burst_vector_internal (vlib_main_t * vm,
				dpdk_device_t * xd,
				struct rte_mbuf **tx_vector)
{
  dpdk_main_t *dm = &dpdk_main;
  u32 n_packets;
  u32 tx_head;
  u32 tx_tail;
  u32 n_retry;
  int rv;
  int queue_id;
  tx_ring_hdr_t *ring;

  ring = vec_header (tx_vector, sizeof (*ring));

  n_packets = ring->tx_head - ring->tx_tail;

  tx_head = ring->tx_head % xd->nb_tx_desc;

  /*
   * Ensure rte_eth_tx_burst is not called with 0 packets, which can lead to
   * unpredictable results.
   */
  ASSERT (n_packets > 0);

  /*
   * Check for tx_vector overflow. If this fails it is a system configuration
   * error. The ring should be sized big enough to handle the largest un-flowed
   * off burst from a traffic manager. A larger size also helps performance
   * a bit because it decreases the probability of having to issue two tx_burst
   * calls due to a ring wrap.
   */
  ASSERT (n_packets < xd->nb_tx_desc);
  ASSERT (ring->tx_tail == 0);

  n_retry = 16;
  queue_id = vm->thread_index;

  do
    {
      /* start the burst at the tail */
      tx_tail = ring->tx_tail % xd->nb_tx_desc;

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

	  dpdk_hqos_metadata_set (hqos,
				  &tx_vector[tx_tail], tx_head - tx_tail);
	  rv = rte_ring_sp_enqueue_burst (hqos->swq,
					  (void **) &tx_vector[tx_tail],
					  (uint16_t) (tx_head - tx_tail), 0);
	}
      else if (PREDICT_TRUE (xd->flags & DPDK_DEVICE_FLAG_PMD))
	{
	  /* no wrap, transmit in one burst */
	  rv = rte_eth_tx_burst (xd->device_index,
				 (uint16_t) queue_id,
				 &tx_vector[tx_tail],
				 (uint16_t) (tx_head - tx_tail));
	}
      else
	{
	  ASSERT (0);
	  rv = 0;
	}

      if (PREDICT_FALSE (xd->lockp != 0))
	*xd->lockp[queue_id] = 0;

      if (PREDICT_FALSE (rv < 0))
	{
	  // emit non-fatal message, bump counter
	  vnet_main_t *vnm = dm->vnet_main;
	  vnet_interface_main_t *im = &vnm->interface_main;
	  u32 node_index;

	  node_index = vec_elt_at_index (im->hw_interfaces,
					 xd->hw_if_index)->tx_node_index;

	  vlib_error_count (vm, node_index, DPDK_TX_FUNC_ERROR_BAD_RETVAL, 1);
	  clib_warning ("rte_eth_tx_burst[%d]: error %d", xd->device_index,
			rv);
	  return n_packets;	// untransmitted packets
	}
      ring->tx_tail += (u16) rv;
      n_packets -= (uint16_t) rv;
    }
  while (rv && n_packets && (n_retry > 0));

  return n_packets;
}

static_always_inline void
dpdk_prefetch_buffer_by_index (vlib_main_t * vm, u32 bi)
{
  vlib_buffer_t *b;
  struct rte_mbuf *mb;
  b = vlib_get_buffer (vm, bi);
  mb = rte_mbuf_from_vlib_buffer (b);
  CLIB_PREFETCH (mb, 2 * CLIB_CACHE_LINE_BYTES, STORE);
  CLIB_PREFETCH (b, CLIB_CACHE_LINE_BYTES, LOAD);
}

static_always_inline void
dpdk_buffer_recycle (vlib_main_t * vm, vlib_node_runtime_t * node,
		     vlib_buffer_t * b, u32 bi, struct rte_mbuf **mbp)
{
  dpdk_main_t *dm = &dpdk_main;
  u32 my_cpu = vm->thread_index;
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

  vec_add1 (dm->recycle[my_cpu], bi);
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
 * node. It first copies packets on the frame to a tx_vector containing the
 * rte_mbuf pointers. It then passes this vector to tx_burst_vector_internal
 * which calls the dpdk tx_burst function.
 */
static uword
dpdk_interface_tx (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * f)
{
  dpdk_main_t *dm = &dpdk_main;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, rd->dev_instance);
  u32 n_packets = f->n_vectors;
  u32 n_left;
  u32 *from;
  struct rte_mbuf **tx_vector;
  u16 i;
  u16 nb_tx_desc = xd->nb_tx_desc;
  int queue_id;
  u32 my_cpu;
  u32 tx_pkts = 0;
  tx_ring_hdr_t *ring;
  u32 n_on_ring;

  my_cpu = vm->thread_index;

  queue_id = my_cpu;

  tx_vector = xd->tx_vectors[queue_id];
  ring = vec_header (tx_vector, sizeof (*ring));

  n_on_ring = ring->tx_head - ring->tx_tail;
  from = vlib_frame_vector_args (f);

  ASSERT (n_packets <= VLIB_FRAME_SIZE);

  if (PREDICT_FALSE (n_on_ring + n_packets > nb_tx_desc))
    {
      /*
       * Overflowing the ring should never happen.
       * If it does then drop the whole frame.
       */
      vlib_error_count (vm, node->node_index, DPDK_TX_FUNC_ERROR_RING_FULL,
			n_packets);

      while (n_packets--)
	{
	  u32 bi0 = from[n_packets];
	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
	  struct rte_mbuf *mb0 = rte_mbuf_from_vlib_buffer (b0);
	  rte_pktmbuf_free (mb0);
	}
      return n_on_ring;
    }

  if (PREDICT_FALSE (dm->tx_pcap_enable))
    {
      n_left = n_packets;
      while (n_left > 0)
	{
	  u32 bi0 = from[0];
	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
	  if (dm->pcap_sw_if_index == 0 ||
	      dm->pcap_sw_if_index == vnet_buffer (b0)->sw_if_index[VLIB_TX])
	    pcap_add_buffer (&dm->pcap_main, vm, bi0, 512);
	  from++;
	  n_left--;
	}
    }

  from = vlib_frame_vector_args (f);
  n_left = n_packets;
  i = ring->tx_head % nb_tx_desc;

  while (n_left >= 8)
    {
      u32 bi0, bi1, bi2, bi3;
      struct rte_mbuf *mb0, *mb1, *mb2, *mb3;
      vlib_buffer_t *b0, *b1, *b2, *b3;
      u32 or_flags;

      dpdk_prefetch_buffer_by_index (vm, from[4]);
      dpdk_prefetch_buffer_by_index (vm, from[5]);
      dpdk_prefetch_buffer_by_index (vm, from[6]);
      dpdk_prefetch_buffer_by_index (vm, from[7]);

      bi0 = from[0];
      bi1 = from[1];
      bi2 = from[2];
      bi3 = from[3];
      from += 4;

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);
      b2 = vlib_get_buffer (vm, bi2);
      b3 = vlib_get_buffer (vm, bi3);

      or_flags = b0->flags | b1->flags | b2->flags | b3->flags;

      if (or_flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  dpdk_validate_rte_mbuf (vm, b0, 1);
	  dpdk_validate_rte_mbuf (vm, b1, 1);
	  dpdk_validate_rte_mbuf (vm, b2, 1);
	  dpdk_validate_rte_mbuf (vm, b3, 1);
	}
      else
	{
	  dpdk_validate_rte_mbuf (vm, b0, 0);
	  dpdk_validate_rte_mbuf (vm, b1, 0);
	  dpdk_validate_rte_mbuf (vm, b2, 0);
	  dpdk_validate_rte_mbuf (vm, b3, 0);
	}

      mb0 = rte_mbuf_from_vlib_buffer (b0);
      mb1 = rte_mbuf_from_vlib_buffer (b1);
      mb2 = rte_mbuf_from_vlib_buffer (b2);
      mb3 = rte_mbuf_from_vlib_buffer (b3);

      if (PREDICT_FALSE ((xd->flags & DPDK_DEVICE_FLAG_TX_OFFLOAD) &&
			 (or_flags &
			  (VNET_BUFFER_F_OFFLOAD_TCP_CKSUM
			   | VNET_BUFFER_F_OFFLOAD_IP_CKSUM
			   | VNET_BUFFER_F_OFFLOAD_UDP_CKSUM))))
	{
	  dpdk_buffer_tx_offload (xd, b0, mb0);
	  dpdk_buffer_tx_offload (xd, b1, mb1);
	  dpdk_buffer_tx_offload (xd, b2, mb2);
	  dpdk_buffer_tx_offload (xd, b3, mb3);
	}

      if (PREDICT_FALSE (or_flags & VLIB_BUFFER_RECYCLE))
	{
	  dpdk_buffer_recycle (vm, node, b0, bi0, &mb0);
	  dpdk_buffer_recycle (vm, node, b1, bi1, &mb1);
	  dpdk_buffer_recycle (vm, node, b2, bi2, &mb2);
	  dpdk_buffer_recycle (vm, node, b3, bi3, &mb3);

	  /* dont enqueue packets if replication failed as they must
	     be sent back to recycle */
	  if (PREDICT_TRUE ((b0->flags & VLIB_BUFFER_REPL_FAIL) == 0))
	    tx_vector[i++ % nb_tx_desc] = mb0;
	  if (PREDICT_TRUE ((b1->flags & VLIB_BUFFER_REPL_FAIL) == 0))
	    tx_vector[i++ % nb_tx_desc] = mb1;
	  if (PREDICT_TRUE ((b2->flags & VLIB_BUFFER_REPL_FAIL) == 0))
	    tx_vector[i++ % nb_tx_desc] = mb2;
	  if (PREDICT_TRUE ((b3->flags & VLIB_BUFFER_REPL_FAIL) == 0))
	    tx_vector[i++ % nb_tx_desc] = mb3;
	}
      else
	{
	  if (PREDICT_FALSE (i + 3 >= nb_tx_desc))
	    {
	      tx_vector[i++ % nb_tx_desc] = mb0;
	      tx_vector[i++ % nb_tx_desc] = mb1;
	      tx_vector[i++ % nb_tx_desc] = mb2;
	      tx_vector[i++ % nb_tx_desc] = mb3;
	      i %= nb_tx_desc;
	    }
	  else
	    {
	      tx_vector[i++] = mb0;
	      tx_vector[i++] = mb1;
	      tx_vector[i++] = mb2;
	      tx_vector[i++] = mb3;
	    }
	}


      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	{
	  if (b0->flags & VLIB_BUFFER_IS_TRACED)
	    dpdk_tx_trace_buffer (dm, node, xd, queue_id, bi0, b0);
	  if (b1->flags & VLIB_BUFFER_IS_TRACED)
	    dpdk_tx_trace_buffer (dm, node, xd, queue_id, bi1, b1);
	  if (b2->flags & VLIB_BUFFER_IS_TRACED)
	    dpdk_tx_trace_buffer (dm, node, xd, queue_id, bi2, b2);
	  if (b3->flags & VLIB_BUFFER_IS_TRACED)
	    dpdk_tx_trace_buffer (dm, node, xd, queue_id, bi3, b3);
	}

      n_left -= 4;
    }
  while (n_left > 0)
    {
      u32 bi0;
      struct rte_mbuf *mb0;
      vlib_buffer_t *b0;

      bi0 = from[0];
      from++;

      b0 = vlib_get_buffer (vm, bi0);

      dpdk_validate_rte_mbuf (vm, b0, 1);

      mb0 = rte_mbuf_from_vlib_buffer (b0);
      dpdk_buffer_tx_offload (xd, b0, mb0);
      dpdk_buffer_recycle (vm, node, b0, bi0, &mb0);

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	if (b0->flags & VLIB_BUFFER_IS_TRACED)
	  dpdk_tx_trace_buffer (dm, node, xd, queue_id, bi0, b0);

      if (PREDICT_TRUE ((b0->flags & VLIB_BUFFER_REPL_FAIL) == 0))
	{
	  tx_vector[i % nb_tx_desc] = mb0;
	  i++;
	}
      n_left--;
    }

  /* account for additional packets in the ring */
  ring->tx_head += n_packets;
  n_on_ring = ring->tx_head - ring->tx_tail;

  /* transmit as many packets as possible */
  n_packets = tx_burst_vector_internal (vm, xd, tx_vector);

  /*
   * tx_pkts is the number of packets successfully transmitted
   * This is the number originally on ring minus the number remaining on ring
   */
  tx_pkts = n_on_ring - n_packets;

  {
    /* If there is no callback then drop any non-transmitted packets */
    if (PREDICT_FALSE (n_packets))
      {
	vlib_simple_counter_main_t *cm;
	vnet_main_t *vnm = vnet_get_main ();

	cm = vec_elt_at_index (vnm->interface_main.sw_if_counters,
			       VNET_INTERFACE_COUNTER_TX_ERROR);

	vlib_increment_simple_counter (cm, my_cpu, xd->vlib_sw_if_index,
				       n_packets);

	vlib_error_count (vm, node->node_index, DPDK_TX_FUNC_ERROR_PKT_DROP,
			  n_packets);

	while (n_packets--)
	  rte_pktmbuf_free (tx_vector[ring->tx_tail + n_packets]);
      }

    /* Reset head/tail to avoid unnecessary wrap */
    ring->tx_head = 0;
    ring->tx_tail = 0;
  }

  /* Recycle replicated buffers */
  if (PREDICT_FALSE (vec_len (dm->recycle[my_cpu])))
    {
      vlib_buffer_free (vm, dm->recycle[my_cpu],
			vec_len (dm->recycle[my_cpu]));
      _vec_len (dm->recycle[my_cpu]) = 0;
    }

  ASSERT (ring->tx_head >= ring->tx_tail);

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

  vlan_offload = rte_eth_dev_get_vlan_offload (xd->device_index);
  vlan_offload |= ETH_VLAN_FILTER_OFFLOAD;

  if ((r = rte_eth_dev_set_vlan_offload (xd->device_index, vlan_offload)))
    {
      xd->num_subifs = prev_subifs;
      err = clib_error_return (0, "rte_eth_dev_set_vlan_offload[%d]: err %d",
			       xd->device_index, r);
      goto done;
    }


  if ((r =
       rte_eth_dev_vlan_filter (xd->device_index, t->sub.eth.outer_vlan_id,
				is_add)))
    {
      xd->num_subifs = prev_subifs;
      err = clib_error_return (0, "rte_eth_dev_vlan_filter[%d]: err %d",
			       xd->device_index, r);
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
  .tx_function = dpdk_interface_tx,
  .tx_function_n_errors = DPDK_TX_FUNC_N_ERROR,
  .tx_function_error_strings = dpdk_tx_func_error_strings,
  .format_device_name = format_dpdk_device_name,
  .format_device = format_dpdk_device,
  .format_tx_trace = format_dpdk_tx_dma_trace,
  .clear_counters = dpdk_clear_hw_interface_counters,
  .admin_up_down_function = dpdk_interface_admin_up_down,
  .subif_add_del_function = dpdk_subif_add_del_function,
  .rx_redirect_to_node = dpdk_set_interface_next_node,
  .mac_addr_change_function = dpdk_set_mac_address,
};

VLIB_DEVICE_TX_FUNCTION_MULTIARCH (dpdk_device_class, dpdk_interface_tx)
/* *INDENT-ON* */

#define UP_DOWN_FLAG_EVENT 1

uword
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
VLIB_REGISTER_NODE (admin_up_down_process_node,static) = {
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
