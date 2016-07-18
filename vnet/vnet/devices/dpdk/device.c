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
#include <vnet/devices/dpdk/dpdk.h>

#include "dpdk_priv.h"
#include <vppinfra/error.h>

#define foreach_dpdk_tx_func_error			\
  _(BAD_RETVAL, "DPDK tx function returned an error")	\
  _(RING_FULL, "Tx packet drops (ring full)")	        \
  _(PKT_DROP, "Tx packet drops (dpdk tx failure)")	\
  _(REPL_FAIL, "Tx packet drops (replication failure)")

typedef enum {
#define _(f,s) DPDK_TX_FUNC_ERROR_##f,
  foreach_dpdk_tx_func_error
#undef _
  DPDK_TX_FUNC_N_ERROR,
} dpdk_tx_func_error_t;

static char * dpdk_tx_func_error_strings[] = {
#define _(n,s) s,
    foreach_dpdk_tx_func_error
#undef _
};

clib_error_t *
dpdk_set_mac_address (vnet_hw_interface_t * hi, char * address)
{
   int error;
   dpdk_main_t * dm = &dpdk_main;
   dpdk_device_t * xd = vec_elt_at_index (dm->devices, hi->dev_instance);

   error=rte_eth_dev_default_mac_addr_set(xd->device_index,
                                          (struct ether_addr *) address);

   if (error) {
     return clib_error_return (0, "mac address set failed: %d", error);
   } else {
     return NULL;
  }
}

clib_error_t *
dpdk_set_mc_filter (vnet_hw_interface_t * hi,
                    struct ether_addr mc_addr_vec[], int naddr)
{
  int error;
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t * xd = vec_elt_at_index (dm->devices, hi->dev_instance);

  error=rte_eth_dev_set_mc_addr_list(xd->device_index, mc_addr_vec, naddr);

  if (error) {
    return clib_error_return (0, "mc addr list failed: %d", error);
  } else {
    return NULL;
  }
}

struct rte_mbuf * dpdk_replicate_packet_mb (vlib_buffer_t * b)
{
  vlib_main_t * vm = vlib_get_main();
  vlib_buffer_main_t * bm = vm->buffer_main;
  struct rte_mbuf * first_mb = 0, * new_mb, * pkt_mb, ** prev_mb_next = 0;
  u8 nb_segs, nb_segs_left;
  u32 copy_bytes;
  unsigned socket_id = rte_socket_id();

  ASSERT (bm->pktmbuf_pools[socket_id]);
  pkt_mb = rte_mbuf_from_vlib_buffer(b);
  nb_segs = pkt_mb->nb_segs;
  for (nb_segs_left = nb_segs; nb_segs_left; nb_segs_left--)
    {
      if (PREDICT_FALSE(pkt_mb == 0))
	{
	  clib_warning ("Missing %d mbuf chain segment(s):   "
			"(nb_segs = %d, nb_segs_left = %d)!",
			nb_segs - nb_segs_left, nb_segs, nb_segs_left);
	  if (first_mb)
	    rte_pktmbuf_free(first_mb);
	  return NULL;
	}
      new_mb = rte_pktmbuf_alloc (bm->pktmbuf_pools[socket_id]);
      if (PREDICT_FALSE(new_mb == 0))
	{
	  if (first_mb)
	    rte_pktmbuf_free(first_mb);
	  return NULL;
	}
      
      /*
       * Copy packet info into 1st segment.
       */
      if (first_mb == 0)
	{
	  first_mb = new_mb;
	  rte_pktmbuf_pkt_len (first_mb) = pkt_mb->pkt_len;
	  first_mb->nb_segs = pkt_mb->nb_segs;
	  first_mb->port = pkt_mb->port;
#ifdef DAW_FIXME // TX Offload support TBD
	  first_mb->vlan_macip = pkt_mb->vlan_macip;
	  first_mb->hash = pkt_mb->hash;
	  first_mb->ol_flags = pkt_mb->ol_flags
#endif
	}
      else
	{
	  ASSERT(prev_mb_next != 0);
	  *prev_mb_next = new_mb;
	}
      
      /*
       * Copy packet segment data into new mbuf segment.
       */
      rte_pktmbuf_data_len (new_mb) = pkt_mb->data_len;
      copy_bytes = pkt_mb->data_len + RTE_PKTMBUF_HEADROOM;
      ASSERT(copy_bytes <= pkt_mb->buf_len);
      clib_memcpy(new_mb->buf_addr, pkt_mb->buf_addr, copy_bytes);

      prev_mb_next = &new_mb->next;
      pkt_mb = pkt_mb->next;
    }

  ASSERT(pkt_mb == 0);
  __rte_mbuf_sanity_check(first_mb, 1);

  return first_mb;
}

struct rte_mbuf * dpdk_zerocopy_replicate_packet_mb (vlib_buffer_t * b)
{
  vlib_main_t * vm = vlib_get_main();
  vlib_buffer_main_t * bm = vm->buffer_main;
  struct rte_mbuf * first_mb = 0, * new_mb, * pkt_mb, ** prev_mb_next = 0;
  u8 nb_segs, nb_segs_left;
  unsigned socket_id = rte_socket_id();

  ASSERT (bm->pktmbuf_pools[socket_id]);
  pkt_mb = rte_mbuf_from_vlib_buffer(b);
  nb_segs = pkt_mb->nb_segs;
  for (nb_segs_left = nb_segs; nb_segs_left; nb_segs_left--)
    {
      if (PREDICT_FALSE(pkt_mb == 0))
	{
	  clib_warning ("Missing %d mbuf chain segment(s):   "
			"(nb_segs = %d, nb_segs_left = %d)!",
			nb_segs - nb_segs_left, nb_segs, nb_segs_left);
	  if (first_mb)
	    rte_pktmbuf_free(first_mb);
	  return NULL;
	}
      new_mb = rte_pktmbuf_clone(pkt_mb, bm->pktmbuf_pools[socket_id]);
      if (PREDICT_FALSE(new_mb == 0))
	{
	  if (first_mb)
	    rte_pktmbuf_free(first_mb);
	  return NULL;
	}
      
      /*
       * Copy packet info into 1st segment.
       */
      if (first_mb == 0)
	{
	  first_mb = new_mb;
	  rte_pktmbuf_pkt_len (first_mb) = pkt_mb->pkt_len;
	  first_mb->nb_segs = pkt_mb->nb_segs;
	  first_mb->port = pkt_mb->port;
#ifdef DAW_FIXME // TX Offload support TBD
	  first_mb->vlan_macip = pkt_mb->vlan_macip;
	  first_mb->hash = pkt_mb->hash;
	  first_mb->ol_flags = pkt_mb->ol_flags
#endif
	}
      else
	{
	  ASSERT(prev_mb_next != 0);
	  *prev_mb_next = new_mb;
	}
      
      /*
       * Copy packet segment data into new mbuf segment.
       */
      rte_pktmbuf_data_len (new_mb) = pkt_mb->data_len;

      prev_mb_next = &new_mb->next;
      pkt_mb = pkt_mb->next;
    }

  ASSERT(pkt_mb == 0);
  __rte_mbuf_sanity_check(first_mb, 1);

  return first_mb;


}

static void
dpdk_tx_trace_buffer (dpdk_main_t * dm,
		      vlib_node_runtime_t * node,
		      dpdk_device_t * xd,
		      u16 queue_id,
		      u32 buffer_index,
		      vlib_buffer_t * buffer)
{
  vlib_main_t * vm = vlib_get_main();
  dpdk_tx_dma_trace_t * t0;
  struct rte_mbuf * mb;

  mb = rte_mbuf_from_vlib_buffer(buffer);

  t0 = vlib_add_trace (vm, node, buffer, sizeof (t0[0]));
  t0->queue_index = queue_id;
  t0->device_index = xd->device_index;
  t0->buffer_index = buffer_index;
  clib_memcpy (&t0->mb, mb, sizeof (t0->mb));
  clib_memcpy (&t0->buffer, buffer, sizeof (buffer[0]) - sizeof (buffer->pre_data));
  clib_memcpy (t0->buffer.pre_data, buffer->data + buffer->current_data,
	  sizeof (t0->buffer.pre_data));
}

/*
 * This function calls the dpdk's tx_burst function to transmit the packets
 * on the tx_vector. It manages a lock per-device if the device does not
 * support multiple queues. It returns the number of packets untransmitted 
 * on the tx_vector. If all packets are transmitted (the normal case), the 
 * function returns 0.
 * 
 * The tx_burst function may not be able to transmit all packets because the 
 * dpdk ring is full. If a flowcontrol callback function has been configured
 * then the function simply returns. If no callback has been configured, the 
 * function will retry calling tx_burst with the remaining packets. This will 
 * continue until all packets are transmitted or tx_burst indicates no packets
 * could be transmitted. (The caller can drop the remaining packets.)
 *
 * The function assumes there is at least one packet on the tx_vector.
 */
static_always_inline
u32 tx_burst_vector_internal (vlib_main_t * vm, 
                              dpdk_device_t * xd,
                              struct rte_mbuf ** tx_vector)
{
  dpdk_main_t * dm = &dpdk_main;
  u32 n_packets;
  u32 tx_head;
  u32 tx_tail;
  u32 n_retry;
  int rv;
  int queue_id;
  tx_ring_hdr_t *ring;

  ring = vec_header(tx_vector, sizeof(*ring));

  n_packets = ring->tx_head - ring->tx_tail;

  tx_head = ring->tx_head % DPDK_TX_RING_SIZE;

  /*
   * Ensure rte_eth_tx_burst is not called with 0 packets, which can lead to
   * unpredictable results.
   */
  ASSERT(n_packets > 0);

  /*
   * Check for tx_vector overflow. If this fails it is a system configuration
   * error. The ring should be sized big enough to handle the largest un-flowed
   * off burst from a traffic manager. A larger size also helps performance
   * a bit because it decreases the probability of having to issue two tx_burst
   * calls due to a ring wrap.
   */
  ASSERT(n_packets < DPDK_TX_RING_SIZE);

  /*
   * If there is no flowcontrol callback, there is only temporary buffering
   * on the tx_vector and so the tail should always be 0.
   */
  ASSERT(dm->flowcontrol_callback || ring->tx_tail == 0);

  /*
   * If there is a flowcontrol callback, don't retry any incomplete tx_bursts. 
   * Apply backpressure instead. If there is no callback, keep retrying until
   * a tx_burst sends no packets. n_retry of 255 essentially means no retry 
   * limit.
   */
  n_retry = dm->flowcontrol_callback ? 0 : 255;

  queue_id = vm->cpu_index;

  do {
      /* start the burst at the tail */
      tx_tail = ring->tx_tail % DPDK_TX_RING_SIZE;

      /* 
       * This device only supports one TX queue,
       * and we're running multi-threaded...
       */
      if (PREDICT_FALSE(xd->dev_type != VNET_DPDK_DEV_VHOST_USER &&
        xd->lockp != 0))
        {
          queue_id = queue_id % xd->tx_q_used;
          while (__sync_lock_test_and_set (xd->lockp[queue_id], 1))
            /* zzzz */
            queue_id = (queue_id + 1) % xd->tx_q_used;
        }

      if (PREDICT_TRUE(xd->dev_type == VNET_DPDK_DEV_ETH)) 
        {
          if (PREDICT_TRUE(tx_head > tx_tail)) 
            {
              /* no wrap, transmit in one burst */
              rv = rte_eth_tx_burst(xd->device_index, 
                                    (uint16_t) queue_id,
                                    &tx_vector[tx_tail], 
                                    (uint16_t) (tx_head-tx_tail));
            }
          else 
            {
              /* 
               * This can only happen if there is a flowcontrol callback.
               * We need to split the transmit into two calls: one for
               * the packets up to the wrap point, and one to continue
               * at the start of the ring.
               * Transmit pkts up to the wrap point.
               */
              rv = rte_eth_tx_burst(xd->device_index, 
                                    (uint16_t) queue_id,
                                    &tx_vector[tx_tail], 
                                    (uint16_t) (DPDK_TX_RING_SIZE - tx_tail));

              /* 
               * If we transmitted everything we wanted, then allow 1 retry 
               * so we can try to transmit the rest. If we didn't transmit
               * everything, stop now.
               */
              n_retry = (rv == DPDK_TX_RING_SIZE - tx_tail) ? 1 : 0;
            }
        } 
      else if (xd->dev_type == VNET_DPDK_DEV_VHOST_USER)
        {
          u32 offset = 0;
          if (xd->need_txlock) {
            queue_id = 0;
            while (__sync_lock_test_and_set (xd->lockp[queue_id], 1));
          }
          else {
              dpdk_device_and_queue_t * dq;
              vec_foreach (dq, dm->devices_by_cpu[vm->cpu_index])
              {
                if (xd->device_index == dq->device)
                    break; 
              }
              assert (dq);
              offset = dq->queue_id * VIRTIO_QNUM;
          }
          if (PREDICT_TRUE(tx_head > tx_tail)) 
            {
              int i; u32 bytes = 0;
              struct rte_mbuf **pkts = &tx_vector[tx_tail];
              for (i = 0; i < (tx_head - tx_tail); i++) {
                  struct rte_mbuf *buff = pkts[i];
                  bytes += rte_pktmbuf_data_len(buff);
              } 
                
              /* no wrap, transmit in one burst */
              rv = rte_vhost_enqueue_burst(&xd->vu_vhost_dev, offset + VIRTIO_RXQ,
                                           &tx_vector[tx_tail],
                                           (uint16_t) (tx_head-tx_tail));
              if (PREDICT_TRUE(rv > 0))
                {
                  dpdk_vu_vring *vring = &(xd->vu_intf->vrings[offset + VIRTIO_TXQ]);
                  vring->packets += rv;
                  vring->bytes += bytes;

                  if (dpdk_vhost_user_want_interrupt(xd, offset + VIRTIO_RXQ)) {
                    vring = &(xd->vu_intf->vrings[offset + VIRTIO_RXQ]);
                    vring->n_since_last_int += rv;

                    f64 now = vlib_time_now (vm);
                    if (vring->int_deadline < now ||
                        vring->n_since_last_int > dm->conf->vhost_coalesce_frames)
                      dpdk_vhost_user_send_interrupt(vm, xd, offset + VIRTIO_RXQ);
                  }

                  int c = rv;
                  while(c--)
                    rte_pktmbuf_free (tx_vector[tx_tail+c]);
                }
            }
          else
            {
              /*
               * If we transmitted everything we wanted, then allow 1 retry
               * so we can try to transmit the rest. If we didn't transmit
               * everything, stop now.
               */
              int i; u32 bytes = 0;
              struct rte_mbuf **pkts = &tx_vector[tx_tail];
              for (i = 0; i < (DPDK_TX_RING_SIZE - tx_tail); i++) {
                  struct rte_mbuf *buff = pkts[i];
                  bytes += rte_pktmbuf_data_len(buff);
              }
              rv = rte_vhost_enqueue_burst(&xd->vu_vhost_dev, offset + VIRTIO_RXQ,
                                           &tx_vector[tx_tail], 
                                           (uint16_t) (DPDK_TX_RING_SIZE - tx_tail));

              if (PREDICT_TRUE(rv > 0))
                {
                  dpdk_vu_vring *vring = &(xd->vu_intf->vrings[offset + VIRTIO_TXQ]);
                  vring->packets += rv;
                  vring->bytes += bytes;

                  if (dpdk_vhost_user_want_interrupt(xd, offset + VIRTIO_RXQ)) {
                    vring = &(xd->vu_intf->vrings[offset + VIRTIO_RXQ]);
                    vring->n_since_last_int += rv;

                    f64 now = vlib_time_now (vm);
                    if (vring->int_deadline < now ||
                        vring->n_since_last_int > dm->conf->vhost_coalesce_frames)
                      dpdk_vhost_user_send_interrupt(vm, xd, offset + VIRTIO_RXQ);
                  }

                  int c = rv;
                  while(c--)
                    rte_pktmbuf_free (tx_vector[tx_tail+c]);
                }

              n_retry = (rv == DPDK_TX_RING_SIZE - tx_tail) ? 1 : 0;
            }

          if (xd->need_txlock)
            *xd->lockp[queue_id] = 0;
        }
#if RTE_LIBRTE_KNI
      else if (xd->dev_type == VNET_DPDK_DEV_KNI)
        {
          if (PREDICT_TRUE(tx_head > tx_tail)) 
            {
              /* no wrap, transmit in one burst */
              rv = rte_kni_tx_burst(xd->kni, 
                                    &tx_vector[tx_tail], 
                                    (uint16_t) (tx_head-tx_tail));
            }
          else 
            {
              /* 
               * This can only happen if there is a flowcontrol callback.
               * We need to split the transmit into two calls: one for
               * the packets up to the wrap point, and one to continue
               * at the start of the ring.
               * Transmit pkts up to the wrap point.
               */
              rv = rte_kni_tx_burst(xd->kni, 
                                    &tx_vector[tx_tail], 
                                    (uint16_t) (DPDK_TX_RING_SIZE - tx_tail));

              /* 
               * If we transmitted everything we wanted, then allow 1 retry 
               * so we can try to transmit the rest. If we didn't transmit
               * everything, stop now.
               */
              n_retry = (rv == DPDK_TX_RING_SIZE - tx_tail) ? 1 : 0;
            }
        } 
#endif
      else
        {
          ASSERT(0);
          rv = 0;
        }

      if (PREDICT_FALSE(xd->dev_type != VNET_DPDK_DEV_VHOST_USER &&
            xd->lockp != 0))
          *xd->lockp[queue_id] = 0;

      if (PREDICT_FALSE(rv < 0))
        {
          // emit non-fatal message, bump counter
          vnet_main_t * vnm = dm->vnet_main;
          vnet_interface_main_t * im = &vnm->interface_main;
          u32 node_index;

          node_index = vec_elt_at_index(im->hw_interfaces, 
                                        xd->vlib_hw_if_index)->tx_node_index;

          vlib_error_count (vm, node_index, DPDK_TX_FUNC_ERROR_BAD_RETVAL, 1);
          clib_warning ("rte_eth_tx_burst[%d]: error %d", xd->device_index, rv);
          return n_packets; // untransmitted packets
        }
      ring->tx_tail += (u16)rv;
      n_packets -= (uint16_t) rv;
  } while (rv && n_packets && (n_retry>0));

  return n_packets;
}


/*
 * This function transmits any packets on the interface's tx_vector and returns
 * the number of packets untransmitted on the tx_vector. If the tx_vector is 
 * empty the function simply returns 0. 
 *
 * It is intended to be called by a traffic manager which has flowed-off an
 * interface to see if the interface can be flowed-on again.
 */
u32 dpdk_interface_tx_vector (vlib_main_t * vm, u32 dev_instance)
{
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t * xd;
  int queue_id;
  struct rte_mbuf ** tx_vector;
  tx_ring_hdr_t *ring;
 
  /* param is dev_instance and not hw_if_index to save another lookup */
  xd = vec_elt_at_index (dm->devices, dev_instance);

  queue_id = vm->cpu_index;
  tx_vector = xd->tx_vectors[queue_id];

  /* If no packets on the ring, don't bother calling tx function */
  ring = vec_header(tx_vector, sizeof(*ring));
  if (ring->tx_head == ring->tx_tail) 
    {
      return 0;
    }

  return tx_burst_vector_internal (vm, xd, tx_vector);
}

/*
 * Transmits the packets on the frame to the interface associated with the
 * node. It first copies packets on the frame to a tx_vector containing the 
 * rte_mbuf pointers. It then passes this vector to tx_burst_vector_internal 
 * which calls the dpdk tx_burst function.
 *
 * The tx_vector is treated slightly differently depending on whether or
 * not a flowcontrol callback function has been configured. If there is no
 * callback, the tx_vector is a temporary array of rte_mbuf packet pointers.
 * Its entries are written and consumed before the function exits. 
 *
 * If there is a callback then the transmit is being invoked in the presence
 * of a traffic manager. Here the tx_vector is treated like a ring of rte_mbuf
 * pointers. If not all packets can be transmitted, the untransmitted packets
 * stay on the tx_vector until the next call. The callback allows the traffic
 * manager to flow-off dequeues to the interface. The companion function
 * dpdk_interface_tx_vector() allows the traffic manager to detect when
 * it should flow-on the interface again.
 */
static uword
dpdk_interface_tx (vlib_main_t * vm,
           vlib_node_runtime_t * node,
           vlib_frame_t * f)
{
  dpdk_main_t * dm = &dpdk_main;
  vnet_interface_output_runtime_t * rd = (void *) node->runtime_data;
  dpdk_device_t * xd = vec_elt_at_index (dm->devices, rd->dev_instance);
  u32 n_packets = f->n_vectors;
  u32 n_left;
  u32 * from;
  struct rte_mbuf ** tx_vector;
  int i;
  int queue_id;
  u32 my_cpu;
  u32 tx_pkts = 0;
  tx_ring_hdr_t *ring;
  u32 n_on_ring;

  my_cpu = vm->cpu_index;

  queue_id = my_cpu;

  tx_vector = xd->tx_vectors[queue_id];
  ring = vec_header(tx_vector, sizeof(*ring));

  n_on_ring = ring->tx_head - ring->tx_tail;
  from = vlib_frame_vector_args (f);

  ASSERT(n_packets <= VLIB_FRAME_SIZE);

  if (PREDICT_FALSE(n_on_ring + n_packets > DPDK_TX_RING_SIZE))
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
          struct rte_mbuf *mb0 = rte_mbuf_from_vlib_buffer(b0);
          rte_pktmbuf_free (mb0);
        }
      return n_on_ring;
    }

  if (PREDICT_FALSE(dm->tx_pcap_enable))
    {
      n_left = n_packets;
      while (n_left > 0)
        {
	  u32 bi0 = from[0];
	  vlib_buffer_t * b0 = vlib_get_buffer (vm, bi0);
	  if (dm->pcap_sw_if_index == 0 ||
	      dm->pcap_sw_if_index == vnet_buffer(b0)->sw_if_index [VLIB_TX])
	      pcap_add_buffer (&dm->pcap_main, vm, bi0, 512);
	  from++;
	  n_left--;
	}
    }

  from = vlib_frame_vector_args (f);
  n_left = n_packets;
  i = ring->tx_head % DPDK_TX_RING_SIZE;

  while (n_left >= 4)
    {
      u32 bi0, bi1;
      u32 pi0, pi1;
      struct rte_mbuf * mb0, * mb1;
      struct rte_mbuf * prefmb0, * prefmb1;
      vlib_buffer_t * b0, * b1;
      vlib_buffer_t * pref0, * pref1;
      i16 delta0, delta1;
      u16 new_data_len0, new_data_len1;
      u16 new_pkt_len0, new_pkt_len1;
      u32 any_clone;

      pi0 = from[2];
      pi1 = from[3];
      pref0 = vlib_get_buffer (vm, pi0);
      pref1 = vlib_get_buffer (vm, pi1);

      prefmb0 = rte_mbuf_from_vlib_buffer(pref0);
      prefmb1 = rte_mbuf_from_vlib_buffer(pref1);

      CLIB_PREFETCH(prefmb0, CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH(pref0, CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH(prefmb1, CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH(pref1, CLIB_CACHE_LINE_BYTES, LOAD);

      bi0 = from[0];
      bi1 = from[1];
      from += 2;
      
      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      mb0 = rte_mbuf_from_vlib_buffer(b0);
      mb1 = rte_mbuf_from_vlib_buffer(b1);

      any_clone = (b0->flags & VLIB_BUFFER_RECYCLE)
          | (b1->flags & VLIB_BUFFER_RECYCLE);
      if (PREDICT_FALSE(any_clone != 0))
        {
            if (PREDICT_FALSE
                ((b0->flags & VLIB_BUFFER_RECYCLE) != 0))
	    {
	      struct rte_mbuf * mb0_new = dpdk_replicate_packet_mb (b0);
	      if (PREDICT_FALSE(mb0_new == 0))
		{
		  vlib_error_count (vm, node->node_index,
				    DPDK_TX_FUNC_ERROR_REPL_FAIL, 1);
		  b0->flags |= VLIB_BUFFER_REPL_FAIL;
		}
	      else
		mb0 = mb0_new;
	      vec_add1 (dm->recycle[my_cpu], bi0);
	    }
          if (PREDICT_FALSE
              ((b1->flags & VLIB_BUFFER_RECYCLE) != 0))
	    {
	      struct rte_mbuf * mb1_new = dpdk_replicate_packet_mb (b1);
	      if (PREDICT_FALSE(mb1_new == 0))
		{
		  vlib_error_count (vm, node->node_index,
				    DPDK_TX_FUNC_ERROR_REPL_FAIL, 1);
		  b1->flags |= VLIB_BUFFER_REPL_FAIL;
		}
	      else
		mb1 = mb1_new;
	      vec_add1 (dm->recycle[my_cpu], bi1);
	    }
	}

      delta0 = PREDICT_FALSE(b0->flags & VLIB_BUFFER_REPL_FAIL) ? 0 :
	vlib_buffer_length_in_chain (vm, b0) - (i16) mb0->pkt_len;
      delta1 = PREDICT_FALSE(b1->flags & VLIB_BUFFER_REPL_FAIL) ? 0 :
	vlib_buffer_length_in_chain (vm, b1) - (i16) mb1->pkt_len;
      
      new_data_len0 = (u16)((i16) mb0->data_len + delta0);
      new_data_len1 = (u16)((i16) mb1->data_len + delta1);
      new_pkt_len0 = (u16)((i16) mb0->pkt_len + delta0);
      new_pkt_len1 = (u16)((i16) mb1->pkt_len + delta1);

      b0->current_length = new_data_len0;
      b1->current_length = new_data_len1;
      mb0->data_len = new_data_len0;
      mb1->data_len = new_data_len1;
      mb0->pkt_len = new_pkt_len0;
      mb1->pkt_len = new_pkt_len1;

      mb0->data_off = (PREDICT_FALSE(b0->flags & VLIB_BUFFER_REPL_FAIL)) ?
	mb0->data_off : (u16)(RTE_PKTMBUF_HEADROOM + b0->current_data);
      mb1->data_off = (PREDICT_FALSE(b1->flags & VLIB_BUFFER_REPL_FAIL)) ?
	mb1->data_off : (u16)(RTE_PKTMBUF_HEADROOM + b1->current_data);

      if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
	{
          if (b0->flags & VLIB_BUFFER_IS_TRACED)
	    dpdk_tx_trace_buffer (dm, node, xd, queue_id, bi0, b0);
          if (b1->flags & VLIB_BUFFER_IS_TRACED)
	    dpdk_tx_trace_buffer (dm, node, xd, queue_id, bi1, b1);
	}

      if (PREDICT_TRUE(any_clone == 0))
        {
	  tx_vector[i % DPDK_TX_RING_SIZE] = mb0;
          i++;
	  tx_vector[i % DPDK_TX_RING_SIZE] = mb1;
          i++;
        }
      else
        {
          /* cloning was done, need to check for failure */
          if (PREDICT_TRUE((b0->flags & VLIB_BUFFER_REPL_FAIL) == 0))
            {
	      tx_vector[i % DPDK_TX_RING_SIZE] = mb0;
              i++;
            }
          if (PREDICT_TRUE((b1->flags & VLIB_BUFFER_REPL_FAIL) == 0))
            {
	      tx_vector[i % DPDK_TX_RING_SIZE] = mb1;
              i++;
            }
        }
      
      n_left -= 2;
    }
  while (n_left > 0)
    {
      u32 bi0;
      struct rte_mbuf * mb0;
      vlib_buffer_t * b0;
      i16 delta0;
      u16 new_data_len0;
      u16 new_pkt_len0;

      bi0 = from[0];
      from++;
      
      b0 = vlib_get_buffer (vm, bi0);

      mb0 = rte_mbuf_from_vlib_buffer(b0);
      if (PREDICT_FALSE((b0->flags & VLIB_BUFFER_RECYCLE) != 0))
	{
	  struct rte_mbuf * mb0_new = dpdk_replicate_packet_mb (b0);
	  if (PREDICT_FALSE(mb0_new == 0))
	    {
	      vlib_error_count (vm, node->node_index,
				DPDK_TX_FUNC_ERROR_REPL_FAIL, 1);
	      b0->flags |= VLIB_BUFFER_REPL_FAIL;
	    }
	  else
	    mb0 = mb0_new;
	  vec_add1 (dm->recycle[my_cpu], bi0);
	}

      delta0 = PREDICT_FALSE(b0->flags & VLIB_BUFFER_REPL_FAIL) ? 0 :
	vlib_buffer_length_in_chain (vm, b0) - (i16) mb0->pkt_len;
      
      new_data_len0 = (u16)((i16) mb0->data_len + delta0);
      new_pkt_len0 = (u16)((i16) mb0->pkt_len + delta0);
      
      b0->current_length = new_data_len0;
      mb0->data_len = new_data_len0;
      mb0->pkt_len = new_pkt_len0;
      mb0->data_off = (PREDICT_FALSE(b0->flags & VLIB_BUFFER_REPL_FAIL)) ?
	mb0->data_off : (u16)(RTE_PKTMBUF_HEADROOM + b0->current_data);

      if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
	if (b0->flags & VLIB_BUFFER_IS_TRACED)
	  dpdk_tx_trace_buffer (dm, node, xd, queue_id, bi0, b0);

      if (PREDICT_TRUE((b0->flags & VLIB_BUFFER_REPL_FAIL) == 0))
        {
	  tx_vector[i % DPDK_TX_RING_SIZE] = mb0;
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

  if (PREDICT_FALSE(dm->flowcontrol_callback != 0))
    {
      if (PREDICT_FALSE(n_packets))
        {
          /* Callback may want to enable flowcontrol */
          dm->flowcontrol_callback(vm, xd->vlib_hw_if_index, ring->tx_head - ring->tx_tail);
        } 
      else 
        {
          /* Reset head/tail to avoid unnecessary wrap */
          ring->tx_head = 0;
          ring->tx_tail = 0;
        }
    }
  else 
    {
      /* If there is no callback then drop any non-transmitted packets */
      if (PREDICT_FALSE(n_packets))
        {
          vlib_simple_counter_main_t * cm;
          vnet_main_t * vnm = vnet_get_main();

          cm = vec_elt_at_index (vnm->interface_main.sw_if_counters,
                                 VNET_INTERFACE_COUNTER_TX_ERROR);

          vlib_increment_simple_counter (cm, my_cpu, xd->vlib_sw_if_index, n_packets);

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
  if (PREDICT_FALSE(vec_len(dm->recycle[my_cpu])))
    {
      vlib_buffer_free (vm, dm->recycle[my_cpu], vec_len(dm->recycle[my_cpu]));
      _vec_len(dm->recycle[my_cpu]) = 0;
    }

  ASSERT(ring->tx_head >= ring->tx_tail);

  return tx_pkts;
}

static int dpdk_device_renumber (vnet_hw_interface_t * hi,
                                 u32 new_dev_instance)
{
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t * xd = vec_elt_at_index (dm->devices, hi->dev_instance);

  if (!xd || xd->dev_type != VNET_DPDK_DEV_VHOST_USER) {
    clib_warning("cannot renumber non-vhost-user interface (sw_if_index: %d)",
		 hi->sw_if_index);
    return 0;
  }

  xd->vu_if_id = new_dev_instance;
  return 0;
}

static void dpdk_clear_hw_interface_counters (u32 instance)
{
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t * xd = vec_elt_at_index (dm->devices, instance);

  /*
   * DAW-FIXME: VMXNET3 device stop/start doesn't work, 
   * therefore fake the stop in the dpdk driver by
   * silently dropping all of the incoming pkts instead of 
   * stopping the driver / hardware.
   */
  if (xd->admin_up != 0xff)
    {
      /*
       * Set the "last_cleared_stats" to the current stats, so that
       * things appear to clear from a display perspective.
       */
      dpdk_update_counters (xd, vlib_time_now (dm->vlib_main));

      clib_memcpy (&xd->last_cleared_stats, &xd->stats, sizeof(xd->stats));
      clib_memcpy (xd->last_cleared_xstats, xd->xstats,
	      vec_len(xd->last_cleared_xstats) *
	      sizeof(xd->last_cleared_xstats[0]));
    }
  else
    {
      /*
       * Internally rte_eth_xstats_reset() is calling rte_eth_stats_reset(),
       * so we're only calling xstats_reset() here.
       */
      rte_eth_xstats_reset (xd->device_index);
      memset (&xd->stats, 0, sizeof(xd->stats));
      memset (&xd->last_stats, 0, sizeof (xd->last_stats));
    }

  if (PREDICT_FALSE(xd->dev_type == VNET_DPDK_DEV_VHOST_USER)) {
    int i;
    for (i = 0; i < xd->rx_q_used * VIRTIO_QNUM; i++) {
      xd->vu_intf->vrings[i].packets = 0;
      xd->vu_intf->vrings[i].bytes = 0;
    }
  }
}

#ifdef RTE_LIBRTE_KNI
static int
kni_config_network_if(u8 port_id, u8 if_up)
{
  vnet_main_t * vnm = vnet_get_main();
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t * xd;
  uword *p;

  p = hash_get (dm->dpdk_device_by_kni_port_id, port_id);
  if (p == 0) {
    clib_warning("unknown interface");
    return 0;
  } else {
    xd = vec_elt_at_index (dm->devices, p[0]);
  }

  vnet_hw_interface_set_flags (vnm, xd->vlib_hw_if_index,
                               if_up ? VNET_HW_INTERFACE_FLAG_LINK_UP |
                               ETH_LINK_FULL_DUPLEX : 0);
  return 0;
}

static int
kni_change_mtu(u8 port_id, unsigned new_mtu)
{
  vnet_main_t * vnm = vnet_get_main();
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t * xd;
  uword *p;
  vnet_hw_interface_t * hif;

  p = hash_get (dm->dpdk_device_by_kni_port_id, port_id);
  if (p == 0) {
    clib_warning("unknown interface");
    return 0;
  } else {
    xd = vec_elt_at_index (dm->devices, p[0]);
  }
  hif = vnet_get_hw_interface (vnm, xd->vlib_hw_if_index);

  hif->max_packet_bytes = new_mtu;

  return 0;
}
#endif

static clib_error_t *
dpdk_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t * hif = vnet_get_hw_interface (vnm, hw_if_index);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t * xd = vec_elt_at_index (dm->devices, hif->dev_instance);
  int rv = 0;

#ifdef RTE_LIBRTE_KNI
  if (xd->dev_type == VNET_DPDK_DEV_KNI)
  {
      if (is_up)
      {
          struct rte_kni_conf conf;
          struct rte_kni_ops ops;
          vlib_main_t * vm = vlib_get_main();
          vlib_buffer_main_t * bm = vm->buffer_main;
          memset(&conf, 0, sizeof(conf));
          snprintf(conf.name, RTE_KNI_NAMESIZE, "vpp%u", xd->kni_port_id);
          conf.mbuf_size = VLIB_BUFFER_DATA_SIZE;
          memset(&ops, 0, sizeof(ops));
          ops.port_id = xd->kni_port_id;
          ops.change_mtu = kni_change_mtu;
          ops.config_network_if = kni_config_network_if;

          xd->kni = rte_kni_alloc(bm->pktmbuf_pools[rte_socket_id()], &conf, &ops);
          if (!xd->kni)
          {
            clib_warning("failed to allocate kni interface");
          }
          else
          {
            hif->max_packet_bytes = 1500; /* kni interface default value */
            xd->admin_up = 1;
          }
      }
      else
      {
        xd->admin_up = 0;
        rte_kni_release(xd->kni);
      }
      return 0;
  }
#endif
  if (xd->dev_type == VNET_DPDK_DEV_VHOST_USER)
    {
      if (is_up)
        {
          if (xd->vu_is_running)
            vnet_hw_interface_set_flags (vnm, xd->vlib_hw_if_index,
                                 VNET_HW_INTERFACE_FLAG_LINK_UP |
                                 ETH_LINK_FULL_DUPLEX );
          xd->admin_up = 1;
        }
      else
        {
          vnet_hw_interface_set_flags (vnm, xd->vlib_hw_if_index, 0);
                              xd->admin_up = 0;
        }

      return 0;
    }


  if (is_up)
    {
      f64 now = vlib_time_now (dm->vlib_main);

      /*
       * DAW-FIXME: VMXNET3 device stop/start doesn't work, 
       * therefore fake the stop in the dpdk driver by
       * silently dropping all of the incoming pkts instead of 
       * stopping the driver / hardware.
       */
      if (xd->admin_up == 0)
	rv = rte_eth_dev_start (xd->device_index);

      if (xd->promisc)
	  rte_eth_promiscuous_enable(xd->device_index);
      else
	  rte_eth_promiscuous_disable(xd->device_index);

      rte_eth_allmulticast_enable (xd->device_index);
      xd->admin_up = 1;
      dpdk_update_counters (xd, now);
      dpdk_update_link_state (xd, now);
    }
  else
    {
      /*
       * DAW-FIXME: VMXNET3 device stop/start doesn't work,
       * therefore fake the stop in the dpdk driver by
       * silently dropping all of the incoming pkts instead of
       * stopping the driver / hardware.
       */
      if (xd->pmd != VNET_DPDK_PMD_VMXNET3)
         xd->admin_up = 0;
      else
         xd->admin_up = ~0;

      rte_eth_allmulticast_disable (xd->device_index);
      vnet_hw_interface_set_flags (vnm, xd->vlib_hw_if_index, 0);

      /*
       * DAW-FIXME: VMXNET3 device stop/start doesn't work, 
       * therefore fake the stop in the dpdk driver by
       * silently dropping all of the incoming pkts instead of 
       * stopping the driver / hardware.
       */
      if (xd->pmd != VNET_DPDK_PMD_VMXNET3)
	  rte_eth_dev_stop (xd->device_index);

      /* For bonded interface, stop slave links */
      if (xd->pmd == VNET_DPDK_PMD_BOND) 
        {
	  u8  slink[16];
	  int nlink = rte_eth_bond_slaves_get(xd->device_index, slink, 16);
	  while (nlink >=1) 
	    {
	      u8 dpdk_port = slink[--nlink];
	      rte_eth_dev_stop (dpdk_port);
	    }
        }
    }

  if (rv < 0)
    clib_warning ("rte_eth_dev_%s error: %d", is_up ? "start" : "stop",
                  rv);

  return /* no error */ 0;
}

/*
 * Dynamically redirect all pkts from a specific interface
 * to the specified node
 */
static void dpdk_set_interface_next_node (vnet_main_t *vnm, u32 hw_if_index,
                                          u32 node_index)
{
  dpdk_main_t * xm = &dpdk_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  dpdk_device_t * xd = vec_elt_at_index (xm->devices, hw->dev_instance);
  
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
                             struct vnet_sw_interface_t * st,
                             int is_add)
{
  dpdk_main_t * xm = &dpdk_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  dpdk_device_t * xd = vec_elt_at_index (xm->devices, hw->dev_instance);
  vnet_sw_interface_t * t = (vnet_sw_interface_t *) st;
  int r, vlan_offload;
  u32 prev_subifs = xd->vlan_subifs;

  if (is_add) xd->vlan_subifs++;
  else if (xd->vlan_subifs) xd->vlan_subifs--;

  if (xd->dev_type != VNET_DPDK_DEV_ETH)
        return 0;

  /* currently we program VLANS only for IXGBE VF and I40E VF */
  if ((xd->pmd != VNET_DPDK_PMD_IXGBEVF) &&
      (xd->pmd != VNET_DPDK_PMD_I40EVF))
        return 0;

  if (t->sub.eth.flags.no_tags == 1)
        return 0;

  if ((t->sub.eth.flags.one_tag != 1) || (t->sub.eth.flags.exact_match != 1 )) {
        xd->vlan_subifs = prev_subifs;
        return clib_error_return (0, "unsupported VLAN setup");
  }

  vlan_offload = rte_eth_dev_get_vlan_offload(xd->device_index);
  vlan_offload |= ETH_VLAN_FILTER_OFFLOAD;

  if ((r = rte_eth_dev_set_vlan_offload(xd->device_index, vlan_offload))) {
        xd->vlan_subifs = prev_subifs;
        return clib_error_return (0, "rte_eth_dev_set_vlan_offload[%d]: err %d",
                                  xd->device_index, r);
  }


  if ((r = rte_eth_dev_vlan_filter(xd->device_index, t->sub.eth.outer_vlan_id, is_add))) {
        xd->vlan_subifs = prev_subifs;
        return clib_error_return (0, "rte_eth_dev_vlan_filter[%d]: err %d",
                                 xd->device_index, r);
  }

  return 0;
}

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
  .no_flatten_output_chains = 1,
  .name_renumber = dpdk_device_renumber,
};

VLIB_DEVICE_TX_FUNCTION_MULTIARCH (dpdk_device_class,
				   dpdk_interface_tx)

void dpdk_set_flowcontrol_callback (vlib_main_t *vm, 
                                    dpdk_flowcontrol_callback_t callback)
{
  dpdk_main.flowcontrol_callback = callback;
}

#define UP_DOWN_FLAG_EVENT 1


u32 dpdk_get_admin_up_down_in_progress (void)
{
  return dpdk_main.admin_up_down_in_progress;
}

uword
admin_up_down_process (vlib_main_t * vm,
                       vlib_node_runtime_t * rt,
                       vlib_frame_t * f)
{
  clib_error_t * error = 0;
  uword event_type;
  uword *event_data = 0;
  u32 sw_if_index;
  u32 flags;

  while (1)  
    { 
      vlib_process_wait_for_event (vm);

      event_type = vlib_process_get_events (vm, &event_data);

      dpdk_main.admin_up_down_in_progress = 1;

      switch (event_type) {
        case UP_DOWN_FLAG_EVENT:
        {
            if (vec_len(event_data) == 2) {
              sw_if_index = event_data[0];
              flags = event_data[1];
              error = vnet_sw_interface_set_flags (vnet_get_main(), sw_if_index, flags);
              clib_error_report(error);
            }
        }
        break;
      }

      vec_reset_length (event_data);

      dpdk_main.admin_up_down_in_progress = 0;

    }
  return 0; /* or not */
}

VLIB_REGISTER_NODE (admin_up_down_process_node,static) = {
    .function = admin_up_down_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "admin-up-down-process",
    .process_log2_n_stack_bytes = 17,  // 256KB
};

/*
 * Asynchronously invoke vnet_sw_interface_set_flags via the admin_up_down 
 * process. Useful for avoiding long blocking delays (>150ms) in the dpdk 
 * drivers.
 * WARNING: when posting this event, no other interface-related calls should
 * be made (e.g. vnet_create_sw_interface()) while the event is being
 * processed (admin_up_down_in_progress). This is required in order to avoid 
 * race conditions in manipulating interface data structures.
 */
void post_sw_interface_set_flags (vlib_main_t *vm, u32 sw_if_index, u32 flags)
{
  uword * d = vlib_process_signal_event_data
      (vm, admin_up_down_process_node.index,
       UP_DOWN_FLAG_EVENT, 2, sizeof(u32));
  d[0] = sw_if_index;
  d[1] = flags;
}

/*
 * Return a copy of the DPDK port stats in dest.
 */
clib_error_t*
dpdk_get_hw_interface_stats (u32 hw_if_index, struct rte_eth_stats* dest)
{
  dpdk_main_t * dm = &dpdk_main;
  vnet_main_t * vnm = vnet_get_main();
  vnet_hw_interface_t * hi = vnet_get_hw_interface (vnm, hw_if_index);
  dpdk_device_t * xd = vec_elt_at_index (dm->devices, hi->dev_instance);

  if (!dest) {
     return clib_error_return (0, "Missing or NULL argument");
  }
  if (!xd) {
     return clib_error_return (0, "Unable to get DPDK device from HW interface");
  }

  dpdk_update_counters (xd, vlib_time_now (dm->vlib_main));

  clib_memcpy(dest, &xd->stats, sizeof(xd->stats));
  return (0);
}

/*
 * Return the number of dpdk mbufs
 */
u32 dpdk_num_mbufs (void)
{
  dpdk_main_t * dm = &dpdk_main;

  return dm->conf->num_mbufs;
}

/*
 * Return the pmd type for a given hardware interface
 */
dpdk_pmd_t dpdk_get_pmd_type (vnet_hw_interface_t *hi)
{
  dpdk_main_t   * dm = &dpdk_main;
  dpdk_device_t * xd;

  assert (hi);

  xd = vec_elt_at_index (dm->devices, hi->dev_instance);

  assert (xd);

  return xd->pmd;
}

/*
 * Return the cpu socket for a given hardware interface
 */
i8 dpdk_get_cpu_socket (vnet_hw_interface_t *hi)
{
  dpdk_main_t   * dm = &dpdk_main;
  dpdk_device_t * xd;

  assert (hi);

  xd = vec_elt_at_index(dm->devices, hi->dev_instance);

  assert (xd);

  return xd->cpu_socket;
}
