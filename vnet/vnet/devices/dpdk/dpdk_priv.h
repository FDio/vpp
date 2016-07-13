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

#define DPDK_NB_RX_DESC_DEFAULT   512
#define DPDK_NB_TX_DESC_DEFAULT   512
#define DPDK_NB_RX_DESC_VIRTIO    256
#define DPDK_NB_TX_DESC_VIRTIO    256
#define DPDK_NB_RX_DESC_10GE    1024
#define DPDK_NB_TX_DESC_10GE    1024
#define DPDK_NB_RX_DESC_40GE    1024
#define DPDK_NB_TX_DESC_40GE    1024
#define DPDK_NB_RX_DESC_ENIC    1024

#if RTE_VERSION >= RTE_VERSION_NUM(16, 7, 0, 0)
#define I40E_DEV_ID_SFP_XL710           0x1572
#define I40E_DEV_ID_QSFP_A              0x1583
#define I40E_DEV_ID_QSFP_B              0x1584
#define I40E_DEV_ID_QSFP_C              0x1585
#define I40E_DEV_ID_10G_BASE_T          0x1586
#define I40E_DEV_ID_VF                  0x154C
#endif

/* These args appear by themselves */
#define foreach_eal_double_hyphen_predicate_arg \
_(no-shconf)                                    \
_(no-hpet)                                      \
_(no-pci)                                       \
_(no-huge)                                      \
_(vmware-tsc-map)                               \
_(virtio-vhost)

#define foreach_eal_single_hyphen_mandatory_arg \
_(coremask, c)                                  \
_(nchannels, n)                                 \

#define foreach_eal_single_hyphen_arg           \
_(blacklist, b)                                 \
_(mem-alloc-request, m)                         \
_(force-ranks, r)

/* These args are preceeded by "--" and followed by a single string */
#define foreach_eal_double_hyphen_arg           \
_(huge-dir)                                     \
_(proc-type)                                    \
_(file-prefix)                                  \
_(vdev)

static inline u32
dpdk_rx_burst ( dpdk_main_t * dm, dpdk_device_t * xd, u16 queue_id)
{
  u32 n_buffers;
  u32 n_left;
  u32 n_this_chunk;

  n_left = VLIB_FRAME_SIZE;
  n_buffers = 0;

  if (PREDICT_TRUE(xd->dev_type == VNET_DPDK_DEV_ETH))
    {
      while (n_left)
        {
          n_this_chunk = rte_eth_rx_burst (xd->device_index, queue_id,
                                           xd->rx_vectors[queue_id] + n_buffers, n_left);
          n_buffers += n_this_chunk;
          n_left -= n_this_chunk;

          /* Empirically, DPDK r1.8 produces vectors w/ 32 or fewer elts */
          if (n_this_chunk < 32)
            break;
      }
    }
#if DPDK_VHOST_USER
  else if (xd->dev_type == VNET_DPDK_DEV_VHOST_USER)
    {
      vlib_main_t * vm = vlib_get_main();
      vlib_buffer_main_t * bm = vm->buffer_main;
      unsigned socket_id = rte_socket_id();
      u32 offset = 0;

      offset = queue_id * VIRTIO_QNUM;

      struct vhost_virtqueue *vq =
        xd->vu_vhost_dev.virtqueue[offset + VIRTIO_TXQ];

      if (PREDICT_FALSE(!vq->enabled))
        return 0;

      struct rte_mbuf **pkts = xd->rx_vectors[queue_id];
      while (n_left) {
          n_this_chunk = rte_vhost_dequeue_burst(&xd->vu_vhost_dev,
                                                 offset + VIRTIO_TXQ,
                                                 bm->pktmbuf_pools[socket_id],
                                                 pkts + n_buffers,
                                                 n_left);
          n_buffers += n_this_chunk;
          n_left -= n_this_chunk;
          if (n_this_chunk == 0)
              break;
      }

      int i; u32 bytes = 0;
      for (i = 0; i < n_buffers; i++) {
          struct rte_mbuf *buff = pkts[i];
          bytes += rte_pktmbuf_data_len(buff);
      } 

      f64 now = vlib_time_now (vm);

      dpdk_vu_vring *vring = NULL;
      /* send pending interrupts if needed */
      if (dpdk_vhost_user_want_interrupt(xd, offset + VIRTIO_TXQ)) {
          vring = &(xd->vu_intf->vrings[offset + VIRTIO_TXQ]);
          vring->n_since_last_int += n_buffers;

          if ((vring->n_since_last_int && (vring->int_deadline < now))
              || (vring->n_since_last_int > dm->conf->vhost_coalesce_frames))
            dpdk_vhost_user_send_interrupt(vm, xd, offset + VIRTIO_TXQ);
      }

      vring = &(xd->vu_intf->vrings[offset + VIRTIO_RXQ]);
      vring->packets += n_buffers;
      vring->bytes += bytes;

      if (dpdk_vhost_user_want_interrupt(xd, offset + VIRTIO_RXQ)) {
          if (vring->n_since_last_int && (vring->int_deadline < now))
            dpdk_vhost_user_send_interrupt(vm, xd, offset + VIRTIO_RXQ);
      }

    }
#endif
#ifdef RTE_LIBRTE_KNI
  else if (xd->dev_type == VNET_DPDK_DEV_KNI)
    {
      n_buffers = rte_kni_rx_burst(xd->kni, xd->rx_vectors[queue_id], VLIB_FRAME_SIZE);
      rte_kni_handle_request(xd->kni);
    }
#endif
  else
    {
      ASSERT(0);
    }

  return n_buffers;
}


static inline void
dpdk_get_xstats (dpdk_device_t * xd)
{
  int len;
  if ((len = rte_eth_xstats_get(xd->device_index, NULL, 0)) > 0)
    {
      vec_validate(xd->xstats, len - 1);
      vec_validate(xd->last_cleared_xstats, len - 1);

      len = rte_eth_xstats_get(xd->device_index, xd->xstats, vec_len(xd->xstats));

      ASSERT(vec_len(xd->xstats) == len);
      ASSERT(vec_len(xd->last_cleared_xstats) == len);

      _vec_len(xd->xstats) = len;
      _vec_len(xd->last_cleared_xstats) = len;

    }
}


static inline void
dpdk_update_counters (dpdk_device_t * xd, f64 now)
{
  vlib_simple_counter_main_t * cm;
  vnet_main_t * vnm = vnet_get_main();
  u32 my_cpu = os_get_cpu_number();
  u64 rxerrors, last_rxerrors;

  /* only update counters for PMD interfaces */
  if (xd->dev_type != VNET_DPDK_DEV_ETH)
    return;

  /*
   * DAW-FIXME: VMXNET3 device stop/start doesn't work,
   * therefore fake the stop in the dpdk driver by
   * silently dropping all of the incoming pkts instead of
   * stopping the driver / hardware.
   */
  if (xd->admin_up != 0xff)
    {
      xd->time_last_stats_update = now ? now : xd->time_last_stats_update;
      clib_memcpy (&xd->last_stats, &xd->stats, sizeof (xd->last_stats));
      rte_eth_stats_get (xd->device_index, &xd->stats);

      /* maybe bump interface rx no buffer counter */
      if (PREDICT_FALSE (xd->stats.rx_nombuf != xd->last_stats.rx_nombuf))
        {
          cm = vec_elt_at_index (vnm->interface_main.sw_if_counters,
                                 VNET_INTERFACE_COUNTER_RX_NO_BUF);

          vlib_increment_simple_counter (cm, my_cpu, xd->vlib_sw_if_index,
                                         xd->stats.rx_nombuf -
                                         xd->last_stats.rx_nombuf);
        }

      /* missed pkt counter */
      if (PREDICT_FALSE (xd->stats.imissed != xd->last_stats.imissed))
        {
          cm = vec_elt_at_index (vnm->interface_main.sw_if_counters,
                                 VNET_INTERFACE_COUNTER_RX_MISS);

          vlib_increment_simple_counter (cm, my_cpu, xd->vlib_sw_if_index,
                                         xd->stats.imissed -
                                         xd->last_stats.imissed);
        }
      rxerrors = xd->stats.ierrors;
      last_rxerrors = xd->last_stats.ierrors;

      if (PREDICT_FALSE (rxerrors != last_rxerrors))
        {
          cm = vec_elt_at_index (vnm->interface_main.sw_if_counters,
                                 VNET_INTERFACE_COUNTER_RX_ERROR);

          vlib_increment_simple_counter (cm, my_cpu, xd->vlib_sw_if_index,
                                         rxerrors - last_rxerrors);
        }
    }

  dpdk_get_xstats(xd);
}
