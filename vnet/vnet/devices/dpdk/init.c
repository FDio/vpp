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

#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/dpdk/dpdk.h>
#include <vlib/unix/physmem.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <string.h>
#include <fcntl.h>

#include "dpdk_priv.h"

dpdk_main_t dpdk_main;

/* force linker to link functions used by vlib and declared weak */
void *vlib_weakly_linked_functions[] = {
  &rte_pktmbuf_init,
  &rte_pktmbuf_pool_init,
};

#define LINK_STATE_ELOGS	0

#define DEFAULT_HUGE_DIR "/run/vpp/hugepages"
#define VPP_RUN_DIR "/run/vpp"

/* Port configuration, mildly modified Intel app values */

static struct rte_eth_conf port_conf_template = {
  .rxmode = {
    .split_hdr_size = 0,
    .header_split   = 0, /**< Header Split disabled */
    .hw_ip_checksum = 0, /**< IP checksum offload disabled */
    .hw_vlan_filter = 0, /**< VLAN filtering disabled */
    .hw_strip_crc   = 1, /**< CRC stripped by hardware */
  },
  .txmode = {
    .mq_mode = ETH_MQ_TX_NONE,
  },
};

clib_error_t *
dpdk_port_setup (dpdk_main_t * dm, dpdk_device_t * xd)
{
  vlib_main_t * vm = vlib_get_main();
  vlib_buffer_main_t * bm = vm->buffer_main;
  int rv;
  int j;

  ASSERT(os_get_cpu_number() == 0);

  if (xd->admin_up) {
    vnet_hw_interface_set_flags (dm->vnet_main, xd->vlib_hw_if_index, 0);
    rte_eth_dev_stop (xd->device_index);
  }

  rv = rte_eth_dev_configure (xd->device_index, xd->rx_q_used,
                              xd->tx_q_used, &xd->port_conf);

  if (rv < 0)
    return clib_error_return (0, "rte_eth_dev_configure[%d]: err %d",
                              xd->device_index, rv);

  /* Set up one TX-queue per worker thread */
  for (j = 0; j < xd->tx_q_used; j++)
    {
      rv = rte_eth_tx_queue_setup(xd->device_index, j, xd->nb_tx_desc,
                                 xd->cpu_socket, &xd->tx_conf);
      if (rv < 0)
        break;
    }

    if (rv < 0)
      return clib_error_return (0, "rte_eth_tx_queue_setup[%d]: err %d",
                                xd->device_index, rv);

  for (j = 0; j < xd->rx_q_used; j++)
    {

      rv = rte_eth_rx_queue_setup(xd->device_index, j, xd->nb_rx_desc,
                                  xd->cpu_socket, 0,
                                  bm->pktmbuf_pools[xd->cpu_socket_id_by_queue[j]]);
      if (rv < 0)
        return clib_error_return (0, "rte_eth_rx_queue_setup[%d]: err %d",
                                  xd->device_index, rv);
    }

  if (xd->admin_up) {
    rte_eth_dev_start (xd->device_index);
  }
  return 0;
}

static u32 dpdk_flag_change (vnet_main_t * vnm, 
                             vnet_hw_interface_t * hi,
                             u32 flags)
{
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t * xd = vec_elt_at_index (dm->devices, hi->dev_instance);
  u32 old = 0;

  if (ETHERNET_INTERFACE_FLAG_CONFIG_PROMISC(flags))
    {
      old = xd->promisc;
      xd->promisc = flags & ETHERNET_INTERFACE_FLAG_ACCEPT_ALL;
      
      if (xd->admin_up)
	{
	  if (xd->promisc)
	    rte_eth_promiscuous_enable(xd->device_index);
	  else
	    rte_eth_promiscuous_disable(xd->device_index);
	}
    }
  else if (ETHERNET_INTERFACE_FLAG_CONFIG_MTU(flags))
    {
      /*
       * DAW-FIXME: The Cisco VIC firmware does not provide an api for a
       *            driver to dynamically change the mtu.  If/when the 
       *            VIC firmware gets fixed, then this should be removed.
       */
      if (xd->pmd == VNET_DPDK_PMD_VICE ||
          xd->pmd == VNET_DPDK_PMD_ENIC)
	{
	  struct rte_eth_dev_info dev_info;

	  /*
	   * Restore mtu to what has been set by CIMC in the firmware cfg.
	   */
	  rte_eth_dev_info_get(xd->device_index, &dev_info);
	  hi->max_packet_bytes = dev_info.max_rx_pktlen;

	  vlib_cli_output (vlib_get_main(), 
			   "Cisco VIC mtu can only be changed "
			   "using CIMC then rebooting the server!");
	}
      else
	{
	  int rv;
      
	  /*
	   * DAW-FIXME: The DPDK VMXNET3 driver does not currently support
	   *            multi-buffer packets.  Max out at 1518 bytes for now.
	   *
	   *            If/when the driver gets fixed, then this should be
	   *            removed.
	   */
	  if ((xd->pmd == VNET_DPDK_PMD_VMXNET3) &&
	      (hi->max_packet_bytes > 1518))
	    {
	      hi->max_packet_bytes = 1518;

	      vlib_cli_output (vlib_get_main(), 
			       "VMXNET3 driver does not  support jumbo frames "
			       "yet -- setting mtu to 1518!");
	    }

	  xd->port_conf.rxmode.max_rx_pkt_len = hi->max_packet_bytes;

	  if (xd->admin_up)
	    rte_eth_dev_stop (xd->device_index);

    rv = rte_eth_dev_configure
      (xd->device_index,
       xd->rx_q_used,
       xd->tx_q_used,
       &xd->port_conf);

	  if (rv < 0)
	    vlib_cli_output (vlib_get_main(), 
			     "rte_eth_dev_configure[%d]: err %d",
			     xd->device_index, rv);

          rte_eth_dev_set_mtu(xd->device_index, hi->max_packet_bytes);

	  if (xd->admin_up)
	    rte_eth_dev_start (xd->device_index);
	}
    }
  return old;
}

#ifdef NETMAP
extern int rte_netmap_probe(void);
#endif

static clib_error_t *
dpdk_lib_init (dpdk_main_t * dm)
{
  u32 nports;
  u32 nb_desc = 0;
  int i;
  clib_error_t * error;
  vlib_main_t * vm = vlib_get_main();
  vlib_thread_main_t * tm = vlib_get_thread_main();
  vnet_sw_interface_t * sw;
  vnet_hw_interface_t * hi;
  dpdk_device_t * xd;
  vlib_thread_registration_t * tr;
  uword * p;

  u32 next_cpu = 0;
  u8 af_packet_port_id = 0;

  dm->input_cpu_first_index = 0;
  dm->input_cpu_count = 1;

  /* find out which cpus will be used for input */
  p = hash_get_mem (tm->thread_registrations_by_name, "io");
  tr = p ? (vlib_thread_registration_t *) p[0] : 0;

  if (!tr || tr->count == 0)
    {
      /* no io threads, workers doing input */
      p = hash_get_mem (tm->thread_registrations_by_name, "workers");
      tr = p ? (vlib_thread_registration_t *) p[0] : 0;
    }
  else
    {
      dm->have_io_threads = 1;
    }

  if (tr && tr->count > 0)
    {
      dm->input_cpu_first_index = tr->first_index;
      dm->input_cpu_count = tr->count;
    }

  vec_validate_aligned (dm->devices_by_cpu, tm->n_vlib_mains - 1,
                        CLIB_CACHE_LINE_BYTES);

  vec_validate_aligned (dm->workers, tm->n_vlib_mains - 1,
                        CLIB_CACHE_LINE_BYTES);

#ifdef NETMAP
  if(rte_netmap_probe() < 0)
    return clib_error_return (0, "rte netmap probe failed");
#endif

  nports = rte_eth_dev_count();
  if (nports < 1) 
    {
      clib_warning ("DPDK drivers found no ports...");
    }

  if (CLIB_DEBUG > 0)
    clib_warning ("DPDK drivers found %d ports...", nports);

  /* 
   * All buffers are all allocated from the same rte_mempool.
   * Thus they all have the same number of data bytes.
   */
  dm->vlib_buffer_free_list_index = 
      vlib_buffer_get_or_create_free_list (
          vm, VLIB_BUFFER_DEFAULT_FREE_LIST_BYTES, "dpdk rx");

  for (i = 0; i < nports; i++)
    {
      u8 addr[6];
      int j;
      struct rte_eth_dev_info dev_info;
      clib_error_t * rv;
      struct rte_eth_link l;

      /* Create vnet interface */
      vec_add2_aligned (dm->devices, xd, 1, CLIB_CACHE_LINE_BYTES);
      xd->nb_rx_desc = DPDK_NB_RX_DESC_DEFAULT;
      xd->nb_tx_desc = DPDK_NB_TX_DESC_DEFAULT;
      xd->cpu_socket = (i8) rte_eth_dev_socket_id(i);
      rte_eth_dev_info_get(i, &dev_info);

      memcpy(&xd->tx_conf, &dev_info.default_txconf,
             sizeof(struct rte_eth_txconf));
      if (dm->no_multi_seg)
        {
          xd->tx_conf.txq_flags |= ETH_TXQ_FLAGS_NOMULTSEGS;
          port_conf_template.rxmode.jumbo_frame = 0;
        }
      else
        {
          xd->tx_conf.txq_flags &= ~ETH_TXQ_FLAGS_NOMULTSEGS;
          port_conf_template.rxmode.jumbo_frame = 1;
        }

      memcpy(&xd->port_conf, &port_conf_template, sizeof(struct rte_eth_conf));

      xd->tx_q_used = dev_info.max_tx_queues < tm->n_vlib_mains ?
                      1 : tm->n_vlib_mains;

      if (dm->use_rss > 1 && dev_info.max_rx_queues >= dm->use_rss)
        {
          xd->rx_q_used = dm->use_rss;
          xd->port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
          xd->port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP;
        }
      else
        xd->rx_q_used = 1;

      xd->dev_type = VNET_DPDK_DEV_ETH;

      /* workaround for drivers not setting driver_name */
      if (!dev_info.driver_name)
        dev_info.driver_name = dev_info.pci_dev->driver->name;
      ASSERT(dev_info.driver_name);

      if (!xd->pmd) {


#define _(s,f) else if (!strcmp(dev_info.driver_name, s)) \
                 xd->pmd = VNET_DPDK_PMD_##f;
        if (0)
          ;
        foreach_dpdk_pmd
#undef _
        else
          xd->pmd = VNET_DPDK_PMD_UNKNOWN;


        switch (xd->pmd) {
          /* 1G adapters */
          case VNET_DPDK_PMD_E1000EM:
          case VNET_DPDK_PMD_IGB:
          case VNET_DPDK_PMD_IGBVF:
            xd->port_type = VNET_DPDK_PORT_TYPE_ETH_1G;
            break;

          /* 10G adapters */
          case VNET_DPDK_PMD_IXGBE:
          case VNET_DPDK_PMD_IXGBEVF:
          case VNET_DPDK_PMD_THUNDERX:
            xd->port_type = VNET_DPDK_PORT_TYPE_ETH_10G;
            xd->nb_rx_desc = DPDK_NB_RX_DESC_10GE;
            xd->nb_tx_desc = DPDK_NB_TX_DESC_10GE;
            break;

          /* Cisco VIC */
          case VNET_DPDK_PMD_VICE:
          case VNET_DPDK_PMD_ENIC:
            rte_eth_link_get_nowait(xd->device_index, &l);
            if (l.link_speed == 40000)
              {
                xd->port_type = VNET_DPDK_PORT_TYPE_ETH_40G;
                xd->nb_rx_desc = DPDK_NB_RX_DESC_40GE;
                xd->nb_tx_desc = DPDK_NB_TX_DESC_40GE;
              }
            else
              {
                xd->port_type = VNET_DPDK_PORT_TYPE_ETH_10G;
                xd->nb_rx_desc = DPDK_NB_RX_DESC_10GE;
                xd->nb_tx_desc = DPDK_NB_TX_DESC_10GE;
              }
            break;

          /* Intel Fortville */
          case VNET_DPDK_PMD_I40E:
          case VNET_DPDK_PMD_I40EVF:
            xd->port_type = VNET_DPDK_PORT_TYPE_ETH_40G;
            xd->nb_rx_desc = DPDK_NB_RX_DESC_40GE;
            xd->nb_tx_desc = DPDK_NB_TX_DESC_40GE;

            switch (dev_info.pci_dev->id.device_id) {
              case I40E_DEV_ID_10G_BASE_T:
              case I40E_DEV_ID_SFP_XL710:
                xd->port_type = VNET_DPDK_PORT_TYPE_ETH_10G;
                break;
              case I40E_DEV_ID_QSFP_A:
              case I40E_DEV_ID_QSFP_B:
              case I40E_DEV_ID_QSFP_C:
                xd->port_type = VNET_DPDK_PORT_TYPE_ETH_40G;
                break;
              case I40E_DEV_ID_VF:
                rte_eth_link_get_nowait(xd->device_index, &l);
                xd->port_type = l.link_speed == 10000 ?
                  VNET_DPDK_PORT_TYPE_ETH_10G : VNET_DPDK_PORT_TYPE_ETH_40G;
                break;
              default:
                xd->port_type = VNET_DPDK_PORT_TYPE_UNKNOWN;
            }
            break;

          case VNET_DPDK_PMD_CXGBE:
            switch (dev_info.pci_dev->id.device_id) {
              case 0x5410: /* T580-LP-cr */
                xd->nb_rx_desc = DPDK_NB_RX_DESC_40GE;
                xd->nb_tx_desc = DPDK_NB_TX_DESC_40GE;
                xd->port_type = VNET_DPDK_PORT_TYPE_ETH_40G;
                break;
              default:
                xd->nb_rx_desc = DPDK_NB_RX_DESC_10GE;
                xd->nb_tx_desc = DPDK_NB_TX_DESC_10GE;
                xd->port_type = VNET_DPDK_PORT_TYPE_UNKNOWN;
            }
            break;

          /* Intel Red Rock Canyon */
          case VNET_DPDK_PMD_FM10K:
            xd->port_type = VNET_DPDK_PORT_TYPE_ETH_SWITCH;
            xd->nb_rx_desc = DPDK_NB_RX_DESC_40GE;
            xd->nb_tx_desc = DPDK_NB_TX_DESC_40GE;
            break;

          /* virtio */
          case VNET_DPDK_PMD_VIRTIO:
            xd->port_type = VNET_DPDK_PORT_TYPE_ETH_1G;
            xd->nb_rx_desc = DPDK_NB_RX_DESC_VIRTIO;
            xd->nb_tx_desc = DPDK_NB_TX_DESC_VIRTIO;
            break;

          /* vmxnet3 */
          case VNET_DPDK_PMD_VMXNET3:
            xd->port_type = VNET_DPDK_PORT_TYPE_ETH_1G;
            xd->tx_conf.txq_flags |= ETH_TXQ_FLAGS_NOMULTSEGS;
            break;

          case VNET_DPDK_PMD_AF_PACKET:
            xd->port_type = VNET_DPDK_PORT_TYPE_AF_PACKET;
            xd->af_packet_port_id = af_packet_port_id++;
            break;

          default:
            xd->port_type = VNET_DPDK_PORT_TYPE_UNKNOWN;
        }

  #ifdef NETMAP
	if(strncmp(dev_info.driver_name, "vale", 4) == 0
	     || strncmp(dev_info.driver_name, "netmap", 6) == 0)
          {
            xd->pmd = VNET_DPDK_PMD_NETMAP;
            xd->port_type = VNET_DPDK_PORT_TYPE_NETMAP;
          }
  #endif

      }

      /*
       * Ensure default mtu is not > the mtu read from the hardware.
       * Otherwise rte_eth_dev_configure() will fail and the port will
       * not be available.
       */
      xd->port_conf.rxmode.max_rx_pkt_len = 
	      (ETHERNET_MAX_PACKET_BYTES > dev_info.max_rx_pktlen) ? 
 	      dev_info.max_rx_pktlen : ETHERNET_MAX_PACKET_BYTES;

      /*
       * DAW-FIXME: VMXNET3 driver doesn't support jumbo / multi-buffer pkts
       */
      if (xd->pmd == VNET_DPDK_PMD_VMXNET3)
        {
          xd->port_conf.rxmode.max_rx_pkt_len = 1518;
          xd->port_conf.rxmode.jumbo_frame = 0;
        }

      if (xd->pmd == VNET_DPDK_PMD_AF_PACKET)
        {
          f64 now = vlib_time_now(vm);
          u32 rnd;
          rnd = (u32) (now * 1e6);
          rnd = random_u32 (&rnd);
          memcpy (addr+2, &rnd, sizeof(rnd));
          addr[0] = 2;
          addr[1] = 0xfe;
        }
      else
        rte_eth_macaddr_get(i,(struct ether_addr *)addr);

      if (xd->tx_q_used < tm->n_vlib_mains)
        {
          xd->lockp = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
                                              CLIB_CACHE_LINE_BYTES);
          memset ((void *) xd->lockp, 0, CLIB_CACHE_LINE_BYTES);
        }

      xd->device_index = xd - dm->devices;
      ASSERT(i == xd->device_index);
      xd->per_interface_next_index = ~0;

      /* assign interface to input thread */
      dpdk_device_and_queue_t * dq;
      int q;

      for (q = 0; q < xd->rx_q_used; q++)
        {
          int cpu = dm->input_cpu_first_index + next_cpu;
          unsigned lcore = vlib_worker_threads[cpu].dpdk_lcore_id;

          /*
           * numa node for worker thread handling this queue
           * needed for taking buffers from the right mempool
           */
          vec_validate(xd->cpu_socket_id_by_queue, q);
          xd->cpu_socket_id_by_queue[q] = rte_lcore_to_socket_id(lcore);

          /*
           * construct vector of (device,queue) pairs for each worker thread
           */
          vec_add2(dm->devices_by_cpu[cpu], dq, 1);
          dq->device = xd->device_index;
          dq->queue_id = q;

          next_cpu++;
          if (next_cpu == dm->input_cpu_count)
            next_cpu = 0;
        }

      vec_validate_aligned (xd->tx_vectors, tm->n_vlib_mains,
                            CLIB_CACHE_LINE_BYTES);
      for (j = 0; j < tm->n_vlib_mains; j++)
        {
          vec_validate_ha (xd->tx_vectors[j], DPDK_TX_RING_SIZE, 
                           sizeof(tx_ring_hdr_t), CLIB_CACHE_LINE_BYTES);
          vec_reset_length (xd->tx_vectors[j]);
        }

      vec_validate_aligned (xd->rx_vectors, xd->rx_q_used,
                            CLIB_CACHE_LINE_BYTES);
      for (j = 0; j< xd->rx_q_used; j++)
        {
          vec_validate_aligned (xd->rx_vectors[j], VLIB_FRAME_SIZE-1,
                                CLIB_CACHE_LINE_BYTES);
          vec_reset_length (xd->rx_vectors[j]);
        }

      vec_validate_aligned (xd->frames, tm->n_vlib_mains,
                            CLIB_CACHE_LINE_BYTES);

      rv = dpdk_port_setup(dm, xd);

      if (rv < 0)
        return rv;

      /* count the number of descriptors used for this device */
      nb_desc += xd->nb_rx_desc + xd->nb_tx_desc * xd->tx_q_used;

      error = ethernet_register_interface
        (dm->vnet_main,
         dpdk_device_class.index,
         xd->device_index,
         /* ethernet address */ addr,
         &xd->vlib_hw_if_index, 
         dpdk_flag_change);
      if (error)
        return error;
      
      sw = vnet_get_hw_sw_interface (dm->vnet_main, xd->vlib_hw_if_index);
      xd->vlib_sw_if_index = sw->sw_if_index;
      hi = vnet_get_hw_interface (dm->vnet_main, xd->vlib_hw_if_index);

      /*
       * DAW-FIXME: The Cisco VIC firmware does not provide an api for a
       *            driver to dynamically change the mtu.  If/when the 
       *            VIC firmware gets fixed, then this should be removed.
       */
      if (xd->pmd == VNET_DPDK_PMD_VICE ||
          xd->pmd == VNET_DPDK_PMD_ENIC)
	{
	  /*
	   * Initialize mtu to what has been set by CIMC in the firmware cfg.
	   */
	  hi->max_packet_bytes = dev_info.max_rx_pktlen;
          /*
           * remove vlan tag from VIC port to fix VLAN0 issue.
           * TODO Handle VLAN tagged traffic
           */
          int vlan_off;
          vlan_off = rte_eth_dev_get_vlan_offload(xd->device_index);
          vlan_off |= ETH_VLAN_STRIP_OFFLOAD;
          rte_eth_dev_set_vlan_offload(xd->device_index, vlan_off);
	}
      /*
       * DAW-FIXME: VMXNET3 driver doesn't support jumbo / multi-buffer pkts
       */
      else if (xd->pmd == VNET_DPDK_PMD_VMXNET3)
	  hi->max_packet_bytes = 1518;

      hi->max_l3_packet_bytes[VLIB_RX] = hi->max_l3_packet_bytes[VLIB_TX] = 
	      xd->port_conf.rxmode.max_rx_pkt_len - sizeof(ethernet_header_t);

     rte_eth_dev_set_mtu(xd->device_index, hi->max_packet_bytes);
    }

  if (dm->num_kni) {
    clib_warning("Initializing KNI interfaces...");
    rte_kni_init(dm->num_kni);
    for (i = 0; i < dm->num_kni; i++)
    {
      u8 addr[6];
      int j;

      /* Create vnet interface */
      vec_add2_aligned (dm->devices, xd, 1, CLIB_CACHE_LINE_BYTES);
      xd->dev_type = VNET_DPDK_DEV_KNI;

      xd->device_index = xd - dm->devices;
      ASSERT(nports + i == xd->device_index);
      xd->per_interface_next_index = ~0;
      xd->kni_port_id = i;
      xd->cpu_socket = -1;
      hash_set (dm->dpdk_device_by_kni_port_id, i, xd - dm->devices);
      xd->rx_q_used = 1;

      /* assign interface to input thread */
      dpdk_device_and_queue_t * dq;
      vec_add2(dm->devices_by_cpu[dm->input_cpu_first_index], dq, 1);
      dq->device = xd->device_index;
      dq->queue_id = 0;

      vec_validate_aligned (xd->tx_vectors, tm->n_vlib_mains,
                            CLIB_CACHE_LINE_BYTES);
      for (j = 0; j < tm->n_vlib_mains; j++)
        {
          vec_validate_ha (xd->tx_vectors[j], DPDK_TX_RING_SIZE, 
                           sizeof(tx_ring_hdr_t), CLIB_CACHE_LINE_BYTES);
          vec_reset_length (xd->tx_vectors[j]);
        }

      vec_validate_aligned (xd->rx_vectors, xd->rx_q_used,
                            CLIB_CACHE_LINE_BYTES);
      for (j = 0; j< xd->rx_q_used; j++)
        {
          vec_validate_aligned (xd->rx_vectors[j], VLIB_FRAME_SIZE-1,
                                CLIB_CACHE_LINE_BYTES);
          vec_reset_length (xd->rx_vectors[j]);
        }

      vec_validate_aligned (xd->frames, tm->n_vlib_mains,
                            CLIB_CACHE_LINE_BYTES);

      /* FIXME Set up one TX-queue per worker thread */

      {
        f64 now = vlib_time_now(vm);
        u32 rnd;
        rnd = (u32) (now * 1e6);
        rnd = random_u32 (&rnd);

        memcpy (addr+2, &rnd, sizeof(rnd));
        addr[0] = 2;
        addr[1] = 0xfe;
      }

      error = ethernet_register_interface
        (dm->vnet_main,
         dpdk_device_class.index,
         xd->device_index,
         /* ethernet address */ addr,
         &xd->vlib_hw_if_index, 
         dpdk_flag_change);

      if (error)
        return error;

      sw = vnet_get_hw_sw_interface (dm->vnet_main, xd->vlib_hw_if_index);
      xd->vlib_sw_if_index = sw->sw_if_index;
      hi = vnet_get_hw_interface (dm->vnet_main, xd->vlib_hw_if_index);
    }
  }

  if (nb_desc > dm->num_mbufs) 
    clib_warning ("%d mbufs allocated but total rx/tx ring size is %d\n",
                  dm->num_mbufs, nb_desc);

  /* init next vhost-user if index */
  dm->next_vu_if_id = 0;

  return 0;
}

/*
 * Tell the vlib physical memory allocator that we've handled
 * the initialization. We don't actually do so until
 * vlib_main(...) callls the dpdk config function.
 */
int vlib_app_physmem_init (vlib_main_t * vm, physmem_main_t * pm,
                           int physmem_required)
{
  return 1;
}

static clib_error_t *
write_sys_fs (char * file_name, char * fmt, ...)
{
  u8 * s;
  int fd;

  fd = open (file_name, O_WRONLY);
  if (fd < 0)
    return clib_error_return_unix (0, "open `%s'", file_name);

  va_list va;
  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);
  vec_add1 (s, 0); // terminate c string

  if (write (fd, s, vec_len (s)) < 0)
      return clib_error_return_unix (0, "write '%s' to '%s'", s, file_name);

  vec_free (s);
  close (fd);
  return 0;
}

#define VIRTIO_PCI_NAME  "virtio-pci"

static clib_error_t * dpdk_bind_eth_kernel_drivers (vlib_main_t * vm,
						    char * pci_dev_id,
						    char * kernel_driver)
{
  dpdk_main_t * dm = &dpdk_main;
  unformat_input_t _in;
  unformat_input_t * in = &_in;
  clib_error_t * error = 0;
  u8 * line = 0, * modcmd = 0, * path = 0;
  u8 * pci_vid = 0, *pci_did = 0, * devname = 0;
  char *driver_name = kernel_driver;
  FILE * fp;

  /* 
   * Bail out now if we're not running as root.
   * This allows non-privileged use of the packet generator, etc.
   */
  if (geteuid() != 0)
    return 0;

  /*
   * Get all ethernet pci device numbers for the device type specified.
   */
  modcmd = format (0, "lspci -nDd %s | grep 0200 | "
		   "awk '{ print $1, $3 }'%c", pci_dev_id, 0);
  if ((fp = popen ((const char *)modcmd, "r")) == NULL)
    {
      error = clib_error_return_unix (0, 
				      "Unable to get %s ethernet pci devices.",
				      pci_dev_id);
      goto done;
    }

  vec_validate (line, BUFSIZ);
  vec_validate (path, BUFSIZ);
  while (fgets ((char *)line, BUFSIZ, fp) != NULL)
    {
      struct stat st;
      u8 bind_uio = 1;
      line[strlen ((char *)line) - 1] = 0; // chomp trailing newline.

      unformat_init_string (in, (char *)line, strlen((char *)line) + 1);
      unformat(in, "%s %s:%s", &devname, &pci_vid, &pci_did);
      unformat_free (in);

      /*
       * Blacklist all ethernet interfaces in the 
       * linux IP routing tables (route --inet --inet6)
       */
      if (strstr ((char *)dm->eth_if_blacklist, (char *)devname))
	continue;

      /*
       * If there are any devices whitelisted, then blacklist all devices
       * which are not explicitly whitelisted.
       */
      if (dm->eth_if_whitelist && 
	  !strstr ((char *)dm->eth_if_whitelist, (char *)devname))
	continue;

#ifdef NETMAP
      /*
       * Optimistically open the device as a netmap device.
       */
      if (eth_nm_open((char *)devname))
        continue;
#endif

      _vec_len (path) = 0;
      path = format (path, "/sys/bus/pci/devices/%s/driver/unbind%c",
		     devname, 0);

      /*
       * If the device is bound to a driver...
       */
      if (stat ((const char *)path, &st) == 0)
	{
	  u8 * device_path;

	  /*
	   * If the interface is not a virtio...
	   */
         if (!driver_name || strcmp(driver_name, VIRTIO_PCI_NAME))
           {
              /*
               * If it is already bound to driver, don't unbind/bind it.
               */
              device_path = format (0, "/sys/bus/pci/drivers/%s/%s/device%c",
                                    driver_name, devname, 0);
              if (stat ((const char *)device_path, &st) == 0)
                bind_uio = 0;

              vec_free (device_path);
           }
	  
	  /*
	   * unbind it from the current driver
	   */
	  if (bind_uio)
	    {
	      _vec_len (path) -= 1;
	      path = format (path, "%c", 0);
	      error = write_sys_fs ((char *)path, "%s", devname);
	      if (error)
		goto done;
	    }
	}

      /*
       * DAW-FIXME: The following bind/unbind dance is necessary for the dpdk
       *            virtio poll-mode driver to work.  
       */
 
      if (driver_name && !strcmp(driver_name, VIRTIO_PCI_NAME))
	{
	  /*
	   * bind interface to the native kernel module
	   */
	  _vec_len (path) = 0;
	  path = format (path, "/sys/bus/pci/drivers/%s/bind%c",
			 driver_name, 0);
	  error = write_sys_fs ((char *)path, "%s", devname);
	  if (error)
	    goto done;

	  /*
	   * unbind interface from the native kernel module
	   */
	  _vec_len (path) -= 5;
	  path = format (path, "unbind%c", 0);
	  error = write_sys_fs ((char *)path, "%s", devname);
	  if (error)
	    goto done;
	}

      /*
       * bind the interface to igb_uio
       */
      if (bind_uio)
	{
          _vec_len (path) = 0;
          path = format (path, "/sys/bus/pci/drivers/%s/new_id%c", driver_name, 0);
          error = write_sys_fs ((char *) path, "%s %s", pci_vid, pci_did);
          if (error)
            continue;

          _vec_len (path) = 0;
          path = format (path, "/sys/bus/pci/drivers/%s/bind%c", driver_name, 0);
	  error = write_sys_fs ((char *) path, "%s", devname);
	  if (error)
            {
              error = 0;
              continue;
            }
	}
    }
  
 done:
  vec_free (line);
  vec_free (path);
  vec_free (devname);
  vec_free (pci_vid);
  vec_free (pci_did);
  vec_free (modcmd);
  pclose (fp);
  return error;
}

static uword
unformat_socket_mem (unformat_input_t * input, va_list * va)
{
  uword ** r = va_arg (* va, uword **);
  int i = 0;
  u32 mem;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, ","))
        hash_set (*r, i, 1024);
      else if (unformat (input, "%u,", &mem))
        hash_set (*r, i, mem);
      else if (unformat (input, "%u", &mem))
        hash_set (*r, i, mem);
      else
        {
          unformat_put_input (input);
          goto done;
        }
      i++;
    }

done:
  return 1;
}

static u32
get_node_free_hugepages_num (u32 node, u32 page_size)
{
  FILE * fp;
  u8 * tmp;

  tmp = format (0, "/sys/devices/system/node/node%u/hugepages/hugepages-%ukB/"
                "free_hugepages%c", node, page_size, 0);
  fp = fopen ((char *) tmp, "r");
  vec_free(tmp);

  if (fp != NULL)
    {
      u8 * buffer = 0;
      u32 pages_avail = 0;

      vec_validate (buffer, 256-1);
      if (fgets ((char *)buffer, 256, fp))
        {
          unformat_input_t in;
          unformat_init_string (&in, (char *) buffer, strlen ((char *) buffer));
          unformat(&in, "%u", &pages_avail);
          unformat_free (&in);
        }
      vec_free(buffer);
      fclose(fp);
      return pages_avail;
    }

  return 0;
}

static clib_error_t *
dpdk_config (vlib_main_t * vm, unformat_input_t * input)
{
  clib_error_t * error = 0;
  dpdk_main_t * dm = &dpdk_main;
  vlib_thread_main_t * tm = vlib_get_thread_main();
  u8 * s, * tmp = 0;
  u8 * pci_dev_id = 0;
  u8 * rte_cmd = 0, * ethname = 0;
  FILE * rte_fp;
  u32 log_level;
  int ret, i;
  char * fmt;
#ifdef NETMAP
  int rxrings, txrings, rxslots, txslots, txburst;
  char * nmnam;
#endif
  unformat_input_t _in;
  unformat_input_t * in = &_in;
  u8 no_pci = 0;
  u8 no_huge = 0;
  u8 huge_dir = 0;
  u8 file_prefix = 0;
  u8 * socket_mem = 0;

  // MATT-FIXME: inverted virtio-vhost logic to use virtio by default
  dm->use_virtio_vhost = 1;

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
      /* Prime the pump */
      if (unformat (input, "no-hugetlb"))
        {
          vec_add1 (dm->eal_init_args, (u8 *) "no-huge");
          no_huge = 1;
        }

      else if (unformat (input, "decimal-interface-names"))
        dm->interface_name_format_decimal = 1;

      else if (unformat (input, "no-multi-seg"))
        dm->no_multi_seg = 1;

      else if (unformat (input, "dev %s", &pci_dev_id))
	{
	  if (dm->eth_if_whitelist)
	    {
	      /*
	       * Don't add duplicate device id's.
	       */
	      if (strstr ((char *)dm->eth_if_whitelist, (char *)pci_dev_id))
		continue;

	      _vec_len (dm->eth_if_whitelist) -= 1; // chomp trailing NULL.
	      dm->eth_if_whitelist = format (dm->eth_if_whitelist, " %s%c",
					     pci_dev_id, 0);
	    }
	  else
	    dm->eth_if_whitelist = format (0, "%s%c", pci_dev_id, 0);
	}

#ifdef NETMAP
     else if (unformat(input, "netmap %s/%d:%d/%d:%d/%d",
                  &nmname, &rxrings, &rxslots, &txrings, &txslots, &txburst)) {
        char * rv;
        rv = (char *)
          eth_nm_args(nmname, rxrings, rxslots, txrings, txslots, txburst);
        if (rv) {
          error = clib_error_return (0, "%s", rv);
          goto done;
        }
      }else if (unformat(input, "netmap %s", &nmname)) {
        char * rv;
        rv = (char *)
          eth_nm_args(nmname, 0, 0, 0, 0, 0);
        if (rv) {
          error = clib_error_return (0, "%s", rv);
          goto done;
        }
      }
#endif

      else if (unformat (input, "num-mbufs %d", &dm->num_mbufs))
        ;
      else if (unformat (input, "kni %d", &dm->num_kni))
        ;
      else if (unformat (input, "uio-driver %s", &dm->uio_driver_name))
	;
      else if (unformat (input, "vhost-user-coalesce-frames %d", &dm->vhost_coalesce_frames))
        ;
      else if (unformat (input, "vhost-user-coalesce-time %f", &dm->vhost_coalesce_time))
        ;
      else if (unformat (input, "enable-vhost-user"))
        dm->use_virtio_vhost = 0;
      else if (unformat (input, "rss %d", &dm->use_rss))
        ;

#define _(a)                                    \
      else if (unformat(input, #a))             \
        {                                       \
          if (!strncmp(#a, "no-pci", 6))        \
            no_pci = 1;                         \
          tmp = format (0, "--%s%c", #a, 0);    \
          vec_add1 (dm->eal_init_args, tmp);    \
        }
      foreach_eal_double_hyphen_predicate_arg
#undef _

#define _(a)                                          \
	else if (unformat(input, #a " %s", &s))	      \
	  {					      \
            if (!strncmp(#a, "huge-dir", 8))          \
              huge_dir = 1;                           \
            else if (!strncmp(#a, "file-prefix", 11)) \
              file_prefix = 1;                        \
            else if (!strncmp(#a, "socket-mem", 10))  \
              socket_mem = vec_dup (s);               \
	    tmp = format (0, "--%s%c", #a, 0);	      \
	    vec_add1 (dm->eal_init_args, tmp);	      \
	    vec_add1 (s, 0);			      \
	    vec_add1 (dm->eal_init_args, s);	      \
	  }
	foreach_eal_double_hyphen_arg
#undef _

#define _(a,b)						\
	  else if (unformat(input, #a " %s", &s))	\
	    {						\
	      tmp = format (0, "-%s%c", #b, 0);		\
	      vec_add1 (dm->eal_init_args, tmp);	\
	      vec_add1 (s, 0);				\
	      vec_add1 (dm->eal_init_args, s);		\
	    }
	  foreach_eal_single_hyphen_arg
#undef _

#define _(a,b)						\
	    else if (unformat(input, #a " %s", &s))	\
	      {						\
		tmp = format (0, "-%s%c", #b, 0);	\
		vec_add1 (dm->eal_init_args, tmp);	\
		vec_add1 (s, 0);			\
		vec_add1 (dm->eal_init_args, s);	\
		dm->a##_set_manually = 1;		\
	      }
	    foreach_eal_single_hyphen_mandatory_arg
#undef _

          else if (unformat(input, "default"))
            ;

	  else
	    {
	      error = clib_error_return (0, "unknown input `%U'",
					 format_unformat_error, input);
	      goto done;
	    }
    }

  if (!dm->uio_driver_name)
    dm->uio_driver_name = format (0, "igb_uio");

  /*
   * Use 1G huge pages if available.
   */
  if (!no_huge && !huge_dir)
    {
      uword * mem_by_socket = hash_create (0, sizeof (uword));
      uword c;
      u8 use_1g = 1;
      u8 use_2m = 1;
      int rv;

      umount(DEFAULT_HUGE_DIR);

      /* Process "socket-mem" parameter value */
      if (vec_len (socket_mem))
        {
          unformat_input_t in;
          unformat_init_vector(&in, socket_mem);
          unformat(&in, "%U", unformat_socket_mem, &mem_by_socket);
          unformat_free(&in);
        }
      else
        use_1g = 0;

      /* check if available enough 1GB pages for each socket */
      clib_bitmap_foreach (c, tm->cpu_socket_bitmap, ({
         uword * p = hash_get (mem_by_socket, c);
         if (p)
           {
             u32 mem = p[0];
             if (mem)
               {
                 u32 pages_num_1g = mem / 1024;
                 u32 pages_num_2m = mem / 2;
                 u32 pages_avail;

                 pages_avail = get_node_free_hugepages_num(c, 1048576);
                 if (!(pages_avail >= pages_num_1g))
                   use_1g = 0;

                 pages_avail = get_node_free_hugepages_num(c, 2048);
                 if (!(pages_avail >= pages_num_2m))
                   use_2m = 0;
              }
           }
      }));

      hash_free (mem_by_socket);

      rv = mkdir(VPP_RUN_DIR, 0755);
      if (rv && errno != EEXIST)
        {
          error = clib_error_return (0, "mkdir '%s' failed errno %d",
                                     VPP_RUN_DIR, errno);
          goto done;
        }

      rv = mkdir(DEFAULT_HUGE_DIR, 0755);
      if (rv && errno != EEXIST)
        {
          error = clib_error_return (0, "mkdir '%s' failed errno %d",
                                     DEFAULT_HUGE_DIR, errno);
          goto done;
        }

      if (use_1g)
        {
          rv = mount("none", DEFAULT_HUGE_DIR, "hugetlbfs", 0, "pagesize=1G");
        }
      else if (use_2m)
        {
          rv = mount("none", DEFAULT_HUGE_DIR, "hugetlbfs", 0, NULL);
        }
      else
        {
          return clib_error_return (0, "not enough free huge pages");
        }

      if (rv)
        {
          error = clib_error_return (0, "mount failed %d", errno);
          goto done;
        }

      tmp = format (0, "--huge-dir%c", 0);
      vec_add1 (dm->eal_init_args, tmp);
      tmp = format (0, "%s%c", DEFAULT_HUGE_DIR, 0);
      vec_add1 (dm->eal_init_args, tmp);
      if (!file_prefix)
        {
          tmp = format (0, "--file-prefix%c", 0);
          vec_add1 (dm->eal_init_args, tmp);
          tmp = format (0, "vpp%c", 0);
          vec_add1 (dm->eal_init_args, tmp);
        }
    }

  /*
   * Blacklist all ethernet interfaces in the linux IP routing tables.
   */
  dm->eth_if_blacklist = format (0, "%c", 0);
  rte_cmd = format (0, "route --inet --inet6 -n|awk '{print $7}'|sort -u|"
                    "egrep $(echo $(ls -1d /sys/class/net/*/device|"
                    "cut -d/ -f5)|sed -s 's/ /|/g')%c", 0);
  if ((rte_fp = popen ((const char *)rte_cmd, "r")) == NULL)
    {
      error = clib_error_return_unix (0, "Unable to find blacklist ethernet"
				      " interface(s) in linux routing tables.");
      goto rte_cmd_err;

    }

  vec_validate (ethname, BUFSIZ);
  while (fgets ((char *)ethname, BUFSIZ, rte_fp) != NULL)
    {
      FILE *rlnk_fp;
      u8 * rlnk_cmd = 0, * devname = 0;

      ethname[strlen ((char *)ethname) - 1] = 0; // chomp trailing newline.

      rlnk_cmd = format (0, "readlink /sys/class/net/%s%c",
			 ethname, 0);

      if ((rlnk_fp = popen ((const char *)rlnk_cmd, "r")) == NULL)
	{
	  error = clib_error_return_unix (0, "Unable to read %s link.",
					  ethname);
	  goto rlnk_cmd_err;
	}

      vec_validate (devname, BUFSIZ);
      while (fgets ((char *)devname, BUFSIZ, rlnk_fp) != NULL)
	{
	  char * pci_id = 0;
	  
	  /*
	   * Extract the device PCI ID name from the link. It is the first
	   * PCI ID searching backwards from the end of the link pathname.
	   * For example:
	   *     readlink /sys/class/net/eth0
	   *     ../../devices/pci0000:00/0000:00:0a.0/virtio4/net/eth0
	   */
	  for (pci_id = (char *)((devname + strlen((char *)devname)));
	       ((u8 *)pci_id > devname) && *pci_id != '.'; pci_id--)
	    ;

	  /*
	   * Verify that the field found is a valid PCI ID.
	   */
	  if ((*(pci_id - 1) == '.') || ((u8 *)(pci_id - 11) < devname) || 
	      (*(pci_id - 11) != '/') || (*(pci_id - 3) != ':') ||
	      (*(pci_id - 6) != ':'))
	    {
	      devname[strlen ((char *)devname) - 1] = 0; // chomp trailing newline.
	      clib_warning ("Unable to extract %s PCI ID (0x%llx \"%s\") "
			    "from 0x%llx \"%s\"", ethname, pci_id, pci_id,
			    devname, devname);
	      continue;
	    }

	  pci_id[2] = 0;
	  pci_id -= 10;

          /* Don't blacklist any interfaces which have been whitelisted.
           */
          if (dm->eth_if_whitelist &&
              strstr ((char *)dm->eth_if_whitelist, (char *)pci_id))
              continue;

	  _vec_len (dm->eth_if_blacklist) -= 1; // chomp trailing NULL.
	  dm->eth_if_blacklist = format (dm->eth_if_blacklist, " %s%c",
					 pci_id, 0);
	}
  
    rlnk_cmd_err:
      pclose (rlnk_fp);
      vec_free (rlnk_cmd);
      vec_free (devname);
    }

 rte_cmd_err:
  pclose (rte_fp);
  vec_free (rte_cmd);
  vec_free (ethname);

  if (error)
    return error;

  /* I'll bet that -c and -n must be the first and second args... */
  if (!dm->coremask_set_manually)
    {
      vlib_thread_registration_t * tr;
      uword * coremask = 0;
      int i;

      /* main thread core */
      coremask = clib_bitmap_set(coremask, tm->main_lcore, 1);

      for (i = 0; i < vec_len (tm->registrations); i++)
        {
          tr = tm->registrations[i];
          coremask = clib_bitmap_or(coremask, tr->coremask);
        }

      vec_insert (dm->eal_init_args, 2, 1);
      dm->eal_init_args[1] = (u8 *) "-c";
      tmp = format (0, "%U%c", format_bitmap_hex, coremask, 0);
      dm->eal_init_args[2] = tmp;
      clib_bitmap_free(coremask);
    }

  if (!dm->nchannels_set_manually)
    {
      vec_insert (dm->eal_init_args, 2, 3);
      dm->eal_init_args[3] = (u8 *) "-n";
      tmp = format (0, "%d", dm->nchannels);
      dm->eal_init_args[4] = tmp;
    }

  /*
   * If there are whitelisted devices,
   * add the whitelist option & device list to the dpdk arg list...
   */
  if (dm->eth_if_whitelist)
    {
      unformat_init_string (in, (char *)dm->eth_if_whitelist,
			    vec_len(dm->eth_if_whitelist) - 1);
      fmt = "-w%c";
    }

  /*
   * Otherwise add the blacklisted devices to the dpdk arg list.
   */
  else
    {
      unformat_init_string (in, (char *)dm->eth_if_blacklist,
			    vec_len(dm->eth_if_blacklist) - 1);
      fmt = "-b%c";
    }

  while (unformat_check_input (in) != UNFORMAT_END_OF_INPUT)
    {
      tmp = format (0, fmt, 0);
      vec_add1 (dm->eal_init_args, tmp);
      unformat (in, "%s", &pci_dev_id);
      vec_add1 (dm->eal_init_args, pci_dev_id);
    }

  if (no_pci == 0)
    {
      /*
       * Bind Virtio pci devices to the igb_uio kernel driver.
       */
      error = dpdk_bind_eth_kernel_drivers (vm, "1af4:1000", VIRTIO_PCI_NAME);
      if (error)
        return error;

      /*
       * Bind vmxnet3 pci devices to the igb_uio kernel driver.
       */
      error = dpdk_bind_eth_kernel_drivers (vm, "15ad:07b0",
                                            (char *) dm->uio_driver_name);
      if (error)
        return error;

      /*
       * Bind Intel ethernet pci devices to igb_uio kernel driver.
       */
      error = dpdk_bind_eth_kernel_drivers (vm, "8086:",
                                            (char *) dm->uio_driver_name);
      /*
       * Bind Cisco VIC ethernet pci devices to igb_uio kernel driver.
       */
      error = dpdk_bind_eth_kernel_drivers (vm, "1137:0043",
                                            (char *) dm->uio_driver_name);
    }

  /* set master-lcore */
  tmp = format (0, "--master-lcore%c", 0);
  vec_add1 (dm->eal_init_args, tmp);
  tmp = format (0, "%u%c", tm->main_lcore, 0);
  vec_add1 (dm->eal_init_args, tmp);

  /* NULL terminate the "argv" vector, in case of stupidity */
  vec_add1 (dm->eal_init_args, 0);
  _vec_len(dm->eal_init_args) -= 1;

  /* Set up DPDK eal and packet mbuf pool early. */

  log_level = (CLIB_DEBUG > 0) ? RTE_LOG_DEBUG : RTE_LOG_NOTICE;

  rte_set_log_level (log_level);

  vm = dm->vlib_main;

  ret = rte_eal_init(vec_len(dm->eal_init_args), (char **) dm->eal_init_args);

  /* lazy umount hugepages */
  umount2(DEFAULT_HUGE_DIR, MNT_DETACH);

  if (ret < 0)
    return clib_error_return (0, "rte_eal_init returned %d", ret);

  /* main thread 1st */
  error = vlib_buffer_pool_create(vm, dm->num_mbufs, MBUF_SIZE, rte_socket_id());
  if (error)
    return error;

  for (i = 0; i < RTE_MAX_LCORE; i++)
    {
      error = vlib_buffer_pool_create(vm, dm->num_mbufs, MBUF_SIZE,
                                      rte_lcore_to_socket_id(i));
      if (error)
        return error;
    }

  if (dm->use_rss)
    {
      vlib_node_runtime_t * rt = vlib_node_get_runtime (vm, dpdk_input_node.index);
      rt->function = dpdk_input_rss;
    }
 done:
  return error;
}

VLIB_CONFIG_FUNCTION (dpdk_config, "dpdk");

void dpdk_update_link_state (dpdk_device_t * xd, f64 now)
{
    vnet_main_t * vnm = vnet_get_main();
    struct rte_eth_link prev_link = xd->link;
    u32 hw_flags =  0;
    u8 hw_flags_chg = 0;

    /* only update link state for PMD interfaces */
    if (xd->dev_type != VNET_DPDK_DEV_ETH)
      return;

    xd->time_last_link_update = now ? now : xd->time_last_link_update;
    memset(&xd->link, 0, sizeof(xd->link));
    rte_eth_link_get_nowait (xd->device_index, &xd->link);

    if (LINK_STATE_ELOGS)
      {
        vlib_main_t * vm = vlib_get_main();
        ELOG_TYPE_DECLARE(e) = {
          .format = 
          "update-link-state: sw_if_index %d, admin_up %d,"
          "old link_state %d new link_state %d",
          .format_args = "i4i1i1i1",
        };

        struct { u32 sw_if_index; u8 admin_up; 
          u8 old_link_state; u8 new_link_state;} *ed;
        ed = ELOG_DATA (&vm->elog_main, e);
        ed->sw_if_index = xd->vlib_sw_if_index;
        ed->admin_up = xd->admin_up;
        ed->old_link_state = (u8)
          vnet_hw_interface_is_link_up (vnm, xd->vlib_hw_if_index);
        ed->new_link_state = (u8) xd->link.link_status;
      }

    if ((xd->admin_up == 1) && 
	((xd->link.link_status != 0) ^ 
	 vnet_hw_interface_is_link_up (vnm, xd->vlib_hw_if_index)))
      {
	hw_flags_chg = 1;
	hw_flags |= (xd->link.link_status ? 
		     VNET_HW_INTERFACE_FLAG_LINK_UP: 0);
      }

    if (hw_flags_chg || (xd->link.link_duplex != prev_link.link_duplex))
      {
	hw_flags_chg = 1;
	switch (xd->link.link_duplex)
	  {
	  case ETH_LINK_HALF_DUPLEX:
	    hw_flags |= VNET_HW_INTERFACE_FLAG_HALF_DUPLEX;
	    break;
	  case ETH_LINK_FULL_DUPLEX:
	    hw_flags |= VNET_HW_INTERFACE_FLAG_FULL_DUPLEX;
	    break;
	  default:
	    break;
	  }
      }
    if (hw_flags_chg || (xd->link.link_speed != prev_link.link_speed))
      {
	hw_flags_chg = 1;
	switch (xd->link.link_speed)
	  {
	  case ETH_LINK_SPEED_10:
	    hw_flags |= VNET_HW_INTERFACE_FLAG_SPEED_10M;
	    break;
	  case ETH_LINK_SPEED_100:
	    hw_flags |= VNET_HW_INTERFACE_FLAG_SPEED_100M;
	    break;
	  case ETH_LINK_SPEED_1000:
	    hw_flags |= VNET_HW_INTERFACE_FLAG_SPEED_1G;
	    break;
	  case ETH_LINK_SPEED_10000:
	    hw_flags |= VNET_HW_INTERFACE_FLAG_SPEED_10G;
	    break;
	  case ETH_LINK_SPEED_40G:
	    hw_flags |= VNET_HW_INTERFACE_FLAG_SPEED_40G;
	    break;
    case 0:
      break;
    default:
      clib_warning("unknown link speed %d", xd->link.link_speed);
	    break;
	  }
      }
    if (hw_flags_chg)
      {
        if (LINK_STATE_ELOGS)
          {
            vlib_main_t * vm = vlib_get_main();

            ELOG_TYPE_DECLARE(e) = {
              .format = "update-link-state: sw_if_index %d, new flags %d",
              .format_args = "i4i4",
            };

            struct { u32 sw_if_index; u32 flags; } *ed;
            ed = ELOG_DATA (&vm->elog_main, e);
            ed->sw_if_index = xd->vlib_sw_if_index;
            ed->flags = hw_flags;
          }
        vnet_hw_interface_set_flags (vnm, xd->vlib_hw_if_index, hw_flags);
      }
}

static uword
dpdk_process (vlib_main_t * vm,
              vlib_node_runtime_t * rt,
              vlib_frame_t * f)
{
  clib_error_t * error;
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t * xd;
  vlib_thread_main_t * tm = vlib_get_thread_main();
  void *vu_state;
  int i;

  error = dpdk_lib_init (dm);

  /* 
   * Turn on the input node if we found some devices to drive
   * and we're not running worker threads or i/o threads
   */

  if (error == 0 && vec_len(dm->devices) > 0)
    {
        if (tm->n_vlib_mains == 1)
          vlib_node_set_state (vm, dpdk_input_node.index,
                               VLIB_NODE_STATE_POLLING);
        else if (tm->main_thread_is_io_node)
          vlib_node_set_state (vm, dpdk_io_input_node.index,
                               VLIB_NODE_STATE_POLLING);
        else if (!dm->have_io_threads)
          for (i=0; i < tm->n_vlib_mains; i++)
            if (vec_len(dm->devices_by_cpu[i]) > 0)
              vlib_node_set_state (vlib_mains[i], dpdk_input_node.index,
                                   VLIB_NODE_STATE_POLLING);
    }

  if (error)
    clib_error_report (error);

  dpdk_vhost_user_process_init(&vu_state);

  dm->io_thread_release = 1;

  f64 now = vlib_time_now (vm);
  vec_foreach (xd, dm->devices)
    {
      dpdk_update_link_state (xd, now);
    }

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 5.0);

      if (dpdk_get_admin_up_down_in_progress())
          /* skip the poll if an admin up down is in progress (on any interface) */
          continue;

      vec_foreach (xd, dm->devices)
	{
	  f64 now = vlib_time_now (vm);
	  if ((now - xd->time_last_stats_update) >= DPDK_STATS_POLL_INTERVAL)
	    dpdk_update_counters (xd, now);
	  if ((now - xd->time_last_link_update) >= DPDK_LINK_POLL_INTERVAL)
	    dpdk_update_link_state (xd, now);

      if (xd->dev_type == VNET_DPDK_DEV_VHOST_USER)
          if (dpdk_vhost_user_process_if(vm, xd, vu_state) != 0)
              continue;
	}
    }

  dpdk_vhost_user_process_cleanup(vu_state);

  return 0; 
}

VLIB_REGISTER_NODE (dpdk_process_node,static) = {
    .function = dpdk_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "dpdk-process",
    .process_log2_n_stack_bytes = 17,
};

clib_error_t *
dpdk_init (vlib_main_t * vm)
{
  dpdk_main_t * dm = &dpdk_main;
  vlib_node_t * ei;
  clib_error_t * error = 0;
  vlib_thread_main_t * tm = vlib_get_thread_main();

  /* verify that structs are cacheline aligned */
  ASSERT(offsetof(dpdk_device_t, cacheline0) == 0);
  ASSERT(offsetof(dpdk_device_t, cacheline1) == CLIB_CACHE_LINE_BYTES);
  ASSERT(offsetof(dpdk_worker_t, cacheline0) == 0);
  ASSERT(offsetof(frame_queue_trace_t, cacheline0) == 0);

  /* Add references to DPDK Driver Constructor functions to get the dynamic
   * loader to pull in the driver library & run the constructors.
   */
#define _(d)                                          \
do {                                                  \
  void devinitfn_ ##d(void);                          \
  __attribute__((unused)) void (* volatile pf)(void); \
  pf = devinitfn_ ##d;                                \
} while(0);

#ifdef RTE_LIBRTE_EM_PMD
  _(em_pmd_drv)
#endif

#ifdef RTE_LIBRTE_IGB_PMD
  _(pmd_igb_drv)
#endif

#ifdef RTE_LIBRTE_IXGBE_PMD
  _(rte_ixgbe_driver)
#endif

#ifdef RTE_LIBRTE_I40E_PMD
  _(rte_i40e_driver)
  _(rte_i40evf_driver)
#endif

#ifdef RTE_LIBRTE_FM10K_PMD
  _(rte_fm10k_driver)
#endif

#ifdef RTE_LIBRTE_VIRTIO_PMD
  _(rte_virtio_driver)
#endif

#ifdef RTE_LIBRTE_VMXNET3_PMD
  _(rte_vmxnet3_driver)
#endif

#ifdef RTE_LIBRTE_VICE_PMD
  _(rte_vice_driver)
#endif

#ifdef RTE_LIBRTE_ENIC_PMD
  _(rte_enic_driver)
#endif

#ifdef RTE_LIBRTE_PMD_AF_PACKET
  _(pmd_af_packet_drv)
#endif

#ifdef RTE_LIBRTE_CXGBE_PMD
  _(rte_cxgbe_driver)
#endif

#undef _

/* 
 * At the moment, the ThunderX NIC driver doesn't have
 * an entry point named "devinitfn_rte_xxx_driver"
 */
#define _(d)                                          \
do {                                                  \
  void d(void);			                      \
  __attribute__((unused)) void (* volatile pf)(void); \
  pf = d;		                              \
} while(0);

#ifdef RTE_LIBRTE_THUNDERVNIC_PMD
_(rte_nicvf_pmd_init)
#endif
#undef _

  dm->vlib_main = vm;
  dm->vnet_main = vnet_get_main();

  ei = vlib_get_node_by_name (vm, (u8 *) "ethernet-input");
  if (ei == 0)
      return clib_error_return (0, "ethernet-input node AWOL");

  dm->ethernet_input_node_index = ei->index;

  dm->nchannels = 4;
  dm->num_mbufs = dm->num_mbufs ? dm->num_mbufs : NB_MBUF;
  vec_add1 (dm->eal_init_args, (u8 *) "vnet");

  dm->dpdk_device_by_kni_port_id = hash_create (0, sizeof (uword));
  dm->vu_sw_if_index_by_listener_fd = hash_create (0, sizeof (uword));
  dm->vu_sw_if_index_by_sock_fd = hash_create (0, sizeof (uword));

  /* $$$ use n_thread_stacks since it's known-good at this point */
  vec_validate (dm->recycle, tm->n_thread_stacks - 1);

  /* initialize EFD (early fast discard) default settings */
  dm->efd.enabled = DPDK_EFD_DISABLED;
  dm->efd.queue_hi_thresh = ((DPDK_EFD_DEFAULT_DEVICE_QUEUE_HI_THRESH_PCT *
                              DPDK_NB_RX_DESC_10GE)/100);
  dm->efd.consec_full_frames_hi_thresh =
      DPDK_EFD_DEFAULT_CONSEC_FULL_FRAMES_HI_THRESH;

  /* vhost-user coalescence frames defaults */
  dm->vhost_coalesce_frames = 32;
  dm->vhost_coalesce_time = 1e-3;

  /* init CLI */
  if ((error = vlib_call_init_function (vm, dpdk_cli_init)))
    return error;

  return error;
}

VLIB_INIT_FUNCTION (dpdk_init);

