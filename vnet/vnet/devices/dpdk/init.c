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
#include <vppinfra/bitmap.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/dpdk/dpdk.h>
#include <vlib/unix/physmem.h>
#include <vlib/pci/pci.h>

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

      /* retry with any other CPU socket */
      if (rv < 0)
        rv = rte_eth_tx_queue_setup(xd->device_index, j, xd->nb_tx_desc,
                                   SOCKET_ID_ANY, &xd->tx_conf);
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

      /* retry with any other CPU socket */
      if (rv < 0)
        rv = rte_eth_rx_queue_setup(xd->device_index, j, xd->nb_rx_desc,
                                    SOCKET_ID_ANY, 0,
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

void
dpdk_device_lock_init(dpdk_device_t * xd)
{
  int q;
  vec_validate(xd->lockp, xd->tx_q_used - 1);
  for (q = 0; q < xd->tx_q_used; q++)
    {
      xd->lockp[q] = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
                                             CLIB_CACHE_LINE_BYTES);
      memset ((void *) xd->lockp[q], 0, CLIB_CACHE_LINE_BYTES);
  }
  xd->need_txlock = 1;
}

void
dpdk_device_lock_free(dpdk_device_t * xd)
{
  int q;

  for (q = 0; q < vec_len(xd->lockp); q++)
    clib_mem_free((void *) xd->lockp[q]);
  vec_free(xd->lockp);
  xd->lockp = 0;
  xd->need_txlock = 0;
}

static clib_error_t *
dpdk_lib_init (dpdk_main_t * dm)
{
  u32 nports;
  u32 nb_desc = 0;
  int i;
  clib_error_t * error;
  vlib_main_t * vm = vlib_get_main();
  vlib_thread_main_t * tm = vlib_get_thread_main();
  vlib_node_runtime_t * rt;
  vnet_sw_interface_t * sw;
  vnet_hw_interface_t * hi;
  dpdk_device_t * xd;
  vlib_thread_registration_t * tr;
  uword * p;

  u32 next_cpu = 0;
  u8 af_packet_port_id = 0;

  dm->input_cpu_first_index = 0;
  dm->input_cpu_count = 1;

  rt = vlib_node_get_runtime (vm, dpdk_input_node.index);
  rt->function = dpdk_input_multiarch_select();

  /* find out which cpus will be used for input */
  p = hash_get_mem (tm->thread_registrations_by_name, "workers");
  tr = p ? (vlib_thread_registration_t *) p[0] : 0;

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

  if (dm->conf->enable_tcp_udp_checksum)
    dm->buffer_flags_template &= ~(IP_BUFFER_L4_CHECKSUM_CORRECT
				   | IP_BUFFER_L4_CHECKSUM_COMPUTED);

  for (i = 0; i < nports; i++)
    {
      u8 addr[6];
      int j;
      struct rte_eth_dev_info dev_info;
      clib_error_t * rv;
      struct rte_eth_link l;
      dpdk_device_config_t * devconf = 0;
      vlib_pci_addr_t pci_addr;
      uword * p = 0;

      rte_eth_dev_info_get(i, &dev_info);
      if (dev_info.pci_dev) /* bonded interface has no pci info */
        {
	  pci_addr.domain = dev_info.pci_dev->addr.domain;
	  pci_addr.bus = dev_info.pci_dev->addr.bus;
	  pci_addr.slot = dev_info.pci_dev->addr.devid;
	  pci_addr.function = dev_info.pci_dev->addr.function;
	  p = hash_get (dm->conf->device_config_index_by_pci_addr, pci_addr.as_u32);
        }

      if (p)
	devconf = pool_elt_at_index (dm->conf->dev_confs, p[0]);
      else
	devconf = &dm->conf->default_devconf;

      /* Create vnet interface */
      vec_add2_aligned (dm->devices, xd, 1, CLIB_CACHE_LINE_BYTES);
      xd->nb_rx_desc = DPDK_NB_RX_DESC_DEFAULT;
      xd->nb_tx_desc = DPDK_NB_TX_DESC_DEFAULT;
      xd->cpu_socket = (i8) rte_eth_dev_socket_id(i);

      clib_memcpy(&xd->tx_conf, &dev_info.default_txconf,
             sizeof(struct rte_eth_txconf));
      if (dm->conf->no_multi_seg)
        {
          xd->tx_conf.txq_flags |= ETH_TXQ_FLAGS_NOMULTSEGS;
          port_conf_template.rxmode.jumbo_frame = 0;
        }
      else
        {
          xd->tx_conf.txq_flags &= ~ETH_TXQ_FLAGS_NOMULTSEGS;
          port_conf_template.rxmode.jumbo_frame = 1;
        }

      clib_memcpy(&xd->port_conf, &port_conf_template, sizeof(struct rte_eth_conf));

      xd->tx_q_used = clib_min(dev_info.max_tx_queues, tm->n_vlib_mains);

      if (devconf->num_tx_queues > 0 && devconf->num_tx_queues < xd->tx_q_used)
        xd->tx_q_used = clib_min(xd->tx_q_used, devconf->num_tx_queues);

      if (devconf->num_rx_queues > 1 && dm->use_rss == 0)
	{
	  rt->function = dpdk_input_rss_multiarch_select();
	  dm->use_rss = 1;
	}

      if (devconf->num_rx_queues > 1 && dev_info.max_rx_queues >= devconf->num_rx_queues)
        {
          xd->rx_q_used = devconf->num_rx_queues;
          xd->port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
          if (devconf->rss_fn == 0)
            xd->port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP;
          else
            xd->port_conf.rx_adv_conf.rss_conf.rss_hf = devconf->rss_fn;
        }
      else
        xd->rx_q_used = 1;

      xd->dev_type = VNET_DPDK_DEV_ETH;

      /* workaround for drivers not setting driver_name */
      if ((!dev_info.driver_name) && (dev_info.pci_dev))
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
	  case VNET_DPDK_PMD_DPAA2:
	    xd->port_type = VNET_DPDK_PORT_TYPE_ETH_10G;
	    break;

          /* Cisco VIC */
          case VNET_DPDK_PMD_VICE:
          case VNET_DPDK_PMD_ENIC:
            rte_eth_link_get_nowait(i, &l);
	    xd->nb_rx_desc = DPDK_NB_RX_DESC_ENIC;
            if (l.link_speed == 40000)
              {
                xd->port_type = VNET_DPDK_PORT_TYPE_ETH_40G;
                xd->nb_tx_desc = DPDK_NB_TX_DESC_40GE;
              }
            else
              {
                xd->port_type = VNET_DPDK_PORT_TYPE_ETH_10G;
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
                rte_eth_link_get_nowait(i, &l);
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

          case VNET_DPDK_PMD_BOND:
            xd->port_type = VNET_DPDK_PORT_TYPE_ETH_BOND;
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
	if (devconf->num_rx_desc)
	  xd->nb_rx_desc = devconf->num_rx_desc;

	if (devconf->num_tx_desc)
	  xd->nb_tx_desc = devconf->num_tx_desc;
      }

      /*
       * Ensure default mtu is not > the mtu read from the hardware.
       * Otherwise rte_eth_dev_configure() will fail and the port will
       * not be available.
       */
      if (ETHERNET_MAX_PACKET_BYTES > dev_info.max_rx_pktlen)
        {
          /*
           * This device does not support the platforms's max frame
           * size. Use it's advertised mru instead.
           */
          xd->port_conf.rxmode.max_rx_pkt_len = dev_info.max_rx_pktlen;
        }
      else
        {
          xd->port_conf.rxmode.max_rx_pkt_len = ETHERNET_MAX_PACKET_BYTES;

          /*
           * Some platforms do not account for Ethernet FCS (4 bytes) in
           * MTU calculations. To interop with them increase mru but only
           * if the device's settings can support it.
           */
          if ((dev_info.max_rx_pktlen >= (ETHERNET_MAX_PACKET_BYTES + 4)) &&
              xd->port_conf.rxmode.hw_strip_crc)
            {
              /*
               * Allow additional 4 bytes (for Ethernet FCS). These bytes are
               * stripped by h/w and so will not consume any buffer memory.
               */
              xd->port_conf.rxmode.max_rx_pkt_len += 4;
            }
        }

#if RTE_VERSION < RTE_VERSION_NUM(16, 4, 0, 0) 
      /*
       * Older VMXNET3 driver doesn't support jumbo / multi-buffer pkts
       */
      if (xd->pmd == VNET_DPDK_PMD_VMXNET3)
        {
          xd->port_conf.rxmode.max_rx_pkt_len = 1518;
          xd->port_conf.rxmode.jumbo_frame = 0;
        }
#endif

      if (xd->pmd == VNET_DPDK_PMD_AF_PACKET)
        {
          f64 now = vlib_time_now(vm);
          u32 rnd;
          rnd = (u32) (now * 1e6);
          rnd = random_u32 (&rnd);
          clib_memcpy (addr+2, &rnd, sizeof(rnd));
          addr[0] = 2;
          addr[1] = 0xfe;
        }
      else
        rte_eth_macaddr_get(i,(struct ether_addr *)addr);

      if (xd->tx_q_used < tm->n_vlib_mains)
        dpdk_device_lock_init(xd);

      xd->device_index = xd - dm->devices;
      ASSERT(i == xd->device_index);
      xd->per_interface_next_index = ~0;

      /* assign interface to input thread */
      dpdk_device_and_queue_t * dq;
      int q;

      if (devconf->workers)
	{
	  int i;
	  q = 0;
	  clib_bitmap_foreach (i, devconf->workers, ({
	    int cpu = dm->input_cpu_first_index + i;
	    unsigned lcore = vlib_worker_threads[cpu].dpdk_lcore_id;
	    vec_validate(xd->cpu_socket_id_by_queue, q);
	    xd->cpu_socket_id_by_queue[q] = rte_lcore_to_socket_id(lcore);
	    vec_add2(dm->devices_by_cpu[cpu], dq, 1);
	    dq->device = xd->device_index;
	    dq->queue_id = q++;
	  }));
	}
      else
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

#if RTE_VERSION < RTE_VERSION_NUM(16, 4, 0, 0) 
      /*
       * Older VMXNET3 driver doesn't support jumbo / multi-buffer pkts
       */
      else if (xd->pmd == VNET_DPDK_PMD_VMXNET3)
	  hi->max_packet_bytes = 1518;
#endif

      hi->max_l3_packet_bytes[VLIB_RX] = hi->max_l3_packet_bytes[VLIB_TX] = 
	      xd->port_conf.rxmode.max_rx_pkt_len - sizeof(ethernet_header_t);

     rte_eth_dev_set_mtu(xd->device_index, hi->max_packet_bytes);
    }

#ifdef RTE_LIBRTE_KNI
  if (dm->conf->num_kni) {
    clib_warning("Initializing KNI interfaces...");
    rte_kni_init(dm->conf->num_kni);
    for (i = 0; i < dm->conf->num_kni; i++)
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

        clib_memcpy (addr+2, &rnd, sizeof(rnd));
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
#endif

  if (nb_desc > dm->conf->num_mbufs) 
    clib_warning ("%d mbufs allocated but total rx/tx ring size is %d\n",
                  dm->conf->num_mbufs, nb_desc);

  /* init next vhost-user if index */
  dm->next_vu_if_id = 0;

  return 0;
}

static void
dpdk_bind_devices_to_uio (dpdk_config_main_t * conf)
{
  vlib_pci_main_t * pm = &pci_main;
  clib_error_t * error;
  vlib_pci_device_t * d;
  pci_config_header_t * c;
  u8 * pci_addr = 0;
  int num_whitelisted = vec_len (conf->dev_confs);

  pool_foreach (d, pm->pci_devs, ({
    dpdk_device_config_t * devconf = 0;
    c = &d->config0.header;
    vec_reset_length (pci_addr);
    pci_addr = format (pci_addr, "%U%c", format_vlib_pci_addr, &d->bus_address, 0);

    if (c->device_class != PCI_CLASS_NETWORK_ETHERNET)
      continue;

    if (num_whitelisted)
      {
	uword * p = hash_get (conf->device_config_index_by_pci_addr, d->bus_address.as_u32);

	if (!p)
	  continue;

	devconf = pool_elt_at_index (conf->dev_confs, p[0]);
      }

    /* virtio */
    if (c->vendor_id == 0x1af4 && c->device_id == 0x1000)
      ;
    /* vmxnet3 */
    else if (c->vendor_id == 0x15ad && c->device_id == 0x07b0)
      ;
    /* all Intel devices */
    else if (c->vendor_id == 0x8086)
      ;
    /* Cisco VIC */
    else if (c->vendor_id == 0x1137 && c->device_id == 0x0043)
      ;
    /* Chelsio T4/T5 */
    else if (c->vendor_id == 0x1425 && (c->device_id & 0xe000) == 0x4000)
      ;
    else
      {
        clib_warning ("Unsupported Ethernet PCI device 0x%04x:0x%04x found "
		      "at PCI address %s\n", (u16) c->vendor_id, (u16) c->device_id,
		      pci_addr);
        continue;
      }

    error = vlib_pci_bind_to_uio (d, (char *) conf->uio_driver_name);

    if (error)
      {
	if (devconf == 0)
	  {
	    pool_get (conf->dev_confs, devconf);
	    hash_set (conf->device_config_index_by_pci_addr, d->bus_address.as_u32,
		      devconf - conf->dev_confs);
	    devconf->pci_addr.as_u32 = d->bus_address.as_u32;
	  }
	devconf->is_blacklisted = 1;
	clib_error_report (error);
      }
  }));
  vec_free (pci_addr);
}

static clib_error_t *
dpdk_device_config (dpdk_config_main_t * conf, vlib_pci_addr_t pci_addr, unformat_input_t * input, u8 is_default)
{
  clib_error_t * error = 0;
  uword * p;
  dpdk_device_config_t * devconf;
  unformat_input_t sub_input;

  if (is_default)
    {
      devconf = &conf->default_devconf;
    }
  else
    {
      p = hash_get (conf->device_config_index_by_pci_addr, pci_addr.as_u32);

      if (!p)
	{
	  pool_get (conf->dev_confs, devconf);
	  hash_set (conf->device_config_index_by_pci_addr, pci_addr.as_u32, devconf - conf->dev_confs);
	}
      else
	return clib_error_return(0, "duplicate configuration for PCI address %U",
				 format_vlib_pci_addr, &pci_addr);
    }

  devconf->pci_addr.as_u32 = pci_addr.as_u32;

  if (!input)
    return 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "num-rx-queues %u", &devconf->num_rx_queues))
	;
      else if (unformat (input, "num-tx-queues %u", &devconf->num_tx_queues))
	;
      else if (unformat (input, "num-rx-desc %u", &devconf->num_rx_desc))
	;
      else if (unformat (input, "num-tx-desc %u", &devconf->num_tx_desc))
	;
      else if (unformat (input, "workers %U", unformat_bitmap_list,
			 &devconf->workers))
	;
      else if (unformat (input, "rss %U", unformat_vlib_cli_sub_input, &sub_input))
        {
          error = unformat_rss_fn(&sub_input, &devconf->rss_fn);
          if (error)
            break;
        }
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  break;
	}
    }

  if (error)
    return error;

  if (devconf->workers && devconf->num_rx_queues == 0)
    devconf->num_rx_queues = clib_bitmap_count_set_bits(devconf->workers);
  else if (devconf->workers &&
	   clib_bitmap_count_set_bits(devconf->workers) != devconf->num_rx_queues)
    error = clib_error_return (0, "%U: number of worker threadds must be "
			       "equal to number of rx queues",
			       format_vlib_pci_addr, &pci_addr);

  return error;
}

static clib_error_t *
dpdk_config (vlib_main_t * vm, unformat_input_t * input)
{
  clib_error_t * error = 0;
  dpdk_main_t * dm = &dpdk_main;
  dpdk_config_main_t * conf = &dpdk_config_main;
  vlib_thread_main_t * tm = vlib_get_thread_main();
  dpdk_device_config_t * devconf;
  vlib_pci_addr_t pci_addr;
  unformat_input_t sub_input;
  u8 * s, * tmp = 0;
  u8 * rte_cmd = 0, * ethname = 0;
  u32 log_level;
  int ret, i;
  int num_whitelisted = 0;
#ifdef NETMAP
  int rxrings, txrings, rxslots, txslots, txburst;
  char * nmnam;
#endif
  u8 no_pci = 0;
  u8 no_huge = 0;
  u8 huge_dir = 0;
  u8 file_prefix = 0;
  u8 * socket_mem = 0;

  conf->device_config_index_by_pci_addr = hash_create (0, sizeof (uword));

  // MATT-FIXME: inverted virtio-vhost logic to use virtio by default
  conf->use_virtio_vhost = 1;

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
      /* Prime the pump */
      if (unformat (input, "no-hugetlb"))
        {
          vec_add1 (conf->eal_init_args, (u8 *) "no-huge");
          no_huge = 1;
        }

      else if (unformat (input, "enable-tcp-udp-checksum"))
	conf->enable_tcp_udp_checksum = 1;

      else if (unformat (input, "decimal-interface-names"))
        conf->interface_name_format_decimal = 1;

      else if (unformat (input, "no-multi-seg"))
        conf->no_multi_seg = 1;

      else if (unformat (input, "dev default %U", unformat_vlib_cli_sub_input,
			 &sub_input))
	{
	  error = dpdk_device_config (conf, (vlib_pci_addr_t) (u32) ~1, &sub_input, 1);

	  if (error)
	    return error;
	}
      else if (unformat (input, "dev %U %U", unformat_vlib_pci_addr, &pci_addr,
			 unformat_vlib_cli_sub_input, &sub_input))
	{
	  error = dpdk_device_config (conf, pci_addr, &sub_input, 0);

	  if (error)
	    return error;

	  num_whitelisted++;
	}
      else if (unformat (input, "dev %U", unformat_vlib_pci_addr, &pci_addr))
	{
	  error = dpdk_device_config (conf, pci_addr, 0, 0);

	  if (error)
	    return error;

	  num_whitelisted++;
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

      else if (unformat (input, "num-mbufs %d", &conf->num_mbufs))
        ;
      else if (unformat (input, "kni %d", &conf->num_kni))
        ;
      else if (unformat (input, "uio-driver %s", &conf->uio_driver_name))
	;
      else if (unformat (input, "socket-mem %s", &socket_mem))
	;
      else if (unformat (input, "vhost-user-coalesce-frames %d", &conf->vhost_coalesce_frames))
        ;
      else if (unformat (input, "vhost-user-coalesce-time %f", &conf->vhost_coalesce_time))
        ;
      else if (unformat (input, "enable-vhost-user"))
        conf->use_virtio_vhost = 0;
      else if (unformat (input, "poll-sleep %d", &dm->poll_sleep))
        ;

#define _(a)                                    \
      else if (unformat(input, #a))             \
        {                                       \
          if (!strncmp(#a, "no-pci", 6))        \
            no_pci = 1;                         \
          tmp = format (0, "--%s%c", #a, 0);    \
          vec_add1 (conf->eal_init_args, tmp);    \
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
	    tmp = format (0, "--%s%c", #a, 0);	      \
	    vec_add1 (conf->eal_init_args, tmp);      \
	    vec_add1 (s, 0);			      \
	    vec_add1 (conf->eal_init_args, s);	      \
	  }
	foreach_eal_double_hyphen_arg
#undef _

#define _(a,b)						\
	  else if (unformat(input, #a " %s", &s))	\
	    {						\
	      tmp = format (0, "-%s%c", #b, 0);		\
	      vec_add1 (conf->eal_init_args, tmp);	\
	      vec_add1 (s, 0);				\
	      vec_add1 (conf->eal_init_args, s);	\
	    }
	  foreach_eal_single_hyphen_arg
#undef _

#define _(a,b)						\
	    else if (unformat(input, #a " %s", &s))	\
	      {						\
		tmp = format (0, "-%s%c", #b, 0);	\
		vec_add1 (conf->eal_init_args, tmp);	\
		vec_add1 (s, 0);			\
		vec_add1 (conf->eal_init_args, s);	\
		conf->a##_set_manually = 1;		\
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

  if (!conf->uio_driver_name)
    conf->uio_driver_name = format (0, "igb_uio%c", 0);

  /*
   * Use 1G huge pages if available.
   */
  if (!no_huge && !huge_dir)
    {
      u32 x, * mem_by_socket = 0;
      uword c = 0;
      u8 use_1g = 1;
      u8 use_2m = 1;
      u8 less_than_1g = 1;
      int rv;

      umount(DEFAULT_HUGE_DIR);

      /* Process "socket-mem" parameter value */
      if (vec_len (socket_mem))
	{
	  unformat_input_t in;
	  unformat_init_vector(&in, socket_mem);
	  while (unformat_check_input (&in) != UNFORMAT_END_OF_INPUT)
	    {
	      if (unformat (&in, "%u,", &x))
		;
	      else if (unformat (&in, "%u", &x))
		;
	      else if (unformat (&in, ","))
		x = 0;
	      else
		break;

	      vec_add1(mem_by_socket, x);

	      if (x > 1023)
		less_than_1g = 0;
	    }
          /* Note: unformat_free vec_frees(in.buffer), aka socket_mem... */
	  unformat_free(&in);
          socket_mem = 0;
	}
      else
	{
	  clib_bitmap_foreach (c, tm->cpu_socket_bitmap, (
	    {
	      vec_validate(mem_by_socket, c);
	      mem_by_socket[c] = 256; /* default per-socket mem */
	    }
	  ));
	}

      /* check if available enough 1GB pages for each socket */
      clib_bitmap_foreach (c, tm->cpu_socket_bitmap, (
        {
	  u32 pages_avail, page_size, mem;
	  u8 *s = 0;
          u8 *p = 0;
	  char * numa_path = "/sys/devices/system/node/node%u/";
          char * nonnuma_path = "/sys/kernel/mm/";
          char * suffix = "hugepages/hugepages-%ukB/free_hugepages%c";
          char * path = NULL;
          struct stat sb_numa, sb_nonnuma;

          p = format(p, numa_path, c);
          stat(numa_path, &sb_numa);
          stat(nonnuma_path, &sb_nonnuma);

          if (S_ISDIR(sb_numa.st_mode)) {
            path = (char*)format((u8*)path, "%s%s", p, suffix);
          } else if (S_ISDIR(sb_nonnuma.st_mode)) {
            path = (char*)format((u8*)path, "%s%s", nonnuma_path, suffix);
          } else {
            use_1g = 0;
            use_2m = 0;
            vec_free(p);
            break;
          }

	  vec_validate(mem_by_socket, c);
	  mem = mem_by_socket[c];

	  page_size = 1024;
	  pages_avail = 0;
	  s = format (s, path, page_size * 1024, 0);
	  vlib_sysfs_read ((char *) s, "%u", &pages_avail);
	  vec_reset_length (s);

	  if (page_size * pages_avail < mem)
	    use_1g = 0;

	  page_size = 2;
	  pages_avail = 0;
	  s = format (s, path, page_size * 1024, 0);
	  vlib_sysfs_read ((char *) s, "%u", &pages_avail);
	  vec_reset_length (s);

	  if (page_size * pages_avail < mem)
	    use_2m = 0;

	  vec_free(s);
	  vec_free(p);
	  vec_free(path);
      }));
      _vec_len (mem_by_socket) = c + 1;

      /* regenerate socket_mem string */
      vec_foreach_index (x, mem_by_socket)
	socket_mem = format (socket_mem, "%s%u",
			     socket_mem ? "," : "",
			     mem_by_socket[x]);
      socket_mem = format (socket_mem, "%c", 0);

      vec_free (mem_by_socket);

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

      if (use_1g && !(less_than_1g && use_2m))
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
      vec_add1 (conf->eal_init_args, tmp);
      tmp = format (0, "%s%c", DEFAULT_HUGE_DIR, 0);
      vec_add1 (conf->eal_init_args, tmp);
      if (!file_prefix)
        {
          tmp = format (0, "--file-prefix%c", 0);
          vec_add1 (conf->eal_init_args, tmp);
          tmp = format (0, "vpp%c", 0);
          vec_add1 (conf->eal_init_args, tmp);
        }
    }

  vec_free (rte_cmd);
  vec_free (ethname);

  if (error)
    return error;

  /* I'll bet that -c and -n must be the first and second args... */
  if (!conf->coremask_set_manually)
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

      vec_insert (conf->eal_init_args, 2, 1);
      conf->eal_init_args[1] = (u8 *) "-c";
      tmp = format (0, "%U%c", format_bitmap_hex, coremask, 0);
      conf->eal_init_args[2] = tmp;
      clib_bitmap_free(coremask);
    }

  if (!conf->nchannels_set_manually)
    {
      vec_insert (conf->eal_init_args, 2, 3);
      conf->eal_init_args[3] = (u8 *) "-n";
      tmp = format (0, "%d", conf->nchannels);
      conf->eal_init_args[4] = tmp;
    }

  if (no_pci == 0 && geteuid() == 0)
    dpdk_bind_devices_to_uio(conf);

#define _(x) \
    if (devconf->x == 0 && conf->default_devconf.x > 0) \
      devconf->x = conf->default_devconf.x ;

  pool_foreach (devconf, conf->dev_confs, ({

    /* default per-device config items */
    foreach_dpdk_device_config_item

    /* add DPDK EAL whitelist/blacklist entry */
    if (num_whitelisted > 0 && devconf->is_blacklisted == 0)
      {
	tmp = format (0, "-w%c", 0);
	vec_add1 (conf->eal_init_args, tmp);
	tmp = format (0, "%U%c", format_vlib_pci_addr, &devconf->pci_addr, 0);
	vec_add1 (conf->eal_init_args, tmp);
      }
    else if (num_whitelisted == 0 && devconf->is_blacklisted != 0)
      {
	tmp = format (0, "-b%c", 0);
	vec_add1 (conf->eal_init_args, tmp);
	tmp = format (0, "%U%c", format_vlib_pci_addr, &devconf->pci_addr, 0);
	vec_add1 (conf->eal_init_args, tmp);
      }
  }));

#undef _

  /* set master-lcore */
  tmp = format (0, "--master-lcore%c", 0);
  vec_add1 (conf->eal_init_args, tmp);
  tmp = format (0, "%u%c", tm->main_lcore, 0);
  vec_add1 (conf->eal_init_args, tmp);

  /* set socket-mem */
  tmp = format (0, "--socket-mem%c", 0);
  vec_add1 (conf->eal_init_args, tmp);
  tmp = format (0, "%s%c", socket_mem, 0);
  vec_add1 (conf->eal_init_args, tmp);

  /* NULL terminate the "argv" vector, in case of stupidity */
  vec_add1 (conf->eal_init_args, 0);
  _vec_len(conf->eal_init_args) -= 1;

  /* Set up DPDK eal and packet mbuf pool early. */

  log_level = (CLIB_DEBUG > 0) ? RTE_LOG_DEBUG : RTE_LOG_NOTICE;

  rte_set_log_level (log_level);

  vm = vlib_get_main ();

  /* make copy of args as rte_eal_init tends to mess up with arg array */
  for (i = 1; i < vec_len(conf->eal_init_args); i++)
    conf->eal_init_args_str = format(conf->eal_init_args_str, "%s ",
                                     conf->eal_init_args[i]);

  ret = rte_eal_init(vec_len(conf->eal_init_args), (char **) conf->eal_init_args);

  /* lazy umount hugepages */
  umount2(DEFAULT_HUGE_DIR, MNT_DETACH);

  if (ret < 0)
    return clib_error_return (0, "rte_eal_init returned %d", ret);

  /* Dump the physical memory layout prior to creating the mbuf_pool */
  fprintf(stdout, "DPDK physical memory layout:\n");
  rte_dump_physmem_layout(stdout);

  /* main thread 1st */
  error = vlib_buffer_pool_create(vm, conf->num_mbufs, rte_socket_id());
  if (error)
    return error;

  for (i = 0; i < RTE_MAX_LCORE; i++)
    {
      error = vlib_buffer_pool_create(vm, conf->num_mbufs,
                                      rte_lcore_to_socket_id(i));
      if (error)
        return error;
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
#if RTE_VERSION >= RTE_VERSION_NUM(16, 4, 0, 0)
    if (hw_flags_chg || (xd->link.link_speed != prev_link.link_speed))
      {
	hw_flags_chg = 1;
	switch (xd->link.link_speed)
	  {
	  case ETH_SPEED_NUM_10M:
	    hw_flags |= VNET_HW_INTERFACE_FLAG_SPEED_10M;
	    break;
	  case ETH_SPEED_NUM_100M:
	    hw_flags |= VNET_HW_INTERFACE_FLAG_SPEED_100M;
	    break;
	  case ETH_SPEED_NUM_1G:
	    hw_flags |= VNET_HW_INTERFACE_FLAG_SPEED_1G;
	    break;
	  case ETH_SPEED_NUM_10G:
	    hw_flags |= VNET_HW_INTERFACE_FLAG_SPEED_10G;
	    break;
	  case ETH_SPEED_NUM_40G:
	    hw_flags |= VNET_HW_INTERFACE_FLAG_SPEED_40G;
	    break;
    case 0:
      break;
    default:
      clib_warning("unknown link speed %d", xd->link.link_speed);
	    break;
	  }
      }
#else
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
#endif
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
  vnet_main_t * vnm = vnet_get_main();
  dpdk_main_t * dm = &dpdk_main;
  ethernet_main_t * em = &ethernet_main;
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
        else
          for (i=0; i < tm->n_vlib_mains; i++)
            if (vec_len(dm->devices_by_cpu[i]) > 0)
              vlib_node_set_state (vlib_mains[i], dpdk_input_node.index,
                                   VLIB_NODE_STATE_POLLING);
    }

  if (error)
    clib_error_report (error);

  dpdk_vhost_user_process_init(&vu_state);

  dm->worker_thread_release = 1;

  f64 now = vlib_time_now (vm);
  vec_foreach (xd, dm->devices)
    {
      dpdk_update_link_state (xd, now);
    }

{ // Extra set up for bond interfaces:
  // 1. Setup MACs for bond interfaces and their slave links which was set
  //    in dpdk_port_setup() but needs to be done again here to take effect.
  // 2. Set max L3 packet size of each bond interface to the lowerst value of 
  //    its slave links 
  // 3. Set up info for bond interface related CLI support.
  int nports = rte_eth_dev_count();
  if (nports > 0) {
      for (i = 0; i < nports; i++) {
	  struct rte_eth_dev_info dev_info;
	  rte_eth_dev_info_get(i, &dev_info);
	  if (!dev_info.driver_name)
	      dev_info.driver_name = dev_info.pci_dev->driver->name;
	  ASSERT(dev_info.driver_name);
	  if (strncmp(dev_info.driver_name, "rte_bond_pmd", 12) == 0) {
	      u8  addr[6]; 
	      u8  slink[16];
	      int nlink = rte_eth_bond_slaves_get(i, slink, 16);
	      if (nlink > 0) {
		  vnet_hw_interface_t * bhi;
		  ethernet_interface_t * bei;
		  /* Get MAC of 1st slave link */
		  rte_eth_macaddr_get(slink[0], (struct ether_addr *)addr);
		  /* Set MAC of bounded interface to that of 1st slave link */
		  rte_eth_bond_mac_address_set(i, (struct ether_addr *)addr);
		  /* Populate MAC of bonded interface in VPP hw tables */
		  bhi = vnet_get_hw_interface(
		      vnm, dm->devices[i].vlib_hw_if_index);
		  bei = pool_elt_at_index(em->interfaces, bhi->hw_instance);
		  clib_memcpy(bhi->hw_address, addr, 6);
		  clib_memcpy(bei->address, addr, 6);
		  /* Init l3 packet size allowed on bonded interface */
		  bhi->max_l3_packet_bytes[VLIB_RX] = 
		  bhi->max_l3_packet_bytes[VLIB_TX] = 
		      ETHERNET_MAX_PACKET_BYTES - sizeof(ethernet_header_t);
		  while (nlink >= 1) { /* for all slave links */
		      int slave = slink[--nlink];
		      dpdk_device_t * sdev = &dm->devices[slave];
		      vnet_hw_interface_t * shi;
		      vnet_sw_interface_t * ssi;
		      /* Add MAC to all slave links except the first one */
		      if (nlink) rte_eth_dev_mac_addr_add(
			  slave, (struct ether_addr *)addr, 0);
		      /* Set slaves bitmap for bonded interface */
		      bhi->bond_info = clib_bitmap_set(
			  bhi->bond_info, sdev->vlib_hw_if_index, 1);
		      /* Set slave link flags on slave interface */
		      shi = vnet_get_hw_interface(vnm, sdev->vlib_hw_if_index);
		      ssi = vnet_get_sw_interface(vnm, sdev->vlib_sw_if_index);
		      shi->bond_info = VNET_HW_INTERFACE_BOND_INFO_SLAVE;
		      ssi->flags |= VNET_SW_INTERFACE_FLAG_BOND_SLAVE;
		      /* Set l3 packet size allowed as the lowest of slave */
		      if (bhi->max_l3_packet_bytes[VLIB_RX] >
			  shi->max_l3_packet_bytes[VLIB_RX]) 
			  bhi->max_l3_packet_bytes[VLIB_RX] =
			  bhi->max_l3_packet_bytes[VLIB_TX] =
			      shi->max_l3_packet_bytes[VLIB_RX];
		  }
	      }
	  }
      }
  }
}

  while (1)
    {
      /*
       * check each time through the loop in case intervals are changed
       */
      f64 min_wait = dm->link_state_poll_interval < dm->stat_poll_interval ?
                     dm->link_state_poll_interval : dm->stat_poll_interval;

      vlib_process_wait_for_event_or_clock (vm, min_wait);

      if (dpdk_get_admin_up_down_in_progress())
          /* skip the poll if an admin up down is in progress (on any interface) */
          continue;

      vec_foreach (xd, dm->devices)
	{
	  f64 now = vlib_time_now (vm);
          if ((now - xd->time_last_stats_update) >= dm->stat_poll_interval)
	    dpdk_update_counters (xd, now);
          if ((now - xd->time_last_link_update) >= dm->link_state_poll_interval)
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

int dpdk_set_stat_poll_interval (f64 interval)
{
  if (interval < DPDK_MIN_STATS_POLL_INTERVAL)
      return (VNET_API_ERROR_INVALID_VALUE);

  dpdk_main.stat_poll_interval = interval;

  return 0;
}

int dpdk_set_link_state_poll_interval (f64 interval)
{
  if (interval < DPDK_MIN_LINK_POLL_INTERVAL)
      return (VNET_API_ERROR_INVALID_VALUE);

  dpdk_main.link_state_poll_interval = interval;

  return 0;
}

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

  dm->vlib_main = vm;
  dm->vnet_main = vnet_get_main();
  dm->conf = &dpdk_config_main;

  ei = vlib_get_node_by_name (vm, (u8 *) "ethernet-input");
  if (ei == 0)
      return clib_error_return (0, "ethernet-input node AWOL");

  dm->ethernet_input_node_index = ei->index;

  dm->conf->nchannels = 4;
  dm->conf->num_mbufs = dm->conf->num_mbufs ? dm->conf->num_mbufs : NB_MBUF;
  vec_add1 (dm->conf->eal_init_args, (u8 *) "vnet");

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
  dm->conf->vhost_coalesce_frames = 32;
  dm->conf->vhost_coalesce_time = 1e-3;

  /* Default vlib_buffer_t flags, DISABLES tcp/udp checksumming... */
  dm->buffer_flags_template = 
    (VLIB_BUFFER_TOTAL_LENGTH_VALID 
     | IP_BUFFER_L4_CHECKSUM_COMPUTED
     | IP_BUFFER_L4_CHECKSUM_CORRECT);

  dm->stat_poll_interval = DPDK_STATS_POLL_INTERVAL;
  dm->link_state_poll_interval = DPDK_LINK_POLL_INTERVAL;

  /* init CLI */
  if ((error = vlib_call_init_function (vm, dpdk_cli_init)))
    return error;

  return error;
}

VLIB_INIT_FUNCTION (dpdk_init);

