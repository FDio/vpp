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
#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>

#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/dpdk/dpdk.h>

#include <vnet/devices/virtio/vhost-user.h>
#include "dpdk_priv.h"

#define VHOST_USER_DEBUG_SOCKET 0

#if VHOST_USER_DEBUG_SOCKET == 1
#define DBG_SOCK(args...) clib_warning(args);
#else
#define DBG_SOCK(args...)
#endif

#if DPDK_VHOST_USER

#define VDEV_ARGS_SIZE 256
#define VDEV_IFACE_CLIENT "eth_vhost%u,iface=%s,queues=%d,client=1"
#define VDEV_IFACE_SERVER "eth_vhost%u,iface=%s,queues=%d"

#define VHOST_DRIVER_NAME_LEN 256

static uint32_t nb_vdev;

static struct rte_eth_conf port_conf_template = {
  .rxmode = {
	     .split_hdr_size = 0,
	     .header_split = 0,	     /**< Header Split disabled */
	     .hw_ip_checksum = 0,    /**< IP checksum offload disabled */
	     .hw_vlan_filter = 0,    /**< VLAN filtering disabled */
	     .hw_strip_crc = 0,	     /**< CRC stripped by hardware */
	     },
  .txmode = {
	     .mq_mode = ETH_MQ_TX_NONE,
	     },
};

struct rte_eth_rxmode rx_mode = {
  .max_rx_pkt_len = ETHER_MAX_LEN,	 /**< Default maximum frame length. */
  .split_hdr_size = 0,
  .header_split = 0,	     /**< Header Split disabled. */
  .hw_ip_checksum = 0,	     /**< IP checksum offload disabled. */
  .hw_vlan_filter = 1,	     /**< VLAN filtering enabled. */
  .hw_vlan_strip = 1,	     /**< VLAN strip enabled. */
  .hw_vlan_extend = 0,	     /**< Extended VLAN disabled. */
  .jumbo_frame = 0,	     /**< Jumbo Frame Support disabled. */
  .hw_strip_crc = 0,	     /**< CRC stripping by hardware disabled. */
};

struct rte_fdir_conf fdir_conf = {
  .mode = RTE_FDIR_MODE_NONE,
  .pballoc = RTE_FDIR_PBALLOC_64K,
  .status = RTE_FDIR_REPORT_STATUS,
  .mask = {
	   .vlan_tci_mask = 0x0,
	   .ipv4_mask = {
			 .src_ip = 0xFFFFFFFF,
			 .dst_ip = 0xFFFFFFFF,
			 },
	   .ipv6_mask = {
			 .src_ip =
			 {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
			 .dst_ip =
			 {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
			 },
	   .src_port_mask = 0xFFFF,
	   .dst_port_mask = 0xFFFF,
	   .mac_addr_byte_mask = 0xFF,
	   .tunnel_type_mask = 1,
	   .tunnel_id_mask = 0xFFFFFFFF,
	   },
  .drop_queue = 127,
};

/*
 * DPDK vhost-user functions
 */

/* portions taken from dpdk
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

static dpdk_device_t *
dpdk_vhost_user_device_from_hw_if_index (u32 hw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  dpdk_main_t *dm = &dpdk_main;
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, hi->dev_instance);

  if ((xd->flags & DPDK_DEVICE_FLAG_VHOST_USER) == 0)
    return 0;

  return xd;
}

static dpdk_device_t *
dpdk_vhost_user_device_from_sw_if_index (u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, sw_if_index);
  ASSERT (sw->type == VNET_SW_INTERFACE_TYPE_HARDWARE);

  return dpdk_vhost_user_device_from_hw_if_index (sw->hw_if_index);
}

static inline void *
map_guest_mem (dpdk_device_t * xd, uword addr)
{
#if 0
  dpdk_vu_intf_t *vui = xd->vu_intf;
  struct virtio_memory *mem = xd->vu_vhost_dev.mem;
  int i;
  for (i = 0; i < mem->nregions; i++)
    {
      if ((mem->regions[i].guest_phys_address <= addr) &&
	  ((mem->regions[i].guest_phys_address +
	    mem->regions[i].memory_size) > addr))
	{
	  return (void *) ((uword) vui->region_addr[i] + addr -
			   (uword) mem->regions[i].guest_phys_address);
	}
    }
  DBG_SOCK ("failed to map guest mem addr %lx", addr);
#endif
  return 0;
}

static clib_error_t *
dpdk_create_vhost_user_if_internal (u32 * hw_if_index, u32 if_id,
				    u8 * hwaddr, uint8_t port_id)
{
  dpdk_main_t *dm = &dpdk_main;
  vlib_main_t *vm = vlib_get_main ();
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vnet_sw_interface_t *sw;
  clib_error_t *error;
  dpdk_device_and_queue_t *dq;
  int num_qpairs;
  dpdk_device_t *xd = NULL;
  u8 addr[6];
  int j;

  num_qpairs = dm->use_rss < 1 ? 1 : tm->n_vlib_mains;

  vlib_worker_thread_barrier_sync (vm);

  int inactive_cnt = vec_len (dm->vu_inactive_interfaces_device_index);
  // if there are any inactive ifaces
  if (inactive_cnt > 0)
    {
      // take last
      u32 vui_idx = dm->vu_inactive_interfaces_device_index[inactive_cnt - 1];
      if (vec_len (dm->devices) > vui_idx)
	{
	  xd = vec_elt_at_index (dm->devices, vui_idx);
	  if (xd->flags & DPDK_DEVICE_FLAG_VHOST_USER)
	    {
	      DBG_SOCK
		("reusing inactive vhost-user interface sw_if_index %d",
		 xd->vlib_sw_if_index);
	    }
	  else
	    {
	      clib_warning
		("error: inactive vhost-user interface sw_if_index %d not VHOST_USER type!",
		 xd->vlib_sw_if_index);
	      // reset so new interface is created
	      xd = NULL;
	    }
	}
      // "remove" from inactive list
      _vec_len (dm->vu_inactive_interfaces_device_index) -= 1;
    }

  if (xd)
    {
      // existing interface used - do not overwrite if_id if not needed
      if (if_id != (u32) ~ 0)
	xd->vu_if_id = if_id;

      // reset lockp
      dpdk_device_lock_free (xd);
      dpdk_device_lock_init (xd);

      // reset tx vectors
      for (j = 0; j < tm->n_vlib_mains; j++)
	{
	  vec_validate_ha (xd->tx_vectors[j], xd->nb_tx_desc,
			   sizeof (tx_ring_hdr_t), CLIB_CACHE_LINE_BYTES);
	  vec_reset_length (xd->tx_vectors[j]);
	}

      // reset rx vector
      for (j = 0; j < xd->rx_q_used; j++)
	{
	  vec_validate_aligned (xd->rx_vectors[j], VLIB_FRAME_SIZE - 1,
				CLIB_CACHE_LINE_BYTES);
	  vec_reset_length (xd->rx_vectors[j]);
	}
    }
  else
    {
      // vui was not retrieved from inactive ifaces - create new
      vec_add2_aligned (dm->devices, xd, 1, CLIB_CACHE_LINE_BYTES);
      xd->flags |= DPDK_DEVICE_FLAG_VHOST_USER;
      xd->rx_q_used = num_qpairs;
      xd->tx_q_used = num_qpairs;

      vec_validate_aligned (xd->rx_vectors, xd->rx_q_used,
			    CLIB_CACHE_LINE_BYTES);

      if (if_id == (u32) ~ 0)
	xd->vu_if_id = dm->next_vu_if_id++;
      else
	xd->vu_if_id = if_id;

      xd->device_index = xd - dm->devices;
      xd->per_interface_next_index = ~0;
      xd->cpu_socket = (i8) rte_eth_dev_socket_id (port_id);

      /*
       * We use the same values as physical devices.
       */
      xd->nb_rx_desc = DPDK_NB_RX_DESC_DEFAULT;
      xd->nb_tx_desc = DPDK_NB_TX_DESC_DEFAULT;

      /*
       * We use the same values as physical devices.
       */
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
      clib_memcpy (&xd->port_conf, &port_conf_template,
		   sizeof (struct rte_eth_conf));

      dpdk_device_lock_init (xd);

      DBG_SOCK
	("tm->n_vlib_mains: %d. TX %d, RX: %d, num_qpairs: %d, Lock: %p",
	 tm->n_vlib_mains, xd->tx_q_used, xd->rx_q_used, num_qpairs,
	 xd->lockp);

      vec_validate_aligned (xd->tx_vectors, tm->n_vlib_mains,
			    CLIB_CACHE_LINE_BYTES);

      for (j = 0; j < tm->n_vlib_mains; j++)
	{
	  vec_validate_ha (xd->tx_vectors[j], xd->nb_tx_desc,
			   sizeof (tx_ring_hdr_t), CLIB_CACHE_LINE_BYTES);
	  vec_reset_length (xd->tx_vectors[j]);
	}

      /* reset rx vector */
      for (j = 0; j < xd->rx_q_used; j++)
	{
	  vec_validate_aligned (xd->rx_vectors[j], VLIB_FRAME_SIZE - 1,
				CLIB_CACHE_LINE_BYTES);
	  vec_reset_length (xd->rx_vectors[j]);
	}

    }

  /* keep the port id for the virtio-net device */
  xd->port_id = port_id;

  /*
   * Generate random MAC address for the interface
   */
  if (hwaddr)
    {
      clib_memcpy (addr, hwaddr, sizeof (addr));
    }
  else
    {
      f64 now = vlib_time_now (vm);
      u32 rnd;
      rnd = (u32) (now * 1e6);
      rnd = random_u32 (&rnd);

      clib_memcpy (addr + 2, &rnd, sizeof (rnd));
      addr[0] = 2;
      addr[1] = 0xfe;
    }

  error = ethernet_register_interface
    (dm->vnet_main, dpdk_device_class.index, xd->device_index,
     /* ethernet address */ addr,
     &xd->vlib_hw_if_index, 0);

  if (error)
    return error;

  sw = vnet_get_hw_sw_interface (dm->vnet_main, xd->vlib_hw_if_index);
  xd->vlib_sw_if_index = sw->sw_if_index;

  *hw_if_index = xd->vlib_hw_if_index;

  DBG_SOCK ("xd->device_index: %d, dm->input_cpu_count: %d, "
	    "dm->input_cpu_first_index: %d\n", xd->device_index,
	    dm->input_cpu_count, dm->input_cpu_first_index);

  int q, next_cpu = 0;
  for (q = 0; q < num_qpairs; q++)
    {
      int cpu = dm->input_cpu_first_index + (next_cpu % dm->input_cpu_count);

      unsigned lcore = vlib_worker_threads[cpu].lcore_id;
      vec_validate (xd->cpu_socket_id_by_queue, q);
      xd->cpu_socket_id_by_queue[q] = rte_lcore_to_socket_id (lcore);

      vec_add2 (dm->devices_by_cpu[cpu], dq, 1);
      dq->device = xd->device_index;
      dq->queue_id = q;
      DBG_SOCK ("CPU for %d = %d. QID: %d", *hw_if_index, cpu, dq->queue_id);

      // start polling if it was not started yet (because of no phys ifaces)
      if (tm->n_vlib_mains == 1
	  && dpdk_input_node.state != VLIB_NODE_STATE_POLLING)
	vlib_node_set_state (vm, dpdk_input_node.index,
			     VLIB_NODE_STATE_POLLING);

      if (tm->n_vlib_mains > 1)
	vlib_node_set_state (vlib_mains[cpu], dpdk_input_node.index,
			     VLIB_NODE_STATE_POLLING);
      next_cpu++;
    }

  vlib_worker_thread_barrier_release (vm);
  return 0;
}


/*
 * vhost-user interface management functions
 */

static inline void
dpdk_vhost_user_if_disconnect (dpdk_device_t * xd)
{
  char name[VHOST_DRIVER_NAME_LEN];
  vnet_main_t *vnm = vnet_get_main ();

  xd->flags &= ~DPDK_DEVICE_FLAG_ADMIN_UP;
  vnet_hw_interface_set_flags (vnm, xd->vlib_hw_if_index, 0);

  rte_eth_dev_detach (xd->port_id, name);

  /* Reset port id */
  xd->port_id = -1;

  DBG_SOCK ("interface ifindex %d disconnected", xd->vlib_sw_if_index);
}

/*
 * 1. create virtio-net devices.
 */
static int
dpdk_vhost_devinit (const char *sock_filename, u8 is_server,
		    uint8_t * port_id)
{
  char vdev_args[VDEV_ARGS_SIZE];
  dpdk_main_t *dm;
  vlib_thread_main_t *tm;
  int num_qpairs;

  dm = &dpdk_main;
  tm = vlib_get_thread_main ();
  num_qpairs = dm->use_rss < 1 ? 1 : tm->n_vlib_mains;

  if (is_server == 0)
    snprintf (vdev_args, VDEV_ARGS_SIZE, VDEV_IFACE_CLIENT,
	      nb_vdev, sock_filename, num_qpairs);
  else
    snprintf (vdev_args, VDEV_ARGS_SIZE, VDEV_IFACE_SERVER,
	      nb_vdev, sock_filename, num_qpairs);

  if (rte_eth_dev_attach (vdev_args, port_id) < 0)
    {
      RTE_LOG (ERR, EAL, "Create vdev failed: %s\n", sock_filename);
      return -2;
    }
  nb_vdev++;

  return 0;
}

/*
 * 2. configure devices
 */
static int
dpdk_port_config (dpdk_main_t * dm, dpdk_device_t * xd, uint8_t port_id)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_main_t *bm = vm->buffer_main;
  struct rte_eth_dev_info dev_info;
  struct rte_eth_txconf *txconf;
  int rv;
  int j;

  if (!xd)
    return -1;

  ASSERT (os_get_cpu_number () == 0);

  if (xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP)
    {
      vnet_hw_interface_set_flags (dm->vnet_main, xd->vlib_hw_if_index, 0);
      rte_eth_dev_stop (xd->port_id);
    }

  rte_eth_dev_info_get (port_id, &dev_info);
  txconf = &dev_info.default_txconf;

  rv = rte_eth_dev_configure (port_id, xd->rx_q_used,
			      xd->tx_q_used, &xd->port_conf);
  if (rv < 0)
    return rv;

  /* Set up one TX-queue per worker thread */
  for (j = 0; j < xd->tx_q_used; j++)
    {
      rv = rte_eth_tx_queue_setup (port_id, j, xd->nb_tx_desc,
				   xd->cpu_socket, txconf);

      /* retry with any other CPU socket */
      if (rv < 0)
	rv = rte_eth_tx_queue_setup (port_id, j, xd->nb_tx_desc,
				     SOCKET_ID_ANY, txconf);
      if (rv < 0)
	break;
    }

  if (rv < 0)
    return rv;

  for (j = 0; j < xd->rx_q_used; j++)
    {
      rv = rte_eth_rx_queue_setup (port_id, j, xd->nb_rx_desc,
				   xd->cpu_socket, 0,
				   bm->pktmbuf_pools[xd->
						     cpu_socket_id_by_queue
						     [j]]);

      /* retry with any other CPU socket */
      if (rv < 0)
	rv = rte_eth_rx_queue_setup (port_id, j, xd->nb_rx_desc,
				     SOCKET_ID_ANY, 0,
				     bm->pktmbuf_pools[xd->
						       cpu_socket_id_by_queue
						       [j]]);
      if (rv < 0)
	return rv;
    }

  return 0;
}

/*
 * 3.start devices
 */
static int
dpdk_pmd_devstart (uint8_t port_id)
{
  if (rte_eth_dev_start (port_id) < 0)
    {
      printf ("Fail to start port %d\n", port_id);
      return -1;
    }
  return 0;
}

/*
 * vhost-user interface control functions used from vpe api
 */

int
dpdk_vhost_user_create_if (vnet_main_t * vnm, vlib_main_t * vm,
			   const char *sock_filename,
			   u8 is_server,
			   u32 * sw_if_index,
			   u64 feature_mask,
			   u8 renumber, u32 custom_dev_instance, u8 * hwaddr)
{
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;
  u32 hw_if_idx = ~0;
  int rv = 0;
  uint8_t port_id;

  /* using virtio vhost user? */
  if (dm->conf->use_virtio_vhost)
    {
      return vhost_user_create_if (vnm, vm, sock_filename, is_server,
				   sw_if_index, feature_mask, renumber,
				   custom_dev_instance, hwaddr);
    }

  rv = dpdk_vhost_devinit (sock_filename, is_server, &port_id);
  if (rv < 0)
    return -1;

  rte_vhost_feature_enable (feature_mask);

  if (renumber)
    {
      /* set next vhost-user if id if custom one is higher or equal */
      if (custom_dev_instance >= dm->next_vu_if_id)
	dm->next_vu_if_id = custom_dev_instance + 1;

      dpdk_create_vhost_user_if_internal (&hw_if_idx, custom_dev_instance,
					  hwaddr, port_id);
    }
  else
    dpdk_create_vhost_user_if_internal (&hw_if_idx, (u32) ~ 0,
					hwaddr, port_id);
  DBG_SOCK ("dpdk vhost-user interface created hw_if_index %d", hw_if_idx);

  xd = dpdk_vhost_user_device_from_hw_if_index (hw_if_idx);
  ASSERT (xd != NULL);

  *sw_if_index = xd->vlib_sw_if_index;

  /* initialize hw flag */
  vnet_hw_interface_set_flags (vnm, xd->vlib_hw_if_index, 0);

  /* configure device */
  rv = dpdk_port_config (dm, xd, port_id);
  if (rv < 0)
    {
      dpdk_vhost_user_delete_if (vnm, vm, *sw_if_index);
      nb_vdev--;
      return -1;
    }

  /* start device */
  rv = dpdk_pmd_devstart (port_id);
  if (rv < 0)
    {
      dpdk_vhost_user_delete_if (vnm, vm, *sw_if_index);
      nb_vdev--;
      return -1;
    }

  return rv;
}

int
dpdk_vhost_user_modify_if (vnet_main_t * vnm, vlib_main_t * vm,
			   const char *sock_filename,
			   u8 is_server,
			   u32 sw_if_index,
			   u64 feature_mask,
			   u8 renumber, u32 custom_dev_instance)
{
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;
  u32 sw_if_idx = ~0;
  int rv = 0;
  uint8_t port_id;

  /* using virtio vhost user? */
  if (dm->conf->use_virtio_vhost)
    {
      return vhost_user_modify_if (vnm, vm, sock_filename, is_server,
				   sw_if_index, feature_mask,
				   renumber, custom_dev_instance);
    }

  xd = dpdk_vhost_user_device_from_sw_if_index (sw_if_index);
  if (xd == NULL)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* remove virtio-net device */
  dpdk_vhost_user_if_disconnect (xd);

  if (renumber)
    vnet_interface_name_renumber (sw_if_idx, custom_dev_instance);

  rv = dpdk_vhost_devinit (sock_filename, is_server, &port_id);
  if (rv < 0)
    {
      /* reclaim dpdk device data structure */
      vec_add1 (dm->vu_inactive_interfaces_device_index, xd->device_index);
      ethernet_delete_interface (vnm, xd->vlib_hw_if_index);
      DBG_SOCK ("deleted (deactivated) vhost-user interface sw_if_index %d",
		sw_if_index);
      return -1;
    }

  xd->port_id = port_id;

  rte_vhost_feature_enable (feature_mask);

  rv = dpdk_port_config (dm, xd, port_id);
  if (rv < 0)
    {
      /*
       * remove virtio-net device
       * and reclaim dpdk device data structure
       */
      dpdk_vhost_user_delete_if (vnm, vm, sw_if_index);
      return -1;
    }

  rv = dpdk_pmd_devstart (port_id);
  if (rv < 0)
    {
      dpdk_vhost_user_delete_if (vnm, vm, sw_if_index);
      return -1;
    }

  return rv;
}

int
dpdk_vhost_user_delete_if (vnet_main_t * vnm, vlib_main_t * vm,
			   u32 sw_if_index)
{
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = NULL;
  int rv = 0;

  /* using virtio vhost user? */
  if (dm->conf->use_virtio_vhost)
    {
      return vhost_user_delete_if (vnm, vm, sw_if_index);
    }

  xd = dpdk_vhost_user_device_from_sw_if_index (sw_if_index);
  if (xd == NULL)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  dpdk_vhost_user_if_disconnect (xd);

  /* add to inactive interface list */
  vec_add1 (dm->vu_inactive_interfaces_device_index, xd->device_index);

  ethernet_delete_interface (vnm, xd->vlib_hw_if_index);
  DBG_SOCK ("deleted (deactivated) vhost-user interface sw_if_index %d",
	    sw_if_index);

  return rv;
}

/* 
 * Currently, this function is not supported,
 * since it needs to access private data
 * structures of virtio-net devices, which are
 * invisible to external applications in DPDK.
*/
int
dpdk_vhost_user_dump_ifs (vnet_main_t * vnm, vlib_main_t * vm,
			  vhost_user_intf_details_t ** out_vuids)
{
  dpdk_main_t *dm = &dpdk_main;

  // using virtio vhost user?
  if (dm->conf->use_virtio_vhost)
    {
      return vhost_user_dump_ifs (vnm, vm, out_vuids);
    }

  return 0;
#if 0
  int rv = 0;
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;
  dpdk_vu_intf_t *vui;
  struct virtio_net *vhost_dev;
  vhost_user_intf_details_t *r_vuids = NULL;
  vhost_user_intf_details_t *vuid = NULL;
  u32 *hw_if_indices = 0;
  vnet_hw_interface_t *hi;
  u8 *s = NULL;
  int i;

  if (!out_vuids)
    return -1;

  // using virtio vhost user?
  if (dm->conf->use_virtio_vhost)
    {
      return vhost_user_dump_ifs (vnm, vm, out_vuids);
    }

  vec_foreach (xd, dm->devices)
  {
    if ((xd->flags & DPDK_DEVICE_FLAG_VHOST_USER) && xd->vu_intf->active)
      vec_add1 (hw_if_indices, xd->vlib_hw_if_index);
  }

  for (i = 0; i < vec_len (hw_if_indices); i++)
    {
      hi = vnet_get_hw_interface (vnm, hw_if_indices[i]);
      xd = dpdk_vhost_user_device_from_hw_if_index (hw_if_indices[i]);
      if (!xd)
	{
	  clib_warning ("invalid vhost-user interface hw_if_index %d",
			hw_if_indices[i]);
	  continue;
	}

      vui = xd->vu_intf;
      ASSERT (vui != NULL);
      vhost_dev = &xd->vu_vhost_dev;
      u32 virtio_net_hdr_sz = (vui->num_vrings > 0 ?
			       vhost_dev->virtqueue[0]->vhost_hlen : 0);

      vec_add2 (r_vuids, vuid, 1);
      vuid->sw_if_index = xd->vlib_sw_if_index;
      vuid->virtio_net_hdr_sz = virtio_net_hdr_sz;
      vuid->features = vhost_dev->features;
      vuid->is_server = vui->sock_is_server;
      vuid->num_regions =
	(vhost_dev->mem != NULL ? vhost_dev->mem->nregions : 0);
      vuid->sock_errno = vui->sock_errno;
      strncpy ((char *) vuid->sock_filename, (char *) vui->sock_filename,
	       ARRAY_LEN (vuid->sock_filename) - 1);

      s = format (s, "%v%c", hi->name, 0);

      strncpy ((char *) vuid->if_name, (char *) s,
	       ARRAY_LEN (vuid->if_name) - 1);
      _vec_len (s) = 0;
    }

  vec_free (s);
  vec_free (hw_if_indices);

  *out_vuids = r_vuids;

  return rv;
#endif
}

#endif

/*
 * CLI functions
 */

static clib_error_t *
dpdk_vhost_user_connect_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
#if DPDK_VHOST_USER
  dpdk_main_t *dm = &dpdk_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *sock_filename = NULL;
  u32 sw_if_index;
  u8 is_server = 0;
  u64 feature_mask = (u64) ~ 0;
  u8 renumber = 0;
  u32 custom_dev_instance = ~0;
  u8 hwaddr[6];
  u8 *hw = NULL;

  if (dm->conf->use_virtio_vhost)
    {
#endif
      return vhost_user_connect_command_fn (vm, input, cmd);
#if DPDK_VHOST_USER
    }

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "socket %s", &sock_filename))
	;
      else if (unformat (line_input, "server"))
	is_server = 1;
      else if (unformat (line_input, "feature-mask 0x%llx", &feature_mask))
	;
      else
	if (unformat
	    (line_input, "hwaddr %U", unformat_ethernet_address, hwaddr))
	hw = hwaddr;
      else if (unformat (line_input, "renumber %d", &custom_dev_instance))
	{
	  renumber = 1;
	}
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  vnet_main_t *vnm = vnet_get_main ();
  if (sock_filename == NULL)
    return clib_error_return (0, "missing socket file");

  dpdk_vhost_user_create_if (vnm, vm, (char *) sock_filename,
			     is_server, &sw_if_index, feature_mask,
			     renumber, custom_dev_instance, hw);

  vec_free (sock_filename);
  vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main (),
		   sw_if_index);
  return 0;
#endif
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dpdk_vhost_user_connect_command, static) = {
    .path = "create vhost-user",
    .short_help = "create vhost-user socket <socket-filename> [server] [feature-mask <hex>] [renumber <dev_instance>]",
    .function = dpdk_vhost_user_connect_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
dpdk_vhost_user_delete_command_fn (vlib_main_t * vm,
				   unformat_input_t * input,
				   vlib_cli_command_t * cmd)
{
  dpdk_main_t *dm = &dpdk_main;
  clib_error_t *error = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;

  if (dm->conf->use_virtio_vhost)
    {
      return vhost_user_delete_command_fn (vm, input, cmd);
    }

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (sw_if_index == ~0)
    {
      error = clib_error_return (0, "invalid sw_if_index",
				 format_unformat_error, input);
      return error;
    }

  vnet_main_t *vnm = vnet_get_main ();

#if DPDK_VHOST_USER
  dpdk_vhost_user_delete_if (vnm, vm, sw_if_index);
#else
  vhost_user_delete_if (vnm, vm, sw_if_index);
#endif

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dpdk_vhost_user_delete_command, static) = {
    .path = "delete vhost-user",
    .short_help = "delete vhost-user sw_if_index <nn>",
    .function = dpdk_vhost_user_delete_command_fn,
};
/* *INDENT-ON* */

#define foreach_dpdk_vhost_feature      \
 _ (VIRTIO_NET_F_MRG_RXBUF)             \
 _ (VIRTIO_NET_F_CTRL_VQ)               \
 _ (VIRTIO_NET_F_CTRL_RX)

/*
 * Currently, this function is not supported,
 * since it needs to access private data
 * structures of virtio-net devices, which are
 * invisible to external applications in DPDK.
 */
static clib_error_t *
show_dpdk_vhost_user_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  dpdk_main_t *dm = &dpdk_main;

  if (dm->conf->use_virtio_vhost)
    {
      return show_vhost_user_command_fn (vm, input, cmd);
    }
  return 0;

#if 0
#if DPDK_VHOST_USER
  clib_error_t *error = 0;
  dpdk_main_t *dm = &dpdk_main;
  vnet_main_t *vnm = vnet_get_main ();
  dpdk_device_t *xd;
  dpdk_vu_intf_t *vui;
  struct virtio_net *vhost_dev;
  u32 hw_if_index, *hw_if_indices = 0;
  vnet_hw_interface_t *hi;
  int i, j, q;
  int show_descr = 0;
  struct virtio_memory *mem;
  struct feat_struct
  {
    u8 bit;
    char *str;
  };
  struct feat_struct *feat_entry;

  static struct feat_struct feat_array[] = {
#define _(f) { .str = #f, .bit = f, },
    foreach_dpdk_vhost_feature
#undef _
    {.str = NULL}
  };

  if (dm->conf->use_virtio_vhost)
    {
#endif
      return show_vhost_user_command_fn (vm, input, cmd);
#if DPDK_VHOST_USER
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index))
	{
	  vec_add1 (hw_if_indices, hw_if_index);
	  vlib_cli_output (vm, "add %d", hw_if_index);
	}
      else if (unformat (input, "descriptors") || unformat (input, "desc"))
	show_descr = 1;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }
  if (vec_len (hw_if_indices) == 0)
    {
      vec_foreach (xd, dm->devices)
      {
	if ((xd->flags DPDK_DEVICE_FLAG_VHOST_USER) && xd->vu_intf->active)
	  vec_add1 (hw_if_indices, xd->vlib_hw_if_index);
      }
    }

  vlib_cli_output (vm, "DPDK vhost-user interfaces");
  vlib_cli_output (vm, "Global:\n  coalesce frames %d time %e\n\n",
		   dm->conf->vhost_coalesce_frames,
		   dm->conf->vhost_coalesce_time);

  for (i = 0; i < vec_len (hw_if_indices); i++)
    {
      hi = vnet_get_hw_interface (vnm, hw_if_indices[i]);

      if (!(xd = dpdk_vhost_user_device_from_hw_if_index (hw_if_indices[i])))
	{
	  error = clib_error_return (0, "not dpdk vhost-user interface: '%s'",
				     hi->name);
	  goto done;
	}
      vui = xd->vu_intf;
      vhost_dev = &xd->vu_vhost_dev;
      mem = vhost_dev->mem;
      u32 virtio_net_hdr_sz = (vui->num_vrings > 0 ?
			       vhost_dev->virtqueue[0]->vhost_hlen : 0);

      vlib_cli_output (vm, "Interface: %v (ifindex %d)",
		       hi->name, hw_if_indices[i]);

      vlib_cli_output (vm, "virtio_net_hdr_sz %d\n features (0x%llx): \n",
		       virtio_net_hdr_sz, xd->vu_vhost_dev.features);

      feat_entry = (struct feat_struct *) &feat_array;
      while (feat_entry->str)
	{
	  if (xd->vu_vhost_dev.features & (1 << feat_entry->bit))
	    vlib_cli_output (vm, "   %s (%d)", feat_entry->str,
			     feat_entry->bit);
	  feat_entry++;
	}

      vlib_cli_output (vm, "\n");

      vlib_cli_output (vm, " socket filename %s type %s errno \"%s\"\n\n",
		       vui->sock_filename,
		       vui->sock_is_server ? "server" : "client",
		       strerror (vui->sock_errno));

      vlib_cli_output (vm, " Memory regions (total %d)\n", mem->nregions);

      if (mem->nregions)
	{
	  vlib_cli_output (vm,
			   " region fd    guest_phys_addr    memory_size        userspace_addr     mmap_offset        mmap_addr\n");
	  vlib_cli_output (vm,
			   " ====== ===== ================== ================== ================== ================== ==================\n");
	}
      for (j = 0; j < mem->nregions; j++)
	{
	  vlib_cli_output (vm,
			   "  %d     %-5d 0x%016lx 0x%016lx 0x%016lx 0x%016lx 0x%016lx\n",
			   j, vui->region_fd[j],
			   mem->regions[j].guest_phys_address,
			   mem->regions[j].memory_size,
			   mem->regions[j].userspace_address,
			   mem->regions[j].address_offset,
			   vui->region_addr[j]);
	}
      for (q = 0; q < vui->num_vrings; q++)
	{
	  struct vhost_virtqueue *vq = vhost_dev->virtqueue[q];
	  const char *qtype = (q & 1) ? "TX" : "RX";

	  vlib_cli_output (vm, "\n Virtqueue %d (%s)\n", q / 2, qtype);

	  vlib_cli_output (vm,
			   "  qsz %d last_used_idx %d last_used_idx_res %d\n",
			   vq->size, vq->last_used_idx,
			   vq->last_used_idx_res);

	  if (vq->avail && vq->used)
	    vlib_cli_output (vm,
			     "  avail.flags %x avail.idx %d used.flags %x used.idx %d\n",
			     vq->avail->flags, vq->avail->idx,
			     vq->used->flags, vq->used->idx);

	  vlib_cli_output (vm, "  kickfd %d callfd %d errfd %d enabled %d\n",
			   vq->kickfd, vq->callfd, vui->vrings[q].errfd,
			   vq->enabled);

	  if (show_descr && vq->enabled)
	    {
	      vlib_cli_output (vm, "\n  descriptor table:\n");
	      vlib_cli_output (vm,
			       "   id          addr         len  flags  next      user_addr\n");
	      vlib_cli_output (vm,
			       "  ===== ================== ===== ====== ===== ==================\n");
	      for (j = 0; j < vq->size; j++)
		{
		  vlib_cli_output (vm,
				   "  %-5d 0x%016lx %-5d 0x%04x %-5d 0x%016lx\n",
				   j, vq->desc[j].addr, vq->desc[j].len,
				   vq->desc[j].flags, vq->desc[j].next,
				   pointer_to_uword (map_guest_mem
						     (xd, vq->desc[j].addr)));
		}
	    }
	}
      vlib_cli_output (vm, "\n");
    }
done:
  vec_free (hw_if_indices);
  return error;
#endif
#endif
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_vhost_user_command, static) = {
    .path = "show vhost-user",
    .short_help = "show vhost-user interface",
    .function = show_dpdk_vhost_user_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
