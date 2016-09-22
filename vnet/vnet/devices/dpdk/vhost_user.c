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

#define VHOST_USER_DEBUG_SOCKET 0

#if VHOST_USER_DEBUG_SOCKET == 1
#define DBG_SOCK(args...) clib_warning(args);
#else
#define DBG_SOCK(args...)
#endif

#if DPDK_VHOST_USER

/* *INDENT-OFF* */
static const char *vhost_message_str[] __attribute__ ((unused)) =
{
    [VHOST_USER_NONE] = "VHOST_USER_NONE",
    [VHOST_USER_GET_FEATURES] = "VHOST_USER_GET_FEATURES",
    [VHOST_USER_SET_FEATURES] = "VHOST_USER_SET_FEATURES",
    [VHOST_USER_SET_OWNER] = "VHOST_USER_SET_OWNER",
    [VHOST_USER_RESET_OWNER] = "VHOST_USER_RESET_OWNER",
    [VHOST_USER_SET_MEM_TABLE] = "VHOST_USER_SET_MEM_TABLE",
    [VHOST_USER_SET_LOG_BASE] = "VHOST_USER_SET_LOG_BASE",
    [VHOST_USER_SET_LOG_FD] = "VHOST_USER_SET_LOG_FD",
    [VHOST_USER_SET_VRING_NUM] = "VHOST_USER_SET_VRING_NUM",
    [VHOST_USER_SET_VRING_ADDR] = "VHOST_USER_SET_VRING_ADDR",
    [VHOST_USER_SET_VRING_BASE] = "VHOST_USER_SET_VRING_BASE",
    [VHOST_USER_GET_VRING_BASE] = "VHOST_USER_GET_VRING_BASE",
    [VHOST_USER_SET_VRING_KICK] = "VHOST_USER_SET_VRING_KICK",
    [VHOST_USER_SET_VRING_CALL] = "VHOST_USER_SET_VRING_CALL",
    [VHOST_USER_SET_VRING_ERR] = "VHOST_USER_SET_VRING_ERR",
    [VHOST_USER_GET_PROTOCOL_FEATURES] = "VHOST_USER_GET_PROTOCOL_FEATURES",
    [VHOST_USER_SET_PROTOCOL_FEATURES] = "VHOST_USER_SET_PROTOCOL_FEATURES",
    [VHOST_USER_GET_QUEUE_NUM] = "VHOST_USER_GET_QUEUE_NUM",
    [VHOST_USER_SET_VRING_ENABLE] = "VHOST_USER_SET_VRING_ENABLE",
};
/* *INDENT-ON* */

static int dpdk_vhost_user_set_vring_enable (u32 hw_if_index,
					     u8 idx, int enable);

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


static uword
qva_to_vva (struct virtio_net *dev, uword qemu_va)
{
  struct virtio_memory_regions *region;
  uword vhost_va = 0;
  uint32_t regionidx = 0;

  /* Find the region where the address lives. */
  for (regionidx = 0; regionidx < dev->mem->nregions; regionidx++)
    {
      region = &dev->mem->regions[regionidx];
      if ((qemu_va >= region->userspace_address) &&
	  (qemu_va <= region->userspace_address + region->memory_size))
	{
	  vhost_va = qemu_va + region->guest_phys_address +
	    region->address_offset - region->userspace_address;
	  break;
	}
    }
  return vhost_va;
}

static dpdk_device_t *
dpdk_vhost_user_device_from_hw_if_index (u32 hw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  dpdk_main_t *dm = &dpdk_main;
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, hi->dev_instance);

  if ((xd->flags DPDK_DEVICE_FLAG_VHOST_USER) == 0)
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

static void
stop_processing_packets (u32 hw_if_index, u8 idx)
{
  dpdk_device_t *xd = dpdk_vhost_user_device_from_hw_if_index (hw_if_index);
  assert (xd);
  xd->vu_vhost_dev.virtqueue[idx]->enabled = 0;
}

static void
disable_interface (dpdk_device_t * xd)
{
  u8 idx;
  int numqs = xd->vu_vhost_dev.virt_qp_nb * VIRTIO_QNUM;
  for (idx = 0; idx < numqs; idx++)
    xd->vu_vhost_dev.virtqueue[idx]->enabled = 0;

  xd->vu_is_running = 0;
}

static inline void *
map_guest_mem (dpdk_device_t * xd, uword addr)
{
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
  return 0;
}

static clib_error_t *
dpdk_create_vhost_user_if_internal (u32 * hw_if_index, u32 if_id, u8 * hwaddr)
{
  dpdk_main_t *dm = &dpdk_main;
  vlib_main_t *vm = vlib_get_main ();
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vnet_sw_interface_t *sw;
  clib_error_t *error;
  dpdk_device_and_queue_t *dq;
  int num_qpairs = 1;
  dpdk_vu_intf_t *vui = NULL;

  num_qpairs = dm->use_rss < 1 ? 1 : tm->n_vlib_mains;

  dpdk_device_t *xd = NULL;
  u8 addr[6];
  int j;

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

      // reset virtqueues
      vui = xd->vu_intf;
      for (j = 0; j < num_qpairs * VIRTIO_QNUM; j++)
	{
	  memset (xd->vu_vhost_dev.virtqueue[j], 0,
		  sizeof (struct vhost_virtqueue));
	  xd->vu_vhost_dev.virtqueue[j]->kickfd = -1;
	  xd->vu_vhost_dev.virtqueue[j]->callfd = -1;
	  xd->vu_vhost_dev.virtqueue[j]->backend = -1;
	  vui->vrings[j].packets = 0;
	  vui->vrings[j].bytes = 0;
	}

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
      xd->vu_vhost_dev.virt_qp_nb = num_qpairs;

      vec_validate_aligned (xd->rx_vectors, xd->rx_q_used,
			    CLIB_CACHE_LINE_BYTES);

      if (if_id == (u32) ~ 0)
	xd->vu_if_id = dm->next_vu_if_id++;
      else
	xd->vu_if_id = if_id;

      xd->device_index = xd - dm->devices;
      xd->per_interface_next_index = ~0;
      xd->vu_intf = clib_mem_alloc (sizeof (*(xd->vu_intf)));

      xd->vu_vhost_dev.mem = clib_mem_alloc (sizeof (struct virtio_memory) +
					     VHOST_MEMORY_MAX_NREGIONS *
					     sizeof (struct
						     virtio_memory_regions));

      /* Will be set when guest sends VHOST_USER_SET_MEM_TABLE cmd */
      xd->vu_vhost_dev.mem->nregions = 0;

      /*
       * New virtqueue structure is an array of VHOST_MAX_QUEUE_PAIRS * 2
       * We need to allocate numq pairs.
       */
      vui = xd->vu_intf;
      for (j = 0; j < num_qpairs * VIRTIO_QNUM; j++)
	{
	  xd->vu_vhost_dev.virtqueue[j] =
	    clib_mem_alloc (sizeof (struct vhost_virtqueue));
	  memset (xd->vu_vhost_dev.virtqueue[j], 0,
		  sizeof (struct vhost_virtqueue));
	  xd->vu_vhost_dev.virtqueue[j]->kickfd = -1;
	  xd->vu_vhost_dev.virtqueue[j]->callfd = -1;
	  xd->vu_vhost_dev.virtqueue[j]->backend = -1;
	  vui->vrings[j].packets = 0;
	  vui->vrings[j].bytes = 0;
	}

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

      // reset rx vector
      for (j = 0; j < xd->rx_q_used; j++)
	{
	  vec_validate_aligned (xd->rx_vectors[j], VLIB_FRAME_SIZE - 1,
				CLIB_CACHE_LINE_BYTES);
	  vec_reset_length (xd->rx_vectors[j]);
	}

    }
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

      unsigned lcore = vlib_worker_threads[cpu].dpdk_lcore_id;
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

#if RTE_VERSION >= RTE_VERSION_NUM(16, 4, 0, 0)
static long
get_huge_page_size (int fd)
{
  struct statfs s;
  fstatfs (fd, &s);
  return s.f_bsize;
}
#endif

static clib_error_t *
dpdk_vhost_user_set_protocol_features (u32 hw_if_index, u64 prot_features)
{
  dpdk_device_t *xd;
  xd = dpdk_vhost_user_device_from_hw_if_index (hw_if_index);
  assert (xd);
  xd->vu_vhost_dev.protocol_features = prot_features;
  return 0;
}

static clib_error_t *
dpdk_vhost_user_get_features (u32 hw_if_index, u64 * features)
{
  *features = rte_vhost_feature_get ();

#if RTE_VERSION >= RTE_VERSION_NUM(16, 4, 0, 0)
#define OFFLOAD_FEATURES ((1ULL << VIRTIO_NET_F_HOST_TSO4) | \
		(1ULL << VIRTIO_NET_F_HOST_TSO6) | \
		(1ULL << VIRTIO_NET_F_CSUM)    | \
		(1ULL << VIRTIO_NET_F_GUEST_CSUM) | \
		(1ULL << VIRTIO_NET_F_GUEST_TSO4) | \
		(1ULL << VIRTIO_NET_F_GUEST_TSO6))

  /* These are not suppoted as bridging/tunneling VHOST
   * interfaces with hardware interfaces/drivers that does
   * not support offloading breaks L4 traffic.
   */
  *features &= (~OFFLOAD_FEATURES);
#endif

  DBG_SOCK ("supported features: 0x%lx", *features);
  return 0;
}

static clib_error_t *
dpdk_vhost_user_set_features (u32 hw_if_index, u64 features)
{
  dpdk_device_t *xd;
  u16 hdr_len = sizeof (struct virtio_net_hdr);


  if (!(xd = dpdk_vhost_user_device_from_hw_if_index (hw_if_index)))
    {
      clib_warning ("not a vhost-user interface");
      return 0;
    }

  xd->vu_vhost_dev.features = features;

  if (xd->vu_vhost_dev.features & (1 << VIRTIO_NET_F_MRG_RXBUF))
    hdr_len = sizeof (struct virtio_net_hdr_mrg_rxbuf);

  int numqs = VIRTIO_QNUM;
  u8 idx;
  int prot_feature = features & (1ULL << VHOST_USER_F_PROTOCOL_FEATURES);
  numqs = xd->vu_vhost_dev.virt_qp_nb * VIRTIO_QNUM;
  for (idx = 0; idx < numqs; idx++)
    {
      xd->vu_vhost_dev.virtqueue[idx]->vhost_hlen = hdr_len;
      /*
       * Spec says, if F_PROTOCOL_FEATURE is not set by the
       * slave, then all the vrings should start off as
       * enabled. If slave negotiates F_PROTOCOL_FEATURE, then
       * slave is responsible to enable it.
       */
      if (!prot_feature)
	dpdk_vhost_user_set_vring_enable (hw_if_index, idx, 1);
    }

  return 0;
}

static clib_error_t *
dpdk_vhost_user_set_mem_table (u32 hw_if_index, vhost_user_memory_t * vum,
			       int fd[])
{
  struct virtio_memory *mem;
  int i;
  dpdk_device_t *xd;
  dpdk_vu_intf_t *vui;

  if (!(xd = dpdk_vhost_user_device_from_hw_if_index (hw_if_index)))
    {
      clib_warning ("not a vhost-user interface");
      return 0;
    }

  vui = xd->vu_intf;
  mem = xd->vu_vhost_dev.mem;

  mem->nregions = vum->nregions;

  for (i = 0; i < mem->nregions; i++)
    {
      u64 mapped_size, mapped_address;

      mem->regions[i].guest_phys_address = vum->regions[i].guest_phys_addr;
      mem->regions[i].guest_phys_address_end =
	vum->regions[i].guest_phys_addr + vum->regions[i].memory_size;
      mem->regions[i].memory_size = vum->regions[i].memory_size;
      mem->regions[i].userspace_address = vum->regions[i].userspace_addr;

      mapped_size = mem->regions[i].memory_size + vum->regions[i].mmap_offset;
      mapped_address =
	pointer_to_uword (mmap
			  (NULL, mapped_size, PROT_READ | PROT_WRITE,
			   MAP_SHARED, fd[i], 0));

      if (uword_to_pointer (mapped_address, void *) == MAP_FAILED)
	{
	  clib_warning ("mmap error");
	  return 0;
	}

      mapped_address += vum->regions[i].mmap_offset;
      vui->region_addr[i] = mapped_address;
      vui->region_fd[i] = fd[i];
      vui->region_offset[i] = vum->regions[i].mmap_offset;
      mem->regions[i].address_offset =
	mapped_address - mem->regions[i].guest_phys_address;

      DBG_SOCK ("map memory region %d addr 0x%lx off 0x%lx len 0x%lx",
		i, vui->region_addr[i], vui->region_offset[i], mapped_size);

      if (vum->regions[i].guest_phys_addr == 0)
	{
	  mem->base_address = vum->regions[i].userspace_addr;
	  mem->mapped_address = mem->regions[i].address_offset;
	}
    }

  disable_interface (xd);
  return 0;
}

static clib_error_t *
dpdk_vhost_user_set_vring_num (u32 hw_if_index, u8 idx, u32 num)
{
  dpdk_device_t *xd;
  struct vhost_virtqueue *vq;

  DBG_SOCK ("idx %u num %u", idx, num);

  if (!(xd = dpdk_vhost_user_device_from_hw_if_index (hw_if_index)))
    {
      clib_warning ("not a vhost-user interface");
      return 0;
    }
  vq = xd->vu_vhost_dev.virtqueue[idx];
  vq->size = num;

  stop_processing_packets (hw_if_index, idx);

  return 0;
}

static clib_error_t *
dpdk_vhost_user_set_vring_addr (u32 hw_if_index, u8 idx, uword desc,
				uword used, uword avail, uword log)
{
  dpdk_device_t *xd;
  struct vhost_virtqueue *vq;

  DBG_SOCK ("idx %u desc 0x%lx used 0x%lx avail 0x%lx log 0x%lx",
	    idx, desc, used, avail, log);

  if (!(xd = dpdk_vhost_user_device_from_hw_if_index (hw_if_index)))
    {
      clib_warning ("not a vhost-user interface");
      return 0;
    }
  vq = xd->vu_vhost_dev.virtqueue[idx];

  vq->desc = (struct vring_desc *) qva_to_vva (&xd->vu_vhost_dev, desc);
  vq->used = (struct vring_used *) qva_to_vva (&xd->vu_vhost_dev, used);
  vq->avail = (struct vring_avail *) qva_to_vva (&xd->vu_vhost_dev, avail);
#if RTE_VERSION >= RTE_VERSION_NUM(16, 4, 0, 0)
  vq->log_guest_addr = log;
#endif

  if (!(vq->desc && vq->used && vq->avail))
    {
      clib_warning ("falied to set vring addr");
    }

  if (vq->last_used_idx != vq->used->idx)
    {
      clib_warning ("last_used_idx (%u) and vq->used->idx (%u) mismatches; "
		    "some packets maybe resent for Tx and dropped for Rx",
		    vq->last_used_idx, vq->used->idx);
      vq->last_used_idx = vq->used->idx;
      vq->last_used_idx_res = vq->used->idx;
    }

  /*
   * Inform the guest that there is no need to inform (kick) the
   * host when it adds buffers. kick results in vmexit and will
   * incur performance degradation.
   *
   * The below function sets a flag in used table. Therefore,
   * should be initialized after initializing vq->used.
   */
  rte_vhost_enable_guest_notification (&xd->vu_vhost_dev, idx, 0);
  stop_processing_packets (hw_if_index, idx);

  return 0;
}

static clib_error_t *
dpdk_vhost_user_get_vring_base (u32 hw_if_index, u8 idx, u32 * num)
{
  dpdk_device_t *xd;
  struct vhost_virtqueue *vq;

  if (!(xd = dpdk_vhost_user_device_from_hw_if_index (hw_if_index)))
    {
      clib_warning ("not a vhost-user interface");
      return 0;
    }

  vq = xd->vu_vhost_dev.virtqueue[idx];
  *num = vq->last_used_idx;

/*
 * From spec:
 * Client must start ring upon receiving a kick
 * (that is, detecting that file descriptor is readable)
 * on the descriptor specified by VHOST_USER_SET_VRING_KICK,
 * and stop ring upon receiving VHOST_USER_GET_VRING_BASE.
 */
  DBG_SOCK ("Stopping vring Q %u of device %d", idx, hw_if_index);
  dpdk_vu_intf_t *vui = xd->vu_intf;

  /* if there is old fd, delete it */
  if (vui->vrings[idx].callfd > 0)
    {
      unix_file_t *uf = pool_elt_at_index (unix_main.file_pool,
					   vui->vrings[idx].callfd_idx);
      unix_file_del (&unix_main, uf);
    }

  vui->vrings[idx].enabled = 0;	/* Reset local copy */
  vui->vrings[idx].callfd = -1;	/* Reset FD */
  vq->enabled = 0;
  vq->desc = NULL;
  vq->used = NULL;
  vq->avail = NULL;
#if RTE_VERSION >= RTE_VERSION_NUM(16, 4, 0, 0)
  vq->log_guest_addr = 0;
#endif

  /* Check if all Qs are disabled */
  int numqs = xd->vu_vhost_dev.virt_qp_nb * VIRTIO_QNUM;
  for (idx = 0; idx < numqs; idx++)
    {
      if (xd->vu_vhost_dev.virtqueue[idx]->enabled)
	break;
    }

  /* If all vrings are disabed then disable device */
  if (idx == numqs)
    {
      DBG_SOCK ("Device %d disabled", hw_if_index);
      xd->vu_is_running = 0;
    }

  return 0;
}

static clib_error_t *
dpdk_vhost_user_set_vring_base (u32 hw_if_index, u8 idx, u32 num)
{
  dpdk_device_t *xd;
  struct vhost_virtqueue *vq;

  DBG_SOCK ("idx %u num %u", idx, num);

  if (!(xd = dpdk_vhost_user_device_from_hw_if_index (hw_if_index)))
    {
      clib_warning ("not a vhost-user interface");
      return 0;
    }

  vq = xd->vu_vhost_dev.virtqueue[idx];
  vq->last_used_idx = num;
  vq->last_used_idx_res = num;

  stop_processing_packets (hw_if_index, idx);

  return 0;
}

static clib_error_t *
dpdk_vhost_user_set_vring_kick (u32 hw_if_index, u8 idx, int fd)
{
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;
  dpdk_vu_vring *vring;
  struct vhost_virtqueue *vq0, *vq1, *vq;
  int index, vu_is_running = 0;

  if (!(xd = dpdk_vhost_user_device_from_hw_if_index (hw_if_index)))
    {
      clib_warning ("not a vhost-user interface");
      return 0;
    }

  vq = xd->vu_vhost_dev.virtqueue[idx];
  vq->kickfd = fd;

  vring = &xd->vu_intf->vrings[idx];
  vq->enabled = (vq->desc && vq->avail && vq->used && vring->enabled) ? 1 : 0;

  /*
   * Set xd->vu_is_running if at least one pair of
   * RX/TX queues are enabled.
   */
  int numqs = VIRTIO_QNUM;
  numqs = xd->vu_vhost_dev.virt_qp_nb * VIRTIO_QNUM;

  for (index = 0; index < numqs; index += 2)
    {
      vq0 = xd->vu_vhost_dev.virtqueue[index];	/* RX */
      vq1 = xd->vu_vhost_dev.virtqueue[index + 1];	/* TX */
      if (vq0->enabled && vq1->enabled)
	{
	  vu_is_running = 1;
	  break;
	}
    }
  DBG_SOCK ("SET_VRING_KICK - idx %d, running %d, fd: %d",
	    idx, vu_is_running, fd);

  xd->vu_is_running = vu_is_running;
  if (xd->vu_is_running && xd->admin_up)
    {
      vnet_hw_interface_set_flags (dm->vnet_main,
				   xd->vlib_hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP |
				   ETH_LINK_FULL_DUPLEX);
    }

  return 0;
}

static int
dpdk_vhost_user_set_vring_enable (u32 hw_if_index, u8 idx, int enable)
{
  dpdk_device_t *xd;
  struct vhost_virtqueue *vq;
  dpdk_vu_intf_t *vui;

  if (!(xd = dpdk_vhost_user_device_from_hw_if_index (hw_if_index)))
    {
      clib_warning ("not a vhost-user interface");
      return 0;
    }

  vui = xd->vu_intf;
  /*
   * Guest vhost driver wrongly enables queue before
   * setting the vring address. Therefore, save a
   * local copy. Reflect it in vq structure if addresses
   * are set. If not, vq will be enabled when vring
   * is kicked.
   */
  vui->vrings[idx].enabled = enable;	/* Save local copy */

  int numqs = xd->vu_vhost_dev.virt_qp_nb * VIRTIO_QNUM;
  while (numqs--)
    {
      if (!vui->vrings[numqs].enabled)
	break;
    }

  if (numqs == -1)		/* All Qs are enabled */
    xd->need_txlock = 0;
  else
    xd->need_txlock = 1;

  vq = xd->vu_vhost_dev.virtqueue[idx];
  if (vq->desc && vq->avail && vq->used)
    xd->vu_vhost_dev.virtqueue[idx]->enabled = enable;

  return 0;
}

static clib_error_t *
dpdk_vhost_user_callfd_read_ready (unix_file_t * uf)
{
  __attribute__ ((unused)) int n;
  u8 buff[8];
  n = read (uf->file_descriptor, ((char *) &buff), 8);
  return 0;
}

static clib_error_t *
dpdk_vhost_user_set_vring_call (u32 hw_if_index, u8 idx, int fd)
{
  dpdk_device_t *xd;
  struct vhost_virtqueue *vq;
  unix_file_t template = { 0 };

  DBG_SOCK ("SET_VRING_CALL - idx %d, fd %d", idx, fd);

  if (!(xd = dpdk_vhost_user_device_from_hw_if_index (hw_if_index)))
    {
      clib_warning ("not a vhost-user interface");
      return 0;
    }

  dpdk_vu_intf_t *vui = xd->vu_intf;

  /* if there is old fd, delete it */
  if (vui->vrings[idx].callfd > -1)
    {
      unix_file_t *uf = pool_elt_at_index (unix_main.file_pool,
					   vui->vrings[idx].callfd_idx);
      unix_file_del (&unix_main, uf);
    }
  vui->vrings[idx].callfd = fd;
  template.read_function = dpdk_vhost_user_callfd_read_ready;
  template.file_descriptor = fd;
  vui->vrings[idx].callfd_idx = unix_file_add (&unix_main, &template);

  vq = xd->vu_vhost_dev.virtqueue[idx];
  vq->callfd = -1;		/* We use locally saved vring->callfd; */

  return 0;
}

u8
dpdk_vhost_user_want_interrupt (dpdk_device_t * xd, int idx)
{
  dpdk_vu_intf_t *vui = xd->vu_intf;
  ASSERT (vui != NULL);

  if (PREDICT_FALSE (vui->num_vrings <= 0))
    return 0;

  dpdk_vu_vring *vring = &(vui->vrings[idx]);
  struct vhost_virtqueue *vq = xd->vu_vhost_dev.virtqueue[idx];

  /* return if vm is interested in interrupts */
  return (vring->callfd > -1)
    && !(vq->avail->flags & VRING_AVAIL_F_NO_INTERRUPT);
}

void
dpdk_vhost_user_send_interrupt (vlib_main_t * vm, dpdk_device_t * xd, int idx)
{
  dpdk_main_t *dm = &dpdk_main;
  dpdk_vu_intf_t *vui = xd->vu_intf;
  ASSERT (vui != NULL);

  if (PREDICT_FALSE (vui->num_vrings <= 0))
    return;

  dpdk_vu_vring *vring = &(vui->vrings[idx]);
  struct vhost_virtqueue *vq = xd->vu_vhost_dev.virtqueue[idx];

  /* if vm is interested in interrupts */
  if ((vring->callfd > -1)
      && !(vq->avail->flags & VRING_AVAIL_F_NO_INTERRUPT))
    {
      eventfd_write (vring->callfd, (eventfd_t) 1);
      vring->n_since_last_int = 0;
      vring->int_deadline =
	vlib_time_now (vm) + dm->conf->vhost_coalesce_time;
    }
}

/*
 * vhost-user interface management functions
 */

// initialize vui with specified attributes
static void
dpdk_vhost_user_vui_init (vnet_main_t * vnm,
			  dpdk_device_t * xd, int sockfd,
			  const char *sock_filename,
			  u8 is_server, u64 feature_mask, u32 * sw_if_index)
{
  int q;
  dpdk_vu_intf_t *vui = xd->vu_intf;
  memset (vui, 0, sizeof (*vui));

  vui->unix_fd = sockfd;
  vui->num_vrings = xd->vu_vhost_dev.virt_qp_nb * VIRTIO_QNUM;
  DBG_SOCK ("dpdk_vhost_user_vui_init VRINGS: %d", vui->num_vrings);
  vui->sock_is_server = is_server;
  strncpy (vui->sock_filename, sock_filename,
	   ARRAY_LEN (vui->sock_filename) - 1);
  vui->sock_errno = 0;
  vui->is_up = 0;
  vui->feature_mask = feature_mask;
  vui->active = 1;
  vui->unix_file_index = ~0;

  for (q = 0; q < vui->num_vrings; q++)
    {
      vui->vrings[q].enabled = 0;
      vui->vrings[q].callfd = -1;
      vui->vrings[q].kickfd = -1;
    }

  vnet_hw_interface_set_flags (vnm, xd->vlib_hw_if_index, 0);

  if (sw_if_index)
    *sw_if_index = xd->vlib_sw_if_index;
}

// register vui and start polling on it
static void
dpdk_vhost_user_vui_register (vlib_main_t * vm, dpdk_device_t * xd)
{
  dpdk_main_t *dm = &dpdk_main;
  dpdk_vu_intf_t *vui = xd->vu_intf;

  hash_set (dm->vu_sw_if_index_by_listener_fd, vui->unix_fd,
	    xd->vlib_sw_if_index);
}

static void
dpdk_unmap_all_mem_regions (dpdk_device_t * xd)
{
  int i, r;
  dpdk_vu_intf_t *vui = xd->vu_intf;
  struct virtio_memory *mem = xd->vu_vhost_dev.mem;

  for (i = 0; i < mem->nregions; i++)
    {
      if (vui->region_addr[i] != -1)
	{

	  long page_sz = get_huge_page_size (vui->region_fd[i]);

	  ssize_t map_sz = RTE_ALIGN_CEIL (mem->regions[i].memory_size +
					   vui->region_offset[i], page_sz);

	  r =
	    munmap ((void *) (vui->region_addr[i] - vui->region_offset[i]),
		    map_sz);

	  DBG_SOCK
	    ("unmap memory region %d addr 0x%lx off 0x%lx len 0x%lx page_sz 0x%x",
	     i, vui->region_addr[i], vui->region_offset[i], map_sz, page_sz);

	  vui->region_addr[i] = -1;

	  if (r == -1)
	    {
	      clib_unix_warning ("failed to unmap memory region");
	    }
	  close (vui->region_fd[i]);
	}
    }
  mem->nregions = 0;
}

static inline void
dpdk_vhost_user_if_disconnect (dpdk_device_t * xd)
{
  dpdk_vu_intf_t *vui = xd->vu_intf;
  vnet_main_t *vnm = vnet_get_main ();
  dpdk_main_t *dm = &dpdk_main;
  struct vhost_virtqueue *vq;
  int q;

  xd->admin_up = 0;
  vnet_hw_interface_set_flags (vnm, xd->vlib_hw_if_index, 0);

  if (vui->unix_file_index != ~0)
    {
      unix_file_del (&unix_main, unix_main.file_pool + vui->unix_file_index);
      vui->unix_file_index = ~0;
    }

  hash_unset (dm->vu_sw_if_index_by_sock_fd, vui->unix_fd);
  hash_unset (dm->vu_sw_if_index_by_listener_fd, vui->unix_fd);
  close (vui->unix_fd);
  vui->unix_fd = -1;
  vui->is_up = 0;

  for (q = 0; q < vui->num_vrings; q++)
    {
      vq = xd->vu_vhost_dev.virtqueue[q];
      if (vui->vrings[q].callfd > -1)
	{
	  unix_file_t *uf = pool_elt_at_index (unix_main.file_pool,
					       vui->vrings[q].callfd_idx);
	  unix_file_del (&unix_main, uf);
	}

      if (vui->vrings[q].kickfd > -1)
	{
	  close (vui->vrings[q].kickfd);
	  vui->vrings[q].kickfd = -1;
	}

      vui->vrings[q].enabled = 0;	/* Reset local copy */
      vui->vrings[q].callfd = -1;	/* Reset FD */
      vq->enabled = 0;
#if RTE_VERSION >= RTE_VERSION_NUM(16, 4, 0, 0)
      vq->log_guest_addr = 0;
#endif
      vq->desc = NULL;
      vq->used = NULL;
      vq->avail = NULL;
    }
  xd->vu_is_running = 0;

  dpdk_unmap_all_mem_regions (xd);
  DBG_SOCK ("interface ifindex %d disconnected", xd->vlib_sw_if_index);
}

static clib_error_t *
dpdk_vhost_user_socket_read (unix_file_t * uf)
{
  int n;
  int fd, number_of_fds = 0;
  int fds[VHOST_MEMORY_MAX_NREGIONS];
  vhost_user_msg_t msg;
  struct msghdr mh;
  struct iovec iov[1];
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;
  dpdk_vu_intf_t *vui;
  struct cmsghdr *cmsg;
  uword *p;
  u8 q;
  vnet_main_t *vnm = vnet_get_main ();

  p = hash_get (dm->vu_sw_if_index_by_sock_fd, uf->file_descriptor);
  if (p == 0)
    {
      DBG_SOCK ("FD %d doesn't belong to any interface", uf->file_descriptor);
      return 0;
    }
  else
    xd = dpdk_vhost_user_device_from_sw_if_index (p[0]);

  ASSERT (xd != NULL);
  vui = xd->vu_intf;

  char control[CMSG_SPACE (VHOST_MEMORY_MAX_NREGIONS * sizeof (int))];

  memset (&mh, 0, sizeof (mh));
  memset (control, 0, sizeof (control));

  /* set the payload */
  iov[0].iov_base = (void *) &msg;
  iov[0].iov_len = VHOST_USER_MSG_HDR_SZ;

  mh.msg_iov = iov;
  mh.msg_iovlen = 1;
  mh.msg_control = control;
  mh.msg_controllen = sizeof (control);

  n = recvmsg (uf->file_descriptor, &mh, 0);

  if (n != VHOST_USER_MSG_HDR_SZ)
    goto close_socket;

  if (mh.msg_flags & MSG_CTRUNC)
    {
      goto close_socket;
    }

  cmsg = CMSG_FIRSTHDR (&mh);

  if (cmsg && (cmsg->cmsg_len > 0) && (cmsg->cmsg_level == SOL_SOCKET) &&
      (cmsg->cmsg_type == SCM_RIGHTS) &&
      (cmsg->cmsg_len - CMSG_LEN (0) <=
       VHOST_MEMORY_MAX_NREGIONS * sizeof (int)))
    {
      number_of_fds = (cmsg->cmsg_len - CMSG_LEN (0)) / sizeof (int);
      clib_memcpy (fds, CMSG_DATA (cmsg), number_of_fds * sizeof (int));
    }

  /* version 1, no reply bit set */
  if ((msg.flags & 7) != 1)
    {
      DBG_SOCK ("malformed message received. closing socket");
      goto close_socket;
    }

  {
    int rv __attribute__ ((unused));
    /* $$$$ pay attention to rv */
    rv = read (uf->file_descriptor, ((char *) &msg) + n, msg.size);
  }

  DBG_SOCK ("VPP VHOST message %s", vhost_message_str[msg.request]);
  switch (msg.request)
    {
    case VHOST_USER_GET_FEATURES:
      DBG_SOCK ("if %d msg VHOST_USER_GET_FEATURES", xd->vlib_hw_if_index);

      msg.flags |= VHOST_USER_REPLY_MASK;

      dpdk_vhost_user_get_features (xd->vlib_hw_if_index, &msg.u64);
      msg.u64 &= vui->feature_mask;
      msg.size = sizeof (msg.u64);
      break;

    case VHOST_USER_SET_FEATURES:
      DBG_SOCK ("if %d msg VHOST_USER_SET_FEATURES features 0x%016lx",
		xd->vlib_hw_if_index, msg.u64);

      dpdk_vhost_user_set_features (xd->vlib_hw_if_index, msg.u64);
      break;

    case VHOST_USER_SET_MEM_TABLE:
      DBG_SOCK ("if %d msg VHOST_USER_SET_MEM_TABLE nregions %d",
		xd->vlib_hw_if_index, msg.memory.nregions);

      if ((msg.memory.nregions < 1) ||
	  (msg.memory.nregions > VHOST_MEMORY_MAX_NREGIONS))
	{

	  DBG_SOCK ("number of mem regions must be between 1 and %i",
		    VHOST_MEMORY_MAX_NREGIONS);

	  goto close_socket;
	}

      if (msg.memory.nregions != number_of_fds)
	{
	  DBG_SOCK ("each memory region must have FD");
	  goto close_socket;
	}

      /* Unmap previously configured memory if necessary */
      dpdk_unmap_all_mem_regions (xd);

      dpdk_vhost_user_set_mem_table (xd->vlib_hw_if_index, &msg.memory, fds);
      break;

    case VHOST_USER_SET_VRING_NUM:
      DBG_SOCK ("if %d msg VHOST_USER_SET_VRING_NUM idx %d num %d",
		xd->vlib_hw_if_index, msg.state.index, msg.state.num);

      if ((msg.state.num > 32768) ||	/* maximum ring size is 32768 */
	  (msg.state.num == 0) ||	/* it cannot be zero */
	  (msg.state.num % 2))	/* must be power of 2 */
	goto close_socket;

      dpdk_vhost_user_set_vring_num (xd->vlib_hw_if_index, msg.state.index,
				     msg.state.num);
      break;

    case VHOST_USER_SET_VRING_ADDR:
      DBG_SOCK ("if %d msg VHOST_USER_SET_VRING_ADDR idx %d",
		xd->vlib_hw_if_index, msg.state.index);

      dpdk_vhost_user_set_vring_addr (xd->vlib_hw_if_index, msg.state.index,
				      msg.addr.desc_user_addr,
				      msg.addr.used_user_addr,
				      msg.addr.avail_user_addr,
				      msg.addr.log_guest_addr);
      break;

    case VHOST_USER_SET_OWNER:
      DBG_SOCK ("if %d msg VHOST_USER_SET_OWNER", xd->vlib_hw_if_index);
      break;

    case VHOST_USER_RESET_OWNER:
      DBG_SOCK ("if %d msg VHOST_USER_RESET_OWNER", xd->vlib_hw_if_index);
      break;

    case VHOST_USER_SET_VRING_CALL:
      q = (u8) (msg.u64 & 0xFF);

      DBG_SOCK ("if %d msg VHOST_USER_SET_VRING_CALL u64 %lx, idx: %d",
		xd->vlib_hw_if_index, msg.u64, q);

      if (!(msg.u64 & 0x100))
	{
	  if (number_of_fds != 1)
	    goto close_socket;
	  fd = fds[0];
	}
      else
	{
	  fd = -1;
	}
      dpdk_vhost_user_set_vring_call (xd->vlib_hw_if_index, q, fd);

      break;

    case VHOST_USER_SET_VRING_KICK:

      q = (u8) (msg.u64 & 0xFF);

      DBG_SOCK ("if %d msg VHOST_USER_SET_VRING_KICK u64 %lx, idx: %d",
		xd->vlib_hw_if_index, msg.u64, q);

      if (!(msg.u64 & 0x100))
	{
	  if (number_of_fds != 1)
	    goto close_socket;

	  if (vui->vrings[q].kickfd > -1)
	    close (vui->vrings[q].kickfd);

	  vui->vrings[q].kickfd = fds[0];
	}
      else
	vui->vrings[q].kickfd = -1;

      dpdk_vhost_user_set_vring_kick (xd->vlib_hw_if_index, q,
				      vui->vrings[q].kickfd);
      break;

    case VHOST_USER_SET_VRING_ERR:

      q = (u8) (msg.u64 & 0xFF);

      DBG_SOCK ("if %d msg VHOST_USER_SET_VRING_ERR u64 %lx, idx: %d",
		xd->vlib_hw_if_index, msg.u64, q);

      if (!(msg.u64 & 0x100))
	{
	  if (number_of_fds != 1)
	    goto close_socket;

	  fd = fds[0];
	}
      else
	fd = -1;

      vui->vrings[q].errfd = fd;
      break;

    case VHOST_USER_SET_VRING_BASE:
      DBG_SOCK ("if %d msg VHOST_USER_SET_VRING_BASE idx %d num %d",
		xd->vlib_hw_if_index, msg.state.index, msg.state.num);

      dpdk_vhost_user_set_vring_base (xd->vlib_hw_if_index, msg.state.index,
				      msg.state.num);
      break;

    case VHOST_USER_GET_VRING_BASE:
      DBG_SOCK ("if %d msg VHOST_USER_GET_VRING_BASE idx %d num %d",
		xd->vlib_hw_if_index, msg.state.index, msg.state.num);

      msg.flags |= VHOST_USER_REPLY_MASK;
      msg.size = sizeof (msg.state);

      dpdk_vhost_user_get_vring_base (xd->vlib_hw_if_index, msg.state.index,
				      &msg.state.num);
      break;

    case VHOST_USER_NONE:
      DBG_SOCK ("if %d msg VHOST_USER_NONE", xd->vlib_hw_if_index);
      break;

    case VHOST_USER_SET_LOG_BASE:
#if RTE_VERSION >= RTE_VERSION_NUM(16, 4, 0, 0)
      DBG_SOCK ("if %d msg VHOST_USER_SET_LOG_BASE", xd->vlib_hw_if_index);

      if (msg.size != sizeof (msg.log))
	{
	  DBG_SOCK
	    ("invalid msg size for VHOST_USER_SET_LOG_BASE: %u instead of %lu",
	     msg.size, sizeof (msg.log));
	  goto close_socket;
	}

      if (!
	  (xd->vu_vhost_dev.protocol_features & (1 <<
						 VHOST_USER_PROTOCOL_F_LOG_SHMFD)))
	{
	  DBG_SOCK
	    ("VHOST_USER_PROTOCOL_F_LOG_SHMFD not set but VHOST_USER_SET_LOG_BASE received");
	  goto close_socket;
	}

      fd = fds[0];
      /* align size to 2M page */
      long page_sz = get_huge_page_size (fd);
      ssize_t map_sz =
	RTE_ALIGN_CEIL (msg.log.size + msg.log.offset, page_sz);

      void *addr = mmap (0, map_sz, PROT_READ | PROT_WRITE,
			 MAP_SHARED, fd, 0);

      DBG_SOCK ("map log region addr 0 len 0x%lx off 0x%lx fd %d mapped %p",
		map_sz, msg.log.offset, fd, addr);

      if (addr == MAP_FAILED)
	{
	  clib_warning ("failed to map memory. errno is %d", errno);
	  goto close_socket;
	}

      xd->vu_vhost_dev.log_base += pointer_to_uword (addr) + msg.log.offset;
      xd->vu_vhost_dev.log_size = msg.log.size;
      msg.flags |= VHOST_USER_REPLY_MASK;
      msg.size = sizeof (msg.u64);
#else
      DBG_SOCK ("if %d msg VHOST_USER_SET_LOG_BASE Not-Implemented",
		xd->vlib_hw_if_index);
#endif
      break;

    case VHOST_USER_SET_LOG_FD:
      DBG_SOCK ("if %d msg VHOST_USER_SET_LOG_FD", xd->vlib_hw_if_index);
      break;

    case VHOST_USER_GET_PROTOCOL_FEATURES:
      DBG_SOCK ("if %d msg VHOST_USER_GET_PROTOCOL_FEATURES",
		xd->vlib_hw_if_index);

      msg.flags |= VHOST_USER_REPLY_MASK;
      msg.u64 = VHOST_USER_PROTOCOL_FEATURES;
      DBG_SOCK ("VHOST_USER_PROTOCOL_FEATURES: %llx",
		VHOST_USER_PROTOCOL_FEATURES);
      msg.size = sizeof (msg.u64);
      break;

    case VHOST_USER_SET_PROTOCOL_FEATURES:
      DBG_SOCK ("if %d msg VHOST_USER_SET_PROTOCOL_FEATURES",
		xd->vlib_hw_if_index);

      DBG_SOCK ("VHOST_USER_SET_PROTOCOL_FEATURES: 0x%lx", msg.u64);
      dpdk_vhost_user_set_protocol_features (xd->vlib_hw_if_index, msg.u64);
      break;

    case VHOST_USER_SET_VRING_ENABLE:
      DBG_SOCK ("%d VPP VHOST_USER_SET_VRING_ENABLE IDX: %d, Enable: %d",
		xd->vlib_hw_if_index, msg.state.index, msg.state.num);
      dpdk_vhost_user_set_vring_enable
	(xd->vlib_hw_if_index, msg.state.index, msg.state.num);
      break;

    case VHOST_USER_GET_QUEUE_NUM:
      DBG_SOCK ("if %d msg VHOST_USER_GET_QUEUE_NUM:", xd->vlib_hw_if_index);

      msg.flags |= VHOST_USER_REPLY_MASK;
      msg.u64 = xd->vu_vhost_dev.virt_qp_nb;
      msg.size = sizeof (msg.u64);
      break;

    default:
      DBG_SOCK ("unknown vhost-user message %d received. closing socket",
		msg.request);
      goto close_socket;
    }

  /* if we have pointers to descriptor table, go up */
  if (!vui->is_up &&
      xd->vu_vhost_dev.virtqueue[VHOST_NET_VRING_IDX_TX]->desc &&
      xd->vu_vhost_dev.virtqueue[VHOST_NET_VRING_IDX_RX]->desc)
    {

      DBG_SOCK ("interface %d connected", xd->vlib_sw_if_index);

      vnet_hw_interface_set_flags (vnm, xd->vlib_hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      vui->is_up = 1;
      xd->admin_up = 1;
    }

  /* if we need to reply */
  if (msg.flags & VHOST_USER_REPLY_MASK)
    {
      n =
	send (uf->file_descriptor, &msg, VHOST_USER_MSG_HDR_SZ + msg.size, 0);
      if (n != (msg.size + VHOST_USER_MSG_HDR_SZ))
	goto close_socket;
    }

  return 0;

close_socket:
  DBG_SOCK ("error: close_socket");
  dpdk_vhost_user_if_disconnect (xd);
  return 0;
}

static clib_error_t *
dpdk_vhost_user_socket_error (unix_file_t * uf)
{
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;
  uword *p;

  p = hash_get (dm->vu_sw_if_index_by_sock_fd, uf->file_descriptor);
  if (p == 0)
    {
      DBG_SOCK ("FD %d doesn't belong to any interface", uf->file_descriptor);
      return 0;
    }
  else
    xd = dpdk_vhost_user_device_from_sw_if_index (p[0]);

  dpdk_vhost_user_if_disconnect (xd);
  return 0;
}

static clib_error_t *
dpdk_vhost_user_socksvr_accept_ready (unix_file_t * uf)
{
  int client_fd, client_len;
  struct sockaddr_un client;
  unix_file_t template = { 0 };
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = NULL;
  dpdk_vu_intf_t *vui;
  uword *p;

  p = hash_get (dm->vu_sw_if_index_by_listener_fd, uf->file_descriptor);
  if (p == 0)
    {
      DBG_SOCK ("fd %d doesn't belong to any interface", uf->file_descriptor);
      return 0;
    }

  xd = dpdk_vhost_user_device_from_sw_if_index (p[0]);
  ASSERT (xd != NULL);
  vui = xd->vu_intf;

  client_len = sizeof (client);
  client_fd = accept (uf->file_descriptor,
		      (struct sockaddr *) &client,
		      (socklen_t *) & client_len);

  if (client_fd < 0)
    return clib_error_return_unix (0, "accept");

  template.read_function = dpdk_vhost_user_socket_read;
  template.error_function = dpdk_vhost_user_socket_error;
  template.file_descriptor = client_fd;
  vui->unix_file_index = unix_file_add (&unix_main, &template);

  vui->client_fd = client_fd;
  hash_set (dm->vu_sw_if_index_by_sock_fd, vui->client_fd,
	    xd->vlib_sw_if_index);

  return 0;
}

// init server socket on specified sock_filename
static int
dpdk_vhost_user_init_server_sock (const char *sock_filename, int *sockfd)
{
  int rv = 0;
  struct sockaddr_un un = { };
  int fd;
  /* create listening socket */
  fd = socket (AF_UNIX, SOCK_STREAM, 0);

  if (fd < 0)
    {
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }

  un.sun_family = AF_UNIX;
  strcpy ((char *) un.sun_path, (char *) sock_filename);

  /* remove if exists */
  unlink ((char *) sock_filename);

  if (bind (fd, (struct sockaddr *) &un, sizeof (un)) == -1)
    {
      rv = VNET_API_ERROR_SYSCALL_ERROR_2;
      goto error;
    }

  if (listen (fd, 1) == -1)
    {
      rv = VNET_API_ERROR_SYSCALL_ERROR_3;
      goto error;
    }

  unix_file_t template = { 0 };
  template.read_function = dpdk_vhost_user_socksvr_accept_ready;
  template.file_descriptor = fd;
  unix_file_add (&unix_main, &template);
  *sockfd = fd;
  return rv;

error:
  close (fd);
  return rv;
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
  int sockfd = -1;
  int rv = 0;

  // using virtio vhost user?
  if (dm->conf->use_virtio_vhost)
    {
      return vhost_user_create_if (vnm, vm, sock_filename, is_server,
				   sw_if_index, feature_mask, renumber,
				   custom_dev_instance, hwaddr);
    }

  if (is_server)
    {
      if ((rv =
	   dpdk_vhost_user_init_server_sock (sock_filename, &sockfd)) != 0)
	{
	  return rv;
	}
    }

  if (renumber)
    {
      // set next vhost-user if id if custom one is higher or equal
      if (custom_dev_instance >= dm->next_vu_if_id)
	dm->next_vu_if_id = custom_dev_instance + 1;

      dpdk_create_vhost_user_if_internal (&hw_if_idx, custom_dev_instance,
					  hwaddr);
    }
  else
    dpdk_create_vhost_user_if_internal (&hw_if_idx, (u32) ~ 0, hwaddr);
  DBG_SOCK ("dpdk vhost-user interface created hw_if_index %d", hw_if_idx);

  xd = dpdk_vhost_user_device_from_hw_if_index (hw_if_idx);
  ASSERT (xd != NULL);

  dpdk_vhost_user_vui_init (vnm, xd, sockfd, sock_filename, is_server,
			    feature_mask, sw_if_index);

  dpdk_vhost_user_vui_register (vm, xd);
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
  dpdk_vu_intf_t *vui = NULL;
  u32 sw_if_idx = ~0;
  int sockfd = -1;
  int rv = 0;

  // using virtio vhost user?
  if (dm->conf->use_virtio_vhost)
    {
      return vhost_user_modify_if (vnm, vm, sock_filename, is_server,
				   sw_if_index, feature_mask, renumber,
				   custom_dev_instance);
    }

  xd = dpdk_vhost_user_device_from_sw_if_index (sw_if_index);

  if (xd == NULL)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vui = xd->vu_intf;

  // interface is inactive
  vui->active = 0;
  // disconnect interface sockets
  dpdk_vhost_user_if_disconnect (xd);

  if (is_server)
    {
      if ((rv =
	   dpdk_vhost_user_init_server_sock (sock_filename, &sockfd)) != 0)
	{
	  return rv;
	}
    }

  dpdk_vhost_user_vui_init (vnm, xd, sockfd, sock_filename, is_server,
			    feature_mask, &sw_if_idx);

  if (renumber)
    {
      vnet_interface_name_renumber (sw_if_idx, custom_dev_instance);
    }

  dpdk_vhost_user_vui_register (vm, xd);

  return rv;
}

int
dpdk_vhost_user_delete_if (vnet_main_t * vnm, vlib_main_t * vm,
			   u32 sw_if_index)
{
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = NULL;
  dpdk_vu_intf_t *vui;
  int rv = 0;

  // using virtio vhost user?
  if (dm->conf->use_virtio_vhost)
    {
      return vhost_user_delete_if (vnm, vm, sw_if_index);
    }

  xd = dpdk_vhost_user_device_from_sw_if_index (sw_if_index);

  if (xd == NULL)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vui = xd->vu_intf;

  // interface is inactive
  vui->active = 0;
  // disconnect interface sockets
  dpdk_vhost_user_if_disconnect (xd);
  // add to inactive interface list
  vec_add1 (dm->vu_inactive_interfaces_device_index, xd->device_index);

  ethernet_delete_interface (vnm, xd->vlib_hw_if_index);
  DBG_SOCK ("deleted (deactivated) vhost-user interface sw_if_index %d",
	    sw_if_index);

  return rv;
}

int
dpdk_vhost_user_dump_ifs (vnet_main_t * vnm, vlib_main_t * vm,
			  vhost_user_intf_details_t ** out_vuids)
{
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
}

/*
 * Processing functions called from dpdk process fn
 */

typedef struct
{
  struct sockaddr_un sun;
  int sockfd;
  unix_file_t template;
  uword *event_data;
} dpdk_vu_process_state;

void
dpdk_vhost_user_process_init (void **ctx)
{
  dpdk_vu_process_state *state =
    clib_mem_alloc (sizeof (dpdk_vu_process_state));
  memset (state, 0, sizeof (*state));
  state->sockfd = socket (AF_UNIX, SOCK_STREAM, 0);
  state->sun.sun_family = AF_UNIX;
  state->template.read_function = dpdk_vhost_user_socket_read;
  state->template.error_function = dpdk_vhost_user_socket_error;
  state->event_data = 0;
  *ctx = state;
}

void
dpdk_vhost_user_process_cleanup (void *ctx)
{
  clib_mem_free (ctx);
}

uword
dpdk_vhost_user_process_if (vlib_main_t * vm, dpdk_device_t * xd, void *ctx)
{
  dpdk_main_t *dm = &dpdk_main;
  dpdk_vu_process_state *state = (dpdk_vu_process_state *) ctx;
  dpdk_vu_intf_t *vui = xd->vu_intf;

  if (vui->sock_is_server || !vui->active)
    return 0;

  if (vui->unix_fd == -1)
    {
      /* try to connect */
      strncpy (state->sun.sun_path, (char *) vui->sock_filename,
	       sizeof (state->sun.sun_path) - 1);

      if (connect
	  (state->sockfd, (struct sockaddr *) &(state->sun),
	   sizeof (struct sockaddr_un)) == 0)
	{
	  vui->sock_errno = 0;
	  vui->unix_fd = state->sockfd;
	  state->template.file_descriptor = state->sockfd;
	  vui->unix_file_index =
	    unix_file_add (&unix_main, &(state->template));
	  hash_set (dm->vu_sw_if_index_by_sock_fd, state->sockfd,
		    xd->vlib_sw_if_index);

	  state->sockfd = socket (AF_UNIX, SOCK_STREAM, 0);
	  if (state->sockfd < 0)
	    return -1;
	}
      else
	{
	  vui->sock_errno = errno;
	}
    }
  else
    {
      /* check if socket is alive */
      int error = 0;
      socklen_t len = sizeof (error);
      int retval =
	getsockopt (vui->unix_fd, SOL_SOCKET, SO_ERROR, &error, &len);

      if (retval)
	dpdk_vhost_user_if_disconnect (xd);
    }
  return 0;
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

static clib_error_t *
show_dpdk_vhost_user_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
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
