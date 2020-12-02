/*
 *------------------------------------------------------------------
 * vhost.c - vhost-user
 *
 * Copyright (c) 2014-2018 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <fcntl.h>		/* for open */
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>		/* for iovec */
#include <netinet/in.h>
#include <sys/vfs.h>

#include <linux/if_arp.h>
#include <linux/if_tun.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <vnet/feature/feature.h>

#include <vnet/devices/virtio/vhost_user.h>
#include <vnet/devices/virtio/vhost_user_inline.h>

/**
 * @file
 * @brief vHost User Device Driver.
 *
 * This file contains the source code for vHost User interface.
 */


vlib_node_registration_t vhost_user_send_interrupt_node;

/* *INDENT-OFF* */
vhost_user_main_t vhost_user_main = {
  .mtu_bytes = 1518,
};

VNET_HW_INTERFACE_CLASS (vhost_interface_class, static) = {
  .name = "vhost-user",
};
/* *INDENT-ON* */

static long
get_huge_page_size (int fd)
{
  struct statfs s;
  fstatfs (fd, &s);
  return s.f_bsize;
}

static void
unmap_all_mem_regions (vhost_user_intf_t * vui)
{
  int i, r, q;
  vhost_user_vring_t *vq;

  for (i = 0; i < vui->nregions; i++)
    {
      if (vui->region_mmap_addr[i] != MAP_FAILED)
	{

	  long page_sz = get_huge_page_size (vui->region_mmap_fd[i]);

	  ssize_t map_sz = (vui->regions[i].memory_size +
			    vui->regions[i].mmap_offset +
			    page_sz - 1) & ~(page_sz - 1);

	  r =
	    munmap (vui->region_mmap_addr[i] - vui->regions[i].mmap_offset,
		    map_sz);

	  vu_log_debug (vui, "unmap memory region %d addr 0x%lx len 0x%lx "
			"page_sz 0x%x", i, vui->region_mmap_addr[i], map_sz,
			page_sz);

	  vui->region_mmap_addr[i] = MAP_FAILED;

	  if (r == -1)
	    {
	      vu_log_err (vui, "failed to unmap memory region (errno %d)",
			  errno);
	    }
	  close (vui->region_mmap_fd[i]);
	}
    }
  vui->nregions = 0;

  for (q = 0; q < VHOST_VRING_MAX_N; q++)
    {
      vq = &vui->vrings[q];
      vq->avail = 0;
      vq->used = 0;
      vq->desc = 0;
    }
}

static_always_inline void
vhost_user_tx_thread_placement (vhost_user_intf_t * vui)
{
  //Let's try to assign one queue to each thread
  u32 qid;
  u32 thread_index = 0;

  vui->use_tx_spinlock = 0;
  while (1)
    {
      for (qid = 0; qid < VHOST_VRING_MAX_N / 2; qid++)
	{
	  vhost_user_vring_t *rxvq = &vui->vrings[VHOST_VRING_IDX_RX (qid)];
	  if (!rxvq->started || !rxvq->enabled)
	    continue;

	  vui->per_cpu_tx_qid[thread_index] = qid;
	  thread_index++;
	  if (thread_index == vlib_get_thread_main ()->n_vlib_mains)
	    return;
	}
      //We need to loop, meaning the spinlock has to be used
      vui->use_tx_spinlock = 1;
      if (thread_index == 0)
	{
	  //Could not find a single valid one
	  for (thread_index = 0;
	       thread_index < vlib_get_thread_main ()->n_vlib_mains;
	       thread_index++)
	    {
	      vui->per_cpu_tx_qid[thread_index] = 0;
	    }
	  return;
	}
    }
}

/**
 * @brief Unassign existing interface/queue to thread mappings and re-assign
 * new interface/queue to thread mappings
 */
static_always_inline void
vhost_user_rx_thread_placement (vhost_user_intf_t * vui, u32 qid)
{
  vhost_user_vring_t *txvq = &vui->vrings[qid];
  vnet_main_t *vnm = vnet_get_main ();
  int rv;
  u32 q = qid >> 1;

  ASSERT ((qid & 1) == 1);	// should be odd
  // Assign new queue mappings for the interface
  vnet_hw_interface_set_input_node (vnm, vui->hw_if_index,
				    vhost_user_input_node.index);
  vnet_hw_interface_assign_rx_thread (vnm, vui->hw_if_index, q, ~0);
  if (txvq->mode == VNET_HW_IF_RX_MODE_UNKNOWN)
    /* Set polling as the default */
    txvq->mode = VNET_HW_IF_RX_MODE_POLLING;
  txvq->qid = q;
  rv = vnet_hw_interface_set_rx_mode (vnm, vui->hw_if_index, q, txvq->mode);
  if (rv)
    vu_log_warn (vui, "unable to set rx mode for interface %d, "
		 "queue %d: rc=%d", vui->hw_if_index, q, rv);
}

/** @brief Returns whether at least one TX and one RX vring are enabled */
static_always_inline int
vhost_user_intf_ready (vhost_user_intf_t * vui)
{
  int i, found[2] = { };	//RX + TX

  for (i = 0; i < VHOST_VRING_MAX_N; i++)
    if (vui->vrings[i].started && vui->vrings[i].enabled)
      found[i & 1] = 1;

  return found[0] && found[1];
}

static_always_inline void
vhost_user_update_iface_state (vhost_user_intf_t * vui)
{
  /* if we have pointers to descriptor table, go up */
  int is_ready = vhost_user_intf_ready (vui);
  if (is_ready != vui->is_ready)
    {
      vu_log_debug (vui, "interface %d %s", vui->sw_if_index,
		    is_ready ? "ready" : "down");
      if (vui->admin_up)
	vnet_hw_interface_set_flags (vnet_get_main (), vui->hw_if_index,
				     is_ready ? VNET_HW_INTERFACE_FLAG_LINK_UP
				     : 0);
      vui->is_ready = is_ready;
    }
}

static void
vhost_user_set_interrupt_pending (vhost_user_intf_t * vui, u32 ifq)
{
  u32 qid;
  vnet_main_t *vnm = vnet_get_main ();

  qid = ifq & 0xff;
  if ((qid & 1) == 0)
    /* Only care about the odd number, or TX, virtqueue */
    return;

  if (vhost_user_intf_ready (vui))
    // qid >> 1 is to convert virtqueue number to vring queue index
    vnet_device_input_set_interrupt_pending (vnm, vui->hw_if_index, qid >> 1);
}

static clib_error_t *
vhost_user_callfd_read_ready (clib_file_t * uf)
{
  __attribute__ ((unused)) int n;
  u8 buff[8];

  n = read (uf->file_descriptor, ((char *) &buff), 8);

  return 0;
}

static_always_inline void
vhost_user_thread_placement (vhost_user_intf_t * vui, u32 qid)
{
  if (qid & 1)			// RX is odd, TX is even
    {
      if (vui->vrings[qid].qid == -1)
	vhost_user_rx_thread_placement (vui, qid);
    }
  else
    vhost_user_tx_thread_placement (vui);
}

static clib_error_t *
vhost_user_kickfd_read_ready (clib_file_t * uf)
{
  __attribute__ ((unused)) int n;
  u8 buff[8];
  vhost_user_intf_t *vui =
    pool_elt_at_index (vhost_user_main.vhost_user_interfaces,
		       uf->private_data >> 8);
  u32 qid = uf->private_data & 0xff;

  n = read (uf->file_descriptor, ((char *) &buff), 8);
  vu_log_debug (vui, "if %d KICK queue %d", uf->private_data >> 8, qid);
  if (!vui->vrings[qid].started ||
      (vhost_user_intf_ready (vui) != vui->is_ready))
    {
      if (vui->vrings[qid].started == 0)
	{
	  vui->vrings[qid].started = 1;
	  vhost_user_thread_placement (vui, qid);
	  vhost_user_update_iface_state (vui);
	}
    }

  vhost_user_set_interrupt_pending (vui, uf->private_data);
  return 0;
}

static_always_inline void
vhost_user_vring_init (vhost_user_intf_t * vui, u32 qid)
{
  vhost_user_vring_t *vring = &vui->vrings[qid];
  clib_memset (vring, 0, sizeof (*vring));
  vring->kickfd_idx = ~0;
  vring->callfd_idx = ~0;
  vring->errfd = -1;
  vring->qid = -1;

  /*
   * We have a bug with some qemu 2.5, and this may be a fix.
   * Feel like interpretation holy text, but this is from vhost-user.txt.
   * "
   * One queue pair is enabled initially. More queues are enabled
   * dynamically, by sending message VHOST_USER_SET_VRING_ENABLE.
   * "
   * Don't know who's right, but this is what DPDK does.
   */
  if (qid == 0 || qid == 1)
    vring->enabled = 1;
}

static_always_inline void
vhost_user_vring_close (vhost_user_intf_t * vui, u32 qid)
{
  vhost_user_vring_t *vring = &vui->vrings[qid];

  if (vring->kickfd_idx != ~0)
    {
      clib_file_t *uf = pool_elt_at_index (file_main.file_pool,
					   vring->kickfd_idx);
      clib_file_del (&file_main, uf);
      vring->kickfd_idx = ~0;
    }
  if (vring->callfd_idx != ~0)
    {
      clib_file_t *uf = pool_elt_at_index (file_main.file_pool,
					   vring->callfd_idx);
      clib_file_del (&file_main, uf);
      vring->callfd_idx = ~0;
    }
  if (vring->errfd != -1)
    {
      close (vring->errfd);
      vring->errfd = -1;
    }

  // save the qid so that we don't need to unassign and assign_rx_thread
  // when the interface comes back up. They are expensive calls.
  u16 q = vui->vrings[qid].qid;
  vhost_user_vring_init (vui, qid);
  vui->vrings[qid].qid = q;
}

static_always_inline void
vhost_user_if_disconnect (vhost_user_intf_t * vui)
{
  vnet_main_t *vnm = vnet_get_main ();
  int q;

  vnet_hw_interface_set_flags (vnm, vui->hw_if_index, 0);

  if (vui->clib_file_index != ~0)
    {
      clib_file_del (&file_main, file_main.file_pool + vui->clib_file_index);
      vui->clib_file_index = ~0;
    }

  vui->is_ready = 0;

  for (q = 0; q < VHOST_VRING_MAX_N; q++)
    vhost_user_vring_close (vui, q);

  unmap_all_mem_regions (vui);
  vu_log_debug (vui, "interface ifindex %d disconnected", vui->sw_if_index);
}

static clib_error_t *
vhost_user_socket_read (clib_file_t * uf)
{
  int n, i, j;
  int fd, number_of_fds = 0;
  int fds[VHOST_MEMORY_MAX_NREGIONS];
  vhost_user_msg_t msg;
  struct msghdr mh;
  struct iovec iov[1];
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui;
  struct cmsghdr *cmsg;
  u8 q;
  clib_file_t template = { 0 };
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();

  vui = pool_elt_at_index (vum->vhost_user_interfaces, uf->private_data);

  char control[CMSG_SPACE (VHOST_MEMORY_MAX_NREGIONS * sizeof (int))];

  clib_memset (&mh, 0, sizeof (mh));
  clib_memset (control, 0, sizeof (control));

  for (i = 0; i < VHOST_MEMORY_MAX_NREGIONS; i++)
    fds[i] = -1;

  /* set the payload */
  iov[0].iov_base = (void *) &msg;
  iov[0].iov_len = VHOST_USER_MSG_HDR_SZ;

  mh.msg_iov = iov;
  mh.msg_iovlen = 1;
  mh.msg_control = control;
  mh.msg_controllen = sizeof (control);

  n = recvmsg (uf->file_descriptor, &mh, 0);

  if (n != VHOST_USER_MSG_HDR_SZ)
    {
      if (n == -1)
	{
	  vu_log_debug (vui, "recvmsg returned error %d %s", errno,
			strerror (errno));
	}
      else
	{
	  vu_log_debug (vui, "n (%d) != VHOST_USER_MSG_HDR_SZ (%d)",
			n, VHOST_USER_MSG_HDR_SZ);
	}
      goto close_socket;
    }

  if (mh.msg_flags & MSG_CTRUNC)
    {
      vu_log_debug (vui, "MSG_CTRUNC is set");
      goto close_socket;
    }

  cmsg = CMSG_FIRSTHDR (&mh);

  if (cmsg && (cmsg->cmsg_len > 0) && (cmsg->cmsg_level == SOL_SOCKET) &&
      (cmsg->cmsg_type == SCM_RIGHTS) &&
      (cmsg->cmsg_len - CMSG_LEN (0) <=
       VHOST_MEMORY_MAX_NREGIONS * sizeof (int)))
    {
      number_of_fds = (cmsg->cmsg_len - CMSG_LEN (0)) / sizeof (int);
      clib_memcpy_fast (fds, CMSG_DATA (cmsg), number_of_fds * sizeof (int));
    }

  /* version 1, no reply bit set */
  if ((msg.flags & 7) != 1)
    {
      vu_log_debug (vui, "malformed message received. closing socket");
      goto close_socket;
    }

  {
    int rv;
    rv =
      read (uf->file_descriptor, ((char *) &msg) + VHOST_USER_MSG_HDR_SZ,
	    msg.size);
    if (rv < 0)
      {
	vu_log_debug (vui, "read failed %s", strerror (errno));
	goto close_socket;
      }
    else if (rv != msg.size)
      {
	vu_log_debug (vui, "message too short (read %dB should be %dB)", rv,
		      msg.size);
	goto close_socket;
      }
  }

  switch (msg.request)
    {
    case VHOST_USER_GET_FEATURES:
      msg.flags |= 4;
      msg.u64 = VIRTIO_FEATURE (VIRTIO_NET_F_MRG_RXBUF) |
	VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_VQ) |
	VIRTIO_FEATURE (VIRTIO_F_ANY_LAYOUT) |
	VIRTIO_FEATURE (VIRTIO_RING_F_INDIRECT_DESC) |
	VIRTIO_FEATURE (VHOST_F_LOG_ALL) |
	VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_ANNOUNCE) |
	VIRTIO_FEATURE (VIRTIO_NET_F_MQ) |
	VIRTIO_FEATURE (VHOST_USER_F_PROTOCOL_FEATURES) |
	VIRTIO_FEATURE (VIRTIO_F_VERSION_1);
      msg.u64 &= vui->feature_mask;

      if (vui->enable_gso)
	msg.u64 |= FEATURE_VIRTIO_NET_F_HOST_GUEST_TSO_FEATURE_BITS;
      if (vui->enable_packed)
	msg.u64 |= VIRTIO_FEATURE (VIRTIO_F_RING_PACKED);

      msg.size = sizeof (msg.u64);
      vu_log_debug (vui, "if %d msg VHOST_USER_GET_FEATURES - reply "
		    "0x%016llx", vui->hw_if_index, msg.u64);
      n =
	send (uf->file_descriptor, &msg, VHOST_USER_MSG_HDR_SZ + msg.size, 0);
      if (n != (msg.size + VHOST_USER_MSG_HDR_SZ))
	{
	  vu_log_debug (vui, "could not send message response");
	  goto close_socket;
	}
      break;

    case VHOST_USER_SET_FEATURES:
      vu_log_debug (vui, "if %d msg VHOST_USER_SET_FEATURES features "
		    "0x%016llx", vui->hw_if_index, msg.u64);

      vui->features = msg.u64;

      if (vui->features &
	  (VIRTIO_FEATURE (VIRTIO_NET_F_MRG_RXBUF) |
	   VIRTIO_FEATURE (VIRTIO_F_VERSION_1)))
	vui->virtio_net_hdr_sz = 12;
      else
	vui->virtio_net_hdr_sz = 10;

      vui->is_any_layout =
	(vui->features & VIRTIO_FEATURE (VIRTIO_F_ANY_LAYOUT)) ? 1 : 0;

      ASSERT (vui->virtio_net_hdr_sz < VLIB_BUFFER_PRE_DATA_SIZE);
      vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, vui->hw_if_index);
      if (vui->enable_gso &&
	  ((vui->features & FEATURE_VIRTIO_NET_F_HOST_GUEST_TSO_FEATURE_BITS)
	   == FEATURE_VIRTIO_NET_F_HOST_GUEST_TSO_FEATURE_BITS))
	{
	  hw->caps |=
	    (VNET_HW_INTERFACE_CAP_SUPPORTS_TCP_GSO |
	     VNET_HW_INTERFACE_CAP_SUPPORTS_TX_TCP_CKSUM |
	     VNET_HW_INTERFACE_CAP_SUPPORTS_TX_UDP_CKSUM);
	}
      else
	{
	  hw->caps &= ~(VNET_HW_INTERFACE_CAP_SUPPORTS_TCP_GSO |
			VNET_HW_INTERFACE_OFFLOAD_FLAG_SUPPORTS_L4_TX_CKSUM);
	}
      vnet_hw_interface_set_flags (vnm, vui->hw_if_index, 0);
      vui->is_ready = 0;
      vhost_user_update_iface_state (vui);
      break;

    case VHOST_USER_SET_MEM_TABLE:
      vu_log_debug (vui, "if %d msg VHOST_USER_SET_MEM_TABLE nregions %d",
		    vui->hw_if_index, msg.memory.nregions);

      if ((msg.memory.nregions < 1) ||
	  (msg.memory.nregions > VHOST_MEMORY_MAX_NREGIONS))
	{
	  vu_log_debug (vui, "number of mem regions must be between 1 and %i",
			VHOST_MEMORY_MAX_NREGIONS);
	  goto close_socket;
	}

      if (msg.memory.nregions != number_of_fds)
	{
	  vu_log_debug (vui, "each memory region must have FD");
	  goto close_socket;
	}

      /* Do the mmap without barrier sync */
      void *region_mmap_addr[VHOST_MEMORY_MAX_NREGIONS];
      for (i = 0; i < msg.memory.nregions; i++)
	{
	  long page_sz = get_huge_page_size (fds[i]);

	  /* align size to page */
	  ssize_t map_sz = (msg.memory.regions[i].memory_size +
			    msg.memory.regions[i].mmap_offset +
			    page_sz - 1) & ~(page_sz - 1);

	  region_mmap_addr[i] = mmap (0, map_sz, PROT_READ | PROT_WRITE,
				      MAP_SHARED, fds[i], 0);
	  if (region_mmap_addr[i] == MAP_FAILED)
	    {
	      vu_log_err (vui, "failed to map memory. errno is %d", errno);
	      for (j = 0; j < i; j++)
		munmap (region_mmap_addr[j], map_sz);
	      goto close_socket;
	    }
	  vu_log_debug (vui, "map memory region %d addr 0 len 0x%lx fd %d "
			"mapped 0x%lx page_sz 0x%x", i, map_sz, fds[i],
			region_mmap_addr[i], page_sz);
	}

      vlib_worker_thread_barrier_sync (vm);
      unmap_all_mem_regions (vui);
      for (i = 0; i < msg.memory.nregions; i++)
	{
	  clib_memcpy_fast (&(vui->regions[i]), &msg.memory.regions[i],
			    sizeof (vhost_user_memory_region_t));

	  vui->region_mmap_addr[i] = region_mmap_addr[i];
	  vui->region_guest_addr_lo[i] = vui->regions[i].guest_phys_addr;
	  vui->region_guest_addr_hi[i] = vui->regions[i].guest_phys_addr +
	    vui->regions[i].memory_size;

	  vui->region_mmap_addr[i] += vui->regions[i].mmap_offset;
	  vui->region_mmap_fd[i] = fds[i];

	  vui->nregions++;
	}

      /*
       * Re-compute desc, used, and avail descriptor table if vring address
       * is set.
       */
      for (q = 0; q < VHOST_VRING_MAX_N; q++)
	{
	  if (vui->vrings[q].desc_user_addr &&
	      vui->vrings[q].used_user_addr && vui->vrings[q].avail_user_addr)
	    {
	      vui->vrings[q].desc =
		map_user_mem (vui, vui->vrings[q].desc_user_addr);
	      vui->vrings[q].used =
		map_user_mem (vui, vui->vrings[q].used_user_addr);
	      vui->vrings[q].avail =
		map_user_mem (vui, vui->vrings[q].avail_user_addr);
	    }
	}
      vlib_worker_thread_barrier_release (vm);
      break;

    case VHOST_USER_SET_VRING_NUM:
      vu_log_debug (vui, "if %d msg VHOST_USER_SET_VRING_NUM idx %d num %d",
		    vui->hw_if_index, msg.state.index, msg.state.num);

      if ((msg.state.num > 32768) ||	/* maximum ring size is 32768 */
	  (msg.state.num == 0) ||	/* it cannot be zero */
	  ((msg.state.num - 1) & msg.state.num))	/* must be power of 2 */
	goto close_socket;
      vui->vrings[msg.state.index].qsz_mask = msg.state.num - 1;
      break;

    case VHOST_USER_SET_VRING_ADDR:
      vu_log_debug (vui, "if %d msg VHOST_USER_SET_VRING_ADDR idx %d",
		    vui->hw_if_index, msg.state.index);

      if (msg.state.index >= VHOST_VRING_MAX_N)
	{
	  vu_log_debug (vui, "invalid vring index VHOST_USER_SET_VRING_ADDR:"
			" %d >= %d", msg.state.index, VHOST_VRING_MAX_N);
	  goto close_socket;
	}

      if (msg.size < sizeof (msg.addr))
	{
	  vu_log_debug (vui, "vhost message is too short (%d < %d)",
			msg.size, sizeof (msg.addr));
	  goto close_socket;
	}

      vring_desc_t *desc = map_user_mem (vui, msg.addr.desc_user_addr);
      vring_used_t *used = map_user_mem (vui, msg.addr.used_user_addr);
      vring_avail_t *avail = map_user_mem (vui, msg.addr.avail_user_addr);

      if ((desc == NULL) || (used == NULL) || (avail == NULL))
	{
	  vu_log_debug (vui, "failed to map user memory for hw_if_index %d",
			vui->hw_if_index);
	  goto close_socket;
	}

      vui->vrings[msg.state.index].desc_user_addr = msg.addr.desc_user_addr;
      vui->vrings[msg.state.index].used_user_addr = msg.addr.used_user_addr;
      vui->vrings[msg.state.index].avail_user_addr = msg.addr.avail_user_addr;

      vlib_worker_thread_barrier_sync (vm);
      vui->vrings[msg.state.index].desc = desc;
      vui->vrings[msg.state.index].used = used;
      vui->vrings[msg.state.index].avail = avail;

      vui->vrings[msg.state.index].log_guest_addr = msg.addr.log_guest_addr;
      vui->vrings[msg.state.index].log_used =
	(msg.addr.flags & (1 << VHOST_VRING_F_LOG)) ? 1 : 0;

      /* Spec says: If VHOST_USER_F_PROTOCOL_FEATURES has not been negotiated,
         the ring is initialized in an enabled state. */
      if (!(vui->features & VIRTIO_FEATURE (VHOST_USER_F_PROTOCOL_FEATURES)))
	vui->vrings[msg.state.index].enabled = 1;

      vui->vrings[msg.state.index].last_used_idx =
	vui->vrings[msg.state.index].last_avail_idx =
	vui->vrings[msg.state.index].used->idx;

      /* tell driver that we don't want interrupts */
      if (vhost_user_is_packed_ring_supported (vui))
	vui->vrings[msg.state.index].used_event->flags =
	  VRING_EVENT_F_DISABLE;
      else
	vui->vrings[msg.state.index].used->flags = VRING_USED_F_NO_NOTIFY;
      vlib_worker_thread_barrier_release (vm);
      vhost_user_update_iface_state (vui);
      break;

    case VHOST_USER_SET_OWNER:
      vu_log_debug (vui, "if %d msg VHOST_USER_SET_OWNER", vui->hw_if_index);
      break;

    case VHOST_USER_RESET_OWNER:
      vu_log_debug (vui, "if %d msg VHOST_USER_RESET_OWNER",
		    vui->hw_if_index);
      break;

    case VHOST_USER_SET_VRING_CALL:
      vu_log_debug (vui, "if %d msg VHOST_USER_SET_VRING_CALL %d",
		    vui->hw_if_index, msg.u64);

      q = (u8) (msg.u64 & 0xFF);

      /* if there is old fd, delete and close it */
      if (vui->vrings[q].callfd_idx != ~0)
	{
	  clib_file_t *uf = pool_elt_at_index (file_main.file_pool,
					       vui->vrings[q].callfd_idx);
	  clib_file_del (&file_main, uf);
	  vui->vrings[q].callfd_idx = ~0;
	}

      if (!(msg.u64 & VHOST_USER_VRING_NOFD_MASK))
	{
	  if (number_of_fds != 1)
	    {
	      vu_log_debug (vui, "More than one fd received !");
	      goto close_socket;
	    }

	  template.read_function = vhost_user_callfd_read_ready;
	  template.file_descriptor = fds[0];
	  template.private_data =
	    ((vui - vhost_user_main.vhost_user_interfaces) << 8) + q;
	  vui->vrings[q].callfd_idx = clib_file_add (&file_main, &template);
	}
      else
	vui->vrings[q].callfd_idx = ~0;
      break;

    case VHOST_USER_SET_VRING_KICK:
      vu_log_debug (vui, "if %d msg VHOST_USER_SET_VRING_KICK %d",
		    vui->hw_if_index, msg.u64);

      q = (u8) (msg.u64 & 0xFF);

      if (vui->vrings[q].kickfd_idx != ~0)
	{
	  clib_file_t *uf = pool_elt_at_index (file_main.file_pool,
					       vui->vrings[q].kickfd_idx);
	  clib_file_del (&file_main, uf);
	  vui->vrings[q].kickfd_idx = ~0;
	}

      if (!(msg.u64 & VHOST_USER_VRING_NOFD_MASK))
	{
	  if (number_of_fds != 1)
	    {
	      vu_log_debug (vui, "More than one fd received !");
	      goto close_socket;
	    }

	  template.read_function = vhost_user_kickfd_read_ready;
	  template.file_descriptor = fds[0];
	  template.private_data =
	    (((uword) (vui - vhost_user_main.vhost_user_interfaces)) << 8) +
	    q;
	  vui->vrings[q].kickfd_idx = clib_file_add (&file_main, &template);
	}
      else
	{
	  //When no kickfd is set, the queue is initialized as started
	  vui->vrings[q].kickfd_idx = ~0;
	  vui->vrings[q].started = 1;
	  vhost_user_thread_placement (vui, q);
	}
      vhost_user_update_iface_state (vui);
      break;

    case VHOST_USER_SET_VRING_ERR:
      vu_log_debug (vui, "if %d msg VHOST_USER_SET_VRING_ERR %d",
		    vui->hw_if_index, msg.u64);

      q = (u8) (msg.u64 & 0xFF);

      if (vui->vrings[q].errfd != -1)
	close (vui->vrings[q].errfd);

      if (!(msg.u64 & VHOST_USER_VRING_NOFD_MASK))
	{
	  if (number_of_fds != 1)
	    goto close_socket;

	  vui->vrings[q].errfd = fds[0];
	}
      else
	vui->vrings[q].errfd = -1;
      break;

    case VHOST_USER_SET_VRING_BASE:
      vu_log_debug (vui,
		    "if %d msg VHOST_USER_SET_VRING_BASE idx %d num 0x%x",
		    vui->hw_if_index, msg.state.index, msg.state.num);
      vlib_worker_thread_barrier_sync (vm);
      vui->vrings[msg.state.index].last_avail_idx = msg.state.num;
      if (vhost_user_is_packed_ring_supported (vui))
	{
	  /*
	   *  0                   1                   2                   3
	   *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   * |    last avail idx           | |     last used idx           | |
	   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   *                                ^                               ^
	   *                                |                               |
	   *                         avail wrap counter       used wrap counter
	   */
	  /* last avail idx at bit 0-14. */
	  vui->vrings[msg.state.index].last_avail_idx =
	    msg.state.num & 0x7fff;
	  /* avail wrap counter at bit 15 */
	  vui->vrings[msg.state.index].avail_wrap_counter =
	    ! !(msg.state.num & (1 << 15));

	  /*
	   * Although last_used_idx is passed in the upper 16 bits in qemu
	   * implementation, in practice, last_avail_idx and last_used_idx are
	   * usually the same. As a result, DPDK does not bother to pass us
	   * last_used_idx. The spec is not clear on thex coding. I figured it
	   * out by reading the qemu code. So let's just read last_avail_idx
	   * and set last_used_idx equals to last_avail_idx.
	   */
	  vui->vrings[msg.state.index].last_used_idx =
	    vui->vrings[msg.state.index].last_avail_idx;
	  vui->vrings[msg.state.index].used_wrap_counter =
	    vui->vrings[msg.state.index].avail_wrap_counter;

	  if (vui->vrings[msg.state.index].avail_wrap_counter == 1)
	    vui->vrings[msg.state.index].avail_wrap_counter =
	      VRING_DESC_F_AVAIL;
	}
      vlib_worker_thread_barrier_release (vm);
      break;

    case VHOST_USER_GET_VRING_BASE:
      if (msg.state.index >= VHOST_VRING_MAX_N)
	{
	  vu_log_debug (vui, "invalid vring index VHOST_USER_GET_VRING_BASE:"
			" %d >= %d", msg.state.index, VHOST_VRING_MAX_N);
	  goto close_socket;
	}

      /* protection is needed to prevent rx/tx from changing last_avail_idx */
      vlib_worker_thread_barrier_sync (vm);
      /*
       * Copy last_avail_idx from the vring before closing it because
       * closing the vring also initializes the vring last_avail_idx
       */
      msg.state.num = vui->vrings[msg.state.index].last_avail_idx;
      if (vhost_user_is_packed_ring_supported (vui))
	{
	  msg.state.num =
	    (vui->vrings[msg.state.index].last_avail_idx & 0x7fff) |
	    (! !vui->vrings[msg.state.index].avail_wrap_counter << 15);
	  msg.state.num |=
	    ((vui->vrings[msg.state.index].last_used_idx & 0x7fff) |
	     (! !vui->vrings[msg.state.index].used_wrap_counter << 15)) << 16;
	}
      msg.flags |= 4;
      msg.size = sizeof (msg.state);

      /*
       * Spec says: Client must [...] stop ring upon receiving
       * VHOST_USER_GET_VRING_BASE
       */
      vhost_user_vring_close (vui, msg.state.index);
      vlib_worker_thread_barrier_release (vm);
      vu_log_debug (vui,
		    "if %d msg VHOST_USER_GET_VRING_BASE idx %d num 0x%x",
		    vui->hw_if_index, msg.state.index, msg.state.num);
      n =
	send (uf->file_descriptor, &msg, VHOST_USER_MSG_HDR_SZ + msg.size, 0);
      if (n != (msg.size + VHOST_USER_MSG_HDR_SZ))
	{
	  vu_log_debug (vui, "could not send message response");
	  goto close_socket;
	}
      vhost_user_update_iface_state (vui);
      break;

    case VHOST_USER_NONE:
      vu_log_debug (vui, "if %d msg VHOST_USER_NONE", vui->hw_if_index);
      break;

    case VHOST_USER_SET_LOG_BASE:
      vu_log_debug (vui, "if %d msg VHOST_USER_SET_LOG_BASE",
		    vui->hw_if_index);

      if (msg.size != sizeof (msg.log))
	{
	  vu_log_debug (vui, "invalid msg size for VHOST_USER_SET_LOG_BASE:"
			" %d instead of %d", msg.size, sizeof (msg.log));
	  goto close_socket;
	}

      if (!(vui->protocol_features & (1 << VHOST_USER_PROTOCOL_F_LOG_SHMFD)))
	{
	  vu_log_debug (vui, "VHOST_USER_PROTOCOL_F_LOG_SHMFD not set but "
			"VHOST_USER_SET_LOG_BASE received");
	  goto close_socket;
	}

      fd = fds[0];
      /* align size to page */
      long page_sz = get_huge_page_size (fd);
      ssize_t map_sz =
	(msg.log.size + msg.log.offset + page_sz - 1) & ~(page_sz - 1);

      void *log_base_addr = mmap (0, map_sz, PROT_READ | PROT_WRITE,
				  MAP_SHARED, fd, 0);

      vu_log_debug (vui, "map log region addr 0 len 0x%lx off 0x%lx fd %d "
		    "mapped 0x%lx", map_sz, msg.log.offset, fd,
		    log_base_addr);

      if (log_base_addr == MAP_FAILED)
	{
	  vu_log_err (vui, "failed to map memory. errno is %d", errno);
	  goto close_socket;
	}

      vlib_worker_thread_barrier_sync (vm);
      vui->log_base_addr = log_base_addr;
      vui->log_base_addr += msg.log.offset;
      vui->log_size = msg.log.size;
      vlib_worker_thread_barrier_release (vm);

      msg.flags |= 4;
      msg.size = sizeof (msg.u64);
      n =
	send (uf->file_descriptor, &msg, VHOST_USER_MSG_HDR_SZ + msg.size, 0);
      if (n != (msg.size + VHOST_USER_MSG_HDR_SZ))
	{
	  vu_log_debug (vui, "could not send message response");
	  goto close_socket;
	}
      break;

    case VHOST_USER_SET_LOG_FD:
      vu_log_debug (vui, "if %d msg VHOST_USER_SET_LOG_FD", vui->hw_if_index);
      break;

    case VHOST_USER_GET_PROTOCOL_FEATURES:
      msg.flags |= 4;
      msg.u64 = (1 << VHOST_USER_PROTOCOL_F_LOG_SHMFD) |
	(1 << VHOST_USER_PROTOCOL_F_MQ);
      msg.size = sizeof (msg.u64);
      vu_log_debug (vui, "if %d msg VHOST_USER_GET_PROTOCOL_FEATURES - "
		    "reply 0x%016llx", vui->hw_if_index, msg.u64);
      n =
	send (uf->file_descriptor, &msg, VHOST_USER_MSG_HDR_SZ + msg.size, 0);
      if (n != (msg.size + VHOST_USER_MSG_HDR_SZ))
	{
	  vu_log_debug (vui, "could not send message response");
	  goto close_socket;
	}
      break;

    case VHOST_USER_SET_PROTOCOL_FEATURES:
      vu_log_debug (vui, "if %d msg VHOST_USER_SET_PROTOCOL_FEATURES "
		    "features 0x%016llx", vui->hw_if_index, msg.u64);
      vui->protocol_features = msg.u64;
      break;

    case VHOST_USER_GET_QUEUE_NUM:
      msg.flags |= 4;
      msg.u64 = VHOST_VRING_MAX_N;
      msg.size = sizeof (msg.u64);
      vu_log_debug (vui, "if %d msg VHOST_USER_GET_QUEUE_NUM - reply %d",
		    vui->hw_if_index, msg.u64);
      n =
	send (uf->file_descriptor, &msg, VHOST_USER_MSG_HDR_SZ + msg.size, 0);
      if (n != (msg.size + VHOST_USER_MSG_HDR_SZ))
	{
	  vu_log_debug (vui, "could not send message response");
	  goto close_socket;
	}
      break;

    case VHOST_USER_SET_VRING_ENABLE:
      vu_log_debug (vui, "if %d VHOST_USER_SET_VRING_ENABLE: %s queue %d",
		    vui->hw_if_index, msg.state.num ? "enable" : "disable",
		    msg.state.index);
      if (msg.state.index >= VHOST_VRING_MAX_N)
	{
	  vu_log_debug (vui, "invalid vring idx VHOST_USER_SET_VRING_ENABLE:"
			" %d >= %d", msg.state.index, VHOST_VRING_MAX_N);
	  goto close_socket;
	}

      vui->vrings[msg.state.index].enabled = msg.state.num;
      vhost_user_thread_placement (vui, msg.state.index);
      vhost_user_update_iface_state (vui);
      break;

    default:
      vu_log_debug (vui, "unknown vhost-user message %d received. "
		    "closing socket", msg.request);
      goto close_socket;
    }

  return 0;

close_socket:
  vlib_worker_thread_barrier_sync (vm);
  vhost_user_if_disconnect (vui);
  vlib_worker_thread_barrier_release (vm);
  vhost_user_update_iface_state (vui);
  return 0;
}

static clib_error_t *
vhost_user_socket_error (clib_file_t * uf)
{
  vlib_main_t *vm = vlib_get_main ();
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui =
    pool_elt_at_index (vum->vhost_user_interfaces, uf->private_data);

  vu_log_debug (vui, "socket error on if %d", vui->sw_if_index);
  vlib_worker_thread_barrier_sync (vm);
  vhost_user_if_disconnect (vui);
  vlib_worker_thread_barrier_release (vm);
  return 0;
}

static clib_error_t *
vhost_user_socksvr_accept_ready (clib_file_t * uf)
{
  int client_fd, client_len;
  struct sockaddr_un client;
  clib_file_t template = { 0 };
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui;

  vui = pool_elt_at_index (vum->vhost_user_interfaces, uf->private_data);

  client_len = sizeof (client);
  client_fd = accept (uf->file_descriptor,
		      (struct sockaddr *) &client,
		      (socklen_t *) & client_len);

  if (client_fd < 0)
    return clib_error_return_unix (0, "accept");

  if (vui->clib_file_index != ~0)
    {
      vu_log_debug (vui, "Close client socket for vhost interface %d, fd %d",
		    vui->sw_if_index, UNIX_GET_FD (vui->clib_file_index));
      clib_file_del (&file_main, file_main.file_pool + vui->clib_file_index);
    }

  vu_log_debug (vui, "New client socket for vhost interface %d, fd %d",
		vui->sw_if_index, client_fd);
  template.read_function = vhost_user_socket_read;
  template.error_function = vhost_user_socket_error;
  template.file_descriptor = client_fd;
  template.private_data = vui - vhost_user_main.vhost_user_interfaces;
  vui->clib_file_index = clib_file_add (&file_main, &template);
  return 0;
}

static clib_error_t *
vhost_user_init (vlib_main_t * vm)
{
  vhost_user_main_t *vum = &vhost_user_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  vum->log_default = vlib_log_register_class ("vhost-user", 0);

  vum->coalesce_frames = 32;
  vum->coalesce_time = 1e-3;

  vec_validate (vum->cpus, tm->n_vlib_mains - 1);

  vhost_cpu_t *cpu;
  vec_foreach (cpu, vum->cpus)
  {
    /* This is actually not necessary as validate already zeroes it
     * Just keeping the loop here for later because I am lazy. */
    cpu->rx_buffers_len = 0;
  }

  vum->random = random_default_seed ();

  mhash_init_c_string (&vum->if_index_by_sock_name, sizeof (uword));

  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (vhost_user_init) =
{
  .runs_after = VLIB_INITS("ip4_init"),
};
/* *INDENT-ON* */

static uword
vhost_user_send_interrupt_process (vlib_main_t * vm,
				   vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  vhost_user_intf_t *vui;
  f64 timeout = 3153600000.0 /* 100 years */ ;
  uword event_type, *event_data = 0;
  vhost_user_main_t *vum = &vhost_user_main;
  u16 qid;
  f64 now, poll_time_remaining;
  f64 next_timeout;
  u8 stop_timer = 0;

  while (1)
    {
      poll_time_remaining =
	vlib_process_wait_for_event_or_clock (vm, timeout);
      event_type = vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      /*
       * Use the remaining timeout if it is less than coalesce time to avoid
       * resetting the existing timer in the middle of expiration
       */
      timeout = poll_time_remaining;
      if (vlib_process_suspend_time_is_zero (timeout) ||
	  (timeout > vum->coalesce_time))
	timeout = vum->coalesce_time;

      now = vlib_time_now (vm);
      switch (event_type)
	{
	case VHOST_USER_EVENT_STOP_TIMER:
	  stop_timer = 1;
	  break;

	case VHOST_USER_EVENT_START_TIMER:
	  stop_timer = 0;
	  if (!vlib_process_suspend_time_is_zero (poll_time_remaining))
	    break;
	  /* fall through */

	case ~0:
	  /* *INDENT-OFF* */
	  pool_foreach (vui, vum->vhost_user_interfaces, {
	      next_timeout = timeout;
	      for (qid = 0; qid < VHOST_VRING_MAX_N / 2; qid += 2)
		{
		  vhost_user_vring_t *rxvq = &vui->vrings[qid];
		  vhost_user_vring_t *txvq = &vui->vrings[qid + 1];

		  if (txvq->qid == -1)
		    continue;
		  if (txvq->n_since_last_int)
		    {
		      if (now >= txvq->int_deadline)
			vhost_user_send_call (vm, txvq);
		      else
			next_timeout = txvq->int_deadline - now;
		    }

		  if (rxvq->n_since_last_int)
		    {
		      if (now >= rxvq->int_deadline)
			vhost_user_send_call (vm, rxvq);
		      else
			next_timeout = rxvq->int_deadline - now;
		    }

		  if ((next_timeout < timeout) && (next_timeout > 0.0))
		    timeout = next_timeout;
		}
	  });
          /* *INDENT-ON* */
	  break;

	default:
	  clib_warning ("BUG: unhandled event type %d", event_type);
	  break;
	}
      /* No less than 1 millisecond */
      if (timeout < 1e-3)
	timeout = 1e-3;
      if (stop_timer)
	timeout = 3153600000.0;
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (vhost_user_send_interrupt_node) = {
    .function = vhost_user_send_interrupt_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "vhost-user-send-interrupt-process",
};
/* *INDENT-ON* */

static uword
vhost_user_process (vlib_main_t * vm,
		    vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui;
  struct sockaddr_un sun;
  int sockfd;
  clib_file_t template = { 0 };
  f64 timeout = 3153600000.0 /* 100 years */ ;
  uword *event_data = 0;

  sockfd = -1;
  sun.sun_family = AF_UNIX;
  template.read_function = vhost_user_socket_read;
  template.error_function = vhost_user_socket_error;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      timeout = 3.0;

      /* *INDENT-OFF* */
      pool_foreach (vui, vum->vhost_user_interfaces, {

	  if (vui->unix_server_index == ~0) { //Nothing to do for server sockets
	      if (vui->clib_file_index == ~0)
		{
		  if ((sockfd < 0) &&
		      ((sockfd = socket (AF_UNIX, SOCK_STREAM, 0)) < 0))
		    {
		      /*
		       * 1st time error or new error for this interface,
		       * spit out the message and record the error
		       */
		      if (!vui->sock_errno || (vui->sock_errno != errno))
			{
			  clib_unix_warning
			    ("Error: Could not open unix socket for %s",
			     vui->sock_filename);
			  vui->sock_errno = errno;
			}
		      continue;
		    }

		  /* try to connect */
		  strncpy (sun.sun_path, (char *) vui->sock_filename,
			   sizeof (sun.sun_path) - 1);

		  /* Avoid hanging VPP if the other end does not accept */
		  if (fcntl(sockfd, F_SETFL, O_NONBLOCK) < 0)
                      clib_unix_warning ("fcntl");

		  if (connect (sockfd, (struct sockaddr *) &sun,
			       sizeof (struct sockaddr_un)) == 0)
		    {
		      /* Set the socket to blocking as it was before */
                      if (fcntl(sockfd, F_SETFL, 0) < 0)
                        clib_unix_warning ("fcntl2");

		      vui->sock_errno = 0;
		      template.file_descriptor = sockfd;
		      template.private_data =
			  vui - vhost_user_main.vhost_user_interfaces;
		      vui->clib_file_index = clib_file_add (&file_main, &template);

		      /* This sockfd is considered consumed */
		      sockfd = -1;
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
		  int fd = UNIX_GET_FD(vui->clib_file_index);
		  int retval =
		      getsockopt (fd, SOL_SOCKET, SO_ERROR, &error, &len);

		  if (retval)
		    {
		      vu_log_debug (vui, "getsockopt returned %d", retval);
		      vhost_user_if_disconnect (vui);
		    }
		}
	  }
      });
      /* *INDENT-ON* */
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (vhost_user_process_node,static) = {
    .function = vhost_user_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "vhost-user-process",
};
/* *INDENT-ON* */

/**
 * Disables and reset interface structure.
 * It can then be either init again, or removed from used interfaces.
 */
static void
vhost_user_term_if (vhost_user_intf_t * vui)
{
  int q;
  vhost_user_main_t *vum = &vhost_user_main;

  // disconnect interface sockets
  vhost_user_if_disconnect (vui);
  vhost_user_update_gso_interface_count (vui, 0 /* delete */ );
  vhost_user_update_iface_state (vui);

  for (q = 0; q < VHOST_VRING_MAX_N; q++)
    {
      // Remove existing queue mapping for the interface
      if (q & 1)
	{
	  int rv;
	  vnet_main_t *vnm = vnet_get_main ();
	  vhost_user_vring_t *txvq = &vui->vrings[q];

	  if (txvq->qid != -1)
	    {
	      rv = vnet_hw_interface_unassign_rx_thread (vnm,
							 vui->hw_if_index,
							 q >> 1);
	      if (rv)
		vu_log_warn (vui, "unable to unassign interface %d, "
			     "queue %d: rc=%d", vui->hw_if_index, q >> 1, rv);
	    }
	}

      clib_mem_free ((void *) vui->vring_locks[q]);
    }

  if (vui->unix_server_index != ~0)
    {
      //Close server socket
      clib_file_t *uf = pool_elt_at_index (file_main.file_pool,
					   vui->unix_server_index);
      clib_file_del (&file_main, uf);
      vui->unix_server_index = ~0;
      unlink (vui->sock_filename);
    }

  mhash_unset (&vum->if_index_by_sock_name, vui->sock_filename,
	       &vui->if_index);
}

int
vhost_user_delete_if (vnet_main_t * vnm, vlib_main_t * vm, u32 sw_if_index)
{
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui;
  int rv = 0;
  vnet_hw_interface_t *hwif;
  u16 qid;

  if (!
      (hwif =
       vnet_get_sup_hw_interface_api_visible_or_null (vnm, sw_if_index))
      || hwif->dev_class_index != vhost_user_device_class.index)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vui = pool_elt_at_index (vum->vhost_user_interfaces, hwif->dev_instance);

  vu_log_debug (vui, "Deleting vhost-user interface %s (instance %d)",
		hwif->name, hwif->dev_instance);

  for (qid = 1; qid < VHOST_VRING_MAX_N / 2; qid += 2)
    {
      vhost_user_vring_t *txvq = &vui->vrings[qid];

      if (txvq->qid == -1)
	continue;
      if ((vum->ifq_count > 0) &&
	  ((txvq->mode == VNET_HW_IF_RX_MODE_INTERRUPT) ||
	   (txvq->mode == VNET_HW_IF_RX_MODE_ADAPTIVE)))
	{
	  vum->ifq_count--;
	  // Stop the timer if there is no more interrupt interface/queue
	  if ((vum->ifq_count == 0) &&
	      (vum->coalesce_time > 0.0) && (vum->coalesce_frames > 0))
	    {
	      vlib_process_signal_event (vm,
					 vhost_user_send_interrupt_node.index,
					 VHOST_USER_EVENT_STOP_TIMER, 0);
	      break;
	    }
	}
    }

  // Disable and reset interface
  vhost_user_term_if (vui);

  // Reset renumbered iface
  if (hwif->dev_instance <
      vec_len (vum->show_dev_instance_by_real_dev_instance))
    vum->show_dev_instance_by_real_dev_instance[hwif->dev_instance] = ~0;

  // Delete ethernet interface
  ethernet_delete_interface (vnm, vui->hw_if_index);

  // Back to pool
  pool_put (vum->vhost_user_interfaces, vui);

  return rv;
}

static clib_error_t *
vhost_user_exit (vlib_main_t * vm)
{
  vnet_main_t *vnm = vnet_get_main ();
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui;

  vlib_worker_thread_barrier_sync (vlib_get_main ());
  /* *INDENT-OFF* */
  pool_foreach (vui, vum->vhost_user_interfaces, {
      vhost_user_delete_if (vnm, vm, vui->sw_if_index);
  });
  /* *INDENT-ON* */
  vlib_worker_thread_barrier_release (vlib_get_main ());
  return 0;
}

VLIB_MAIN_LOOP_EXIT_FUNCTION (vhost_user_exit);

/**
 * Open server unix socket on specified sock_filename.
 */
static int
vhost_user_init_server_sock (const char *sock_filename, int *sock_fd)
{
  int rv = 0;
  struct sockaddr_un un = { };
  int fd;
  /* create listening socket */
  if ((fd = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
    return VNET_API_ERROR_SYSCALL_ERROR_1;

  un.sun_family = AF_UNIX;
  strncpy ((char *) un.sun_path, (char *) sock_filename,
	   sizeof (un.sun_path) - 1);

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

  *sock_fd = fd;
  return 0;

error:
  close (fd);
  return rv;
}

/**
 * Create ethernet interface for vhost user interface.
 */
static void
vhost_user_create_ethernet (vnet_main_t * vnm, vlib_main_t * vm,
			    vhost_user_intf_t * vui, u8 * hwaddress)
{
  vhost_user_main_t *vum = &vhost_user_main;
  u8 hwaddr[6];
  clib_error_t *error;

  /* create hw and sw interface */
  if (hwaddress)
    {
      clib_memcpy (hwaddr, hwaddress, 6);
    }
  else
    {
      random_u32 (&vum->random);
      clib_memcpy (hwaddr + 2, &vum->random, sizeof (vum->random));
      hwaddr[0] = 2;
      hwaddr[1] = 0xfe;
    }

  error = ethernet_register_interface
    (vnm,
     vhost_user_device_class.index,
     vui - vum->vhost_user_interfaces /* device instance */ ,
     hwaddr /* ethernet address */ ,
     &vui->hw_if_index, 0 /* flag change */ );

  if (error)
    clib_error_report (error);
}

/*
 *  Initialize vui with specified attributes
 */
static void
vhost_user_vui_init (vnet_main_t * vnm,
		     vhost_user_intf_t * vui,
		     int server_sock_fd,
		     const char *sock_filename,
		     u64 feature_mask, u32 * sw_if_index, u8 enable_gso,
		     u8 enable_packed)
{
  vnet_sw_interface_t *sw;
  int q;
  vhost_user_main_t *vum = &vhost_user_main;
  vnet_hw_interface_t *hw;

  hw = vnet_get_hw_interface (vnm, vui->hw_if_index);
  sw = vnet_get_hw_sw_interface (vnm, vui->hw_if_index);
  if (server_sock_fd != -1)
    {
      clib_file_t template = { 0 };
      template.read_function = vhost_user_socksvr_accept_ready;
      template.file_descriptor = server_sock_fd;
      template.private_data = vui - vum->vhost_user_interfaces;	//hw index
      vui->unix_server_index = clib_file_add (&file_main, &template);
    }
  else
    {
      vui->unix_server_index = ~0;
    }

  vui->sw_if_index = sw->sw_if_index;
  strncpy (vui->sock_filename, sock_filename,
	   ARRAY_LEN (vui->sock_filename) - 1);
  vui->sock_errno = 0;
  vui->is_ready = 0;
  vui->feature_mask = feature_mask;
  vui->clib_file_index = ~0;
  vui->log_base_addr = 0;
  vui->if_index = vui - vum->vhost_user_interfaces;
  vui->enable_gso = enable_gso;
  vui->enable_packed = enable_packed;
  /*
   * enable_gso takes precedence over configurable feature mask if there
   * is a clash.
   *   if feature mask disables gso, but enable_gso is configured,
   *     then gso is enable
   *   if feature mask enables gso, but enable_gso is not configured,
   *     then gso is enable
   *
   * if gso is enable via feature mask, it must enable both host and guest
   * gso feature mask, we don't support one sided GSO or partial GSO.
   */
  if ((vui->enable_gso == 0) &&
      ((feature_mask & FEATURE_VIRTIO_NET_F_HOST_GUEST_TSO_FEATURE_BITS) ==
       (FEATURE_VIRTIO_NET_F_HOST_GUEST_TSO_FEATURE_BITS)))
    vui->enable_gso = 1;
  vhost_user_update_gso_interface_count (vui, 1 /* add */ );
  mhash_set_mem (&vum->if_index_by_sock_name, vui->sock_filename,
		 &vui->if_index, 0);

  for (q = 0; q < VHOST_VRING_MAX_N; q++)
    vhost_user_vring_init (vui, q);

  hw->caps |= VNET_HW_INTERFACE_CAP_SUPPORTS_INT_MODE;
  vnet_hw_interface_set_flags (vnm, vui->hw_if_index, 0);

  if (sw_if_index)
    *sw_if_index = vui->sw_if_index;

  for (q = 0; q < VHOST_VRING_MAX_N; q++)
    {
      vui->vring_locks[q] = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
						    CLIB_CACHE_LINE_BYTES);
      clib_memset ((void *) vui->vring_locks[q], 0, CLIB_CACHE_LINE_BYTES);
    }

  vec_validate (vui->per_cpu_tx_qid,
		vlib_get_thread_main ()->n_vlib_mains - 1);
  vhost_user_tx_thread_placement (vui);
}

int
vhost_user_create_if (vnet_main_t * vnm, vlib_main_t * vm,
		      const char *sock_filename,
		      u8 is_server,
		      u32 * sw_if_index,
		      u64 feature_mask,
		      u8 renumber, u32 custom_dev_instance, u8 * hwaddr,
		      u8 enable_gso, u8 enable_packed)
{
  vhost_user_intf_t *vui = NULL;
  u32 sw_if_idx = ~0;
  int rv = 0;
  int server_sock_fd = -1;
  vhost_user_main_t *vum = &vhost_user_main;
  uword *if_index;

  if (sock_filename == NULL || !(strlen (sock_filename) > 0))
    {
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }

  if_index = mhash_get (&vum->if_index_by_sock_name, (void *) sock_filename);
  if (if_index)
    {
      if (sw_if_index)
	{
	  vui = &vum->vhost_user_interfaces[*if_index];
	  *sw_if_index = vui->sw_if_index;
	}
      return VNET_API_ERROR_IF_ALREADY_EXISTS;
    }

  if (is_server)
    {
      if ((rv =
	   vhost_user_init_server_sock (sock_filename, &server_sock_fd)) != 0)
	{
	  return rv;
	}
    }

  /* Protect the uninitialized vui from being dispatched by rx/tx */
  vlib_worker_thread_barrier_sync (vm);
  pool_get (vhost_user_main.vhost_user_interfaces, vui);
  vhost_user_create_ethernet (vnm, vm, vui, hwaddr);
  vlib_worker_thread_barrier_release (vm);

  vhost_user_vui_init (vnm, vui, server_sock_fd, sock_filename,
		       feature_mask, &sw_if_idx, enable_gso, enable_packed);
  vnet_sw_interface_set_mtu (vnm, vui->sw_if_index, 9000);
  vhost_user_rx_thread_placement (vui, 1);

  if (renumber)
    vnet_interface_name_renumber (sw_if_idx, custom_dev_instance);

  if (sw_if_index)
    *sw_if_index = sw_if_idx;

  // Process node must connect
  vlib_process_signal_event (vm, vhost_user_process_node.index, 0, 0);

  return rv;
}

int
vhost_user_modify_if (vnet_main_t * vnm, vlib_main_t * vm,
		      const char *sock_filename,
		      u8 is_server,
		      u32 sw_if_index,
		      u64 feature_mask, u8 renumber, u32 custom_dev_instance,
		      u8 enable_gso, u8 enable_packed)
{
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui = NULL;
  u32 sw_if_idx = ~0;
  int server_sock_fd = -1;
  int rv = 0;
  vnet_hw_interface_t *hwif;
  uword *if_index;

  if (!
      (hwif =
       vnet_get_sup_hw_interface_api_visible_or_null (vnm, sw_if_index))
      || hwif->dev_class_index != vhost_user_device_class.index)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (sock_filename == NULL || !(strlen (sock_filename) > 0))
    return VNET_API_ERROR_INVALID_ARGUMENT;

  vui = vec_elt_at_index (vum->vhost_user_interfaces, hwif->dev_instance);

  /*
   * Disallow changing the interface to have the same path name
   * as other interface
   */
  if_index = mhash_get (&vum->if_index_by_sock_name, (void *) sock_filename);
  if (if_index && (*if_index != vui->if_index))
    return VNET_API_ERROR_IF_ALREADY_EXISTS;

  // First try to open server socket
  if (is_server)
    if ((rv = vhost_user_init_server_sock (sock_filename,
					   &server_sock_fd)) != 0)
      return rv;

  vhost_user_term_if (vui);
  vhost_user_vui_init (vnm, vui, server_sock_fd,
		       sock_filename, feature_mask, &sw_if_idx, enable_gso,
		       enable_packed);

  if (renumber)
    vnet_interface_name_renumber (sw_if_idx, custom_dev_instance);

  // Process node must connect
  vlib_process_signal_event (vm, vhost_user_process_node.index, 0, 0);

  return rv;
}

clib_error_t *
vhost_user_connect_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *sock_filename = NULL;
  u32 sw_if_index;
  u8 is_server = 0;
  u64 feature_mask = (u64) ~ (0ULL);
  u8 renumber = 0;
  u32 custom_dev_instance = ~0;
  u8 hwaddr[6];
  u8 *hw = NULL;
  clib_error_t *error = NULL;
  u8 enable_gso = 0, enable_packed = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  /* GSO feature is disable by default */
  feature_mask &= ~FEATURE_VIRTIO_NET_F_HOST_GUEST_TSO_FEATURE_BITS;
  /* packed-ring feature is disable by default */
  feature_mask &= ~VIRTIO_FEATURE (VIRTIO_F_RING_PACKED);
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "socket %s", &sock_filename))
	;
      else if (unformat (line_input, "server"))
	is_server = 1;
      else if (unformat (line_input, "gso"))
	enable_gso = 1;
      else if (unformat (line_input, "packed"))
	enable_packed = 1;
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
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  vnet_main_t *vnm = vnet_get_main ();

  int rv;
  if ((rv = vhost_user_create_if (vnm, vm, (char *) sock_filename,
				  is_server, &sw_if_index, feature_mask,
				  renumber, custom_dev_instance, hw,
				  enable_gso, enable_packed)))
    {
      error = clib_error_return (0, "vhost_user_create_if returned %d", rv);
      goto done;
    }

  vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main (),
		   sw_if_index);

done:
  vec_free (sock_filename);
  unformat_free (line_input);

  return error;
}

clib_error_t *
vhost_user_delete_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat
	       (line_input, "%U", unformat_vnet_sw_interface, vnm,
		&sw_if_index))
	{
	  vnet_hw_interface_t *hwif =
	    vnet_get_sup_hw_interface_api_visible_or_null (vnm, sw_if_index);
	  if (hwif == NULL ||
	      vhost_user_device_class.index != hwif->dev_class_index)
	    {
	      error = clib_error_return (0, "Not a vhost interface");
	      goto done;
	    }
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  vhost_user_delete_if (vnm, vm, sw_if_index);

done:
  unformat_free (line_input);

  return error;
}

int
vhost_user_dump_ifs (vnet_main_t * vnm, vlib_main_t * vm,
		     vhost_user_intf_details_t ** out_vuids)
{
  int rv = 0;
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui;
  vhost_user_intf_details_t *r_vuids = NULL;
  vhost_user_intf_details_t *vuid = NULL;
  u32 *hw_if_indices = 0;
  vnet_hw_interface_t *hi;
  int i;

  if (!out_vuids)
    return -1;

  pool_foreach (vui, vum->vhost_user_interfaces,
		vec_add1 (hw_if_indices, vui->hw_if_index);
    );

  for (i = 0; i < vec_len (hw_if_indices); i++)
    {
      hi = vnet_get_hw_interface (vnm, hw_if_indices[i]);
      vui = pool_elt_at_index (vum->vhost_user_interfaces, hi->dev_instance);

      vec_add2 (r_vuids, vuid, 1);
      vuid->sw_if_index = vui->sw_if_index;
      vuid->virtio_net_hdr_sz = vui->virtio_net_hdr_sz;
      vuid->features = vui->features;
      vuid->num_regions = vui->nregions;
      vuid->is_server = vui->unix_server_index != ~0;
      vuid->sock_errno = vui->sock_errno;
      snprintf ((char *) vuid->sock_filename, sizeof (vuid->sock_filename),
		"%s", vui->sock_filename);
      memcpy_s (vuid->if_name, sizeof (vuid->if_name), hi->name,
		clib_min (vec_len (hi->name), sizeof (vuid->if_name) - 1));
      vuid->if_name[sizeof (vuid->if_name) - 1] = 0;
    }

  vec_free (hw_if_indices);

  *out_vuids = r_vuids;

  return rv;
}

static u8 *
format_vhost_user_desc (u8 * s, va_list * args)
{
  char *fmt = va_arg (*args, char *);
  vhost_user_intf_t *vui = va_arg (*args, vhost_user_intf_t *);
  vring_desc_t *desc_table = va_arg (*args, vring_desc_t *);
  int idx = va_arg (*args, int);
  u32 *mem_hint = va_arg (*args, u32 *);

  s = format (s, fmt, idx, desc_table[idx].addr, desc_table[idx].len,
	      desc_table[idx].flags, desc_table[idx].next,
	      pointer_to_uword (map_guest_mem (vui, desc_table[idx].addr,
					       mem_hint)));
  return s;
}

static u8 *
format_vhost_user_vring (u8 * s, va_list * args)
{
  char *fmt = va_arg (*args, char *);
  vhost_user_intf_t *vui = va_arg (*args, vhost_user_intf_t *);
  int q = va_arg (*args, int);

  s = format (s, fmt, vui->vrings[q].avail->flags, vui->vrings[q].avail->idx,
	      vui->vrings[q].used->flags, vui->vrings[q].used->idx);
  return s;
}

static void
vhost_user_show_fds (vlib_main_t * vm, vhost_user_intf_t * vui, int q)
{
  int kickfd = UNIX_GET_FD (vui->vrings[q].kickfd_idx);
  int callfd = UNIX_GET_FD (vui->vrings[q].callfd_idx);

  vlib_cli_output (vm, "  kickfd %d callfd %d errfd %d\n", kickfd, callfd,
		   vui->vrings[q].errfd);
}

static void
vhost_user_show_desc (vlib_main_t * vm, vhost_user_intf_t * vui, int q,
		      int show_descr, int show_verbose)
{
  int j;
  u32 mem_hint = 0;
  u32 idx;
  u32 n_entries;
  vring_desc_t *desc_table;

  if (vui->vrings[q].avail && vui->vrings[q].used)
    vlib_cli_output (vm, "%U", format_vhost_user_vring,
		     "  avail.flags %x avail.idx %d used.flags %x used.idx %d\n",
		     vui, q);

  vhost_user_show_fds (vm, vui, q);

  if (show_descr)
    {
      vlib_cli_output (vm, "\n  descriptor table:\n");
      vlib_cli_output (vm,
		       "  slot         addr         len  flags  next      "
		       "user_addr\n");
      vlib_cli_output (vm,
		       "  ===== ================== ===== ====== ===== "
		       "==================\n");
      for (j = 0; j < vui->vrings[q].qsz_mask + 1; j++)
	{
	  desc_table = vui->vrings[q].desc;
	  vlib_cli_output (vm, "%U", format_vhost_user_desc,
			   "  %-5d 0x%016lx %-5d 0x%04x %-5d 0x%016lx\n", vui,
			   desc_table, j, &mem_hint);
	  if (show_verbose && (desc_table[j].flags & VRING_DESC_F_INDIRECT))
	    {
	      n_entries = desc_table[j].len / sizeof (vring_desc_t);
	      desc_table = map_guest_mem (vui, desc_table[j].addr, &mem_hint);
	      if (desc_table)
		{
		  for (idx = 0; idx < clib_min (20, n_entries); idx++)
		    {
		      vlib_cli_output
			(vm, "%U", format_vhost_user_desc,
			 ">  %-4u 0x%016lx %-5u 0x%04x %-5u 0x%016lx\n", vui,
			 desc_table, idx, &mem_hint);
		    }
		  if (n_entries >= 20)
		    vlib_cli_output (vm, "Skip displaying entries 20...%u\n",
				     n_entries);
		}
	    }
	}
    }
}

static u8 *
format_vhost_user_packed_desc (u8 * s, va_list * args)
{
  char *fmt = va_arg (*args, char *);
  vhost_user_intf_t *vui = va_arg (*args, vhost_user_intf_t *);
  vring_packed_desc_t *desc_table = va_arg (*args, vring_packed_desc_t *);
  int idx = va_arg (*args, int);
  u32 *mem_hint = va_arg (*args, u32 *);

  s = format (s, fmt, idx, desc_table[idx].addr, desc_table[idx].len,
	      desc_table[idx].flags, desc_table[idx].id,
	      pointer_to_uword (map_guest_mem (vui, desc_table[idx].addr,
					       mem_hint)));
  return s;
}

static u8 *
format_vhost_user_vring_packed (u8 * s, va_list * args)
{
  char *fmt = va_arg (*args, char *);
  vhost_user_intf_t *vui = va_arg (*args, vhost_user_intf_t *);
  int q = va_arg (*args, int);

  s = format (s, fmt, vui->vrings[q].avail_event->flags,
	      vui->vrings[q].avail_event->off_wrap,
	      vui->vrings[q].used_event->flags,
	      vui->vrings[q].used_event->off_wrap,
	      vui->vrings[q].avail_wrap_counter,
	      vui->vrings[q].used_wrap_counter);
  return s;
}

static void
vhost_user_show_desc_packed (vlib_main_t * vm, vhost_user_intf_t * vui, int q,
			     int show_descr, int show_verbose)
{
  int j;
  u32 mem_hint = 0;
  u32 idx;
  u32 n_entries;
  vring_packed_desc_t *desc_table;

  if (vui->vrings[q].avail_event && vui->vrings[q].used_event)
    vlib_cli_output (vm, "%U", format_vhost_user_vring_packed,
		     "  avail_event.flags %x avail_event.off_wrap %u "
		     "used_event.flags %x used_event.off_wrap %u\n"
		     "  avail wrap counter %u, used wrap counter %u\n",
		     vui, q);

  vhost_user_show_fds (vm, vui, q);

  if (show_descr)
    {
      vlib_cli_output (vm, "\n  descriptor table:\n");
      vlib_cli_output (vm,
		       "  slot         addr         len  flags  id    "
		       "user_addr\n");
      vlib_cli_output (vm,
		       "  ===== ================== ===== ====== ===== "
		       "==================\n");
      for (j = 0; j < vui->vrings[q].qsz_mask + 1; j++)
	{
	  desc_table = vui->vrings[q].packed_desc;
	  vlib_cli_output (vm, "%U", format_vhost_user_packed_desc,
			   "  %-5u 0x%016lx %-5u 0x%04x %-5u 0x%016lx\n", vui,
			   desc_table, j, &mem_hint);
	  if (show_verbose && (desc_table[j].flags & VRING_DESC_F_INDIRECT))
	    {
	      n_entries = desc_table[j].len >> 4;
	      desc_table = map_guest_mem (vui, desc_table[j].addr, &mem_hint);
	      if (desc_table)
		{
		  for (idx = 0; idx < clib_min (20, n_entries); idx++)
		    {
		      vlib_cli_output
			(vm, "%U", format_vhost_user_packed_desc,
			 ">  %-4u 0x%016lx %-5u 0x%04x %-5u 0x%016lx\n", vui,
			 desc_table, idx, &mem_hint);
		    }
		  if (n_entries >= 20)
		    vlib_cli_output (vm, "Skip displaying entries 20...%u\n",
				     n_entries);
		}
	    }
	}
    }
}

clib_error_t *
show_vhost_user_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  vnet_main_t *vnm = vnet_get_main ();
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui;
  u32 hw_if_index, *hw_if_indices = 0;
  vnet_hw_interface_t *hi;
  u16 qid;
  u32 ci;
  int i, j, q;
  int show_descr = 0;
  int show_verbose = 0;
  struct feat_struct
  {
    u8 bit;
    char *str;
  };
  struct feat_struct *feat_entry;

  static struct feat_struct feat_array[] = {
#define _(s,b) { .str = #s, .bit = b, },
    foreach_virtio_net_features
#undef _
    {.str = NULL}
  };

#define foreach_protocol_feature \
  _(VHOST_USER_PROTOCOL_F_MQ) \
  _(VHOST_USER_PROTOCOL_F_LOG_SHMFD)

  static struct feat_struct proto_feat_array[] = {
#define _(s) { .str = #s, .bit = s},
    foreach_protocol_feature
#undef _
    {.str = NULL}
  };

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index))
	{
	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	  if (vhost_user_device_class.index != hi->dev_class_index)
	    {
	      error = clib_error_return (0, "unknown input `%U'",
					 format_unformat_error, input);
	      goto done;
	    }
	  vec_add1 (hw_if_indices, hw_if_index);
	}
      else if (unformat (input, "descriptors") || unformat (input, "desc"))
	show_descr = 1;
      else if (unformat (input, "verbose"))
	show_verbose = 1;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }
  if (vec_len (hw_if_indices) == 0)
    {
      pool_foreach (vui, vum->vhost_user_interfaces,
		    vec_add1 (hw_if_indices, vui->hw_if_index);
	);
    }
  vlib_cli_output (vm, "Virtio vhost-user interfaces");
  vlib_cli_output (vm, "Global:\n  coalesce frames %d time %e",
		   vum->coalesce_frames, vum->coalesce_time);
  vlib_cli_output (vm, "  Number of rx virtqueues in interrupt mode: %d",
		   vum->ifq_count);
  vlib_cli_output (vm, "  Number of GSO interfaces: %d", vum->gso_count);

  for (i = 0; i < vec_len (hw_if_indices); i++)
    {
      hi = vnet_get_hw_interface (vnm, hw_if_indices[i]);
      vui = pool_elt_at_index (vum->vhost_user_interfaces, hi->dev_instance);
      vlib_cli_output (vm, "Interface: %U (ifindex %d)",
		       format_vnet_hw_if_index_name, vnm, hw_if_indices[i],
		       hw_if_indices[i]);
      if (vui->enable_gso)
	vlib_cli_output (vm, "  GSO enable");
      if (vui->enable_packed)
	vlib_cli_output (vm, "  Packed ring enable");

      vlib_cli_output (vm, "virtio_net_hdr_sz %d\n"
		       " features mask (0x%llx): \n"
		       " features (0x%llx): \n",
		       vui->virtio_net_hdr_sz, vui->feature_mask,
		       vui->features);

      feat_entry = (struct feat_struct *) &feat_array;
      while (feat_entry->str)
	{
	  if (vui->features & (1ULL << feat_entry->bit))
	    vlib_cli_output (vm, "   %s (%d)", feat_entry->str,
			     feat_entry->bit);
	  feat_entry++;
	}

      vlib_cli_output (vm, "  protocol features (0x%llx)",
		       vui->protocol_features);
      feat_entry = (struct feat_struct *) &proto_feat_array;
      while (feat_entry->str)
	{
	  if (vui->protocol_features & (1ULL << feat_entry->bit))
	    vlib_cli_output (vm, "   %s (%d)", feat_entry->str,
			     feat_entry->bit);
	  feat_entry++;
	}

      vlib_cli_output (vm, "\n");

      vlib_cli_output (vm, " socket filename %s type %s errno \"%s\"\n\n",
		       vui->sock_filename,
		       (vui->unix_server_index != ~0) ? "server" : "client",
		       strerror (vui->sock_errno));

      vlib_cli_output (vm, " rx placement: ");

      for (qid = 1; qid < VHOST_VRING_MAX_N / 2; qid += 2)
	{
	  vnet_main_t *vnm = vnet_get_main ();
	  uword thread_index;
	  vnet_hw_if_rx_mode mode;
	  vhost_user_vring_t *txvq = &vui->vrings[qid];

	  if (txvq->qid == -1)
	    continue;
	  thread_index =
	    vnet_get_device_input_thread_index (vnm, vui->hw_if_index,
						qid >> 1);
	  vnet_hw_interface_get_rx_mode (vnm, vui->hw_if_index, qid >> 1,
					 &mode);
	  vlib_cli_output (vm, "   thread %d on vring %d, %U\n",
			   thread_index, qid,
			   format_vnet_hw_if_rx_mode, mode);
	}

      vlib_cli_output (vm, " tx placement: %s\n",
		       vui->use_tx_spinlock ? "spin-lock" : "lock-free");

      vec_foreach_index (ci, vui->per_cpu_tx_qid)
      {
	vlib_cli_output (vm, "   thread %d on vring %d\n", ci,
			 VHOST_VRING_IDX_RX (vui->per_cpu_tx_qid[ci]));
      }

      vlib_cli_output (vm, "\n");

      vlib_cli_output (vm, " Memory regions (total %d)\n", vui->nregions);

      if (vui->nregions)
	{
	  vlib_cli_output (vm,
			   " region fd    guest_phys_addr    memory_size        userspace_addr     mmap_offset        mmap_addr\n");
	  vlib_cli_output (vm,
			   " ====== ===== ================== ================== ================== ================== ==================\n");
	}
      for (j = 0; j < vui->nregions; j++)
	{
	  vlib_cli_output (vm,
			   "  %d     %-5d 0x%016lx 0x%016lx 0x%016lx 0x%016lx 0x%016lx\n",
			   j, vui->region_mmap_fd[j],
			   vui->regions[j].guest_phys_addr,
			   vui->regions[j].memory_size,
			   vui->regions[j].userspace_addr,
			   vui->regions[j].mmap_offset,
			   pointer_to_uword (vui->region_mmap_addr[j]));
	}
      for (q = 0; q < VHOST_VRING_MAX_N; q++)
	{
	  if (!vui->vrings[q].started)
	    continue;

	  vlib_cli_output (vm, "\n Virtqueue %d (%s%s)\n", q,
			   (q & 1) ? "RX" : "TX",
			   vui->vrings[q].enabled ? "" : " disabled");

	  vlib_cli_output (vm,
			   "  qsz %d last_avail_idx %d last_used_idx %d\n",
			   vui->vrings[q].qsz_mask + 1,
			   vui->vrings[q].last_avail_idx,
			   vui->vrings[q].last_used_idx);

	  if (vhost_user_is_packed_ring_supported (vui))
	    vhost_user_show_desc_packed (vm, vui, q, show_descr,
					 show_verbose);
	  else
	    vhost_user_show_desc (vm, vui, q, show_descr, show_verbose);
	}
      vlib_cli_output (vm, "\n");
    }
done:
  vec_free (hw_if_indices);
  return error;
}

/*
 * CLI functions
 */

/*?
 * Create a vHost User interface. Once created, a new virtual interface
 * will exist with the name '<em>VirtualEthernet0/0/x</em>', where '<em>x</em>'
 * is the next free index.
 *
 * There are several parameters associated with a vHost interface:
 *
 * - <b>socket <socket-filename></b> - Name of the linux socket used by hypervisor
 * and VPP to manage the vHost interface. If in '<em>server</em>' mode, VPP will
 * create the socket if it does not already exist. If in '<em>client</em>' mode,
 * hypervisor will create the socket if it does not already exist. The VPP code
 * is indifferent to the file location. However, if SELinux is enabled, then the
 * socket needs to be created in '<em>/var/run/vpp/</em>'.
 *
 * - <b>server</b> - Optional flag to indicate that VPP should be the server for
 * the linux socket. If not provided, VPP will be the client. In '<em>server</em>'
 *  mode, the VM can be reset without tearing down the vHost Interface. In
 * '<em>client</em>' mode, VPP can be reset without bringing down the VM and
 * tearing down the vHost Interface.
 *
 * - <b>feature-mask <hex></b> - Optional virtio/vhost feature set negotiated at
 * startup. <b>This is intended for degugging only.</b> It is recommended that this
 * parameter not be used except by experienced users. By default, all supported
 * features will be advertised. Otherwise, provide the set of features desired.
 *   - 0x000008000 (15) - VIRTIO_NET_F_MRG_RXBUF
 *   - 0x000020000 (17) - VIRTIO_NET_F_CTRL_VQ
 *   - 0x000200000 (21) - VIRTIO_NET_F_GUEST_ANNOUNCE
 *   - 0x000400000 (22) - VIRTIO_NET_F_MQ
 *   - 0x004000000 (26) - VHOST_F_LOG_ALL
 *   - 0x008000000 (27) - VIRTIO_F_ANY_LAYOUT
 *   - 0x010000000 (28) - VIRTIO_F_INDIRECT_DESC
 *   - 0x040000000 (30) - VHOST_USER_F_PROTOCOL_FEATURES
 *   - 0x100000000 (32) - VIRTIO_F_VERSION_1
 *
 * - <b>hwaddr <mac-addr></b> - Optional ethernet address, can be in either
 * X:X:X:X:X:X unix or X.X.X cisco format.
 *
 * - <b>renumber <dev_instance></b> - Optional parameter which allows the instance
 * in the name to be specified. If instance already exists, name will be used
 * anyway and multiple instances will have the same name. Use with caution.
 *
 * @cliexpar
 * Example of how to create a vhost interface with VPP as the client and all features enabled:
 * @cliexstart{create vhost-user socket /var/run/vpp/vhost1.sock}
 * VirtualEthernet0/0/0
 * @cliexend
 * Example of how to create a vhost interface with VPP as the server and with just
 * multiple queues enabled:
 * @cliexstart{create vhost-user socket /var/run/vpp/vhost2.sock server feature-mask 0x40400000}
 * VirtualEthernet0/0/1
 * @cliexend
 * Once the vHost interface is created, enable the interface using:
 * @cliexcmd{set interface state VirtualEthernet0/0/0 up}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vhost_user_connect_command, static) = {
    .path = "create vhost-user",
    .short_help = "create vhost-user socket <socket-filename> [server] "
    "[feature-mask <hex>] [hwaddr <mac-addr>] [renumber <dev_instance>] [gso] "
    "[packed]",
    .function = vhost_user_connect_command_fn,
    .is_mp_safe = 1,
};
/* *INDENT-ON* */

/*?
 * Delete a vHost User interface using the interface name or the
 * software interface index. Use the '<em>show interface</em>'
 * command to determine the software interface index. On deletion,
 * the linux socket will not be deleted.
 *
 * @cliexpar
 * Example of how to delete a vhost interface by name:
 * @cliexcmd{delete vhost-user VirtualEthernet0/0/1}
 * Example of how to delete a vhost interface by software interface index:
 * @cliexcmd{delete vhost-user sw_if_index 1}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vhost_user_delete_command, static) = {
    .path = "delete vhost-user",
    .short_help = "delete vhost-user {<interface> | sw_if_index <sw_idx>}",
    .function = vhost_user_delete_command_fn,
};

/*?
 * Display the attributes of a single vHost User interface (provide interface
 * name), multiple vHost User interfaces (provide a list of interface names seperated
 * by spaces) or all Vhost User interfaces (omit an interface name to display all
 * vHost interfaces).
 *
 * @cliexpar
 * @parblock
 * Example of how to display a vhost interface:
 * @cliexstart{show vhost-user VirtualEthernet0/0/0}
 * Virtio vhost-user interfaces
 * Global:
 *   coalesce frames 32 time 1e-3
 * Interface: VirtualEthernet0/0/0 (ifindex 1)
 * virtio_net_hdr_sz 12
 *  features mask (0xffffffffffffffff):
 *  features (0x50408000):
 *    VIRTIO_NET_F_MRG_RXBUF (15)
 *    VIRTIO_NET_F_MQ (22)
 *    VIRTIO_F_INDIRECT_DESC (28)
 *    VHOST_USER_F_PROTOCOL_FEATURES (30)
 *   protocol features (0x3)
 *    VHOST_USER_PROTOCOL_F_MQ (0)
 *    VHOST_USER_PROTOCOL_F_LOG_SHMFD (1)
 *
 *  socket filename /var/run/vpp/vhost1.sock type client errno "Success"
 *
 * rx placement:
 *    thread 1 on vring 1
 *    thread 1 on vring 5
 *    thread 2 on vring 3
 *    thread 2 on vring 7
 *  tx placement: spin-lock
 *    thread 0 on vring 0
 *    thread 1 on vring 2
 *    thread 2 on vring 0
 *
 * Memory regions (total 2)
 * region fd    guest_phys_addr    memory_size        userspace_addr     mmap_offset        mmap_addr
 * ====== ===== ================== ================== ================== ================== ==================
 *   0     60    0x0000000000000000 0x00000000000a0000 0x00002aaaaac00000 0x0000000000000000 0x00002aab2b400000
 *   1     61    0x00000000000c0000 0x000000003ff40000 0x00002aaaaacc0000 0x00000000000c0000 0x00002aababcc0000
 *
 *  Virtqueue 0 (TX)
 *   qsz 256 last_avail_idx 0 last_used_idx 0
 *   avail.flags 1 avail.idx 128 used.flags 1 used.idx 0
 *   kickfd 62 callfd 64 errfd -1
 *
 *  Virtqueue 1 (RX)
 *   qsz 256 last_avail_idx 0 last_used_idx 0
 *   avail.flags 1 avail.idx 0 used.flags 1 used.idx 0
 *   kickfd 65 callfd 66 errfd -1
 *
 *  Virtqueue 2 (TX)
 *   qsz 256 last_avail_idx 0 last_used_idx 0
 *   avail.flags 1 avail.idx 128 used.flags 1 used.idx 0
 *   kickfd 63 callfd 70 errfd -1
 *
 *  Virtqueue 3 (RX)
 *   qsz 256 last_avail_idx 0 last_used_idx 0
 *   avail.flags 1 avail.idx 0 used.flags 1 used.idx 0
 *   kickfd 72 callfd 74 errfd -1
 *
 *  Virtqueue 4 (TX disabled)
 *   qsz 256 last_avail_idx 0 last_used_idx 0
 *   avail.flags 1 avail.idx 0 used.flags 1 used.idx 0
 *   kickfd 76 callfd 78 errfd -1
 *
 *  Virtqueue 5 (RX disabled)
 *   qsz 256 last_avail_idx 0 last_used_idx 0
 *   avail.flags 1 avail.idx 0 used.flags 1 used.idx 0
 *   kickfd 80 callfd 82 errfd -1
 *
 *  Virtqueue 6 (TX disabled)
 *   qsz 256 last_avail_idx 0 last_used_idx 0
 *  avail.flags 1 avail.idx 0 used.flags 1 used.idx 0
 *   kickfd 84 callfd 86 errfd -1
 *
 *  Virtqueue 7 (RX disabled)
 *   qsz 256 last_avail_idx 0 last_used_idx 0
 *   avail.flags 1 avail.idx 0 used.flags 1 used.idx 0
 *   kickfd 88 callfd 90 errfd -1
 *
 * @cliexend
 *
 * The optional '<em>descriptors</em>' parameter will display the same output as
 * the previous example but will include the descriptor table for each queue.
 * The output is truncated below:
 * @cliexstart{show vhost-user VirtualEthernet0/0/0 descriptors}
 * Virtio vhost-user interfaces
 * Global:
 *   coalesce frames 32 time 1e-3
 * Interface: VirtualEthernet0/0/0 (ifindex 1)
 * virtio_net_hdr_sz 12
 *  features mask (0xffffffffffffffff):
 *  features (0x50408000):
 *    VIRTIO_NET_F_MRG_RXBUF (15)
 *    VIRTIO_NET_F_MQ (22)
 * :
 *  Virtqueue 0 (TX)
 *   qsz 256 last_avail_idx 0 last_used_idx 0
 *   avail.flags 1 avail.idx 128 used.flags 1 used.idx 0
 *   kickfd 62 callfd 64 errfd -1
 *
 *   descriptor table:
 *    id          addr         len  flags  next      user_addr
 *   ===== ================== ===== ====== ===== ==================
 *   0     0x0000000010b6e974 2060  0x0002 1     0x00002aabbc76e974
 *   1     0x0000000010b6e034 2060  0x0002 2     0x00002aabbc76e034
 *   2     0x0000000010b6d6f4 2060  0x0002 3     0x00002aabbc76d6f4
 *   3     0x0000000010b6cdb4 2060  0x0002 4     0x00002aabbc76cdb4
 *   4     0x0000000010b6c474 2060  0x0002 5     0x00002aabbc76c474
 *   5     0x0000000010b6bb34 2060  0x0002 6     0x00002aabbc76bb34
 *   6     0x0000000010b6b1f4 2060  0x0002 7     0x00002aabbc76b1f4
 *   7     0x0000000010b6a8b4 2060  0x0002 8     0x00002aabbc76a8b4
 *   8     0x0000000010b69f74 2060  0x0002 9     0x00002aabbc769f74
 *   9     0x0000000010b69634 2060  0x0002 10    0x00002aabbc769634
 *   10    0x0000000010b68cf4 2060  0x0002 11    0x00002aabbc768cf4
 * :
 *   249   0x0000000000000000 0     0x0000 250   0x00002aab2b400000
 *   250   0x0000000000000000 0     0x0000 251   0x00002aab2b400000
 *   251   0x0000000000000000 0     0x0000 252   0x00002aab2b400000
 *   252   0x0000000000000000 0     0x0000 253   0x00002aab2b400000
 *   253   0x0000000000000000 0     0x0000 254   0x00002aab2b400000
 *   254   0x0000000000000000 0     0x0000 255   0x00002aab2b400000
 *   255   0x0000000000000000 0     0x0000 32768 0x00002aab2b400000
 *
 *  Virtqueue 1 (RX)
 *   qsz 256 last_avail_idx 0 last_used_idx 0
 * :
 * @cliexend
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_vhost_user_command, static) = {
    .path = "show vhost-user",
    .short_help = "show vhost-user [<interface> [<interface> [..]]] "
    "[[descriptors] [verbose]]",
    .function = show_vhost_user_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
vhost_user_config (vlib_main_t * vm, unformat_input_t * input)
{
  vhost_user_main_t *vum = &vhost_user_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "coalesce-frames %d", &vum->coalesce_frames))
	;
      else if (unformat (input, "coalesce-time %f", &vum->coalesce_time))
	;
      else if (unformat (input, "dont-dump-memory"))
	vum->dont_dump_vhost_user_memory = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  return 0;
}

/* vhost-user { ... } configuration. */
VLIB_CONFIG_FUNCTION (vhost_user_config, "vhost-user");

void
vhost_user_unmap_all (void)
{
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui;

  if (vum->dont_dump_vhost_user_memory)
    {
      pool_foreach (vui, vum->vhost_user_interfaces,
		    unmap_all_mem_regions (vui);
	);
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
