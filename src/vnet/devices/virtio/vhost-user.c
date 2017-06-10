/*
 *------------------------------------------------------------------
 * vhost.c - vhost-user
 *
 * Copyright (c) 2014 Cisco and/or its affiliates.
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

#include <vnet/ip/ip.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <vnet/feature/feature.h>

#include <vnet/devices/virtio/vhost-user.h>

/**
 * @file
 * @brief vHost User Device Driver.
 *
 * This file contains the source code for vHost User interface.
 */


#define VHOST_DEBUG_VQ 0

#define DBG_SOCK(args...)			\
  {						\
    vhost_user_main_t *_vum = &vhost_user_main; \
    if (_vum->debug)				\
      clib_warning(args);			\
  };

#if VHOST_DEBUG_VQ == 1
#define DBG_VQ(args...) clib_warning(args);
#else
#define DBG_VQ(args...)
#endif

/*
 * When an RX queue is down but active, received packets
 * must be discarded. This value controls up to how many
 * packets will be discarded during each round.
 */
#define VHOST_USER_DOWN_DISCARD_COUNT 256

/*
 * When the number of available buffers gets under this threshold,
 * RX node will start discarding packets.
 */
#define VHOST_USER_RX_BUFFER_STARVATION 32

/*
 * On the receive side, the host should free descriptors as soon
 * as possible in order to avoid TX drop in the VM.
 * This value controls the number of copy operations that are stacked
 * before copy is done for all and descriptors are given back to
 * the guest.
 * The value 64 was obtained by testing (48 and 128 were not as good).
 */
#define VHOST_USER_RX_COPY_THRESHOLD 64
/*
 * On the transmit side, we keep processing the buffers from vlib in the while
 * loop and prepare the copy order to be executed later. However, the static
 * array which we keep the copy order is limited to VHOST_USER_COPY_ARRAY_N
 * entries. In order to not corrupt memory, we have to do the copy when the
 * static array reaches the copy threshold. We subtract 40 in case the code
 * goes into the inner loop for a maximum of 64k frames which may require
 * more array entries.
 */
#define VHOST_USER_TX_COPY_THRESHOLD (VHOST_USER_COPY_ARRAY_N - 40)

#define UNIX_GET_FD(unixfd_idx) \
    (unixfd_idx != ~0) ? \
	pool_elt_at_index (file_main.file_pool, \
			   unixfd_idx)->file_descriptor : -1;

#define foreach_virtio_trace_flags \
  _ (SIMPLE_CHAINED, 0, "Simple descriptor chaining") \
  _ (SINGLE_DESC,  1, "Single descriptor packet") \
  _ (INDIRECT, 2, "Indirect descriptor") \
  _ (MAP_ERROR, 4, "Memory mapping error")

typedef enum
{
#define _(n,i,s) VIRTIO_TRACE_F_##n,
  foreach_virtio_trace_flags
#undef _
} virtio_trace_flag_t;

vlib_node_registration_t vhost_user_input_node;

#define foreach_vhost_user_tx_func_error      \
  _(NONE, "no error")  \
  _(NOT_READY, "vhost vring not ready")  \
  _(DOWN, "vhost interface is down")  \
  _(PKT_DROP_NOBUF, "tx packet drops (no available descriptors)")  \
  _(PKT_DROP_NOMRG, "tx packet drops (cannot merge descriptors)")  \
  _(MMAP_FAIL, "mmap failure") \
  _(INDIRECT_OVERFLOW, "indirect descriptor table overflow")

typedef enum
{
#define _(f,s) VHOST_USER_TX_FUNC_ERROR_##f,
  foreach_vhost_user_tx_func_error
#undef _
    VHOST_USER_TX_FUNC_N_ERROR,
} vhost_user_tx_func_error_t;

static char *vhost_user_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_vhost_user_tx_func_error
#undef _
};

#define foreach_vhost_user_input_func_error      \
  _(NO_ERROR, "no error")  \
  _(NO_BUFFER, "no available buffer")  \
  _(MMAP_FAIL, "mmap failure")  \
  _(INDIRECT_OVERFLOW, "indirect descriptor overflows table")  \
  _(UNDERSIZED_FRAME, "undersized ethernet frame received (< 14 bytes)") \
  _(FULL_RX_QUEUE, "full rx queue (possible driver tx drop)")

typedef enum
{
#define _(f,s) VHOST_USER_INPUT_FUNC_ERROR_##f,
  foreach_vhost_user_input_func_error
#undef _
    VHOST_USER_INPUT_FUNC_N_ERROR,
} vhost_user_input_func_error_t;

static char *vhost_user_input_func_error_strings[] = {
#define _(n,s) s,
  foreach_vhost_user_input_func_error
#undef _
};

/* *INDENT-OFF* */
static vhost_user_main_t vhost_user_main = {
  .mtu_bytes = 1518,
};

VNET_HW_INTERFACE_CLASS (vhost_interface_class, static) = {
  .name = "vhost-user",
};
/* *INDENT-ON* */

static u8 *
format_vhost_user_interface_name (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  u32 show_dev_instance = ~0;
  vhost_user_main_t *vum = &vhost_user_main;

  if (i < vec_len (vum->show_dev_instance_by_real_dev_instance))
    show_dev_instance = vum->show_dev_instance_by_real_dev_instance[i];

  if (show_dev_instance != ~0)
    i = show_dev_instance;

  s = format (s, "VirtualEthernet0/0/%d", i);
  return s;
}

static int
vhost_user_name_renumber (vnet_hw_interface_t * hi, u32 new_dev_instance)
{
  // FIXME: check if the new dev instance is already used
  vhost_user_main_t *vum = &vhost_user_main;
  vec_validate_init_empty (vum->show_dev_instance_by_real_dev_instance,
			   hi->dev_instance, ~0);

  vum->show_dev_instance_by_real_dev_instance[hi->dev_instance] =
    new_dev_instance;

  DBG_SOCK ("renumbered vhost-user interface dev_instance %d to %d",
	    hi->dev_instance, new_dev_instance);

  return 0;
}

static_always_inline void *
map_guest_mem (vhost_user_intf_t * vui, uword addr, u32 * hint)
{
  int i = *hint;
  if (PREDICT_TRUE ((vui->regions[i].guest_phys_addr <= addr) &&
		    ((vui->regions[i].guest_phys_addr +
		      vui->regions[i].memory_size) > addr)))
    {
      return (void *) (vui->region_mmap_addr[i] + addr -
		       vui->regions[i].guest_phys_addr);
    }
#if __SSE4_2__
  __m128i rl, rh, al, ah, r;
  al = _mm_set1_epi64x (addr + 1);
  ah = _mm_set1_epi64x (addr);

  rl = _mm_loadu_si128 ((__m128i *) & vui->region_guest_addr_lo[0]);
  rl = _mm_cmpgt_epi64 (al, rl);
  rh = _mm_loadu_si128 ((__m128i *) & vui->region_guest_addr_hi[0]);
  rh = _mm_cmpgt_epi64 (rh, ah);
  r = _mm_and_si128 (rl, rh);

  rl = _mm_loadu_si128 ((__m128i *) & vui->region_guest_addr_lo[2]);
  rl = _mm_cmpgt_epi64 (al, rl);
  rh = _mm_loadu_si128 ((__m128i *) & vui->region_guest_addr_hi[2]);
  rh = _mm_cmpgt_epi64 (rh, ah);
  r = _mm_blend_epi16 (r, _mm_and_si128 (rl, rh), 0x22);

  rl = _mm_loadu_si128 ((__m128i *) & vui->region_guest_addr_lo[4]);
  rl = _mm_cmpgt_epi64 (al, rl);
  rh = _mm_loadu_si128 ((__m128i *) & vui->region_guest_addr_hi[4]);
  rh = _mm_cmpgt_epi64 (rh, ah);
  r = _mm_blend_epi16 (r, _mm_and_si128 (rl, rh), 0x44);

  rl = _mm_loadu_si128 ((__m128i *) & vui->region_guest_addr_lo[6]);
  rl = _mm_cmpgt_epi64 (al, rl);
  rh = _mm_loadu_si128 ((__m128i *) & vui->region_guest_addr_hi[6]);
  rh = _mm_cmpgt_epi64 (rh, ah);
  r = _mm_blend_epi16 (r, _mm_and_si128 (rl, rh), 0x88);

  r = _mm_shuffle_epi8 (r, _mm_set_epi64x (0, 0x0e060c040a020800));
  i = __builtin_ctzll (_mm_movemask_epi8 (r) |
		       (1 << VHOST_MEMORY_MAX_NREGIONS));

  if (i < vui->nregions)
    {
      *hint = i;
      return (void *) (vui->region_mmap_addr[i] + addr -
		       vui->regions[i].guest_phys_addr);
    }

#else
  for (i = 0; i < vui->nregions; i++)
    {
      if ((vui->regions[i].guest_phys_addr <= addr) &&
	  ((vui->regions[i].guest_phys_addr + vui->regions[i].memory_size) >
	   addr))
	{
	  *hint = i;
	  return (void *) (vui->region_mmap_addr[i] + addr -
			   vui->regions[i].guest_phys_addr);
	}
    }
#endif
  DBG_VQ ("failed to map guest mem addr %llx", addr);
  *hint = 0;
  return 0;
}

static inline void *
map_user_mem (vhost_user_intf_t * vui, uword addr)
{
  int i;
  for (i = 0; i < vui->nregions; i++)
    {
      if ((vui->regions[i].userspace_addr <= addr) &&
	  ((vui->regions[i].userspace_addr + vui->regions[i].memory_size) >
	   addr))
	{
	  return (void *) (vui->region_mmap_addr[i] + addr -
			   vui->regions[i].userspace_addr);
	}
    }
  return 0;
}

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
  int i, r;
  for (i = 0; i < vui->nregions; i++)
    {
      if (vui->region_mmap_addr[i] != (void *) -1)
	{

	  long page_sz = get_huge_page_size (vui->region_mmap_fd[i]);

	  ssize_t map_sz = (vui->regions[i].memory_size +
			    vui->regions[i].mmap_offset +
			    page_sz - 1) & ~(page_sz - 1);

	  r =
	    munmap (vui->region_mmap_addr[i] - vui->regions[i].mmap_offset,
		    map_sz);

	  DBG_SOCK
	    ("unmap memory region %d addr 0x%lx len 0x%lx page_sz 0x%x", i,
	     vui->region_mmap_addr[i], map_sz, page_sz);

	  vui->region_mmap_addr[i] = (void *) -1;

	  if (r == -1)
	    {
	      clib_warning ("failed to unmap memory region (errno %d)",
			    errno);
	    }
	  close (vui->region_mmap_fd[i]);
	}
    }
  vui->nregions = 0;
}

static void
vhost_user_tx_thread_placement (vhost_user_intf_t * vui)
{
  //Let's try to assign one queue to each thread
  u32 qid = 0;
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
static void
vhost_user_rx_thread_placement ()
{
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui;
  vhost_user_vring_t *txvq;
  vnet_main_t *vnm = vnet_get_main ();
  u32 qid;
  int rv;
  u16 *queue;

  // Scrap all existing mappings for all interfaces/queues
  /* *INDENT-OFF* */
  pool_foreach (vui, vum->vhost_user_interfaces, {
      vec_foreach (queue, vui->rx_queues)
	{
	  rv = vnet_hw_interface_unassign_rx_thread (vnm, vui->hw_if_index,
						     *queue);
	  if (rv)
	    clib_warning ("Warning: unable to unassign interface %d, "
			  "queue %d: rc=%d", vui->hw_if_index, *queue, rv);
	}
      vec_reset_length (vui->rx_queues);
  });
  /* *INDENT-ON* */

  // Create the rx_queues for all interfaces
  /* *INDENT-OFF* */
  pool_foreach (vui, vum->vhost_user_interfaces, {
      for (qid = 0; qid < VHOST_VRING_MAX_N / 2; qid++)
	{
	  txvq = &vui->vrings[VHOST_VRING_IDX_TX (qid)];
	  if (txvq->started)
	    {
	      if (txvq->mode == VNET_HW_INTERFACE_RX_MODE_UNKNOWN)
		/* Set polling as the default */
		txvq->mode = VNET_HW_INTERFACE_RX_MODE_POLLING;
	      vec_add1 (vui->rx_queues, qid);
	    }
	}
  });
  /* *INDENT-ON* */

  // Assign new mappings for all interfaces/queues
  /* *INDENT-OFF* */
  pool_foreach (vui, vum->vhost_user_interfaces, {
      vnet_hw_interface_set_input_node (vnm, vui->hw_if_index,
					vhost_user_input_node.index);
      vec_foreach (queue, vui->rx_queues)
	{
	  vnet_hw_interface_assign_rx_thread (vnm, vui->hw_if_index, *queue,
					      ~0);
	  txvq = &vui->vrings[VHOST_VRING_IDX_TX (*queue)];
	  rv = vnet_hw_interface_set_rx_mode (vnm, vui->hw_if_index, *queue,
					      txvq->mode);
	  if (rv)
	    clib_warning ("Warning: unable to set rx mode for interface %d, "
			  "queue %d: rc=%d", vui->hw_if_index, *queue, rv);
	}
  });
  /* *INDENT-ON* */
}

/** @brief Returns whether at least one TX and one RX vring are enabled */
int
vhost_user_intf_ready (vhost_user_intf_t * vui)
{
  int i, found[2] = { };	//RX + TX

  for (i = 0; i < VHOST_VRING_MAX_N; i++)
    if (vui->vrings[i].started && vui->vrings[i].enabled)
      found[i & 1] = 1;

  return found[0] && found[1];
}

static void
vhost_user_update_iface_state (vhost_user_intf_t * vui)
{
  /* if we have pointers to descriptor table, go up */
  int is_up = vhost_user_intf_ready (vui);
  if (is_up != vui->is_up)
    {
      DBG_SOCK ("interface %d %s", vui->sw_if_index,
		is_up ? "ready" : "down");
      vnet_hw_interface_set_flags (vnet_get_main (), vui->hw_if_index,
				   is_up ? VNET_HW_INTERFACE_FLAG_LINK_UP :
				   0);
      vui->is_up = is_up;
    }
  vhost_user_rx_thread_placement ();
  vhost_user_tx_thread_placement (vui);
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
  DBG_SOCK ("if %d KICK queue %d", uf->private_data >> 8, qid);
  if (!vui->vrings[qid].started ||
      (vhost_user_intf_ready (vui) != vui->is_up))
    {
      vlib_worker_thread_barrier_sync (vlib_get_main ());
      vui->vrings[qid].started = 1;
      vhost_user_update_iface_state (vui);
      vlib_worker_thread_barrier_release (vlib_get_main ());
    }

  vhost_user_set_interrupt_pending (vui, uf->private_data);
  return 0;
}

/**
 * @brief Try once to lock the vring
 * @return 0 on success, non-zero on failure.
 */
static inline int
vhost_user_vring_try_lock (vhost_user_intf_t * vui, u32 qid)
{
  return __sync_lock_test_and_set (vui->vring_locks[qid], 1);
}

/**
 * @brief Spin until the vring is successfully locked
 */
static inline void
vhost_user_vring_lock (vhost_user_intf_t * vui, u32 qid)
{
  while (vhost_user_vring_try_lock (vui, qid))
    ;
}

/**
 * @brief Unlock the vring lock
 */
static inline void
vhost_user_vring_unlock (vhost_user_intf_t * vui, u32 qid)
{
  *vui->vring_locks[qid] = 0;
}

static inline void
vhost_user_vring_init (vhost_user_intf_t * vui, u32 qid)
{
  vhost_user_vring_t *vring = &vui->vrings[qid];
  memset (vring, 0, sizeof (*vring));
  vring->kickfd_idx = ~0;
  vring->callfd_idx = ~0;
  vring->errfd = -1;

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

static inline void
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
  vhost_user_vring_init (vui, qid);
}

static inline void
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

  vui->is_up = 0;

  for (q = 0; q < VHOST_VRING_MAX_N; q++)
    vhost_user_vring_close (vui, q);

  unmap_all_mem_regions (vui);
  DBG_SOCK ("interface ifindex %d disconnected", vui->sw_if_index);
}

#define VHOST_LOG_PAGE 0x1000
static_always_inline void
vhost_user_log_dirty_pages_2 (vhost_user_intf_t * vui,
			      u64 addr, u64 len, u8 is_host_address)
{
  if (PREDICT_TRUE (vui->log_base_addr == 0
		    || !(vui->features & (1 << FEAT_VHOST_F_LOG_ALL))))
    {
      return;
    }
  if (is_host_address)
    {
      addr = pointer_to_uword (map_user_mem (vui, (uword) addr));
    }
  if (PREDICT_FALSE ((addr + len - 1) / VHOST_LOG_PAGE / 8 >= vui->log_size))
    {
      DBG_SOCK ("vhost_user_log_dirty_pages(): out of range\n");
      return;
    }

  CLIB_MEMORY_BARRIER ();
  u64 page = addr / VHOST_LOG_PAGE;
  while (page * VHOST_LOG_PAGE < addr + len)
    {
      ((u8 *) vui->log_base_addr)[page / 8] |= 1 << page % 8;
      page++;
    }
}

static_always_inline void
vhost_user_log_dirty_pages (vhost_user_intf_t * vui, u64 addr, u64 len)
{
  vhost_user_log_dirty_pages_2 (vui, addr, len, 0);
}

#define vhost_user_log_dirty_ring(vui, vq, member) \
  if (PREDICT_FALSE(vq->log_used)) { \
    vhost_user_log_dirty_pages(vui, vq->log_guest_addr + STRUCT_OFFSET_OF(vring_used_t, member), \
                             sizeof(vq->used->member)); \
  }

static clib_error_t *
vhost_user_socket_read (clib_file_t * uf)
{
  int n, i;
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

  vui = pool_elt_at_index (vum->vhost_user_interfaces, uf->private_data);

  char control[CMSG_SPACE (VHOST_MEMORY_MAX_NREGIONS * sizeof (int))];

  memset (&mh, 0, sizeof (mh));
  memset (control, 0, sizeof (control));

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

  /* Stop workers to avoid end of the world */
  vlib_worker_thread_barrier_sync (vlib_get_main ());

  if (n != VHOST_USER_MSG_HDR_SZ)
    {
      if (n == -1)
	{
	  DBG_SOCK ("recvmsg returned error %d %s", errno, strerror (errno));
	}
      else
	{
	  DBG_SOCK ("n (%d) != VHOST_USER_MSG_HDR_SZ (%d)",
		    n, VHOST_USER_MSG_HDR_SZ);
	}
      goto close_socket;
    }

  if (mh.msg_flags & MSG_CTRUNC)
    {
      DBG_SOCK ("MSG_CTRUNC is set");
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
    int rv;
    rv =
      read (uf->file_descriptor, ((char *) &msg) + VHOST_USER_MSG_HDR_SZ,
	    msg.size);
    if (rv < 0)
      {
	DBG_SOCK ("read failed %s", strerror (errno));
	goto close_socket;
      }
    else if (rv != msg.size)
      {
	DBG_SOCK ("message too short (read %dB should be %dB)", rv, msg.size);
	goto close_socket;
      }
  }

  switch (msg.request)
    {
    case VHOST_USER_GET_FEATURES:
      msg.flags |= 4;
      msg.u64 = (1ULL << FEAT_VIRTIO_NET_F_MRG_RXBUF) |
	(1ULL << FEAT_VIRTIO_NET_F_CTRL_VQ) |
	(1ULL << FEAT_VIRTIO_F_ANY_LAYOUT) |
	(1ULL << FEAT_VIRTIO_F_INDIRECT_DESC) |
	(1ULL << FEAT_VHOST_F_LOG_ALL) |
	(1ULL << FEAT_VIRTIO_NET_F_GUEST_ANNOUNCE) |
	(1ULL << FEAT_VIRTIO_NET_F_MQ) |
	(1ULL << FEAT_VHOST_USER_F_PROTOCOL_FEATURES) |
	(1ULL << FEAT_VIRTIO_F_VERSION_1);
      msg.u64 &= vui->feature_mask;
      msg.size = sizeof (msg.u64);
      DBG_SOCK ("if %d msg VHOST_USER_GET_FEATURES - reply 0x%016llx",
		vui->hw_if_index, msg.u64);
      break;

    case VHOST_USER_SET_FEATURES:
      DBG_SOCK ("if %d msg VHOST_USER_SET_FEATURES features 0x%016llx",
		vui->hw_if_index, msg.u64);

      vui->features = msg.u64;

      if (vui->features &
	  ((1 << FEAT_VIRTIO_NET_F_MRG_RXBUF) |
	   (1ULL << FEAT_VIRTIO_F_VERSION_1)))
	vui->virtio_net_hdr_sz = 12;
      else
	vui->virtio_net_hdr_sz = 10;

      vui->is_any_layout =
	(vui->features & (1 << FEAT_VIRTIO_F_ANY_LAYOUT)) ? 1 : 0;

      ASSERT (vui->virtio_net_hdr_sz < VLIB_BUFFER_PRE_DATA_SIZE);
      vnet_hw_interface_set_flags (vnm, vui->hw_if_index, 0);
      vui->is_up = 0;

      /*for (q = 0; q < VHOST_VRING_MAX_N; q++)
         vhost_user_vring_close(&vui->vrings[q]); */

      break;

    case VHOST_USER_SET_MEM_TABLE:
      DBG_SOCK ("if %d msg VHOST_USER_SET_MEM_TABLE nregions %d",
		vui->hw_if_index, msg.memory.nregions);

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
      unmap_all_mem_regions (vui);
      for (i = 0; i < msg.memory.nregions; i++)
	{
	  clib_memcpy (&(vui->regions[i]), &msg.memory.regions[i],
		       sizeof (vhost_user_memory_region_t));

	  long page_sz = get_huge_page_size (fds[i]);

	  /* align size to 2M page */
	  ssize_t map_sz = (vui->regions[i].memory_size +
			    vui->regions[i].mmap_offset +
			    page_sz - 1) & ~(page_sz - 1);

	  vui->region_mmap_addr[i] = mmap (0, map_sz, PROT_READ | PROT_WRITE,
					   MAP_SHARED, fds[i], 0);
	  vui->region_guest_addr_lo[i] = vui->regions[i].guest_phys_addr;
	  vui->region_guest_addr_hi[i] = vui->regions[i].guest_phys_addr +
	    vui->regions[i].memory_size;

	  DBG_SOCK
	    ("map memory region %d addr 0 len 0x%lx fd %d mapped 0x%lx "
	     "page_sz 0x%x", i, map_sz, fds[i], vui->region_mmap_addr[i],
	     page_sz);

	  if (vui->region_mmap_addr[i] == MAP_FAILED)
	    {
	      clib_warning ("failed to map memory. errno is %d", errno);
	      goto close_socket;
	    }
	  vui->region_mmap_addr[i] += vui->regions[i].mmap_offset;
	  vui->region_mmap_fd[i] = fds[i];
	}
      vui->nregions = msg.memory.nregions;
      break;

    case VHOST_USER_SET_VRING_NUM:
      DBG_SOCK ("if %d msg VHOST_USER_SET_VRING_NUM idx %d num %d",
		vui->hw_if_index, msg.state.index, msg.state.num);

      if ((msg.state.num > 32768) ||	/* maximum ring size is 32768 */
	  (msg.state.num == 0) ||	/* it cannot be zero */
	  ((msg.state.num - 1) & msg.state.num))	/* must be power of 2 */
	goto close_socket;
      vui->vrings[msg.state.index].qsz_mask = msg.state.num - 1;
      break;

    case VHOST_USER_SET_VRING_ADDR:
      DBG_SOCK ("if %d msg VHOST_USER_SET_VRING_ADDR idx %d",
		vui->hw_if_index, msg.state.index);

      if (msg.state.index >= VHOST_VRING_MAX_N)
	{
	  DBG_SOCK ("invalid vring index VHOST_USER_SET_VRING_ADDR:"
		    " %d >= %d", msg.state.index, VHOST_VRING_MAX_N);
	  goto close_socket;
	}

      if (msg.size < sizeof (msg.addr))
	{
	  DBG_SOCK ("vhost message is too short (%d < %d)",
		    msg.size, sizeof (msg.addr));
	  goto close_socket;
	}

      vui->vrings[msg.state.index].desc = (vring_desc_t *)
	map_user_mem (vui, msg.addr.desc_user_addr);
      vui->vrings[msg.state.index].used = (vring_used_t *)
	map_user_mem (vui, msg.addr.used_user_addr);
      vui->vrings[msg.state.index].avail = (vring_avail_t *)
	map_user_mem (vui, msg.addr.avail_user_addr);

      if ((vui->vrings[msg.state.index].desc == NULL) ||
	  (vui->vrings[msg.state.index].used == NULL) ||
	  (vui->vrings[msg.state.index].avail == NULL))
	{
	  DBG_SOCK ("failed to map user memory for hw_if_index %d",
		    vui->hw_if_index);
	  goto close_socket;
	}

      vui->vrings[msg.state.index].log_guest_addr = msg.addr.log_guest_addr;
      vui->vrings[msg.state.index].log_used =
	(msg.addr.flags & (1 << VHOST_VRING_F_LOG)) ? 1 : 0;

      /* Spec says: If VHOST_USER_F_PROTOCOL_FEATURES has not been negotiated,
         the ring is initialized in an enabled state. */
      if (!(vui->features & (1 << FEAT_VHOST_USER_F_PROTOCOL_FEATURES)))
	{
	  vui->vrings[msg.state.index].enabled = 1;
	}

      vui->vrings[msg.state.index].last_used_idx =
	vui->vrings[msg.state.index].last_avail_idx =
	vui->vrings[msg.state.index].used->idx;

      /* tell driver that we don't want interrupts */
      vui->vrings[msg.state.index].used->flags = VRING_USED_F_NO_NOTIFY;
      break;

    case VHOST_USER_SET_OWNER:
      DBG_SOCK ("if %d msg VHOST_USER_SET_OWNER", vui->hw_if_index);
      break;

    case VHOST_USER_RESET_OWNER:
      DBG_SOCK ("if %d msg VHOST_USER_RESET_OWNER", vui->hw_if_index);
      break;

    case VHOST_USER_SET_VRING_CALL:
      DBG_SOCK ("if %d msg VHOST_USER_SET_VRING_CALL %d",
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
	      DBG_SOCK ("More than one fd received !");
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
      DBG_SOCK ("if %d msg VHOST_USER_SET_VRING_KICK %d",
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
	      DBG_SOCK ("More than one fd received !");
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
	}

      break;

    case VHOST_USER_SET_VRING_ERR:
      DBG_SOCK ("if %d msg VHOST_USER_SET_VRING_ERR %d",
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
      DBG_SOCK ("if %d msg VHOST_USER_SET_VRING_BASE idx %d num %d",
		vui->hw_if_index, msg.state.index, msg.state.num);

      vui->vrings[msg.state.index].last_avail_idx = msg.state.num;
      break;

    case VHOST_USER_GET_VRING_BASE:
      if (msg.state.index >= VHOST_VRING_MAX_N)
	{
	  DBG_SOCK ("invalid vring index VHOST_USER_GET_VRING_BASE:"
		    " %d >= %d", msg.state.index, VHOST_VRING_MAX_N);
	  goto close_socket;
	}

      /*
       * Copy last_avail_idx from the vring before closing it because
       * closing the vring also initializes the vring last_avail_idx
       */
      msg.state.num = vui->vrings[msg.state.index].last_avail_idx;
      msg.flags |= 4;
      msg.size = sizeof (msg.state);

      /* Spec says: Client must [...] stop ring upon receiving VHOST_USER_GET_VRING_BASE. */
      vhost_user_vring_close (vui, msg.state.index);
      DBG_SOCK ("if %d msg VHOST_USER_GET_VRING_BASE idx %d num %d",
		vui->hw_if_index, msg.state.index, msg.state.num);
      break;

    case VHOST_USER_NONE:
      DBG_SOCK ("if %d msg VHOST_USER_NONE", vui->hw_if_index);

      break;

    case VHOST_USER_SET_LOG_BASE:
      {
	DBG_SOCK ("if %d msg VHOST_USER_SET_LOG_BASE", vui->hw_if_index);

	if (msg.size != sizeof (msg.log))
	  {
	    DBG_SOCK
	      ("invalid msg size for VHOST_USER_SET_LOG_BASE: %d instead of %d",
	       msg.size, sizeof (msg.log));
	    goto close_socket;
	  }

	if (!
	    (vui->protocol_features & (1 << VHOST_USER_PROTOCOL_F_LOG_SHMFD)))
	  {
	    DBG_SOCK
	      ("VHOST_USER_PROTOCOL_F_LOG_SHMFD not set but VHOST_USER_SET_LOG_BASE received");
	    goto close_socket;
	  }

	fd = fds[0];
	/* align size to 2M page */
	long page_sz = get_huge_page_size (fd);
	ssize_t map_sz =
	  (msg.log.size + msg.log.offset + page_sz - 1) & ~(page_sz - 1);

	vui->log_base_addr = mmap (0, map_sz, PROT_READ | PROT_WRITE,
				   MAP_SHARED, fd, 0);

	DBG_SOCK
	  ("map log region addr 0 len 0x%lx off 0x%lx fd %d mapped 0x%lx",
	   map_sz, msg.log.offset, fd, vui->log_base_addr);

	if (vui->log_base_addr == MAP_FAILED)
	  {
	    clib_warning ("failed to map memory. errno is %d", errno);
	    goto close_socket;
	  }

	vui->log_base_addr += msg.log.offset;
	vui->log_size = msg.log.size;

	msg.flags |= 4;
	msg.size = sizeof (msg.u64);

	break;
      }

    case VHOST_USER_SET_LOG_FD:
      DBG_SOCK ("if %d msg VHOST_USER_SET_LOG_FD", vui->hw_if_index);

      break;

    case VHOST_USER_GET_PROTOCOL_FEATURES:
      msg.flags |= 4;
      msg.u64 = (1 << VHOST_USER_PROTOCOL_F_LOG_SHMFD) |
	(1 << VHOST_USER_PROTOCOL_F_MQ);
      msg.size = sizeof (msg.u64);
      DBG_SOCK
	("if %d msg VHOST_USER_GET_PROTOCOL_FEATURES - reply 0x%016llx",
	 vui->hw_if_index, msg.u64);
      break;

    case VHOST_USER_SET_PROTOCOL_FEATURES:
      DBG_SOCK
	("if %d msg VHOST_USER_SET_PROTOCOL_FEATURES features 0x%016llx",
	 vui->hw_if_index, msg.u64);

      vui->protocol_features = msg.u64;

      break;

    case VHOST_USER_GET_QUEUE_NUM:
      msg.flags |= 4;
      msg.u64 = VHOST_VRING_MAX_N;
      msg.size = sizeof (msg.u64);
      DBG_SOCK ("if %d msg VHOST_USER_GET_QUEUE_NUM - reply %d",
		vui->hw_if_index, msg.u64);
      break;

    case VHOST_USER_SET_VRING_ENABLE:
      DBG_SOCK ("if %d VHOST_USER_SET_VRING_ENABLE: %s queue %d",
		vui->hw_if_index, msg.state.num ? "enable" : "disable",
		msg.state.index);
      if (msg.state.index >= VHOST_VRING_MAX_N)
	{
	  DBG_SOCK ("invalid vring index VHOST_USER_SET_VRING_ENABLE:"
		    " %d >= %d", msg.state.index, VHOST_VRING_MAX_N);
	  goto close_socket;
	}

      vui->vrings[msg.state.index].enabled = msg.state.num;
      break;

    default:
      DBG_SOCK ("unknown vhost-user message %d received. closing socket",
		msg.request);
      goto close_socket;
    }

  /* if we need to reply */
  if (msg.flags & 4)
    {
      n =
	send (uf->file_descriptor, &msg, VHOST_USER_MSG_HDR_SZ + msg.size, 0);
      if (n != (msg.size + VHOST_USER_MSG_HDR_SZ))
	{
	  DBG_SOCK ("could not send message response");
	  goto close_socket;
	}
    }

  vhost_user_update_iface_state (vui);
  vlib_worker_thread_barrier_release (vlib_get_main ());
  return 0;

close_socket:
  vhost_user_if_disconnect (vui);
  vhost_user_update_iface_state (vui);
  vlib_worker_thread_barrier_release (vlib_get_main ());
  return 0;
}

static clib_error_t *
vhost_user_socket_error (clib_file_t * uf)
{
  vlib_main_t *vm = vlib_get_main ();
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui =
    pool_elt_at_index (vum->vhost_user_interfaces, uf->private_data);

  DBG_SOCK ("socket error on if %d", vui->sw_if_index);
  vlib_worker_thread_barrier_sync (vm);
  vhost_user_if_disconnect (vui);
  vhost_user_rx_thread_placement ();
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

  DBG_SOCK ("New client socket for vhost interface %d", vui->sw_if_index);
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
  clib_error_t *error;
  vhost_user_main_t *vum = &vhost_user_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  error = vlib_call_init_function (vm, ip4_init);
  if (error)
    return error;

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

VLIB_INIT_FUNCTION (vhost_user_init);

static u8 *
format_vhost_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  CLIB_UNUSED (vnet_main_t * vnm) = vnet_get_main ();
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_trace_t *t = va_arg (*va, vhost_trace_t *);
  vhost_user_intf_t *vui = pool_elt_at_index (vum->vhost_user_interfaces,
					      t->device_index);

  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, vui->sw_if_index);

  u32 indent = format_get_indent (s);

  s = format (s, "%U %U queue %d\n", format_white_space, indent,
	      format_vnet_sw_interface_name, vnm, sw, t->qid);

  s = format (s, "%U virtio flags:\n", format_white_space, indent);
#define _(n,i,st) \
	  if (t->virtio_ring_flags & (1 << VIRTIO_TRACE_F_##n)) \
	    s = format (s, "%U  %s %s\n", format_white_space, indent, #n, st);
  foreach_virtio_trace_flags
#undef _
    s = format (s, "%U virtio_net_hdr first_desc_len %u\n",
		format_white_space, indent, t->first_desc_len);

  s = format (s, "%U   flags 0x%02x gso_type %u\n",
	      format_white_space, indent,
	      t->hdr.hdr.flags, t->hdr.hdr.gso_type);

  if (vui->virtio_net_hdr_sz == 12)
    s = format (s, "%U   num_buff %u",
		format_white_space, indent, t->hdr.num_buffers);

  return s;
}

void
vhost_user_rx_trace (vhost_trace_t * t,
		     vhost_user_intf_t * vui, u16 qid,
		     vlib_buffer_t * b, vhost_user_vring_t * txvq)
{
  vhost_user_main_t *vum = &vhost_user_main;
  u32 last_avail_idx = txvq->last_avail_idx;
  u32 desc_current = txvq->avail->ring[last_avail_idx & txvq->qsz_mask];
  vring_desc_t *hdr_desc = 0;
  virtio_net_hdr_mrg_rxbuf_t *hdr;
  u32 hint = 0;

  memset (t, 0, sizeof (*t));
  t->device_index = vui - vum->vhost_user_interfaces;
  t->qid = qid;

  hdr_desc = &txvq->desc[desc_current];
  if (txvq->desc[desc_current].flags & VIRTQ_DESC_F_INDIRECT)
    {
      t->virtio_ring_flags |= 1 << VIRTIO_TRACE_F_INDIRECT;
      /* Header is the first here */
      hdr_desc = map_guest_mem (vui, txvq->desc[desc_current].addr, &hint);
    }
  if (txvq->desc[desc_current].flags & VIRTQ_DESC_F_NEXT)
    {
      t->virtio_ring_flags |= 1 << VIRTIO_TRACE_F_SIMPLE_CHAINED;
    }
  if (!(txvq->desc[desc_current].flags & VIRTQ_DESC_F_NEXT) &&
      !(txvq->desc[desc_current].flags & VIRTQ_DESC_F_INDIRECT))
    {
      t->virtio_ring_flags |= 1 << VIRTIO_TRACE_F_SINGLE_DESC;
    }

  t->first_desc_len = hdr_desc ? hdr_desc->len : 0;

  if (!hdr_desc || !(hdr = map_guest_mem (vui, hdr_desc->addr, &hint)))
    {
      t->virtio_ring_flags |= 1 << VIRTIO_TRACE_F_MAP_ERROR;
    }
  else
    {
      u32 len = vui->virtio_net_hdr_sz;
      memcpy (&t->hdr, hdr, len > hdr_desc->len ? hdr_desc->len : len);
    }
}

static inline void
vhost_user_send_call (vlib_main_t * vm, vhost_user_vring_t * vq)
{
  vhost_user_main_t *vum = &vhost_user_main;
  u64 x = 1;
  int fd = UNIX_GET_FD (vq->callfd_idx);
  int rv;

  rv = write (fd, &x, sizeof (x));
  if (rv <= 0)
    {
      clib_unix_warning
	("Error: Could not write to unix socket for callfd %d", fd);
      return;
    }

  vq->n_since_last_int = 0;
  vq->int_deadline = vlib_time_now (vm) + vum->coalesce_time;
}

static_always_inline u32
vhost_user_input_copy (vhost_user_intf_t * vui, vhost_copy_t * cpy,
		       u16 copy_len, u32 * map_hint)
{
  void *src0, *src1, *src2, *src3;
  if (PREDICT_TRUE (copy_len >= 4))
    {
      if (PREDICT_FALSE (!(src2 = map_guest_mem (vui, cpy[0].src, map_hint))))
	return 1;
      if (PREDICT_FALSE (!(src3 = map_guest_mem (vui, cpy[1].src, map_hint))))
	return 1;

      while (PREDICT_TRUE (copy_len >= 4))
	{
	  src0 = src2;
	  src1 = src3;

	  if (PREDICT_FALSE
	      (!(src2 = map_guest_mem (vui, cpy[2].src, map_hint))))
	    return 1;
	  if (PREDICT_FALSE
	      (!(src3 = map_guest_mem (vui, cpy[3].src, map_hint))))
	    return 1;

	  CLIB_PREFETCH (src2, 64, LOAD);
	  CLIB_PREFETCH (src3, 64, LOAD);

	  clib_memcpy ((void *) cpy[0].dst, src0, cpy[0].len);
	  clib_memcpy ((void *) cpy[1].dst, src1, cpy[1].len);
	  copy_len -= 2;
	  cpy += 2;
	}
    }
  while (copy_len)
    {
      if (PREDICT_FALSE (!(src0 = map_guest_mem (vui, cpy->src, map_hint))))
	return 1;
      clib_memcpy ((void *) cpy->dst, src0, cpy->len);
      copy_len -= 1;
      cpy += 1;
    }
  return 0;
}

/**
 * Try to discard packets from the tx ring (VPP RX path).
 * Returns the number of discarded packets.
 */
u32
vhost_user_rx_discard_packet (vlib_main_t * vm,
			      vhost_user_intf_t * vui,
			      vhost_user_vring_t * txvq, u32 discard_max)
{
  /*
   * On the RX side, each packet corresponds to one descriptor
   * (it is the same whether it is a shallow descriptor, chained, or indirect).
   * Therefore, discarding a packet is like discarding a descriptor.
   */
  u32 discarded_packets = 0;
  u32 avail_idx = txvq->avail->idx;
  while (discarded_packets != discard_max)
    {
      if (avail_idx == txvq->last_avail_idx)
	goto out;

      u16 desc_chain_head =
	txvq->avail->ring[txvq->last_avail_idx & txvq->qsz_mask];
      txvq->last_avail_idx++;
      txvq->used->ring[txvq->last_used_idx & txvq->qsz_mask].id =
	desc_chain_head;
      txvq->used->ring[txvq->last_used_idx & txvq->qsz_mask].len = 0;
      vhost_user_log_dirty_ring (vui, txvq,
				 ring[txvq->last_used_idx & txvq->qsz_mask]);
      txvq->last_used_idx++;
      discarded_packets++;
    }

out:
  CLIB_MEMORY_BARRIER ();
  txvq->used->idx = txvq->last_used_idx;
  vhost_user_log_dirty_ring (vui, txvq, idx);
  return discarded_packets;
}

/*
 * In case of overflow, we need to rewind the array of allocated buffers.
 */
static void
vhost_user_input_rewind_buffers (vlib_main_t * vm,
				 vhost_cpu_t * cpu, vlib_buffer_t * b_head)
{
  u32 bi_current = cpu->rx_buffers[cpu->rx_buffers_len];
  vlib_buffer_t *b_current = vlib_get_buffer (vm, bi_current);
  b_current->current_length = 0;
  b_current->flags = 0;
  while (b_current != b_head)
    {
      cpu->rx_buffers_len++;
      bi_current = cpu->rx_buffers[cpu->rx_buffers_len];
      b_current = vlib_get_buffer (vm, bi_current);
      b_current->current_length = 0;
      b_current->flags = 0;
    }
  cpu->rx_buffers_len++;
}

static u32
vhost_user_if_input (vlib_main_t * vm,
		     vhost_user_main_t * vum,
		     vhost_user_intf_t * vui,
		     u16 qid, vlib_node_runtime_t * node,
		     vnet_hw_interface_rx_mode mode)
{
  vhost_user_vring_t *txvq = &vui->vrings[VHOST_VRING_IDX_TX (qid)];
  u16 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u16 n_left;
  u32 n_left_to_next, *to_next;
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  u32 n_trace = vlib_get_trace_count (vm, node);
  u32 map_hint = 0;
  u16 thread_index = vlib_get_thread_index ();
  u16 copy_len = 0;

  {
    /* do we have pending interrupts ? */
    vhost_user_vring_t *rxvq = &vui->vrings[VHOST_VRING_IDX_RX (qid)];
    f64 now = vlib_time_now (vm);

    if ((txvq->n_since_last_int) && (txvq->int_deadline < now))
      vhost_user_send_call (vm, txvq);

    if ((rxvq->n_since_last_int) && (rxvq->int_deadline < now))
      vhost_user_send_call (vm, rxvq);
  }

  /*
   * For adaptive mode, it is optimized to reduce interrupts.
   * If the scheduler switches the input node to polling due
   * to burst of traffic, we tell the driver no interrupt.
   * When the traffic subsides, the scheduler switches the node back to
   * interrupt mode. We must tell the driver we want interrupt.
   */
  if (PREDICT_FALSE (mode == VNET_HW_INTERFACE_RX_MODE_ADAPTIVE))
    {
      if ((node->flags &
	   VLIB_NODE_FLAG_SWITCH_FROM_POLLING_TO_INTERRUPT_MODE) ||
	  !(node->flags &
	    VLIB_NODE_FLAG_SWITCH_FROM_INTERRUPT_TO_POLLING_MODE))
	/* Tell driver we want notification */
	txvq->used->flags = 0;
      else
	/* Tell driver we don't want notification */
	txvq->used->flags = VRING_USED_F_NO_NOTIFY;
    }

  if (PREDICT_FALSE (txvq->avail->flags & 0xFFFE))
    return 0;

  n_left = (u16) (txvq->avail->idx - txvq->last_avail_idx);

  /* nothing to do */
  if (PREDICT_FALSE (n_left == 0))
    return 0;

  if (PREDICT_FALSE (!vui->admin_up || !(txvq->enabled)))
    {
      /*
       * Discard input packet if interface is admin down or vring is not
       * enabled.
       * "For example, for a networking device, in the disabled state
       * client must not supply any new RX packets, but must process
       * and discard any TX packets."
       */
      vhost_user_rx_discard_packet (vm, vui, txvq,
				    VHOST_USER_DOWN_DISCARD_COUNT);
      return 0;
    }

  if (PREDICT_FALSE (n_left == (txvq->qsz_mask + 1)))
    {
      /*
       * Informational error logging when VPP is not
       * receiving packets fast enough.
       */
      vlib_error_count (vm, node->node_index,
			VHOST_USER_INPUT_FUNC_ERROR_FULL_RX_QUEUE, 1);
    }

  if (n_left > VLIB_FRAME_SIZE)
    n_left = VLIB_FRAME_SIZE;

  /*
   * For small packets (<2kB), we will not need more than one vlib buffer
   * per packet. In case packets are bigger, we will just yeld at some point
   * in the loop and come back later. This is not an issue as for big packet,
   * processing cost really comes from the memory copy.
   * The assumption is that big packets will fit in 40 buffers.
   */
  if (PREDICT_FALSE (vum->cpus[thread_index].rx_buffers_len < n_left + 1 ||
		     vum->cpus[thread_index].rx_buffers_len < 40))
    {
      u32 curr_len = vum->cpus[thread_index].rx_buffers_len;
      vum->cpus[thread_index].rx_buffers_len +=
	vlib_buffer_alloc_from_free_list (vm,
					  vum->cpus[thread_index].rx_buffers +
					  curr_len,
					  VHOST_USER_RX_BUFFERS_N - curr_len,
					  VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);

      if (PREDICT_FALSE
	  (vum->cpus[thread_index].rx_buffers_len <
	   VHOST_USER_RX_BUFFER_STARVATION))
	{
	  /* In case of buffer starvation, discard some packets from the queue
	   * and log the event.
	   * We keep doing best effort for the remaining packets. */
	  u32 flush = (n_left + 1 > vum->cpus[thread_index].rx_buffers_len) ?
	    n_left + 1 - vum->cpus[thread_index].rx_buffers_len : 1;
	  flush = vhost_user_rx_discard_packet (vm, vui, txvq, flush);

	  n_left -= flush;
	  vlib_increment_simple_counter (vnet_main.
					 interface_main.sw_if_counters +
					 VNET_INTERFACE_COUNTER_DROP,
					 vlib_get_thread_index (),
					 vui->sw_if_index, flush);

	  vlib_error_count (vm, vhost_user_input_node.index,
			    VHOST_USER_INPUT_FUNC_ERROR_NO_BUFFER, flush);
	}
    }

  while (n_left > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b_head, *b_current;
	  u32 bi_current;
	  u16 desc_current;
	  u32 desc_data_offset;
	  vring_desc_t *desc_table = txvq->desc;

	  if (PREDICT_FALSE (vum->cpus[thread_index].rx_buffers_len <= 1))
	    {
	      /* Not enough rx_buffers
	       * Note: We yeld on 1 so we don't need to do an additional
	       * check for the next buffer prefetch.
	       */
	      n_left = 0;
	      break;
	    }

	  desc_current =
	    txvq->avail->ring[txvq->last_avail_idx & txvq->qsz_mask];
	  vum->cpus[thread_index].rx_buffers_len--;
	  bi_current = (vum->cpus[thread_index].rx_buffers)
	    [vum->cpus[thread_index].rx_buffers_len];
	  b_head = b_current = vlib_get_buffer (vm, bi_current);
	  to_next[0] = bi_current;	//We do that now so we can forget about bi_current
	  to_next++;
	  n_left_to_next--;

	  vlib_prefetch_buffer_with_index (vm,
					   (vum->
					    cpus[thread_index].rx_buffers)
					   [vum->cpus[thread_index].
					    rx_buffers_len - 1], LOAD);

	  /* Just preset the used descriptor id and length for later */
	  txvq->used->ring[txvq->last_used_idx & txvq->qsz_mask].id =
	    desc_current;
	  txvq->used->ring[txvq->last_used_idx & txvq->qsz_mask].len = 0;
	  vhost_user_log_dirty_ring (vui, txvq,
				     ring[txvq->last_used_idx &
					  txvq->qsz_mask]);

	  /* The buffer should already be initialized */
	  b_head->total_length_not_including_first_buffer = 0;
	  b_head->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;

	  if (PREDICT_FALSE (n_trace))
	    {
	      //TODO: next_index is not exactly known at that point
	      vlib_trace_buffer (vm, node, next_index, b_head,
				 /* follow_chain */ 0);
	      vhost_trace_t *t0 =
		vlib_add_trace (vm, node, b_head, sizeof (t0[0]));
	      vhost_user_rx_trace (t0, vui, qid, b_head, txvq);
	      n_trace--;
	      vlib_set_trace_count (vm, node, n_trace);
	    }

	  /* This depends on the setup but is very consistent
	   * So I think the CPU branch predictor will make a pretty good job
	   * at optimizing the decision. */
	  if (txvq->desc[desc_current].flags & VIRTQ_DESC_F_INDIRECT)
	    {
	      desc_table = map_guest_mem (vui, txvq->desc[desc_current].addr,
					  &map_hint);
	      desc_current = 0;
	      if (PREDICT_FALSE (desc_table == 0))
		{
		  vlib_error_count (vm, node->node_index,
				    VHOST_USER_INPUT_FUNC_ERROR_MMAP_FAIL, 1);
		  goto out;
		}
	    }

	  if (PREDICT_TRUE (vui->is_any_layout) ||
	      (!(desc_table[desc_current].flags & VIRTQ_DESC_F_NEXT)))
	    {
	      /* ANYLAYOUT or single buffer */
	      desc_data_offset = vui->virtio_net_hdr_sz;
	    }
	  else
	    {
	      /* CSR case without ANYLAYOUT, skip 1st buffer */
	      desc_data_offset = desc_table[desc_current].len;
	    }

	  while (1)
	    {
	      /* Get more input if necessary. Or end of packet. */
	      if (desc_data_offset == desc_table[desc_current].len)
		{
		  if (PREDICT_FALSE (desc_table[desc_current].flags &
				     VIRTQ_DESC_F_NEXT))
		    {
		      desc_current = desc_table[desc_current].next;
		      desc_data_offset = 0;
		    }
		  else
		    {
		      goto out;
		    }
		}

	      /* Get more output if necessary. Or end of packet. */
	      if (PREDICT_FALSE
		  (b_current->current_length == VLIB_BUFFER_DATA_SIZE))
		{
		  if (PREDICT_FALSE
		      (vum->cpus[thread_index].rx_buffers_len == 0))
		    {
		      /* Cancel speculation */
		      to_next--;
		      n_left_to_next++;

		      /*
		       * Checking if there are some left buffers.
		       * If not, just rewind the used buffers and stop.
		       * Note: Scheduled copies are not cancelled. This is
		       * not an issue as they would still be valid. Useless,
		       * but valid.
		       */
		      vhost_user_input_rewind_buffers (vm,
						       &vum->cpus
						       [thread_index],
						       b_head);
		      n_left = 0;
		      goto stop;
		    }

		  /* Get next output */
		  vum->cpus[thread_index].rx_buffers_len--;
		  u32 bi_next =
		    (vum->cpus[thread_index].rx_buffers)[vum->cpus
							 [thread_index].rx_buffers_len];
		  b_current->next_buffer = bi_next;
		  b_current->flags |= VLIB_BUFFER_NEXT_PRESENT;
		  bi_current = bi_next;
		  b_current = vlib_get_buffer (vm, bi_current);
		}

	      /* Prepare a copy order executed later for the data */
	      vhost_copy_t *cpy = &vum->cpus[thread_index].copy[copy_len];
	      copy_len++;
	      u32 desc_data_l =
		desc_table[desc_current].len - desc_data_offset;
	      cpy->len = VLIB_BUFFER_DATA_SIZE - b_current->current_length;
	      cpy->len = (cpy->len > desc_data_l) ? desc_data_l : cpy->len;
	      cpy->dst = (uword) (vlib_buffer_get_current (b_current) +
				  b_current->current_length);
	      cpy->src = desc_table[desc_current].addr + desc_data_offset;

	      desc_data_offset += cpy->len;

	      b_current->current_length += cpy->len;
	      b_head->total_length_not_including_first_buffer += cpy->len;
	    }

	out:
	  CLIB_PREFETCH (&n_left, sizeof (n_left), LOAD);

	  n_rx_bytes += b_head->total_length_not_including_first_buffer;
	  n_rx_packets++;

	  b_head->total_length_not_including_first_buffer -=
	    b_head->current_length;

	  /* consume the descriptor and return it as used */
	  txvq->last_avail_idx++;
	  txvq->last_used_idx++;

	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b_head);

	  vnet_buffer (b_head)->sw_if_index[VLIB_RX] = vui->sw_if_index;
	  vnet_buffer (b_head)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	  b_head->error = 0;

	  {
	    u32 next0 = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;

	    /* redirect if feature path enabled */
	    vnet_feature_start_device_input_x1 (vui->sw_if_index, &next0,
						b_head);

	    u32 bi = to_next[-1];	//Cannot use to_next[-1] in the macro
	    vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					     to_next, n_left_to_next,
					     bi, next0);
	  }

	  n_left--;

	  /*
	   * Although separating memory copies from virtio ring parsing
	   * is beneficial, we can offer to perform the copies from time
	   * to time in order to free some space in the ring.
	   */
	  if (PREDICT_FALSE (copy_len >= VHOST_USER_RX_COPY_THRESHOLD))
	    {
	      if (PREDICT_FALSE
		  (vhost_user_input_copy (vui, vum->cpus[thread_index].copy,
					  copy_len, &map_hint)))
		{
		  vlib_error_count (vm, node->node_index,
				    VHOST_USER_INPUT_FUNC_ERROR_MMAP_FAIL, 1);
		}
	      copy_len = 0;

	      /* give buffers back to driver */
	      CLIB_MEMORY_BARRIER ();
	      txvq->used->idx = txvq->last_used_idx;
	      vhost_user_log_dirty_ring (vui, txvq, idx);
	    }
	}
    stop:
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Do the memory copies */
  if (PREDICT_FALSE
      (vhost_user_input_copy (vui, vum->cpus[thread_index].copy,
			      copy_len, &map_hint)))
    {
      vlib_error_count (vm, node->node_index,
			VHOST_USER_INPUT_FUNC_ERROR_MMAP_FAIL, 1);
    }

  /* give buffers back to driver */
  CLIB_MEMORY_BARRIER ();
  txvq->used->idx = txvq->last_used_idx;
  vhost_user_log_dirty_ring (vui, txvq, idx);

  /* interrupt (call) handling */
  if ((txvq->callfd_idx != ~0) &&
      !(txvq->avail->flags & VRING_AVAIL_F_NO_INTERRUPT))
    {
      txvq->n_since_last_int += n_rx_packets;

      if (txvq->n_since_last_int > vum->coalesce_frames)
	vhost_user_send_call (vm, txvq);
    }

  /* increase rx counters */
  vlib_increment_combined_counter
    (vnet_main.interface_main.combined_sw_if_counters
     + VNET_INTERFACE_COUNTER_RX,
     vlib_get_thread_index (), vui->sw_if_index, n_rx_packets, n_rx_bytes);

  vnet_device_increment_rx_packets (thread_index, n_rx_packets);

  return n_rx_packets;
}

static uword
vhost_user_input (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * f)
{
  vhost_user_main_t *vum = &vhost_user_main;
  uword n_rx_packets = 0;
  vhost_user_intf_t *vui;
  vnet_device_input_runtime_t *rt =
    (vnet_device_input_runtime_t *) node->runtime_data;
  vnet_device_and_queue_t *dq;

  vec_foreach (dq, rt->devices_and_queues)
  {
    if (clib_smp_swap (&dq->interrupt_pending, 0) ||
	(node->state == VLIB_NODE_STATE_POLLING))
      {
	vui =
	  pool_elt_at_index (vum->vhost_user_interfaces, dq->dev_instance);
	n_rx_packets = vhost_user_if_input (vm, vum, vui, dq->queue_id, node,
					    dq->mode);
      }
  }

  return n_rx_packets;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (vhost_user_input_node) = {
  .function = vhost_user_input,
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "vhost-user-input",
  .sibling_of = "device-input",

  /* Will be enabled if/when hardware is detected. */
  .state = VLIB_NODE_STATE_DISABLED,

  .format_buffer = format_ethernet_header_with_length,
  .format_trace = format_vhost_trace,

  .n_errors = VHOST_USER_INPUT_FUNC_N_ERROR,
  .error_strings = vhost_user_input_func_error_strings,
};

VLIB_NODE_FUNCTION_MULTIARCH (vhost_user_input_node, vhost_user_input)
/* *INDENT-ON* */


void
vhost_user_tx_trace (vhost_trace_t * t,
		     vhost_user_intf_t * vui, u16 qid,
		     vlib_buffer_t * b, vhost_user_vring_t * rxvq)
{
  vhost_user_main_t *vum = &vhost_user_main;
  u32 last_avail_idx = rxvq->last_avail_idx;
  u32 desc_current = rxvq->avail->ring[last_avail_idx & rxvq->qsz_mask];
  vring_desc_t *hdr_desc = 0;
  u32 hint = 0;

  memset (t, 0, sizeof (*t));
  t->device_index = vui - vum->vhost_user_interfaces;
  t->qid = qid;

  hdr_desc = &rxvq->desc[desc_current];
  if (rxvq->desc[desc_current].flags & VIRTQ_DESC_F_INDIRECT)
    {
      t->virtio_ring_flags |= 1 << VIRTIO_TRACE_F_INDIRECT;
      /* Header is the first here */
      hdr_desc = map_guest_mem (vui, rxvq->desc[desc_current].addr, &hint);
    }
  if (rxvq->desc[desc_current].flags & VIRTQ_DESC_F_NEXT)
    {
      t->virtio_ring_flags |= 1 << VIRTIO_TRACE_F_SIMPLE_CHAINED;
    }
  if (!(rxvq->desc[desc_current].flags & VIRTQ_DESC_F_NEXT) &&
      !(rxvq->desc[desc_current].flags & VIRTQ_DESC_F_INDIRECT))
    {
      t->virtio_ring_flags |= 1 << VIRTIO_TRACE_F_SINGLE_DESC;
    }

  t->first_desc_len = hdr_desc ? hdr_desc->len : 0;
}

static_always_inline u32
vhost_user_tx_copy (vhost_user_intf_t * vui, vhost_copy_t * cpy,
		    u16 copy_len, u32 * map_hint)
{
  void *dst0, *dst1, *dst2, *dst3;
  if (PREDICT_TRUE (copy_len >= 4))
    {
      if (PREDICT_FALSE (!(dst2 = map_guest_mem (vui, cpy[0].dst, map_hint))))
	return 1;
      if (PREDICT_FALSE (!(dst3 = map_guest_mem (vui, cpy[1].dst, map_hint))))
	return 1;
      while (PREDICT_TRUE (copy_len >= 4))
	{
	  dst0 = dst2;
	  dst1 = dst3;

	  if (PREDICT_FALSE
	      (!(dst2 = map_guest_mem (vui, cpy[2].dst, map_hint))))
	    return 1;
	  if (PREDICT_FALSE
	      (!(dst3 = map_guest_mem (vui, cpy[3].dst, map_hint))))
	    return 1;

	  CLIB_PREFETCH ((void *) cpy[2].src, 64, LOAD);
	  CLIB_PREFETCH ((void *) cpy[3].src, 64, LOAD);

	  clib_memcpy (dst0, (void *) cpy[0].src, cpy[0].len);
	  clib_memcpy (dst1, (void *) cpy[1].src, cpy[1].len);

	  vhost_user_log_dirty_pages_2 (vui, cpy[0].dst, cpy[0].len, 1);
	  vhost_user_log_dirty_pages_2 (vui, cpy[1].dst, cpy[1].len, 1);
	  copy_len -= 2;
	  cpy += 2;
	}
    }
  while (copy_len)
    {
      if (PREDICT_FALSE (!(dst0 = map_guest_mem (vui, cpy->dst, map_hint))))
	return 1;
      clib_memcpy (dst0, (void *) cpy->src, cpy->len);
      vhost_user_log_dirty_pages_2 (vui, cpy->dst, cpy->len, 1);
      copy_len -= 1;
      cpy += 1;
    }
  return 0;
}


static uword
vhost_user_tx (vlib_main_t * vm,
	       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 *buffers = vlib_frame_args (frame);
  u32 n_left = frame->n_vectors;
  vhost_user_main_t *vum = &vhost_user_main;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  vhost_user_intf_t *vui =
    pool_elt_at_index (vum->vhost_user_interfaces, rd->dev_instance);
  u32 qid = ~0;
  vhost_user_vring_t *rxvq;
  u8 error;
  u32 thread_index = vlib_get_thread_index ();
  u32 map_hint = 0;
  u8 retry = 8;
  u16 copy_len;
  u16 tx_headers_len;

  if (PREDICT_FALSE (!vui->admin_up))
    {
      error = VHOST_USER_TX_FUNC_ERROR_DOWN;
      goto done3;
    }

  if (PREDICT_FALSE (!vui->is_up))
    {
      error = VHOST_USER_TX_FUNC_ERROR_NOT_READY;
      goto done3;
    }

  qid =
    VHOST_VRING_IDX_RX (*vec_elt_at_index
			(vui->per_cpu_tx_qid, thread_index));
  rxvq = &vui->vrings[qid];
  if (PREDICT_FALSE (vui->use_tx_spinlock))
    vhost_user_vring_lock (vui, qid);

retry:
  error = VHOST_USER_TX_FUNC_ERROR_NONE;
  tx_headers_len = 0;
  copy_len = 0;
  while (n_left > 0)
    {
      vlib_buffer_t *b0, *current_b0;
      u16 desc_head, desc_index, desc_len;
      vring_desc_t *desc_table;
      uword buffer_map_addr;
      u32 buffer_len;
      u16 bytes_left;

      if (PREDICT_TRUE (n_left > 1))
	vlib_prefetch_buffer_with_index (vm, buffers[1], LOAD);

      b0 = vlib_get_buffer (vm, buffers[0]);

      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  vum->cpus[thread_index].current_trace =
	    vlib_add_trace (vm, node, b0,
			    sizeof (*vum->cpus[thread_index].current_trace));
	  vhost_user_tx_trace (vum->cpus[thread_index].current_trace,
			       vui, qid / 2, b0, rxvq);
	}

      if (PREDICT_FALSE (rxvq->last_avail_idx == rxvq->avail->idx))
	{
	  error = VHOST_USER_TX_FUNC_ERROR_PKT_DROP_NOBUF;
	  goto done;
	}

      desc_table = rxvq->desc;
      desc_head = desc_index =
	rxvq->avail->ring[rxvq->last_avail_idx & rxvq->qsz_mask];

      /* Go deeper in case of indirect descriptor
       * I don't know of any driver providing indirect for RX. */
      if (PREDICT_FALSE (rxvq->desc[desc_head].flags & VIRTQ_DESC_F_INDIRECT))
	{
	  if (PREDICT_FALSE
	      (rxvq->desc[desc_head].len < sizeof (vring_desc_t)))
	    {
	      error = VHOST_USER_TX_FUNC_ERROR_INDIRECT_OVERFLOW;
	      goto done;
	    }
	  if (PREDICT_FALSE
	      (!(desc_table =
		 map_guest_mem (vui, rxvq->desc[desc_index].addr,
				&map_hint))))
	    {
	      error = VHOST_USER_TX_FUNC_ERROR_MMAP_FAIL;
	      goto done;
	    }
	  desc_index = 0;
	}

      desc_len = vui->virtio_net_hdr_sz;
      buffer_map_addr = desc_table[desc_index].addr;
      buffer_len = desc_table[desc_index].len;

      {
	// Get a header from the header array
	virtio_net_hdr_mrg_rxbuf_t *hdr =
	  &vum->cpus[thread_index].tx_headers[tx_headers_len];
	tx_headers_len++;
	hdr->hdr.flags = 0;
	hdr->hdr.gso_type = 0;
	hdr->num_buffers = 1;	//This is local, no need to check

	// Prepare a copy order executed later for the header
	vhost_copy_t *cpy = &vum->cpus[thread_index].copy[copy_len];
	copy_len++;
	cpy->len = vui->virtio_net_hdr_sz;
	cpy->dst = buffer_map_addr;
	cpy->src = (uword) hdr;
      }

      buffer_map_addr += vui->virtio_net_hdr_sz;
      buffer_len -= vui->virtio_net_hdr_sz;
      bytes_left = b0->current_length;
      current_b0 = b0;
      while (1)
	{
	  if (buffer_len == 0)
	    {			//Get new output
	      if (desc_table[desc_index].flags & VIRTQ_DESC_F_NEXT)
		{
		  //Next one is chained
		  desc_index = desc_table[desc_index].next;
		  buffer_map_addr = desc_table[desc_index].addr;
		  buffer_len = desc_table[desc_index].len;
		}
	      else if (vui->virtio_net_hdr_sz == 12)	//MRG is available
		{
		  virtio_net_hdr_mrg_rxbuf_t *hdr =
		    &vum->cpus[thread_index].tx_headers[tx_headers_len - 1];

		  //Move from available to used buffer
		  rxvq->used->ring[rxvq->last_used_idx & rxvq->qsz_mask].id =
		    desc_head;
		  rxvq->used->ring[rxvq->last_used_idx & rxvq->qsz_mask].len =
		    desc_len;
		  vhost_user_log_dirty_ring (vui, rxvq,
					     ring[rxvq->last_used_idx &
						  rxvq->qsz_mask]);

		  rxvq->last_avail_idx++;
		  rxvq->last_used_idx++;
		  hdr->num_buffers++;
		  desc_len = 0;

		  if (PREDICT_FALSE
		      (rxvq->last_avail_idx == rxvq->avail->idx))
		    {
		      //Dequeue queued descriptors for this packet
		      rxvq->last_used_idx -= hdr->num_buffers - 1;
		      rxvq->last_avail_idx -= hdr->num_buffers - 1;
		      error = VHOST_USER_TX_FUNC_ERROR_PKT_DROP_NOBUF;
		      goto done;
		    }

		  desc_table = rxvq->desc;
		  desc_head = desc_index =
		    rxvq->avail->ring[rxvq->last_avail_idx & rxvq->qsz_mask];
		  if (PREDICT_FALSE
		      (rxvq->desc[desc_head].flags & VIRTQ_DESC_F_INDIRECT))
		    {
		      //It is seriously unlikely that a driver will put indirect descriptor
		      //after non-indirect descriptor.
		      if (PREDICT_FALSE
			  (rxvq->desc[desc_head].len < sizeof (vring_desc_t)))
			{
			  error = VHOST_USER_TX_FUNC_ERROR_INDIRECT_OVERFLOW;
			  goto done;
			}
		      if (PREDICT_FALSE
			  (!(desc_table =
			     map_guest_mem (vui,
					    rxvq->desc[desc_index].addr,
					    &map_hint))))
			{
			  error = VHOST_USER_TX_FUNC_ERROR_MMAP_FAIL;
			  goto done;
			}
		      desc_index = 0;
		    }
		  buffer_map_addr = desc_table[desc_index].addr;
		  buffer_len = desc_table[desc_index].len;
		}
	      else
		{
		  error = VHOST_USER_TX_FUNC_ERROR_PKT_DROP_NOMRG;
		  goto done;
		}
	    }

	  {
	    vhost_copy_t *cpy = &vum->cpus[thread_index].copy[copy_len];
	    copy_len++;
	    cpy->len = bytes_left;
	    cpy->len = (cpy->len > buffer_len) ? buffer_len : cpy->len;
	    cpy->dst = buffer_map_addr;
	    cpy->src = (uword) vlib_buffer_get_current (current_b0) +
	      current_b0->current_length - bytes_left;

	    bytes_left -= cpy->len;
	    buffer_len -= cpy->len;
	    buffer_map_addr += cpy->len;
	    desc_len += cpy->len;

	    CLIB_PREFETCH (&rxvq->desc, CLIB_CACHE_LINE_BYTES, LOAD);
	  }

	  // Check if vlib buffer has more data. If not, get more or break.
	  if (PREDICT_TRUE (!bytes_left))
	    {
	      if (PREDICT_FALSE
		  (current_b0->flags & VLIB_BUFFER_NEXT_PRESENT))
		{
		  current_b0 = vlib_get_buffer (vm, current_b0->next_buffer);
		  bytes_left = current_b0->current_length;
		}
	      else
		{
		  //End of packet
		  break;
		}
	    }
	}

      //Move from available to used ring
      rxvq->used->ring[rxvq->last_used_idx & rxvq->qsz_mask].id = desc_head;
      rxvq->used->ring[rxvq->last_used_idx & rxvq->qsz_mask].len = desc_len;
      vhost_user_log_dirty_ring (vui, rxvq,
				 ring[rxvq->last_used_idx & rxvq->qsz_mask]);
      rxvq->last_avail_idx++;
      rxvq->last_used_idx++;

      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  vum->cpus[thread_index].current_trace->hdr =
	    vum->cpus[thread_index].tx_headers[tx_headers_len - 1];
	}

      n_left--;			//At the end for error counting when 'goto done' is invoked

      /*
       * Do the copy periodically to prevent
       * vum->cpus[thread_index].copy array overflow and corrupt memory
       */
      if (PREDICT_FALSE (copy_len >= VHOST_USER_TX_COPY_THRESHOLD))
	{
	  if (PREDICT_FALSE
	      (vhost_user_tx_copy (vui, vum->cpus[thread_index].copy,
				   copy_len, &map_hint)))
	    {
	      vlib_error_count (vm, node->node_index,
				VHOST_USER_TX_FUNC_ERROR_MMAP_FAIL, 1);
	    }
	  copy_len = 0;

	  /* give buffers back to driver */
	  CLIB_MEMORY_BARRIER ();
	  rxvq->used->idx = rxvq->last_used_idx;
	  vhost_user_log_dirty_ring (vui, rxvq, idx);
	}
      buffers++;
    }

done:
  //Do the memory copies
  if (PREDICT_FALSE
      (vhost_user_tx_copy (vui, vum->cpus[thread_index].copy,
			   copy_len, &map_hint)))
    {
      vlib_error_count (vm, node->node_index,
			VHOST_USER_TX_FUNC_ERROR_MMAP_FAIL, 1);
    }

  CLIB_MEMORY_BARRIER ();
  rxvq->used->idx = rxvq->last_used_idx;
  vhost_user_log_dirty_ring (vui, rxvq, idx);

  /*
   * When n_left is set, error is always set to something too.
   * In case error is due to lack of remaining buffers, we go back up and
   * retry.
   * The idea is that it is better to waste some time on packets
   * that have been processed already than dropping them and get
   * more fresh packets with a good likelyhood that they will be dropped too.
   * This technique also gives more time to VM driver to pick-up packets.
   * In case the traffic flows from physical to virtual interfaces, this
   * technique will end-up leveraging the physical NIC buffer in order to
   * absorb the VM's CPU jitter.
   */
  if (n_left && (error == VHOST_USER_TX_FUNC_ERROR_PKT_DROP_NOBUF) && retry)
    {
      retry--;
      goto retry;
    }

  /* interrupt (call) handling */
  if ((rxvq->callfd_idx != ~0) &&
      !(rxvq->avail->flags & VRING_AVAIL_F_NO_INTERRUPT))
    {
      rxvq->n_since_last_int += frame->n_vectors - n_left;

      if (rxvq->n_since_last_int > vum->coalesce_frames)
	vhost_user_send_call (vm, rxvq);
    }

  vhost_user_vring_unlock (vui, qid);

done3:
  if (PREDICT_FALSE (n_left && error != VHOST_USER_TX_FUNC_ERROR_NONE))
    {
      vlib_error_count (vm, node->node_index, error, n_left);
      vlib_increment_simple_counter
	(vnet_main.interface_main.sw_if_counters
	 + VNET_INTERFACE_COUNTER_DROP,
	 thread_index, vui->sw_if_index, n_left);
    }

  vlib_buffer_free (vm, vlib_frame_args (frame), frame->n_vectors);
  return frame->n_vectors;
}

static uword
vhost_user_send_interrupt_process (vlib_main_t * vm,
				   vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  vhost_user_intf_t *vui;
  f64 timeout = 3153600000.0 /* 100 years */ ;
  uword event_type, *event_data = 0;
  vhost_user_main_t *vum = &vhost_user_main;
  u16 *queue;
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
	      vec_foreach (queue, vui->rx_queues)
		{
		  vhost_user_vring_t *rxvq =
		    &vui->vrings[VHOST_VRING_IDX_RX (*queue)];
		  vhost_user_vring_t *txvq =
		    &vui->vrings[VHOST_VRING_IDX_TX (*queue)];

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
VLIB_REGISTER_NODE (vhost_user_send_interrupt_node,static) = {
    .function = vhost_user_send_interrupt_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "vhost-user-send-interrupt-process",
};
/* *INDENT-ON* */

static clib_error_t *
vhost_user_interface_rx_mode_change (vnet_main_t * vnm, u32 hw_if_index,
				     u32 qid, vnet_hw_interface_rx_mode mode)
{
  vlib_main_t *vm = vnm->vlib_main;
  vnet_hw_interface_t *hif = vnet_get_hw_interface (vnm, hw_if_index);
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui =
    pool_elt_at_index (vum->vhost_user_interfaces, hif->dev_instance);
  vhost_user_vring_t *txvq = &vui->vrings[VHOST_VRING_IDX_TX (qid)];

  if ((mode == VNET_HW_INTERFACE_RX_MODE_INTERRUPT) ||
      (mode == VNET_HW_INTERFACE_RX_MODE_ADAPTIVE))
    {
      if (txvq->kickfd_idx == ~0)
	{
	  // We cannot support interrupt mode if the driver opts out
	  return clib_error_return (0, "Driver does not support interrupt");
	}
      if (txvq->mode == VNET_HW_INTERFACE_RX_MODE_POLLING)
	{
	  vum->ifq_count++;
	  // Start the timer if this is the first encounter on interrupt
	  // interface/queue
	  if ((vum->ifq_count == 1) &&
	      (vum->coalesce_time > 0.0) && (vum->coalesce_frames > 0))
	    vlib_process_signal_event (vm,
				       vhost_user_send_interrupt_node.index,
				       VHOST_USER_EVENT_START_TIMER, 0);
	}
    }
  else if (mode == VNET_HW_INTERFACE_RX_MODE_POLLING)
    {
      if (((txvq->mode == VNET_HW_INTERFACE_RX_MODE_INTERRUPT) ||
	   (txvq->mode == VNET_HW_INTERFACE_RX_MODE_ADAPTIVE)) &&
	  vum->ifq_count)
	{
	  vum->ifq_count--;
	  // Stop the timer if there is no more interrupt interface/queue
	  if ((vum->ifq_count == 0) &&
	      (vum->coalesce_time > 0.0) && (vum->coalesce_frames > 0))
	    vlib_process_signal_event (vm,
				       vhost_user_send_interrupt_node.index,
				       VHOST_USER_EVENT_STOP_TIMER, 0);
	}
    }

  txvq->mode = mode;
  if (mode == VNET_HW_INTERFACE_RX_MODE_POLLING)
    txvq->used->flags = VRING_USED_F_NO_NOTIFY;
  else if ((mode == VNET_HW_INTERFACE_RX_MODE_ADAPTIVE) ||
	   (mode == VNET_HW_INTERFACE_RX_MODE_INTERRUPT))
    txvq->used->flags = 0;
  else
    {
      clib_warning ("BUG: unhandled mode %d changed for if %d queue %d", mode,
		    hw_if_index, qid);
      return clib_error_return (0, "unsupported");
    }

  return 0;
}

static clib_error_t *
vhost_user_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index,
				    u32 flags)
{
  vnet_hw_interface_t *hif = vnet_get_hw_interface (vnm, hw_if_index);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui =
    pool_elt_at_index (vum->vhost_user_interfaces, hif->dev_instance);

  vui->admin_up = is_up;

  if (is_up && vui->is_up)
    vnet_hw_interface_set_flags (vnm, vui->hw_if_index,
				 VNET_HW_INTERFACE_FLAG_LINK_UP);

  return /* no error */ 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (vhost_user_dev_class,static) = {
  .name = "vhost-user",
  .tx_function = vhost_user_tx,
  .tx_function_n_errors = VHOST_USER_TX_FUNC_N_ERROR,
  .tx_function_error_strings = vhost_user_tx_func_error_strings,
  .format_device_name = format_vhost_user_interface_name,
  .name_renumber = vhost_user_name_renumber,
  .admin_up_down_function = vhost_user_interface_admin_up_down,
  .rx_mode_change_function = vhost_user_interface_rx_mode_change,
  .format_tx_trace = format_vhost_trace,
};

VLIB_DEVICE_TX_FUNCTION_MULTIARCH (vhost_user_dev_class,
				   vhost_user_tx)
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
		      DBG_SOCK ("getsockopt returned %d", retval);
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
  vhost_user_update_iface_state (vui);

  for (q = 0; q < VHOST_VRING_MAX_N; q++)
    {
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
  u16 *queue;

  if (!(hwif = vnet_get_sup_hw_interface (vnm, sw_if_index)) ||
      hwif->dev_class_index != vhost_user_dev_class.index)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  DBG_SOCK ("Deleting vhost-user interface %s (instance %d)",
	    hwif->name, hwif->dev_instance);

  vui = pool_elt_at_index (vum->vhost_user_interfaces, hwif->dev_instance);

  vec_foreach (queue, vui->rx_queues)
  {
    vhost_user_vring_t *txvq;

    txvq = &vui->vrings[VHOST_VRING_IDX_TX (*queue)];
    if ((vum->ifq_count > 0) &&
	((txvq->mode == VNET_HW_INTERFACE_RX_MODE_INTERRUPT) ||
	 (txvq->mode == VNET_HW_INTERFACE_RX_MODE_ADAPTIVE)))
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
     vhost_user_dev_class.index,
     vui - vum->vhost_user_interfaces /* device instance */ ,
     hwaddr /* ethernet address */ ,
     &vui->hw_if_index, 0 /* flag change */ );

  if (error)
    clib_error_report (error);

  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, vui->hw_if_index);
  hi->max_l3_packet_bytes[VLIB_RX] = hi->max_l3_packet_bytes[VLIB_TX] = 9000;
}

/*
 *  Initialize vui with specified attributes
 */
static void
vhost_user_vui_init (vnet_main_t * vnm,
		     vhost_user_intf_t * vui,
		     int server_sock_fd,
		     const char *sock_filename,
		     u64 feature_mask, u32 * sw_if_index)
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
  vui->is_up = 0;
  vui->feature_mask = feature_mask;
  vui->clib_file_index = ~0;
  vui->log_base_addr = 0;
  vui->if_index = vui - vum->vhost_user_interfaces;
  mhash_set_mem (&vum->if_index_by_sock_name, vui->sock_filename,
		 &vui->if_index, 0);

  for (q = 0; q < VHOST_VRING_MAX_N; q++)
    vhost_user_vring_init (vui, q);

  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
  vnet_hw_interface_set_flags (vnm, vui->hw_if_index, 0);

  if (sw_if_index)
    *sw_if_index = vui->sw_if_index;

  for (q = 0; q < VHOST_VRING_MAX_N; q++)
    {
      vui->vring_locks[q] = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
						    CLIB_CACHE_LINE_BYTES);
      memset ((void *) vui->vring_locks[q], 0, CLIB_CACHE_LINE_BYTES);
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
		      u8 renumber, u32 custom_dev_instance, u8 * hwaddr)
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

  pool_get (vhost_user_main.vhost_user_interfaces, vui);

  vhost_user_create_ethernet (vnm, vm, vui, hwaddr);
  vhost_user_vui_init (vnm, vui, server_sock_fd, sock_filename,
		       feature_mask, &sw_if_idx);

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
		      u64 feature_mask, u8 renumber, u32 custom_dev_instance)
{
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui = NULL;
  u32 sw_if_idx = ~0;
  int server_sock_fd = -1;
  int rv = 0;
  vnet_hw_interface_t *hwif;
  uword *if_index;

  if (!(hwif = vnet_get_sup_hw_interface (vnm, sw_if_index)) ||
      hwif->dev_class_index != vhost_user_dev_class.index)
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
		       sock_filename, feature_mask, &sw_if_idx);

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
				  renumber, custom_dev_instance, hw)))
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
	    vnet_get_sup_hw_interface (vnm, sw_if_index);
	  if (hwif == NULL ||
	      vhost_user_dev_class.index != hwif->dev_class_index)
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
  u8 *s = NULL;
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
  u16 *queue;
  u32 ci;
  int i, j, q;
  int show_descr = 0;
  struct feat_struct
  {
    u8 bit;
    char *str;
  };
  struct feat_struct *feat_entry;

  static struct feat_struct feat_array[] = {
#define _(s,b) { .str = #s, .bit = b, },
    foreach_virtio_net_feature
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
	  vec_add1 (hw_if_indices, hw_if_index);
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
      pool_foreach (vui, vum->vhost_user_interfaces,
		    vec_add1 (hw_if_indices, vui->hw_if_index);
	);
    }
  vlib_cli_output (vm, "Virtio vhost-user interfaces");
  vlib_cli_output (vm, "Global:\n  coalesce frames %d time %e",
		   vum->coalesce_frames, vum->coalesce_time);
  vlib_cli_output (vm, "  number of rx virtqueues in interrupt mode: %d",
		   vum->ifq_count);

  for (i = 0; i < vec_len (hw_if_indices); i++)
    {
      hi = vnet_get_hw_interface (vnm, hw_if_indices[i]);
      vui = pool_elt_at_index (vum->vhost_user_interfaces, hi->dev_instance);
      vlib_cli_output (vm, "Interface: %s (ifindex %d)",
		       hi->name, hw_if_indices[i]);

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

      vec_foreach (queue, vui->rx_queues)
      {
	vnet_main_t *vnm = vnet_get_main ();
	uword thread_index;
	vnet_hw_interface_rx_mode mode;

	thread_index = vnet_get_device_input_thread_index (vnm,
							   vui->hw_if_index,
							   *queue);
	vnet_hw_interface_get_rx_mode (vnm, vui->hw_if_index, *queue, &mode);
	vlib_cli_output (vm, "   thread %d on vring %d, %U\n",
			 thread_index, VHOST_VRING_IDX_TX (*queue),
			 format_vnet_hw_interface_rx_mode, mode);
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

	  if (vui->vrings[q].avail && vui->vrings[q].used)
	    vlib_cli_output (vm,
			     "  avail.flags %x avail.idx %d used.flags %x used.idx %d\n",
			     vui->vrings[q].avail->flags,
			     vui->vrings[q].avail->idx,
			     vui->vrings[q].used->flags,
			     vui->vrings[q].used->idx);

	  int kickfd = UNIX_GET_FD (vui->vrings[q].kickfd_idx);
	  int callfd = UNIX_GET_FD (vui->vrings[q].callfd_idx);
	  vlib_cli_output (vm, "  kickfd %d callfd %d errfd %d\n",
			   kickfd, callfd, vui->vrings[q].errfd);

	  if (show_descr)
	    {
	      vlib_cli_output (vm, "\n  descriptor table:\n");
	      vlib_cli_output (vm,
			       "   id          addr         len  flags  next      user_addr\n");
	      vlib_cli_output (vm,
			       "  ===== ================== ===== ====== ===== ==================\n");
	      for (j = 0; j < vui->vrings[q].qsz_mask + 1; j++)
		{
		  u32 mem_hint = 0;
		  vlib_cli_output (vm,
				   "  %-5d 0x%016lx %-5d 0x%04x %-5d 0x%016lx\n",
				   j, vui->vrings[q].desc[j].addr,
				   vui->vrings[q].desc[j].len,
				   vui->vrings[q].desc[j].flags,
				   vui->vrings[q].desc[j].next,
				   pointer_to_uword (map_guest_mem
						     (vui,
						      vui->vrings[q].desc[j].
						      addr, &mem_hint)));
		}
	    }
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
 * - <b>socket <socket-filename></b> - Name of the linux socket used by QEMU/VM and
 * VPP to manage the vHost interface. If socket does not already exist, VPP will
 * create the socket.
 *
 * - <b>server</b> - Optional flag to indicate that VPP should be the server for the
 * linux socket. If not provided, VPP will be the client.
 *
 * - <b>feature-mask <hex></b> - Optional virtio/vhost feature set negotiated at
 * startup. By default, all supported features will be advertised. Otherwise,
 * provide the set of features desired.
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
 * - <b>mode [interrupt | polling]</b> - Optional parameter specifying
 * the input thread polling policy.
 *
 * @cliexpar
 * Example of how to create a vhost interface with VPP as the client and all features enabled:
 * @cliexstart{create vhost-user socket /tmp/vhost1.sock}
 * VirtualEthernet0/0/0
 * @cliexend
 * Example of how to create a vhost interface with VPP as the server and with just
 * multiple queues enabled:
 * @cliexstart{create vhost-user socket /tmp/vhost2.sock server feature-mask 0x40400000}
 * VirtualEthernet0/0/1
 * @cliexend
 * Once the vHost interface is created, enable the interface using:
 * @cliexcmd{set interface state VirtualEthernet0/0/0 up}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vhost_user_connect_command, static) = {
    .path = "create vhost-user",
    .short_help = "create vhost-user socket <socket-filename> [server] "
    "[feature-mask <hex>] [hwaddr <mac-addr>] [renumber <dev_instance>] ",
    .function = vhost_user_connect_command_fn,
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
 *  socket filename /tmp/vhost1.sock type client errno "Success"
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
    .short_help = "show vhost-user [<interface> [<interface> [..]]] [descriptors]",
    .function = show_vhost_user_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
debug_vhost_user_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  vhost_user_main_t *vum = &vhost_user_main;
  u8 onoff = 0;
  u8 input_found = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing argument");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (input_found)
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}

      if (unformat (line_input, "on"))
	{
	  input_found = 1;
	  onoff = 1;
	}
      else if (unformat (line_input, "off"))
	{
	  input_found = 1;
	  onoff = 0;
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  vum->debug = onoff;

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (debug_vhost_user_command, static) = {
    .path = "debug vhost-user",
    .short_help = "debug vhost-user <on | off>",
    .function = debug_vhost_user_command_fn,
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
