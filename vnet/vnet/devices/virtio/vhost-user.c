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

#include <vnet/devices/virtio/vhost-user.h>

#define VHOST_USER_DEBUG_SOCKET 0
#define VHOST_USER_DEBUG_VQ 0

/* Set to get virtio_net_hdr in buffer pre-data
   details will be shown in  packet trace */
#define VHOST_USER_COPY_TX_HDR 0

#if VHOST_USER_DEBUG_SOCKET == 1
#define DBG_SOCK(args...) clib_warning(args);
#else
#define DBG_SOCK(args...)
#endif

#if VHOST_USER_DEBUG_VQ == 1
#define DBG_VQ(args...) clib_warning(args);
#else
#define DBG_VQ(args...)
#endif

vlib_node_registration_t vhost_user_input_node;

#define foreach_vhost_user_tx_func_error      \
  _(NONE, "no error")  \
  _(NOT_READY, "vhost user state error")  \
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
  vhost_user_main_t *vum = &vhost_user_main;

  vec_validate_init_empty (vum->show_dev_instance_by_real_dev_instance,
			   hi->dev_instance, ~0);

  vum->show_dev_instance_by_real_dev_instance[hi->dev_instance] =
    new_dev_instance;

  DBG_SOCK ("renumbered vhost-user interface dev_instance %d to %d",
	    hi->dev_instance, new_dev_instance);

  return 0;
}


static inline void *
map_guest_mem (vhost_user_intf_t * vui, uword addr)
{
  int i;
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
  i = __builtin_ctzll (_mm_movemask_epi8 (r));

  if (i < vui->nregions)
    {
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
	  return (void *) (vui->region_mmap_addr[i] + addr -
			   vui->regions[i].guest_phys_addr);
	}
    }
#endif
  DBG_VQ ("failed to map guest mem addr %llx", addr);
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
			    page_sz) & ~(page_sz - 1);

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


static clib_error_t *
vhost_user_callfd_read_ready (unix_file_t * uf)
{
  __attribute__ ((unused)) int n;
  u8 buff[8];
  n = read (uf->file_descriptor, ((char *) &buff), 8);
  return 0;
}

static inline void
vhost_user_if_disconnect (vhost_user_intf_t * vui)
{
  vhost_user_main_t *vum = &vhost_user_main;
  vnet_main_t *vnm = vnet_get_main ();
  int q;

  vnet_hw_interface_set_flags (vnm, vui->hw_if_index, 0);

  if (vui->unix_file_index != ~0)
    {
      unix_file_del (&unix_main, unix_main.file_pool + vui->unix_file_index);
      vui->unix_file_index = ~0;
    }
  else
    close (vui->unix_fd);

  hash_unset (vum->vhost_user_interface_index_by_sock_fd, vui->unix_fd);
  hash_unset (vum->vhost_user_interface_index_by_listener_fd, vui->unix_fd);
  vui->unix_fd = -1;
  vui->is_up = 0;
  for (q = 0; q < vui->num_vrings; q++)
    {
      if (vui->vrings[q].callfd > -1)
	{
	  unix_file_t *uf = pool_elt_at_index (unix_main.file_pool,
					       vui->vrings[q].callfd_idx);
	  unix_file_del (&unix_main, uf);
	}

      if (vui->vrings[q].kickfd > -1)
	close (vui->vrings[q].kickfd);

      vui->vrings[q].callfd = -1;
      vui->vrings[q].kickfd = -1;
      vui->vrings[q].desc = NULL;
      vui->vrings[q].avail = NULL;
      vui->vrings[q].used = NULL;
      vui->vrings[q].log_guest_addr = 0;
      vui->vrings[q].log_used = 0;
    }

  unmap_all_mem_regions (vui);
  DBG_SOCK ("interface ifindex %d disconnected", vui->sw_if_index);
}

#define VHOST_LOG_PAGE 0x1000
always_inline void
vhost_user_log_dirty_pages (vhost_user_intf_t * vui, u64 addr, u64 len)
{
  if (PREDICT_TRUE (vui->log_base_addr == 0
		    || !(vui->features & (1 << FEAT_VHOST_F_LOG_ALL))))
    {
      return;
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

#define vhost_user_log_dirty_ring(vui, vq, member) \
  if (PREDICT_FALSE(vq->log_used)) { \
    vhost_user_log_dirty_pages(vui, vq->log_guest_addr + STRUCT_OFFSET_OF(vring_used_t, member), \
                             sizeof(vq->used->member)); \
  }

static clib_error_t *
vhost_user_socket_read (unix_file_t * uf)
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
  uword *p;
  u8 q;
  unix_file_t template = { 0 };
  vnet_main_t *vnm = vnet_get_main ();

  p = hash_get (vum->vhost_user_interface_index_by_sock_fd,
		uf->file_descriptor);
  if (p == 0)
    {
      DBG_SOCK ("FD %d doesn't belong to any interface", uf->file_descriptor);
      return 0;
    }
  else
    vui = vec_elt_at_index (vum->vhost_user_interfaces, p[0]);

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

  switch (msg.request)
    {
    case VHOST_USER_GET_FEATURES:
      DBG_SOCK ("if %d msg VHOST_USER_GET_FEATURES", vui->hw_if_index);

      msg.flags |= 4;
      msg.u64 = (1 << FEAT_VIRTIO_NET_F_MRG_RXBUF) |
	(1 << FEAT_VIRTIO_F_ANY_LAYOUT) |
	(1 << FEAT_VIRTIO_F_INDIRECT_DESC) |
	(1 << FEAT_VHOST_F_LOG_ALL) |
	(1 << FEAT_VIRTIO_NET_F_GUEST_ANNOUNCE) |
	(1 << FEAT_VHOST_USER_F_PROTOCOL_FEATURES) |
	(1UL << FEAT_VIRTIO_F_VERSION_1);
      msg.u64 &= vui->feature_mask;

      msg.size = sizeof (msg.u64);
      break;

    case VHOST_USER_SET_FEATURES:
      DBG_SOCK ("if %d msg VHOST_USER_SET_FEATURES features 0x%016llx",
		vui->hw_if_index, msg.u64);

      vui->features = msg.u64;

      if (vui->features & (1 << FEAT_VIRTIO_NET_F_MRG_RXBUF))
	vui->virtio_net_hdr_sz = 12;
      else
	vui->virtio_net_hdr_sz = 10;

      vui->is_any_layout =
	(vui->features & (1 << FEAT_VIRTIO_F_ANY_LAYOUT)) ? 1 : 0;

      ASSERT (vui->virtio_net_hdr_sz < VLIB_BUFFER_PRE_DATA_SIZE);
      vnet_hw_interface_set_flags (vnm, vui->hw_if_index, 0);
      vui->is_up = 0;

      for (q = 0; q < 2; q++)
	{
	  vui->vrings[q].desc = 0;
	  vui->vrings[q].avail = 0;
	  vui->vrings[q].used = 0;
	  vui->vrings[q].log_guest_addr = 0;
	  vui->vrings[q].log_used = 0;
	}

      DBG_SOCK ("interface %d disconnected", vui->sw_if_index);

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
			    page_sz) & ~(page_sz - 1);

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
	  (msg.state.num % 2))	/* must be power of 2 */
	goto close_socket;
      vui->vrings[msg.state.index].qsz = msg.state.num;
      break;

    case VHOST_USER_SET_VRING_ADDR:
      DBG_SOCK ("if %d msg VHOST_USER_SET_VRING_ADDR idx %d",
		vui->hw_if_index, msg.state.index);

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
	vui->vrings[msg.state.index].used->idx;

      /* tell driver that we don't want interrupts */
      vui->vrings[msg.state.index].used->flags |= 1;
      break;

    case VHOST_USER_SET_OWNER:
      DBG_SOCK ("if %d msg VHOST_USER_SET_OWNER", vui->hw_if_index);
      break;

    case VHOST_USER_RESET_OWNER:
      DBG_SOCK ("if %d msg VHOST_USER_RESET_OWNER", vui->hw_if_index);
      break;

    case VHOST_USER_SET_VRING_CALL:
      DBG_SOCK ("if %d msg VHOST_USER_SET_VRING_CALL u64 %d",
		vui->hw_if_index, msg.u64);

      q = (u8) (msg.u64 & 0xFF);

      if (!(msg.u64 & 0x100))
	{
	  if (number_of_fds != 1)
	    goto close_socket;

	  /* if there is old fd, delete it */
	  if (vui->vrings[q].callfd > -1)
	    {
	      unix_file_t *uf = pool_elt_at_index (unix_main.file_pool,
						   vui->vrings[q].callfd_idx);
	      unix_file_del (&unix_main, uf);
	    }
	  vui->vrings[q].callfd = fds[0];
	  template.read_function = vhost_user_callfd_read_ready;
	  template.file_descriptor = fds[0];
	  vui->vrings[q].callfd_idx = unix_file_add (&unix_main, &template);
	}
      else
	vui->vrings[q].callfd = -1;
      break;

    case VHOST_USER_SET_VRING_KICK:
      DBG_SOCK ("if %d msg VHOST_USER_SET_VRING_KICK u64 %d",
		vui->hw_if_index, msg.u64);

      q = (u8) (msg.u64 & 0xFF);

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
      break;

    case VHOST_USER_SET_VRING_ERR:
      DBG_SOCK ("if %d msg VHOST_USER_SET_VRING_ERR u64 %d",
		vui->hw_if_index, msg.u64);

      q = (u8) (msg.u64 & 0xFF);

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
		vui->hw_if_index, msg.state.index, msg.state.num);

      vui->vrings[msg.state.index].last_avail_idx = msg.state.num;
      break;

    case VHOST_USER_GET_VRING_BASE:
      DBG_SOCK ("if %d msg VHOST_USER_GET_VRING_BASE idx %d num %d",
		vui->hw_if_index, msg.state.index, msg.state.num);

      /* Spec says: Client must [...] stop ring upon receiving VHOST_USER_GET_VRING_BASE. */
      vui->vrings[msg.state.index].enabled = 0;

      msg.state.num = vui->vrings[msg.state.index].last_avail_idx;
      msg.flags |= 4;
      msg.size = sizeof (msg.state);
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
	  (msg.log.size + msg.log.offset + page_sz) & ~(page_sz - 1);

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
      DBG_SOCK ("if %d msg VHOST_USER_GET_PROTOCOL_FEATURES",
		vui->hw_if_index);

      msg.flags |= 4;
      msg.u64 = (1 << VHOST_USER_PROTOCOL_F_LOG_SHMFD);
      msg.size = sizeof (msg.u64);
      break;

    case VHOST_USER_SET_PROTOCOL_FEATURES:
      DBG_SOCK ("if %d msg VHOST_USER_SET_PROTOCOL_FEATURES features 0x%lx",
		vui->hw_if_index, msg.u64);

      vui->protocol_features = msg.u64;

      break;

    case VHOST_USER_SET_VRING_ENABLE:
      DBG_SOCK ("if %d VHOST_USER_SET_VRING_ENABLE, enable: %d",
		vui->hw_if_index, msg.state.num);
      vui->vrings[msg.state.index].enabled = msg.state.num;
      break;

    default:
      DBG_SOCK ("unknown vhost-user message %d received. closing socket",
		msg.request);
      goto close_socket;
    }

  /* if we have pointers to descriptor table, go up */
  if (!vui->is_up &&
      vui->vrings[VHOST_NET_VRING_IDX_TX].desc &&
      vui->vrings[VHOST_NET_VRING_IDX_RX].desc)
    {

      DBG_SOCK ("interface %d connected", vui->sw_if_index);

      vnet_hw_interface_set_flags (vnm, vui->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      vui->is_up = 1;

    }

  /* if we need to reply */
  if (msg.flags & 4)
    {
      n =
	send (uf->file_descriptor, &msg, VHOST_USER_MSG_HDR_SZ + msg.size, 0);
      if (n != (msg.size + VHOST_USER_MSG_HDR_SZ))
	goto close_socket;
    }

  return 0;

close_socket:
  vhost_user_if_disconnect (vui);
  return 0;
}

static clib_error_t *
vhost_user_socket_error (unix_file_t * uf)
{
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui;
  uword *p;

  p = hash_get (vum->vhost_user_interface_index_by_sock_fd,
		uf->file_descriptor);
  if (p == 0)
    {
      DBG_SOCK ("fd %d doesn't belong to any interface", uf->file_descriptor);
      return 0;
    }
  else
    vui = vec_elt_at_index (vum->vhost_user_interfaces, p[0]);

  vhost_user_if_disconnect (vui);
  return 0;
}

static clib_error_t *
vhost_user_socksvr_accept_ready (unix_file_t * uf)
{
  int client_fd, client_len;
  struct sockaddr_un client;
  unix_file_t template = { 0 };
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui;
  uword *p;

  p = hash_get (vum->vhost_user_interface_index_by_listener_fd,
		uf->file_descriptor);
  if (p == 0)
    {
      DBG_SOCK ("fd %d doesn't belong to any interface", uf->file_descriptor);
      return 0;
    }
  else
    vui = vec_elt_at_index (vum->vhost_user_interfaces, p[0]);

  client_len = sizeof (client);
  client_fd = accept (uf->file_descriptor,
		      (struct sockaddr *) &client,
		      (socklen_t *) & client_len);

  if (client_fd < 0)
    return clib_error_return_unix (0, "accept");

  template.read_function = vhost_user_socket_read;
  template.error_function = vhost_user_socket_error;
  template.file_descriptor = client_fd;
  vui->unix_file_index = unix_file_add (&unix_main, &template);

  vui->client_fd = client_fd;
  hash_set (vum->vhost_user_interface_index_by_sock_fd, vui->client_fd,
	    vui - vum->vhost_user_interfaces);

  return 0;
}

static clib_error_t *
vhost_user_init (vlib_main_t * vm)
{
  clib_error_t *error;
  vhost_user_main_t *vum = &vhost_user_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_thread_registration_t *tr;
  uword *p;

  error = vlib_call_init_function (vm, ip4_init);
  if (error)
    return error;

  vum->vhost_user_interface_index_by_listener_fd =
    hash_create (0, sizeof (uword));
  vum->vhost_user_interface_index_by_sock_fd =
    hash_create (0, sizeof (uword));
  vum->vhost_user_interface_index_by_sw_if_index =
    hash_create (0, sizeof (uword));
  vum->coalesce_frames = 32;
  vum->coalesce_time = 1e-3;

  vec_validate_aligned (vum->rx_buffers, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  /* find out which cpus will be used for input */
  vum->input_cpu_first_index = 0;
  vum->input_cpu_count = 1;
  p = hash_get_mem (tm->thread_registrations_by_name, "workers");
  tr = p ? (vlib_thread_registration_t *) p[0] : 0;

  if (tr && tr->count > 0)
    {
      vum->input_cpu_first_index = tr->first_index;
      vum->input_cpu_count = tr->count;
    }

  return 0;
}

VLIB_INIT_FUNCTION (vhost_user_init);

static clib_error_t *
vhost_user_exit (vlib_main_t * vm)
{
  /* TODO cleanup */
  return 0;
}

VLIB_MAIN_LOOP_EXIT_FUNCTION (vhost_user_exit);

enum
{
  VHOST_USER_RX_NEXT_ETHERNET_INPUT,
  VHOST_USER_RX_NEXT_DROP,
  VHOST_USER_RX_N_NEXT,
};


typedef struct
{
  u16 virtqueue;
  u16 device_index;
#if VHOST_USER_COPY_TX_HDR == 1
  virtio_net_hdr_t hdr;
#endif
} vhost_user_input_trace_t;

static u8 *
format_vhost_user_input_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  CLIB_UNUSED (vnet_main_t * vnm) = vnet_get_main ();
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_input_trace_t *t = va_arg (*va, vhost_user_input_trace_t *);
  vhost_user_intf_t *vui = vec_elt_at_index (vum->vhost_user_interfaces,
					     t->device_index);

  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, vui->sw_if_index);

#if VHOST_USER_COPY_TX_HDR == 1
  uword indent = format_get_indent (s);
#endif

  s = format (s, "%U virtqueue %d",
	      format_vnet_sw_interface_name, vnm, sw, t->virtqueue);

#if VHOST_USER_COPY_TX_HDR == 1
  s = format (s, "\n%Uvirtio_net_hdr flags 0x%02x gso_type %u hdr_len %u",
	      format_white_space, indent,
	      t->hdr.flags, t->hdr.gso_type, t->hdr.hdr_len);
#endif

  return s;
}

void
vhost_user_rx_trace (vlib_main_t * vm,
		     vlib_node_runtime_t * node,
		     vhost_user_intf_t * vui, i16 virtqueue)
{
  u32 *b, n_left;
  vhost_user_main_t *vum = &vhost_user_main;

  u32 next_index = VHOST_USER_RX_NEXT_ETHERNET_INPUT;

  n_left = vec_len (vui->d_trace_buffers);
  b = vui->d_trace_buffers;

  while (n_left >= 1)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      vhost_user_input_trace_t *t0;

      bi0 = b[0];
      n_left -= 1;

      b0 = vlib_get_buffer (vm, bi0);
      vlib_trace_buffer (vm, node, next_index, b0, /* follow_chain */ 0);
      t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
      t0->virtqueue = virtqueue;
      t0->device_index = vui - vum->vhost_user_interfaces;
#if VHOST_USER_COPY_TX_HDR == 1
      clib_memcpy (&t0->hdr, b0->pre_data, sizeof (virtio_net_hdr_t));
#endif

      b += 1;
    }
}

static inline void
vhost_user_send_call (vlib_main_t * vm, vhost_user_vring_t * vq)
{
  vhost_user_main_t *vum = &vhost_user_main;
  u64 x = 1;
  int rv __attribute__ ((unused));
  /* $$$$ pay attention to rv */
  rv = write (vq->callfd, &x, sizeof (x));
  vq->n_since_last_int = 0;
  vq->int_deadline = vlib_time_now (vm) + vum->coalesce_time;
}


static u32
vhost_user_if_input (vlib_main_t * vm,
		     vhost_user_main_t * vum,
		     vhost_user_intf_t * vui, vlib_node_runtime_t * node)
{
  vhost_user_vring_t *txvq = &vui->vrings[VHOST_NET_VRING_IDX_TX];
  vhost_user_vring_t *rxvq = &vui->vrings[VHOST_NET_VRING_IDX_RX];
  uword n_rx_packets = 0, n_rx_bytes = 0;
  uword n_left;
  u32 n_left_to_next, *to_next;
  u32 next_index = 0;
  u32 next0;
  uword n_trace = vlib_get_trace_count (vm, node);
  u16 qsz_mask;
  u32 cpu_index, rx_len, drops, flush;
  f64 now = vlib_time_now (vm);

  vec_reset_length (vui->d_trace_buffers);

  /* no descriptor ptr - bail out */
  if (PREDICT_FALSE (!txvq->desc || !txvq->avail || !txvq->enabled))
    return 0;

  /* do we have pending intterupts ? */
  if ((txvq->n_since_last_int) && (txvq->int_deadline < now))
    vhost_user_send_call (vm, txvq);

  if ((rxvq->n_since_last_int) && (rxvq->int_deadline < now))
    vhost_user_send_call (vm, rxvq);

  /* only bit 0 of avail.flags is used so we don't want to deal with this
     interface if any other bit is set */
  if (PREDICT_FALSE (txvq->avail->flags & 0xFFFE))
    return 0;

  n_left = (u16) (txvq->avail->idx - txvq->last_avail_idx);

  /* nothing to do */
  if (PREDICT_FALSE (n_left == 0))
    return 0;

  if (PREDICT_FALSE (n_left == txvq->qsz))
    {
      //Informational error logging when VPP is not receiving packets fast enough
      vlib_error_count (vm, node->node_index,
			VHOST_USER_INPUT_FUNC_ERROR_FULL_RX_QUEUE, 1);
    }

  if (PREDICT_FALSE (!vui->admin_up))
    {
      /* if intf is admin down, just drop all packets waiting in the ring */
      txvq->last_avail_idx = txvq->last_used_idx = txvq->avail->idx;
      CLIB_MEMORY_BARRIER ();
      txvq->used->idx = txvq->last_used_idx;
      vhost_user_log_dirty_ring (vui, txvq, idx);
      vhost_user_send_call (vm, txvq);
      return 0;
    }

  qsz_mask = txvq->qsz - 1;
  cpu_index = os_get_cpu_number ();
  drops = 0;
  flush = 0;

  if (n_left > VLIB_FRAME_SIZE)
    n_left = VLIB_FRAME_SIZE;

  /* Allocate some buffers.
   * Note that buffers that are chained for jumbo
   * frames are allocated separately using a slower path.
   * The idea is to be certain to have enough buffers at least
   * to cycle through the descriptors without having to check for errors.
   * For jumbo frames, the bottleneck is memory copy anyway.
   */
  if (PREDICT_FALSE (!vum->rx_buffers[cpu_index]))
    {
      vec_alloc (vum->rx_buffers[cpu_index], 2 * VLIB_FRAME_SIZE);

      if (PREDICT_FALSE (!vum->rx_buffers[cpu_index]))
	flush = n_left;		//Drop all input
    }

  if (PREDICT_FALSE (_vec_len (vum->rx_buffers[cpu_index]) < n_left))
    {
      u32 curr_len = _vec_len (vum->rx_buffers[cpu_index]);
      _vec_len (vum->rx_buffers[cpu_index]) +=
	vlib_buffer_alloc_from_free_list (vm,
					  vum->rx_buffers[cpu_index] +
					  curr_len,
					  2 * VLIB_FRAME_SIZE - curr_len,
					  VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);

      if (PREDICT_FALSE (n_left > _vec_len (vum->rx_buffers[cpu_index])))
	flush = n_left - _vec_len (vum->rx_buffers[cpu_index]);
    }

  if (PREDICT_FALSE (flush))
    {
      //Remove some input buffers
      drops += flush;
      n_left -= flush;
      vlib_error_count (vm, vhost_user_input_node.index,
			VHOST_USER_INPUT_FUNC_ERROR_NO_BUFFER, flush);
      while (flush)
	{
	  u16 desc_chain_head =
	    txvq->avail->ring[txvq->last_avail_idx & qsz_mask];
	  txvq->last_avail_idx++;
	  txvq->used->ring[txvq->last_used_idx & qsz_mask].id =
	    desc_chain_head;
	  txvq->used->ring[txvq->last_used_idx & qsz_mask].len = 0;
	  vhost_user_log_dirty_ring (vui, txvq,
				     ring[txvq->last_used_idx & qsz_mask]);
	  txvq->last_used_idx++;
	  flush--;
	}
    }

  rx_len = vec_len (vum->rx_buffers[cpu_index]);	//vector might be null
  while (n_left > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b_head, *b_current;
	  u32 bi_head, bi_current;
	  u16 desc_chain_head, desc_current;
	  u8 error = VHOST_USER_INPUT_FUNC_ERROR_NO_ERROR;

	  if (PREDICT_TRUE (n_left > 1))
	    {
	      u32 next_desc =
		txvq->avail->ring[(txvq->last_avail_idx + 1) & qsz_mask];
	      void *buffer_addr =
		map_guest_mem (vui, txvq->desc[next_desc].addr);
	      if (PREDICT_TRUE (buffer_addr != 0))
		CLIB_PREFETCH (buffer_addr, 64, STORE);

	      u32 bi = vum->rx_buffers[cpu_index][rx_len - 2];
	      vlib_prefetch_buffer_with_index (vm, bi, STORE);
	      CLIB_PREFETCH (vlib_get_buffer (vm, bi)->data, 128, STORE);
	    }

	  desc_chain_head = desc_current =
	    txvq->avail->ring[txvq->last_avail_idx & qsz_mask];
	  bi_head = bi_current = vum->rx_buffers[cpu_index][--rx_len];
	  b_head = b_current = vlib_get_buffer (vm, bi_head);
	  vlib_buffer_chain_init (b_head);

	  uword offset;
	  if (PREDICT_TRUE (vui->is_any_layout) ||
	      (!(txvq->desc[desc_current].flags & VIRTQ_DESC_F_NEXT) &&
	       !(txvq->desc[desc_current].flags & VIRTQ_DESC_F_INDIRECT)))
	    {
	      /* ANYLAYOUT or single buffer */
	      offset = vui->virtio_net_hdr_sz;
	    }
	  else
	    {
	      /* CSR case without ANYLAYOUT, skip 1st buffer */
	      offset = txvq->desc[desc_current].len;
	    }

	  vring_desc_t *desc_table = txvq->desc;
	  u32 desc_index = desc_current;

	  if (txvq->desc[desc_current].flags & VIRTQ_DESC_F_INDIRECT)
	    {
	      desc_table = map_guest_mem (vui, txvq->desc[desc_current].addr);
	      desc_index = 0;
	      if (PREDICT_FALSE (desc_table == 0))
		{
		  error = VHOST_USER_INPUT_FUNC_ERROR_MMAP_FAIL;
		  goto out;
		}
	    }

	  while (1)
	    {
	      void *buffer_addr =
		map_guest_mem (vui, desc_table[desc_index].addr);
	      if (PREDICT_FALSE (buffer_addr == 0))
		{
		  error = VHOST_USER_INPUT_FUNC_ERROR_MMAP_FAIL;
		  goto out;
		}

	      if (PREDICT_TRUE
		  (desc_table[desc_index].flags & VIRTQ_DESC_F_NEXT))
		{
		  CLIB_PREFETCH (&desc_table[desc_table[desc_index].next],
				 sizeof (vring_desc_t), STORE);
		}

#if VHOST_USER_COPY_TX_HDR == 1
	      if (PREDICT_TRUE (offset))
		clib_memcpy (b->pre_data, buffer_addr, sizeof (virtio_net_hdr_t));	/* 12 byte hdr is not used on tx */
#endif

	      if (desc_table[desc_index].len > offset)
		{
		  u16 len = desc_table[desc_index].len - offset;
		  u16 copied = vlib_buffer_chain_append_data_with_alloc (vm,
									 VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX,
									 b_head,
									 &b_current,
									 buffer_addr
									 +
									 offset,
									 len);
		  if (copied != len)
		    {
		      error = VHOST_USER_INPUT_FUNC_ERROR_NO_BUFFER;
		      break;
		    }
		}
	      offset = 0;

	      /* if next flag is set, take next desc in the chain */
	      if ((desc_table[desc_index].flags & VIRTQ_DESC_F_NEXT))
		desc_index = desc_table[desc_index].next;
	      else
		goto out;
	    }
	out:

	  /* consume the descriptor and return it as used */
	  txvq->last_avail_idx++;
	  txvq->used->ring[txvq->last_used_idx & qsz_mask].id =
	    desc_chain_head;
	  txvq->used->ring[txvq->last_used_idx & qsz_mask].len = 0;
	  vhost_user_log_dirty_ring (vui, txvq,
				     ring[txvq->last_used_idx & qsz_mask]);
	  txvq->last_used_idx++;

	  //It is important to free RX as fast as possible such that the TX
	  //process does not drop packets
	  if ((txvq->last_used_idx & 0x3f) == 0)	// Every 64 packets
	    txvq->used->idx = txvq->last_used_idx;

	  if (PREDICT_FALSE (b_head->current_length < 14 &&
			     error == VHOST_USER_INPUT_FUNC_ERROR_NO_ERROR))
	    error = VHOST_USER_INPUT_FUNC_ERROR_UNDERSIZED_FRAME;

	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b_head);

	  vnet_buffer (b_head)->sw_if_index[VLIB_RX] = vui->sw_if_index;
	  vnet_buffer (b_head)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	  b_head->error = node->errors[error];

	  if (PREDICT_FALSE (n_trace > n_rx_packets))
	    vec_add1 (vui->d_trace_buffers, bi_head);

	  if (PREDICT_FALSE (error))
	    {
	      drops++;
	      next0 = VHOST_USER_RX_NEXT_DROP;
	    }
	  else
	    {
	      n_rx_bytes +=
		b_head->current_length +
		b_head->total_length_not_including_first_buffer;
	      n_rx_packets++;
	      next0 = VHOST_USER_RX_NEXT_ETHERNET_INPUT;
	    }

	  to_next[0] = bi_head;
	  to_next++;
	  n_left_to_next--;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi_head, next0);
	  n_left--;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);

    }

  if (PREDICT_TRUE (vum->rx_buffers[cpu_index] != 0))
    _vec_len (vum->rx_buffers[cpu_index]) = rx_len;

  /* give buffers back to driver */
  CLIB_MEMORY_BARRIER ();
  txvq->used->idx = txvq->last_used_idx;
  vhost_user_log_dirty_ring (vui, txvq, idx);

  if (PREDICT_FALSE (vec_len (vui->d_trace_buffers) > 0))
    {
      vhost_user_rx_trace (vm, node, vui, VHOST_NET_VRING_IDX_TX);
      vlib_set_trace_count (vm, node,
			    n_trace - vec_len (vui->d_trace_buffers));
    }

  /* interrupt (call) handling */
  if ((txvq->callfd > -1) && !(txvq->avail->flags & 1))
    {
      txvq->n_since_last_int += n_rx_packets;

      if (txvq->n_since_last_int > vum->coalesce_frames)
	vhost_user_send_call (vm, txvq);
    }

  if (PREDICT_FALSE (drops))
    {
      vlib_increment_simple_counter
	(vnet_main.interface_main.sw_if_counters
	 + VNET_INTERFACE_COUNTER_DROP, os_get_cpu_number (),
	 vui->sw_if_index, drops);
    }

  /* increase rx counters */
  vlib_increment_combined_counter
    (vnet_main.interface_main.combined_sw_if_counters
     + VNET_INTERFACE_COUNTER_RX,
     os_get_cpu_number (), vui->sw_if_index, n_rx_packets, n_rx_bytes);

  return n_rx_packets;
}

static uword
vhost_user_input (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * f)
{
  vhost_user_main_t *vum = &vhost_user_main;
  u32 cpu_index = os_get_cpu_number ();
  vhost_user_intf_t *vui;
  uword n_rx_packets = 0;
  int i;

  for (i = 0; i < vec_len (vum->vhost_user_interfaces); i++)
    {
      vui = vec_elt_at_index (vum->vhost_user_interfaces, i);
      if (vui->is_up)
	{
	  if ((i % vum->input_cpu_count) ==
	      (cpu_index - vum->input_cpu_first_index))
	    n_rx_packets += vhost_user_if_input (vm, vum, vui, node);
	}
    }
  return n_rx_packets;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (vhost_user_input_node) = {
  .function = vhost_user_input,
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "vhost-user-input",

  /* Will be enabled if/when hardware is detected. */
  .state = VLIB_NODE_STATE_DISABLED,

  .format_buffer = format_ethernet_header_with_length,
  .format_trace = format_vhost_user_input_trace,

  .n_errors = VHOST_USER_INPUT_FUNC_N_ERROR,
  .error_strings = vhost_user_input_func_error_strings,

  .n_next_nodes = VHOST_USER_RX_N_NEXT,
  .next_nodes = {
    [VHOST_USER_RX_NEXT_DROP] = "error-drop",
    [VHOST_USER_RX_NEXT_ETHERNET_INPUT] = "ethernet-input",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (vhost_user_input_node, vhost_user_input)
/* *INDENT-ON* */

static uword
vhost_user_intfc_tx (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 *buffers = vlib_frame_args (frame);
  u32 n_left = 0;
  vhost_user_main_t *vum = &vhost_user_main;
  uword n_packets = 0;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  vhost_user_intf_t *vui =
    vec_elt_at_index (vum->vhost_user_interfaces, rd->dev_instance);
  vhost_user_vring_t *rxvq = &vui->vrings[VHOST_NET_VRING_IDX_RX];
  u16 qsz_mask;
  u8 error = VHOST_USER_TX_FUNC_ERROR_NONE;

  n_left = n_packets = frame->n_vectors;

  if (PREDICT_FALSE (!vui->is_up))
    goto done2;

  if (PREDICT_FALSE
      (!rxvq->desc || !rxvq->avail || vui->sock_errno != 0 || !rxvq->enabled))
    {
      error = VHOST_USER_TX_FUNC_ERROR_NOT_READY;
      goto done2;
    }

  if (PREDICT_FALSE (vui->lockp != 0))
    {
      while (__sync_lock_test_and_set (vui->lockp, 1))
	;
    }

  /* only bit 0 of avail.flags is used so we don't want to deal with this
     interface if any other bit is set */
  if (PREDICT_FALSE (rxvq->avail->flags & 0xFFFE))
    {
      error = VHOST_USER_TX_FUNC_ERROR_NOT_READY;
      goto done2;
    }

  if (PREDICT_FALSE ((rxvq->avail->idx == rxvq->last_avail_idx)))
    {
      error = VHOST_USER_TX_FUNC_ERROR_PKT_DROP_NOBUF;
      goto done2;
    }

  qsz_mask = rxvq->qsz - 1;	/* qsz is always power of 2 */

  while (n_left > 0)
    {
      vlib_buffer_t *b0, *current_b0;
      u16 desc_head, desc_index, desc_len;
      vring_desc_t *desc_table;
      void *buffer_addr;
      u32 buffer_len;

      b0 = vlib_get_buffer (vm, buffers[0]);
      buffers++;

      if (PREDICT_FALSE (rxvq->last_avail_idx == rxvq->avail->idx))
	{
	  error = VHOST_USER_TX_FUNC_ERROR_PKT_DROP_NOBUF;
	  goto done;
	}

      desc_table = rxvq->desc;
      desc_head = desc_index =
	rxvq->avail->ring[rxvq->last_avail_idx & qsz_mask];
      if (rxvq->desc[desc_head].flags & VIRTQ_DESC_F_INDIRECT)
	{
	  if (PREDICT_FALSE
	      (rxvq->desc[desc_head].len < sizeof (vring_desc_t)))
	    {
	      error = VHOST_USER_TX_FUNC_ERROR_INDIRECT_OVERFLOW;
	      goto done;
	    }
	  if (PREDICT_FALSE
	      (!(desc_table =
		 map_guest_mem (vui, rxvq->desc[desc_index].addr))))
	    {
	      error = VHOST_USER_TX_FUNC_ERROR_MMAP_FAIL;
	      goto done;
	    }
	  desc_index = 0;
	}

      desc_len = vui->virtio_net_hdr_sz;

      if (PREDICT_FALSE
	  (!(buffer_addr = map_guest_mem (vui, desc_table[desc_index].addr))))
	{
	  error = VHOST_USER_TX_FUNC_ERROR_MMAP_FAIL;
	  goto done;
	}
      buffer_len = desc_table[desc_index].len;

      CLIB_PREFETCH (buffer_addr,
		     clib_min (buffer_len, 2 * CLIB_CACHE_LINE_BYTES), STORE);

      virtio_net_hdr_mrg_rxbuf_t *hdr =
	(virtio_net_hdr_mrg_rxbuf_t *) buffer_addr;
      hdr->hdr.flags = 0;
      hdr->hdr.gso_type = 0;
      if (vui->virtio_net_hdr_sz == 12)
	hdr->num_buffers = 1;

      vhost_user_log_dirty_pages (vui, desc_table[desc_index].addr,
				  vui->virtio_net_hdr_sz);

      u16 bytes_left = b0->current_length;
      buffer_addr += vui->virtio_net_hdr_sz;
      buffer_len -= vui->virtio_net_hdr_sz;
      current_b0 = b0;
      while (1)
	{
	  if (!bytes_left)
	    {			//Get new input
	      if (current_b0->flags & VLIB_BUFFER_NEXT_PRESENT)
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

	  if (buffer_len == 0)
	    {			//Get new output
	      if (desc_table[desc_index].flags & VIRTQ_DESC_F_NEXT)
		{
		  //Next one is chained
		  desc_index = desc_table[desc_index].next;
		  if (PREDICT_FALSE
		      (!(buffer_addr =
			 map_guest_mem (vui, desc_table[desc_index].addr))))
		    {
		      rxvq->last_used_idx -= hdr->num_buffers - 1;
		      rxvq->last_avail_idx -= hdr->num_buffers - 1;
		      error = VHOST_USER_TX_FUNC_ERROR_MMAP_FAIL;
		      goto done;
		    }
		  buffer_len = desc_table[desc_index].len;
		}
	      else if (vui->virtio_net_hdr_sz == 12)	//MRG is available
		{
		  //Move from available to used buffer
		  rxvq->used->ring[rxvq->last_used_idx & qsz_mask].id =
		    desc_head;
		  rxvq->used->ring[rxvq->last_used_idx & qsz_mask].len =
		    desc_len;
		  vhost_user_log_dirty_ring (vui, rxvq,
					     ring[rxvq->last_used_idx &
						  qsz_mask]);
		  rxvq->last_avail_idx++;
		  rxvq->last_used_idx++;
		  hdr->num_buffers++;

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
		    rxvq->avail->ring[rxvq->last_avail_idx & qsz_mask];
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
					    rxvq->desc[desc_index].addr))))
			{
			  error = VHOST_USER_TX_FUNC_ERROR_MMAP_FAIL;
			  goto done;
			}
		      desc_index = 0;
		    }

		  if (PREDICT_FALSE
		      (!(buffer_addr =
			 map_guest_mem (vui, desc_table[desc_index].addr))))
		    {
		      error = VHOST_USER_TX_FUNC_ERROR_MMAP_FAIL;
		      goto done;
		    }
		  buffer_len = desc_table[desc_index].len;
		  CLIB_PREFETCH (buffer_addr,
				 clib_min (buffer_len,
					   2 * CLIB_CACHE_LINE_BYTES), STORE);
		}
	      else
		{
		  error = VHOST_USER_TX_FUNC_ERROR_PKT_DROP_NOMRG;
		  goto done;
		}
	    }

	  u16 bytes_to_copy = bytes_left;
	  bytes_to_copy =
	    (bytes_to_copy > buffer_len) ? buffer_len : bytes_to_copy;
	  clib_memcpy (buffer_addr,
		       vlib_buffer_get_current (current_b0) +
		       current_b0->current_length - bytes_left,
		       bytes_to_copy);

	  vhost_user_log_dirty_pages (vui,
				      desc_table[desc_index].addr +
				      desc_table[desc_index].len -
				      bytes_left - bytes_to_copy,
				      bytes_to_copy);

	  bytes_left -= bytes_to_copy;
	  buffer_len -= bytes_to_copy;
	  buffer_addr += bytes_to_copy;
	  desc_len += bytes_to_copy;
	}

      if (PREDICT_TRUE (n_left >= 2))
	{
	  vlib_prefetch_buffer_with_index (vm, buffers[1], STORE);
	  CLIB_PREFETCH (&n_left, sizeof (n_left), STORE);
	}

      //Move from available to used ring
      rxvq->used->ring[rxvq->last_used_idx & qsz_mask].id = desc_head;
      rxvq->used->ring[rxvq->last_used_idx & qsz_mask].len = desc_len;
      vhost_user_log_dirty_ring (vui, rxvq,
				 ring[rxvq->last_used_idx & qsz_mask]);

      rxvq->last_avail_idx++;
      rxvq->last_used_idx++;

      n_left--;			//At the end for error counting when 'goto done' is invoked
    }

done:
  CLIB_MEMORY_BARRIER ();
  rxvq->used->idx = rxvq->last_used_idx;
  vhost_user_log_dirty_ring (vui, rxvq, idx);

  /* interrupt (call) handling */
  if ((rxvq->callfd > -1) && !(rxvq->avail->flags & 1))
    {
      rxvq->n_since_last_int += n_packets - n_left;

      if (rxvq->n_since_last_int > vum->coalesce_frames)
	vhost_user_send_call (vm, rxvq);
    }

done2:

  if (PREDICT_FALSE (vui->lockp != 0))
    *vui->lockp = 0;

  if (PREDICT_FALSE (n_left && error != VHOST_USER_TX_FUNC_ERROR_NONE))
    {
      vlib_error_count (vm, node->node_index, error, n_left);
      vlib_increment_simple_counter
	(vnet_main.interface_main.sw_if_counters
	 + VNET_INTERFACE_COUNTER_DROP,
	 os_get_cpu_number (), vui->sw_if_index, n_left);
    }

  vlib_buffer_free (vm, vlib_frame_args (frame), frame->n_vectors);
  return frame->n_vectors;
}

static clib_error_t *
vhost_user_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index,
				    u32 flags)
{
  vnet_hw_interface_t *hif = vnet_get_hw_interface (vnm, hw_if_index);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui =
    vec_elt_at_index (vum->vhost_user_interfaces, hif->dev_instance);

  vui->admin_up = is_up;

  if (is_up)
    vnet_hw_interface_set_flags (vnm, vui->hw_if_index,
				 VNET_HW_INTERFACE_FLAG_LINK_UP);

  return /* no error */ 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (vhost_user_dev_class,static) = {
  .name = "vhost-user",
  .tx_function = vhost_user_intfc_tx,
  .tx_function_n_errors = VHOST_USER_TX_FUNC_N_ERROR,
  .tx_function_error_strings = vhost_user_tx_func_error_strings,
  .format_device_name = format_vhost_user_interface_name,
  .name_renumber = vhost_user_name_renumber,
  .admin_up_down_function = vhost_user_interface_admin_up_down,
  .no_flatten_output_chains = 1,
};

VLIB_DEVICE_TX_FUNCTION_MULTIARCH (vhost_user_dev_class,
				   vhost_user_intfc_tx)
/* *INDENT-ON* */

static uword
vhost_user_process (vlib_main_t * vm,
		    vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui;
  struct sockaddr_un sun;
  int sockfd;
  unix_file_t template = { 0 };
  f64 timeout = 3153600000.0 /* 100 years */ ;
  uword *event_data = 0;

  sockfd = socket (AF_UNIX, SOCK_STREAM, 0);
  sun.sun_family = AF_UNIX;
  template.read_function = vhost_user_socket_read;
  template.error_function = vhost_user_socket_error;


  if (sockfd < 0)
    return 0;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      timeout = 3.0;

      vec_foreach (vui, vum->vhost_user_interfaces)
      {

	if (vui->sock_is_server || !vui->active)
	  continue;

	if (vui->unix_fd == -1)
	  {
	    /* try to connect */

	    strncpy (sun.sun_path, (char *) vui->sock_filename,
		     sizeof (sun.sun_path) - 1);

	    if (connect
		(sockfd, (struct sockaddr *) &sun,
		 sizeof (struct sockaddr_un)) == 0)
	      {
		vui->sock_errno = 0;
		vui->unix_fd = sockfd;
		template.file_descriptor = sockfd;
		vui->unix_file_index = unix_file_add (&unix_main, &template);
		hash_set (vum->vhost_user_interface_index_by_sock_fd, sockfd,
			  vui - vum->vhost_user_interfaces);

		sockfd = socket (AF_UNIX, SOCK_STREAM, 0);
		if (sockfd < 0)
		  return 0;
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
	      vhost_user_if_disconnect (vui);
	  }
      }
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

int
vhost_user_delete_if (vnet_main_t * vnm, vlib_main_t * vm, u32 sw_if_index)
{
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui;
  uword *p = NULL;
  int rv = 0;

  p = hash_get (vum->vhost_user_interface_index_by_sw_if_index, sw_if_index);
  if (p == 0)
    {
      return VNET_API_ERROR_INVALID_SW_IF_INDEX;
    }
  else
    {
      vui = vec_elt_at_index (vum->vhost_user_interfaces, p[0]);
    }

  // interface is inactive
  vui->active = 0;
  // disconnect interface sockets
  vhost_user_if_disconnect (vui);
  // add to inactive interface list
  vec_add1 (vum->vhost_user_inactive_interfaces_index, p[0]);

  // reset renumbered iface
  if (p[0] < vec_len (vum->show_dev_instance_by_real_dev_instance))
    vum->show_dev_instance_by_real_dev_instance[p[0]] = ~0;

  ethernet_delete_interface (vnm, vui->hw_if_index);
  DBG_SOCK ("deleted (deactivated) vhost-user interface instance %d", p[0]);

  return rv;
}

// init server socket on specified sock_filename
static int
vhost_user_init_server_sock (const char *sock_filename, int *sockfd)
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

  unix_file_t template = { 0 };
  template.read_function = vhost_user_socksvr_accept_ready;
  template.file_descriptor = fd;
  unix_file_add (&unix_main, &template);
  *sockfd = fd;
  return rv;

error:
  close (fd);
  return rv;
}

// get new vhost_user_intf_t from inactive interfaces or create new one
static vhost_user_intf_t *
vhost_user_vui_new ()
{
  vhost_user_main_t *vum = &vhost_user_main;
  vhost_user_intf_t *vui = NULL;
  int inactive_cnt = vec_len (vum->vhost_user_inactive_interfaces_index);
  // if there are any inactive ifaces
  if (inactive_cnt > 0)
    {
      // take last
      u32 vui_idx =
	vum->vhost_user_inactive_interfaces_index[inactive_cnt - 1];
      if (vec_len (vum->vhost_user_interfaces) > vui_idx)
	{
	  vui = vec_elt_at_index (vum->vhost_user_interfaces, vui_idx);
	  DBG_SOCK ("reusing inactive vhost-user interface index %d",
		    vui_idx);
	}
      // "remove" from inactive list
      _vec_len (vum->vhost_user_inactive_interfaces_index) -= 1;
    }

  // vui was not retrieved from inactive ifaces - create new
  if (!vui)
    vec_add2 (vum->vhost_user_interfaces, vui, 1);
  return vui;
}

// create ethernet interface for vhost user intf
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
      f64 now = vlib_time_now (vm);
      u32 rnd;
      rnd = (u32) (now * 1e6);
      rnd = random_u32 (&rnd);

      clib_memcpy (hwaddr + 2, &rnd, sizeof (rnd));
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

// initialize vui with specified attributes
static void
vhost_user_vui_init (vnet_main_t * vnm,
		     vhost_user_intf_t * vui, int sockfd,
		     const char *sock_filename,
		     u8 is_server, u64 feature_mask, u32 * sw_if_index)
{
  vnet_sw_interface_t *sw;
  sw = vnet_get_hw_sw_interface (vnm, vui->hw_if_index);
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  int q;

  vui->unix_fd = sockfd;
  vui->sw_if_index = sw->sw_if_index;
  vui->num_vrings = 2;
  vui->sock_is_server = is_server;
  strncpy (vui->sock_filename, sock_filename,
	   ARRAY_LEN (vui->sock_filename) - 1);
  vui->sock_errno = 0;
  vui->is_up = 0;
  vui->feature_mask = feature_mask;
  vui->active = 1;
  vui->unix_file_index = ~0;
  vui->log_base_addr = 0;

  for (q = 0; q < 2; q++)
    {
      vui->vrings[q].enabled = 0;
      vui->vrings[q].callfd = -1;
      vui->vrings[q].kickfd = -1;
    }

  vnet_hw_interface_set_flags (vnm, vui->hw_if_index, 0);

  if (sw_if_index)
    *sw_if_index = vui->sw_if_index;

  if (tm->n_vlib_mains > 1)
    {
      vui->lockp = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
					   CLIB_CACHE_LINE_BYTES);
      memset ((void *) vui->lockp, 0, CLIB_CACHE_LINE_BYTES);
    }
}

// register vui and start polling on it
static void
vhost_user_vui_register (vlib_main_t * vm, vhost_user_intf_t * vui)
{
  vhost_user_main_t *vum = &vhost_user_main;
  int cpu_index;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  hash_set (vum->vhost_user_interface_index_by_listener_fd, vui->unix_fd,
	    vui - vum->vhost_user_interfaces);
  hash_set (vum->vhost_user_interface_index_by_sw_if_index, vui->sw_if_index,
	    vui - vum->vhost_user_interfaces);

  /* start polling */
  cpu_index = vum->input_cpu_first_index +
    (vui - vum->vhost_user_interfaces) % vum->input_cpu_count;

  if (tm->n_vlib_mains == 1)
    vlib_node_set_state (vm, vhost_user_input_node.index,
			 VLIB_NODE_STATE_POLLING);
  else
    vlib_node_set_state (vlib_mains[cpu_index], vhost_user_input_node.index,
			 VLIB_NODE_STATE_POLLING);

  /* tell process to start polling for sockets */
  vlib_process_signal_event (vm, vhost_user_process_node.index, 0, 0);
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
  int sockfd = -1;
  int rv = 0;

  if (is_server)
    {
      if ((rv = vhost_user_init_server_sock (sock_filename, &sockfd)) != 0)
	{
	  return rv;
	}
    }

  vui = vhost_user_vui_new ();
  ASSERT (vui != NULL);

  vhost_user_create_ethernet (vnm, vm, vui, hwaddr);
  vhost_user_vui_init (vnm, vui, sockfd, sock_filename, is_server,
		       feature_mask, &sw_if_idx);

  if (renumber)
    {
      vnet_interface_name_renumber (sw_if_idx, custom_dev_instance);
    }

  vhost_user_vui_register (vm, vui);

  if (sw_if_index)
    *sw_if_index = sw_if_idx;

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
  int sockfd = -1;
  int rv = 0;
  uword *p = NULL;

  p = hash_get (vum->vhost_user_interface_index_by_sw_if_index, sw_if_index);
  if (p == 0)
    {
      return VNET_API_ERROR_INVALID_SW_IF_INDEX;
    }
  else
    {
      vui = vec_elt_at_index (vum->vhost_user_interfaces, p[0]);
    }

  // interface is inactive
  vui->active = 0;
  // disconnect interface sockets
  vhost_user_if_disconnect (vui);

  if (is_server)
    {
      if ((rv = vhost_user_init_server_sock (sock_filename, &sockfd)) != 0)
	{
	  return rv;
	}
    }

  vhost_user_vui_init (vnm, vui, sockfd, sock_filename, is_server,
		       feature_mask, &sw_if_idx);

  if (renumber)
    {
      vnet_interface_name_renumber (sw_if_idx, custom_dev_instance);
    }

  vhost_user_vui_register (vm, vui);

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
  u64 feature_mask = (u64) ~ 0;
  u8 renumber = 0;
  u32 custom_dev_instance = ~0;
  u8 hwaddr[6];
  u8 *hw = NULL;

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

  int rv;
  if ((rv = vhost_user_create_if (vnm, vm, (char *) sock_filename,
				  is_server, &sw_if_index, feature_mask,
				  renumber, custom_dev_instance, hw)))
    {
      vec_free (sock_filename);
      return clib_error_return (0, "vhost_user_create_if returned %d", rv);
    }

  vec_free (sock_filename);
  vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main (),
		   sw_if_index);
  return 0;
}

clib_error_t *
vhost_user_delete_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;

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

  vnet_main_t *vnm = vnet_get_main ();

  vhost_user_delete_if (vnm, vm, sw_if_index);

  return 0;
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

  vec_foreach (vui, vum->vhost_user_interfaces)
  {
    if (vui->active)
      vec_add1 (hw_if_indices, vui->hw_if_index);
  }

  for (i = 0; i < vec_len (hw_if_indices); i++)
    {
      hi = vnet_get_hw_interface (vnm, hw_if_indices[i]);
      vui = vec_elt_at_index (vum->vhost_user_interfaces, hi->dev_instance);

      vec_add2 (r_vuids, vuid, 1);
      vuid->sw_if_index = vui->sw_if_index;
      vuid->virtio_net_hdr_sz = vui->virtio_net_hdr_sz;
      vuid->features = vui->features;
      vuid->is_server = vui->sock_is_server;
      vuid->num_regions = vui->nregions;
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
      vec_foreach (vui, vum->vhost_user_interfaces)
      {
	if (vui->active)
	  vec_add1 (hw_if_indices, vui->hw_if_index);
      }
    }
  vlib_cli_output (vm, "Virtio vhost-user interfaces");
  vlib_cli_output (vm, "Global:\n  coalesce frames %d time %e\n\n",
		   vum->coalesce_frames, vum->coalesce_time);

  for (i = 0; i < vec_len (hw_if_indices); i++)
    {
      hi = vnet_get_hw_interface (vnm, hw_if_indices[i]);
      vui = vec_elt_at_index (vum->vhost_user_interfaces, hi->dev_instance);
      vlib_cli_output (vm, "Interface: %s (ifindex %d)",
		       hi->name, hw_if_indices[i]);

      vlib_cli_output (vm, "virtio_net_hdr_sz %d\n features (0x%llx): \n",
		       vui->virtio_net_hdr_sz, vui->features);

      feat_entry = (struct feat_struct *) &feat_array;
      while (feat_entry->str)
	{
	  if (vui->features & (1 << feat_entry->bit))
	    vlib_cli_output (vm, "   %s (%d)", feat_entry->str,
			     feat_entry->bit);
	  feat_entry++;
	}

      vlib_cli_output (vm, "\n");


      vlib_cli_output (vm, " socket filename %s type %s errno \"%s\"\n\n",
		       vui->sock_filename,
		       vui->sock_is_server ? "server" : "client",
		       strerror (vui->sock_errno));

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
      for (q = 0; q < vui->num_vrings; q++)
	{
	  vlib_cli_output (vm, "\n Virtqueue %d\n", q);

	  vlib_cli_output (vm,
			   "  qsz %d last_avail_idx %d last_used_idx %d\n",
			   vui->vrings[q].qsz, vui->vrings[q].last_avail_idx,
			   vui->vrings[q].last_used_idx);

	  if (vui->vrings[q].avail && vui->vrings[q].used)
	    vlib_cli_output (vm,
			     "  avail.flags %x avail.idx %d used.flags %x used.idx %d\n",
			     vui->vrings[q].avail->flags,
			     vui->vrings[q].avail->idx,
			     vui->vrings[q].used->flags,
			     vui->vrings[q].used->idx);

	  vlib_cli_output (vm, "  kickfd %d callfd %d errfd %d\n",
			   vui->vrings[q].kickfd,
			   vui->vrings[q].callfd, vui->vrings[q].errfd);

	  if (show_descr)
	    {
	      vlib_cli_output (vm, "\n  descriptor table:\n");
	      vlib_cli_output (vm,
			       "   id          addr         len  flags  next      user_addr\n");
	      vlib_cli_output (vm,
			       "  ===== ================== ===== ====== ===== ==================\n");
	      for (j = 0; j < vui->vrings[q].qsz; j++)
		{
		  vlib_cli_output (vm,
				   "  %-5d 0x%016lx %-5d 0x%04x %-5d 0x%016lx\n",
				   j, vui->vrings[q].desc[j].addr,
				   vui->vrings[q].desc[j].len,
				   vui->vrings[q].desc[j].flags,
				   vui->vrings[q].desc[j].next,
				   pointer_to_uword (map_guest_mem
						     (vui,
						      vui->vrings[q].desc[j].
						      addr)));
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

#if DPDK == 0
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vhost_user_connect_command, static) = {
    .path = "create vhost-user",
    .short_help = "create vhost-user socket <socket-filename> [server] [feature-mask <hex>] [renumber <dev_instance>]",
    .function = vhost_user_connect_command_fn,
};

VLIB_CLI_COMMAND (vhost_user_delete_command, static) = {
    .path = "delete vhost-user",
    .short_help = "delete vhost-user sw_if_index <nn>",
    .function = vhost_user_delete_command_fn,
};

VLIB_CLI_COMMAND (show_vhost_user_command, static) = {
    .path = "show vhost-user",
    .short_help = "show vhost-user interface",
    .function = show_vhost_user_command_fn,
};
/* *INDENT-ON* */
#endif

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
      vec_foreach (vui, vum->vhost_user_interfaces)
      {
	unmap_all_mem_regions (vui);
      }
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
