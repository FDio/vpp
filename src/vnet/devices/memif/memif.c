/*
 *------------------------------------------------------------------
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#define _GNU_SOURCE
#include <stdint.h>
#include <net/if.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/mman.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/memif/memif.h>

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE 1024
#endif
#define MFD_ALLOW_SEALING       0x0002U
#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#define F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)

#define F_SEAL_SEAL     0x0001  /* prevent further seals from being set */
#define F_SEAL_SHRINK   0x0002  /* prevent file from shrinking */
#define F_SEAL_GROW     0x0004  /* prevent file from growing */
#define F_SEAL_WRITE    0x0008  /* prevent writes */

#ifndef __NR_memfd_create
#if defined __x86_64__
#define __NR_memfd_create 319
#elif defined __arm__
#define __NR_memfd_create 385
#elif defined __aarch64__
#define __NR_memfd_create 279
#else
#error "__NR_memfd_create unknown for this architecture"
#endif
#endif

memif_main_t memif_main;

static inline int
memfd_create (const char *name, unsigned int flags)
{
  return syscall (__NR_memfd_create, name, flags);
}

static u32
memif_eth_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hi, u32 flags)
{
  /* nothing for now */
  return 0;
}

static void
memif_connect (vlib_main_t * vm, memif_if_t * mif)
{
  vnet_main_t *vnm = vnet_get_main ();
  int num_rings = mif->num_s2m_rings + mif->num_m2s_rings;
  memif_ring_data_t *rd = NULL;

  vec_validate_aligned (mif->ring_data, num_rings - 1, CLIB_CACHE_LINE_BYTES);
  vec_foreach (rd, mif->ring_data)
  {
    rd->last_head = 0;
  }

  mif->flags |= MEMIF_IF_FLAG_CONNECTED;
  vnet_hw_interface_set_flags (vnm, mif->hw_if_index,
                               VNET_HW_INTERFACE_FLAG_LINK_UP);
}

static void
memif_disconnect (vlib_main_t * vm, memif_if_t * mif)
{
  vnet_main_t *vnm = vnet_get_main ();

  mif->flags &= ~MEMIF_IF_FLAG_CONNECTED;
  vnet_hw_interface_set_flags (vnm, mif->hw_if_index, 0);
}

static void
free_memif_region(memif_region_t *region)
{
  if (region)
    {
      if (region->mem != 0)
        {
          munmap (region->mem, region->size);
          region->mem = 0;
          region->size = 0;
        }
      if (region->fd > -1)
        {
          close (region->fd);
          region->fd = -1;
        }
    }
}

static void
close_memif_conn (memif_main_t * mm, memif_if_t * mif)
{
  memif_region_t *region;

  if (mif->conn_file_index != ~0)
    {
      unix_file_del (&unix_main, unix_main.file_pool + mif->conn_file_index);
      mif->conn_file_index = ~0;
    }
  if (mif->conn_fd > -1)
    {
      close (mif->conn_fd);
      mif->conn_fd = -1;
    }
  if (!(mif->flags & MEMIF_IF_FLAG_IS_SLAVE))
    {
      vec_foreach(region, mif->regions)
      {
        free_memif_region(region);
      }
      vec_free(mif->regions);
    }
}

static clib_error_t *
memif_fd_read_ready (unix_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  vlib_main_t *vm = vlib_get_main ();
  char ctl[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct ucred))] = { 0 };
  struct msghdr mh = { 0 };
  struct iovec iov[1];
  struct ucred *cr = 0;
  u32 idx = uf->private_data;
  memif_if_t *mif = vec_elt_at_index (mm->interfaces, idx);
  memif_msg_t msg;
  struct cmsghdr *cmsg;
  ssize_t size;
  int mfd = -1;
  memif_region_t region = { 0, 0, -1 };

  iov[0].iov_base = (void *) &msg;
  iov[0].iov_len = sizeof (memif_msg_t);
  mh.msg_iov = iov;
  mh.msg_iovlen = 1;
  mh.msg_control = ctl;
  mh.msg_controllen = sizeof (ctl);

  size = recvmsg (uf->file_descriptor, &mh, 0);
  if (size != sizeof (memif_msg_t))
    {
      if (0 == size)
        {
          close_memif_conn(mm, mif);
          memif_disconnect(vm, mif);
          return 0;
        }
      // TODO better error handling
      clib_unix_error ("recvmsg");
      return 0;
    }

  /* Process anciliary data */
  cmsg = CMSG_FIRSTHDR (&mh);
  while (cmsg)
    {
      if (cmsg->cmsg_level == SOL_SOCKET
          && cmsg->cmsg_type == SCM_CREDENTIALS)
        cr = (struct ucred *) CMSG_DATA (cmsg);
      else if (cmsg->cmsg_level == SOL_SOCKET
               && cmsg->cmsg_type == SCM_RIGHTS)
        {
          clib_memcpy (&mfd, CMSG_DATA (cmsg), sizeof (mfd));
        }
      cmsg = CMSG_NXTHDR (&mh, cmsg);
    }

  if (mfd == -1)
    return 0;

  region.fd = mfd;
  region.size = msg.shared_mem_size;
  if ((region.mem =
       mmap (NULL, msg.shared_mem_size, PROT_READ | PROT_WRITE, MAP_SHARED,
             mfd, 0)) == MAP_FAILED)
    clib_unix_error ("mmap");

  mif->log2_ring_size = msg.log2_ring_size;
  mif->num_s2m_rings = msg.num_s2m_rings;
  mif->num_m2s_rings = msg.num_m2s_rings;
  mif->buffer_size = msg.buffer_size;
  mif->remote_pid = cr->pid;
  mif->remote_uid = cr->uid;
  vec_add1 (mif->regions, region);

  memif_connect (vm, mif);

  return 0;
}

static clib_error_t *
memif_fd_accept_ready (unix_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  memif_if_t *mif;
  int addr_len;
  struct sockaddr_un client;
  unix_file_t template = { 0 };

  mif = pool_elt_at_index (mm->interfaces, uf->private_data);

  if (mif->conn_fd > -1)
    {
      clib_unix_warning("already connected/connecting");
      return 0;
    }

  addr_len = sizeof (client);
  mif->conn_fd = accept (uf->file_descriptor,
                         (struct sockaddr *) &client,
                         (socklen_t *) &addr_len);

  if (mif->conn_fd < 0)
    return clib_error_return_unix (0, "accept");

  template.read_function = memif_fd_read_ready;
  template.file_descriptor = mif->conn_fd;
  template.private_data = mif->if_index;
  mif->conn_file_index = unix_file_add (&unix_main, &template);

  return 0;
}


static void
memif_connect_master (vlib_main_t * vm, memif_if_t * mif)
{
  memif_msg_t msg;
  struct msghdr mh = { 0 };
  struct iovec iov[1];
  struct cmsghdr *cmsg;
  int mfd;
  int rv;
  char ctl[CMSG_SPACE(sizeof(int))] = { 0 };
  memif_ring_t *ring = NULL;
  int i, j;
  memif_region_t region = { 0 };
  u64 buffer_offset;

  msg.log2_ring_size = mif->log2_ring_size;
  msg.num_s2m_rings = mif->num_s2m_rings;
  msg.num_m2s_rings = mif->num_m2s_rings;
  msg.buffer_size = mif->buffer_size;

  if (vec_len(mif->regions) == 0)
    {
      buffer_offset = sizeof (memif_shm_t) +
        (mif->num_s2m_rings + mif->num_m2s_rings) * memif_get_ring_size(mif);

      msg.shared_mem_size = buffer_offset +
        mif->buffer_size * (1 << mif->log2_ring_size) * (mif->num_s2m_rings +
                                                         mif->num_m2s_rings);

      // FIXME Error Handling
      if ((mfd = memfd_create ("shared mem", MFD_ALLOW_SEALING)) == -1)
        clib_unix_error ("memfd_create");

      region.fd = mfd;
      region.size = msg.shared_mem_size;

      if ((fcntl (mfd, F_ADD_SEALS, F_SEAL_SHRINK)) == -1)
        clib_unix_error ("fcntl");

      if ((ftruncate (mfd, msg.shared_mem_size)) == -1)
        clib_unix_error ("ftruncate");

      if ((region.mem =
           mmap (NULL, msg.shared_mem_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                 mfd, 0)) == MAP_FAILED)
        clib_unix_error ("mmap");

      ((memif_shm_t *) region.mem)->cookie = 0xdeadbeef;
      vec_add1 (mif->regions, region);

      for (i = 0; i < mif->num_s2m_rings; i++)
        {
          ring = memif_get_ring (mif, MEMIF_RING_S2M, i);
          ring->head = ring->tail = 0;
          for (j = 0; j < (1 << mif->log2_ring_size); j++)
            {
              u16 slot = i * (1 << mif->log2_ring_size) + j;
              ring->desc[j].region = 0;
              ring->desc[j].offset = buffer_offset + (slot * mif->buffer_size);
              ring->desc[j].buffer_length = mif->buffer_size;
            }
        }
      for (i = 0; i < mif->num_m2s_rings; i++)
        {
          ring = memif_get_ring (mif, MEMIF_RING_M2S, i);
          ring->head = ring->tail = 0;
          for (j = 0; j < (1 << mif->log2_ring_size); j++)
            {
              u16 slot = (i + mif->num_s2m_rings) * (1 << mif->log2_ring_size) + j;
              ring->desc[j].region = 0;
              ring->desc[j].offset = buffer_offset + (slot * mif->buffer_size);
              ring->desc[j].buffer_length = mif->buffer_size;
            }
        }
    }
  else
    {
      /* re-use already allocated shared memory segment */
      msg.shared_mem_size = mif->regions[0].size;
      mfd = mif->regions[0].fd;

      for (i = 0; i < mif->num_s2m_rings; i++)
        {
          ring = memif_get_ring (mif, MEMIF_RING_S2M, i);
          ring->head = ring->tail = 0;
        }
      for (i = 0; i < mif->num_m2s_rings; i++)
        {
          ring = memif_get_ring (mif, MEMIF_RING_M2S, i);
          ring->head = ring->tail = 0;
       }
    }


  iov[0].iov_base = (void *) &msg;
  iov[0].iov_len = sizeof (memif_msg_t);
  mh.msg_iov = iov;
  mh.msg_iovlen = 1;

  mh.msg_control = ctl;
  mh.msg_controllen = sizeof (ctl);
  cmsg = CMSG_FIRSTHDR (&mh);
  cmsg->cmsg_len = CMSG_LEN (sizeof (mfd));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  clib_memcpy (CMSG_DATA (cmsg), &mfd, sizeof (mfd));

  rv = sendmsg (mif->conn_fd, &mh, 0);

  if (rv < 0)
    clib_unix_warning ("sendmsg");

  memif_connect (vm, mif);
}

static uword
memif_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  memif_main_t *mm = &memif_main;
  memif_if_t *mif;
  struct sockaddr_un sun;
  int sockfd;
#define UNREACHABLE_TIMEOUT  3153600000.0 /* 100 years */
  f64 timeout = UNREACHABLE_TIMEOUT;
  uword *event_data = 0;
  unix_file_t template = { 0 };

  sockfd = socket (AF_UNIX, SOCK_STREAM, 0);
  sun.sun_family = AF_UNIX;
  template.read_function = memif_fd_read_ready;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      if (pool_elts(mm->interfaces) > 0)
        {
          timeout = 3.0;
        }
      else
        {
          timeout = UNREACHABLE_TIMEOUT;
        }

      vec_foreach (mif, mm->interfaces)
      {
        if ((mif->flags & MEMIF_IF_FLAG_ADMIN_UP) == 0)
          continue;

        if (mif->flags & MEMIF_IF_FLAG_CONNECTED)
          continue;

        if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
          {
            strncpy (sun.sun_path, (char *) mif->socket_file_name,
                     sizeof (sun.sun_path) - 1);

            if (connect
                (sockfd, (struct sockaddr *) &sun,
                 sizeof (struct sockaddr_un)) == 0)
              {
                //vui->sock_errno = 0;
                mif->conn_fd = sockfd;
                template.file_descriptor = sockfd;
                template.private_data = mif->if_index;
                mif->conn_file_index = unix_file_add (&unix_main, &template);
                memif_connect_master (vm, mif);

                /* grab another fd */
                sockfd = socket (AF_UNIX, SOCK_STREAM, 0);
                if (sockfd < 0)
                  return 0;
              }
          }
      }
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (memif_process_node,static) = {
  .function = memif_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "memif-process",
};
/* *INDENT-ON* */

static void
close_memif_if (memif_main_t * mm, memif_if_t * mif)
{
  memif_region_t *region;
  close_memif_conn(mm, mif);

  if (mif->sock_file_index != ~0)
    {
      unix_file_del (&unix_main, unix_main.file_pool + mif->sock_file_index);
      mif->sock_file_index = ~0;
    }
  if (mif->sock_fd > -1)
    {
       close (mif->sock_fd);
       mif->sock_fd = -1;
    }
  if (mif->lockp != 0)
    {
      clib_mem_free ((void *)mif->lockp);
      mif->lockp = 0;
    }
  vec_foreach(region, mif->regions)
  {
    free_memif_region(region);
  }
  vec_free(mif->regions);

  mhash_unset (&mm->if_index_by_sock_file_name, mif->socket_file_name,
               &mif->if_index);
  vec_free (mif->socket_file_name);
  vec_free (mif->ring_data);

  memset (mif, 0, sizeof (*mif));
  pool_put (mm->interfaces, mif);
}

int
memif_worker_thread_enable ()
{
  /* if worker threads are enabled, switch to polling mode */
  foreach_vlib_main (({
                        vlib_node_set_state (this_vlib_main,
                                             memif_input_node.index,
                                             VLIB_NODE_STATE_POLLING);
                       }));

  return 0;
}

int
memif_worker_thread_disable ()
{
  foreach_vlib_main (({
                        vlib_node_set_state (this_vlib_main,
                                             memif_input_node.index,
                                             VLIB_NODE_STATE_INTERRUPT);
                       }));

  return 0;
}

int
memif_create_if (vlib_main_t * vm, memif_create_if_args_t * args)
{
  memif_main_t *mm = &memif_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  memif_if_t *mif = 0;
  vnet_sw_interface_t *sw;
  clib_error_t *error = 0;
  vnet_main_t *vnm = vnet_get_main ();
  int ret = 0;
  uword *p;
  u8 hw_addr[6];

  p = mhash_get (&mm->if_index_by_sock_file_name, args->socket_file_name);
  if (p)
    return VNET_API_ERROR_SUBIF_ALREADY_EXISTS;

  pool_get (mm->interfaces, mif);
  memset (mif, 0, sizeof (*mif));
  mif->if_index = mif - mm->interfaces;
  mif->sock_fd = mif->conn_fd = -1;
  mif->sock_file_index = mif->conn_file_index = ~0;
  mif->hw_if_index = ~0;

  if (tm->n_vlib_mains > 1)
    {
      mif->lockp = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
                                           CLIB_CACHE_LINE_BYTES);
      memset ((void *) mif->lockp, 0, CLIB_CACHE_LINE_BYTES);
    }

  // TODO set mac manually
  {
    f64 now = vlib_time_now (vm);
    u32 rnd;
    rnd = (u32) (now * 1e6);
    rnd = random_u32 (&rnd);

    memcpy (hw_addr + 2, &rnd, sizeof (rnd));
    hw_addr[0] = 2;
    hw_addr[1] = 0xfe;
  }

  error = ethernet_register_interface (vnm, memif_device_class.index,
                                       mif->if_index, hw_addr,
                                       &mif->hw_if_index,
                                       memif_eth_flag_change);

  if (error)
    {
      clib_error_report (error);
      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

  sw = vnet_get_hw_sw_interface (vnm, mif->hw_if_index);
  mif->sw_if_index = sw->sw_if_index;
  mif->per_interface_next_index = ~0;

  // TODO Make configurable
  mif->log2_ring_size = args->log2_ring_size;
  mif->num_s2m_rings = 1;
  mif->num_m2s_rings = 1;
  mif->buffer_size = 2048;

  mhash_set_mem (&mm->if_index_by_sock_file_name, args->socket_file_name,
                 &mif->if_index, 0);
  mif->socket_file_name = args->socket_file_name;

  args->sw_if_index = mif->sw_if_index;

  if (args->is_master)
    {
      int fd;
      struct sockaddr_un un = { 0 };
      int on = 1;

      if ((fd = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
        {
          ret = VNET_API_ERROR_SYSCALL_ERROR_2;
          goto error;
        }

      un.sun_family = AF_UNIX;
      strncpy ((char *) un.sun_path, (char *) mif->socket_file_name,
               sizeof (un.sun_path) - 1);

      // FIXME unsecure
      unlink ((char *) mif->socket_file_name);

      if (setsockopt (fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof (on)) < 0)
        {
          ret = VNET_API_ERROR_SYSCALL_ERROR_3;
          goto error;
        }
      if (bind (fd, (struct sockaddr *) &un, sizeof (un)) == -1)
        {
          ret = VNET_API_ERROR_SYSCALL_ERROR_4;
          goto error;
        }

      if (listen (fd, 1) == -1)
        {
          ret = VNET_API_ERROR_SYSCALL_ERROR_5;
          goto error;
        }

      unix_file_t template = { 0 };
      template.read_function = memif_fd_accept_ready;
      template.file_descriptor = mif->sock_fd = fd;
      template.private_data = mif->if_index;
      mif->sock_file_index = unix_file_add (&unix_main, &template);
    }
  else
    {
      mif->flags |= MEMIF_IF_FLAG_IS_SLAVE;
      mif->sock_fd = -1;
    }

#if 0
  /*use configured or generate random MAC address */
  if (hw_addr_set)
    memcpy (hw_addr, hw_addr_set, 6);
  else if (tm->n_vlib_mains > 1 && pool_elts (mm->interfaces) == 1)
    memif_worker_thread_enable ();
#endif

  vlib_process_signal_event (vm, memif_process_node.index, 0, 0);
  return 0;

error:
  if (mif->hw_if_index != ~0)
    {
      ethernet_delete_interface (vnm, mif->hw_if_index);
      mif->hw_if_index = ~0;
    }
  close_memif_if (mm, mif);
  return ret;
}

int
memif_delete_if (vlib_main_t * vm, u8 * host_if_name)
{
  vnet_main_t *vnm = vnet_get_main ();
  memif_main_t *mm = &memif_main;
  memif_if_t *mif;
  uword *p;

  p = mhash_get (&mm->if_index_by_sock_file_name, host_if_name);
  if (p == NULL)
    {
      clib_warning ("unix socket file %s does not exist", host_if_name);
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }
  mif = pool_elt_at_index (mm->interfaces, p[0]);

  /* bring down the interface */
  vnet_hw_interface_set_flags (vnm, mif->hw_if_index, 0);

  ethernet_delete_interface (vnm, mif->hw_if_index);

  close_memif_if (mm, mif);

#if 0
  if (tm->n_vlib_mains > 1 && pool_elts (mm->interfaces) == 0)
    memif_worker_thread_disable ();
#endif

  return 0;
}

static clib_error_t *
memif_init (vlib_main_t * vm)
{
  memif_main_t *mm = &memif_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_thread_registration_t *tr;
  uword *p;

  memset (mm, 0, sizeof (memif_main_t));

  mm->input_cpu_first_index = 0;
  mm->input_cpu_count = 1;

  /* find out which cpus will be used for input */
  p = hash_get_mem (tm->thread_registrations_by_name, "workers");
  tr = p ? (vlib_thread_registration_t *) p[0] : 0;

  if (tr && tr->count > 0)
    {
      mm->input_cpu_first_index = tr->first_index;
      mm->input_cpu_count = tr->count;
    }

  mhash_init_vec_string (&mm->if_index_by_sock_file_name, sizeof (uword));

  vec_validate_aligned (mm->rx_buffers, tm->n_vlib_mains - 1,
                        CLIB_CACHE_LINE_BYTES);

  return 0;
}

VLIB_INIT_FUNCTION (memif_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
