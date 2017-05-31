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
#include <sys/prctl.h>
#include <sys/eventfd.h>
#include <inttypes.h>
#include <limits.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ethernet/ethernet.h>
#include <vpp/app/version.h>
#include <memif/memif.h>

#define MEMIF_DEBUG 1

#if MEMIF_DEBUG == 1
#define DBG_LOG(...) clib_warning(__VA_ARGS__)
#define DBG_UNIX_LOG(...) clib_unix_warning(__VA_ARGS__)
#else
#define DBG_LOG(...)
#endif

memif_main_t memif_main;

static clib_error_t *memif_conn_fd_read_ready_master (unix_file_t * uf);
static clib_error_t *memif_conn_fd_read_ready_slave (unix_file_t * uf);
static clib_error_t *memif_int_fd_read_ready (unix_file_t * uf);

static u32
memif_eth_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hi, u32 flags)
{
  /* nothing for now */
  return 0;
}

static void
memif_disconnect (vlib_main_t * vm, memif_if_t * mif)
{
  vnet_main_t *vnm = vnet_get_main ();
  u8 rid;

  if (mif == 0)
    return;

  DBG_LOG ("disconnect %u", mif->dev_instance);

  vec_foreach_index (rid, mif->rx_int_unix_file_index)
    if (mif->rx_int_unix_file_index[rid] != ~0)
    {
      unix_file_del_by_index (&unix_main, mif->rx_int_unix_file_index[rid]);
      DBG_LOG ("unix_file_del idx %u", mif->rx_int_unix_file_index[rid]);
      mif->rx_int_unix_file_index[rid] = ~0;
      mif->rx_int_fd[rid] = -1;
    }

  vec_foreach_index (rid, mif->tx_int_unix_file_index)
    if (mif->tx_int_unix_file_index[rid] != ~0)
    {
      unix_file_del_by_index (&unix_main, mif->tx_int_unix_file_index[rid]);
      DBG_LOG ("unix_file_del idx %u", mif->tx_int_unix_file_index[rid]);
      mif->tx_int_unix_file_index[rid] = ~0;
      mif->tx_int_fd[rid] = -1;
    }

  mif->flags &= ~(MEMIF_IF_FLAG_CONNECTED | MEMIF_IF_FLAG_CONNECTING);

  if (mif->hw_if_index != ~0)
    vnet_hw_interface_set_flags (vnm, mif->hw_if_index, 0);

  for (rid = 0; rid < memif_get_rx_queues (mif); rid++)
    {
      int rv;
      rv = vnet_hw_interface_unassign_rx_thread (vnm, mif->hw_if_index, rid);
      if (rv)
	DBG_LOG ("Warning: unable to unassign interface %d, "
		 "queue %d: rc=%d", mif->hw_if_index, rid, rv);
    }


  // TODO: properly munmap + close memif-owned shared memory segments
  vec_free (mif->regions);
}


static void
memif_connect (vlib_main_t * vm, memif_if_t * mif)
{
  vnet_main_t *vnm = vnet_get_main ();
  int num_rings = mif->num_s2m_rings + mif->num_m2s_rings;
  memif_ring_data_t *rd = NULL;
  unix_file_t template = { 0 };
  u8 rid;

  DBG_LOG ("connect %u", mif->dev_instance);

  vec_validate_aligned (mif->ring_data, num_rings - 1, CLIB_CACHE_LINE_BYTES);
  vec_foreach (rd, mif->ring_data) rd->last_head = 0;

  template.read_function = memif_int_fd_read_ready;
  template.private_data = mif->dev_instance;

  for (rid = 0; rid < memif_get_rx_queues (mif); rid++)
    {
      int rv;
      if (mif->rx_int_fd[rid] > -1)
	{
	  template.file_descriptor = mif->rx_int_fd[rid];
	  ASSERT (mif->rx_int_unix_file_index[rid] == ~0);
	  mif->rx_int_unix_file_index[rid] =
	    unix_file_add (&unix_main, &template);
	  DBG_LOG ("unix_file_add fd %d pd %u idx %u",
		   template.file_descriptor, template.private_data,
		   mif->rx_int_unix_file_index[rid]);
	}
      vnet_hw_interface_assign_rx_thread (vnm, mif->hw_if_index, rid, ~0);
      rv = vnet_hw_interface_set_rx_mode (vnm, mif->hw_if_index, rid,
					  VNET_HW_INTERFACE_RX_MODE_INTERRUPT);
      if (rv)
	clib_warning
	  ("Warning: unable to set rx mode for interface %d queue %d: "
	   "rc=%d", mif->hw_if_index, rid, rv);
    }

  mif->flags &= ~MEMIF_IF_FLAG_CONNECTING;
  mif->flags |= MEMIF_IF_FLAG_CONNECTED;

  vnet_hw_interface_set_flags (vnm, mif->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);
}

static clib_error_t *
memif_process_connect_req (memif_socket_file_t * msf, int fd,
			   memif_msg_t * req, struct ucred *slave_cr,
			   int *fds, uword conn_unix_file_index)
{
  memif_main_t *mm = &memif_main;
  vlib_main_t *vm = vlib_get_main ();
  memif_if_t *mif = 0;
  memif_msg_t resp = { 0 };
  //unix_file_t template = { 0 };
  void *shm;
  uword *p;
  u8 retval = 0;
  static clib_error_t *error = 0;

  if (fds[0] == -1)
    {
      DBG_LOG ("Connection request is missing shared memory file descriptor");
      retval = 1;
      goto response;
    }

  //FIXME
  if (fds[1] == -1)
    {
      DBG_LOG
	("Connection request is missing interrupt line file descriptor");
      retval = 2;
      goto response;
    }

  if (slave_cr == NULL)
    {
      DBG_LOG ("Connection request is missing slave credentials");
      retval = 3;
      goto response;
    }

  p = mhash_get (&msf->dev_instance_by_key, &req->key);
  if (!p)
    {
      DBG_LOG ("Connection request with unmatched key (0x%" PRIx64 ")",
	       req->key);
      retval = 4;
      goto response;
    }

  mif = vec_elt_at_index (mm->interfaces, p[0]);

  if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
    {
      DBG_LOG ("Memif slave does not accept connection requests");
      retval = 6;
      goto response;
    }

  if (mif->conn_fd != -1)
    {
      DBG_LOG ("Memif with key 0x%" PRIx64 " is already connected", mif->key);
      retval = 7;
      goto response;
    }

  if ((mif->flags & MEMIF_IF_FLAG_ADMIN_UP) == 0)
    {
      /* just silently decline the request */
      retval = 8;
      goto response;
    }

  if (req->shared_mem_size < sizeof (memif_shm_t))
    {
      DBG_LOG
	("Unexpectedly small shared memory segment received from slave.");
      retval = 9;
      goto response;
    }

  if ((shm = mmap (NULL, req->shared_mem_size, PROT_READ | PROT_WRITE,
		   MAP_SHARED, fds[0], 0)) == MAP_FAILED)
    {
      DBG_UNIX_LOG
	("Failed to map shared memory segment received from slave memif");
      error = clib_error_return_unix (0, "mmap fd %d", fds[0]);
      retval = 10;
      goto response;
    }

  if (((memif_shm_t *) shm)->cookie != 0xdeadbeef)
    {
      DBG_LOG
	("Possibly corrupted shared memory segment received from slave memif");
      munmap (shm, req->shared_mem_size);
      retval = 11;
      goto response;
    }

  mif->log2_ring_size = req->log2_ring_size;
  mif->num_s2m_rings = req->num_s2m_rings;
  mif->num_m2s_rings = req->num_m2s_rings;
  mif->buffer_size = req->buffer_size;
  mif->remote_pid = slave_cr->pid;
  mif->remote_uid = slave_cr->uid;
  vec_add1 (mif->regions, shm);

  vec_validate_init_empty_aligned (mif->rx_int_fd, memif_get_rx_queues (mif),
				   ~0, CLIB_CACHE_LINE_BYTES);
  vec_validate_init_empty_aligned (mif->tx_int_fd, memif_get_tx_queues (mif),
				   ~0, CLIB_CACHE_LINE_BYTES);
  vec_validate_init_empty (mif->rx_int_unix_file_index,
			   memif_get_rx_queues (mif), ~0);
  vec_validate_init_empty (mif->tx_int_unix_file_index,
			   memif_get_tx_queues (mif), ~0);

  mif->rx_int_fd[0] = fds[2];
  mif->tx_int_fd[0] = fds[1];
  mif->conn_fd = fd;
  mif->conn_unix_file_index = conn_unix_file_index;
  hash_set (msf->dev_instance_by_fd, mif->conn_fd, mif->dev_instance);

  memif_connect (vm, mif);

response:
  resp.version = MEMIF_VERSION;
  resp.type = MEMIF_MSG_TYPE_CONNECT_RESP;
  resp.retval = retval;
  if (send (fd, &resp, sizeof (resp), 0) < 0)
    {
      DBG_UNIX_LOG ("Failed to send connection response");
      error = clib_error_return_unix (0, "send fd %d", fd);
      memif_disconnect (vm, mif);
    }
  //FIXME
  if (retval > 0)
    {
      if (fds[0] >= 0)
	close (fds[0]);
      if (fds[1] >= 0)
	close (fds[1]);
    }
  return error;
}

static clib_error_t *
memif_process_connect_resp (memif_if_t * mif, memif_msg_t * resp)
{
  vlib_main_t *vm = vlib_get_main ();

  if ((mif->flags & MEMIF_IF_FLAG_IS_SLAVE) == 0)
    {
      DBG_LOG ("Memif master does not accept connection responses");
      return 0;
    }

  if ((mif->flags & MEMIF_IF_FLAG_CONNECTING) == 0)
    {
      DBG_LOG ("Unexpected connection response");
      return 0;
    }

  if (resp->retval == 0)
    memif_connect (vm, mif);
  else
    memif_disconnect (vm, mif);

  return 0;
}

static clib_error_t *
memif_conn_fd_read_ready_internal (unix_file_t * uf, int is_master)
{
  memif_main_t *mm = &memif_main;
  memif_socket_file_t *msf =
    pool_elt_at_index (mm->socket_files, uf->private_data);
  vlib_main_t *vm = vlib_get_main ();
  memif_if_t *mif = 0;
  int fd_array[3] = { -1, -1, -1 };
  char ctl[CMSG_SPACE (sizeof (fd_array)) +
	   CMSG_SPACE (sizeof (struct ucred))] = { 0 };
  struct msghdr mh = { 0 };
  struct iovec iov[1];
  struct ucred *cr = 0;
  memif_msg_t msg = { 0 };
  struct cmsghdr *cmsg;
  ssize_t size;
  static clib_error_t *error = 0;
  uword *p;
  uword conn_unix_file_index = ~0;

  p = hash_get (msf->dev_instance_by_fd, uf->file_descriptor);
  if (p)
    {
      mif = vec_elt_at_index (mm->interfaces, p[0]);
    }
  else
    {
      /* This is new connection, remove index from pending vector */
      int i;
      vec_foreach_index (i, msf->pending_file_indices)
	if (msf->pending_file_indices[i] == uf - unix_main.file_pool)
	{
	  conn_unix_file_index = msf->pending_file_indices[i];
	  vec_del1 (msf->pending_file_indices, i);
	  break;
	}
      ASSERT (conn_unix_file_index != ~0);
    }

  iov[0].iov_base = (void *) &msg;
  iov[0].iov_len = sizeof (memif_msg_t);
  mh.msg_iov = iov;
  mh.msg_iovlen = 1;
  mh.msg_control = ctl;
  mh.msg_controllen = sizeof (ctl);

  /* receive the incoming message */
  size = recvmsg (uf->file_descriptor, &mh, 0);
  if (size != sizeof (memif_msg_t))
    {
      if (size == 0)
	goto disconnect;

      DBG_UNIX_LOG ("Malformed message received on fd %d",
		    uf->file_descriptor);
      error = clib_error_return_unix (0, "recvmsg fd %d",
				      uf->file_descriptor);
      goto disconnect;
    }

  /* check version of the sender's memif plugin */
  if (msg.version != MEMIF_VERSION)
    {
      DBG_LOG ("Memif version mismatch");
      goto disconnect;
    }

  /* process the message based on its type */
  switch (msg.type)
    {
    case MEMIF_MSG_TYPE_CONNECT_REQ:
      /* Read anciliary data */
      cmsg = CMSG_FIRSTHDR (&mh);
      while (cmsg)
	{
	  if (cmsg->cmsg_level == SOL_SOCKET
	      && cmsg->cmsg_type == SCM_CREDENTIALS)
	    {
	      cr = (struct ucred *) CMSG_DATA (cmsg);
	    }
	  else if (cmsg->cmsg_level == SOL_SOCKET
		   && cmsg->cmsg_type == SCM_RIGHTS)
	    {
	      memcpy (fd_array, CMSG_DATA (cmsg), sizeof (fd_array));
	    }
	  cmsg = CMSG_NXTHDR (&mh, cmsg);
	}

      return memif_process_connect_req (msf, uf->file_descriptor, &msg, cr,
					fd_array, conn_unix_file_index);

    case MEMIF_MSG_TYPE_CONNECT_RESP:
      if (mif == 0)
	{
	  DBG_LOG ("Received unexpected connection response");
	  return 0;
	}
      return memif_process_connect_resp (mif, &msg);

    case MEMIF_MSG_TYPE_DISCONNECT:
      goto disconnect;

    default:
      DBG_LOG ("Received unknown message type (0x%x)", msg.type);
      goto disconnect;
    }

  return 0;

disconnect:
  if (conn_unix_file_index == ~0)
    memif_disconnect (vm, mif);
  return error;
}

static clib_error_t *
memif_int_fd_read_ready (unix_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  vnet_main_t *vnm = vnet_get_main ();
  memif_if_t *mif = vec_elt_at_index (mm->interfaces, uf->private_data);
  u64 b;
  ssize_t size;

  size = read (uf->file_descriptor, &b, sizeof (b));
  if (0 == size)
    {
      /* interrupt line was disconnected */
      unix_file_del_by_index (&unix_main, mif->rx_int_unix_file_index[0]);	//FIXME
      DBG_LOG ("unix_file_del idx %u", mif->rx_int_unix_file_index[0]);	//FIXME
      mif->rx_int_unix_file_index[0] = ~0;
      mif->rx_int_fd[0] = -1;
    }
  else
    vnet_device_input_set_interrupt_pending (vnm, mif->hw_if_index, 0);

  clib_warning ("int %u", b);
  return 0;
}

static clib_error_t *
memif_conn_fd_read_ready_master (unix_file_t * uf)
{
  return memif_conn_fd_read_ready_internal (uf, /* is_master */ 1);
}

static clib_error_t *
memif_conn_fd_read_ready_slave (unix_file_t * uf)
{
  return memif_conn_fd_read_ready_internal (uf, /* is_master */ 0);
}

static clib_error_t *
memif_conn_fd_error (unix_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  vlib_main_t *vm = vlib_get_main ();
  memif_socket_file_t *msf =
    pool_elt_at_index (mm->socket_files, uf->private_data);
  memif_if_t *mif;
  uword *p;

  DBG_LOG ("error fd %d pd %u", uf->file_descriptor, uf->private_data);

  p = hash_get (msf->dev_instance_by_fd, uf->file_descriptor);
  if (p)
    {
      mif = vec_elt_at_index (mm->interfaces, p[0]);
      memif_disconnect (vm, mif);
    }
  else
    clib_warning ("Error on unknown file descriptor %d", uf->file_descriptor);
  return 0;
}

static clib_error_t *
memif_conn_fd_accept_ready (unix_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  memif_socket_file_t *msf =
    pool_elt_at_index (mm->socket_files, uf->private_data);
  int addr_len;
  struct sockaddr_un client;
  int conn_fd;
  unix_file_t template = { 0 };
  uword unix_file_index;


  addr_len = sizeof (client);
  conn_fd = accept (uf->file_descriptor,
		    (struct sockaddr *) &client, (socklen_t *) & addr_len);

  if (conn_fd < 0)
    return clib_error_return_unix (0, "accept fd %d", uf->file_descriptor);

  template.read_function = memif_conn_fd_read_ready_master;
  template.error_function = memif_conn_fd_error;
  template.file_descriptor = conn_fd;
  template.private_data = uf->private_data;
  unix_file_index = unix_file_add (&unix_main, &template);
  DBG_LOG ("unix_file_add fd %d pd %u idx %u", template.file_descriptor,
	   template.private_data, unix_file_index);

  vec_add1 (msf->pending_file_indices, unix_file_index);

  return 0;
}

static void
memif_connect_to_master (vlib_main_t * vm, memif_if_t * mif)
{
  memif_main_t *mm = &memif_main;
  memif_socket_file_t *msf =
    pool_elt_at_index (mm->socket_files, mif->socket_file_index);
  memif_msg_t msg;
  struct msghdr mh = { 0 };
  struct iovec iov[1];
  struct cmsghdr *cmsg;
  int mfd = -1;
  int rv;
  int fd_array[3] = { -1, -1, -1 };
  char ctl[CMSG_SPACE (sizeof (fd_array))];
  memif_ring_t *ring = NULL;
  int i, j;
  void *shm = 0;
  u64 buffer_offset;
  unix_file_t template = { 0 };
  int rid;

  template.read_function = memif_conn_fd_read_ready_slave;
  template.file_descriptor = mif->conn_fd;
  template.private_data = mif->socket_file_index;
  ASSERT (mif->conn_unix_file_index == ~0);
  mif->conn_unix_file_index = unix_file_add (&unix_main, &template);
  DBG_LOG ("unix_file_add fd %d pd %u idx %u", template.file_descriptor,
	   template.private_data, mif->conn_unix_file_index);
  hash_set (msf->dev_instance_by_fd, mif->conn_fd, mif->dev_instance);

  msg.version = MEMIF_VERSION;
  msg.type = MEMIF_MSG_TYPE_CONNECT_REQ;
  msg.key = mif->key;
  msg.log2_ring_size = mif->log2_ring_size;
  msg.num_s2m_rings = mif->num_s2m_rings;
  msg.num_m2s_rings = mif->num_m2s_rings;
  msg.buffer_size = mif->buffer_size;

  buffer_offset = sizeof (memif_shm_t) +
    (mif->num_s2m_rings + mif->num_m2s_rings) *
    (sizeof (memif_ring_t) +
     sizeof (memif_desc_t) * (1 << mif->log2_ring_size));

  msg.shared_mem_size = buffer_offset +
    mif->buffer_size * (1 << mif->log2_ring_size) * (mif->num_s2m_rings +
						     mif->num_m2s_rings);

  if ((mfd = memfd_create ("shared mem", MFD_ALLOW_SEALING)) == -1)
    {
      DBG_LOG ("Failed to create anonymous file");
      goto error;
    }

  if ((fcntl (mfd, F_ADD_SEALS, F_SEAL_SHRINK)) == -1)
    {
      DBG_UNIX_LOG ("Failed to seal an anonymous file off from truncating");
      goto error;
    }

  if ((ftruncate (mfd, msg.shared_mem_size)) == -1)
    {
      DBG_UNIX_LOG ("Failed to extend the size of an anonymous file");
      goto error;
    }

  if ((shm = mmap (NULL, msg.shared_mem_size, PROT_READ | PROT_WRITE,
		   MAP_SHARED, mfd, 0)) == MAP_FAILED)
    {
      DBG_UNIX_LOG ("Failed to map anonymous file into memory");
      goto error;
    }

  vec_add1 (mif->regions, shm);
  ((memif_shm_t *) mif->regions[0])->cookie = 0xdeadbeef;

  for (i = 0; i < mif->num_s2m_rings; i++)
    {
      ring = memif_get_ring (mif, MEMIF_RING_S2M, i);
      ring->head = ring->tail = 0;
      for (j = 0; j < (1 << mif->log2_ring_size); j++)
	{
	  u16 slot = i * (1 << mif->log2_ring_size) + j;
	  ring->desc[j].region = 0;
	  ring->desc[j].offset =
	    buffer_offset + (u32) (slot * mif->buffer_size);
	  ring->desc[j].buffer_length = mif->buffer_size;
	}
    }
  for (i = 0; i < mif->num_m2s_rings; i++)
    {
      ring = memif_get_ring (mif, MEMIF_RING_M2S, i);
      ring->head = ring->tail = 0;
      for (j = 0; j < (1 << mif->log2_ring_size); j++)
	{
	  u16 slot =
	    (i + mif->num_s2m_rings) * (1 << mif->log2_ring_size) + j;
	  ring->desc[j].region = 0;
	  ring->desc[j].offset =
	    buffer_offset + (u32) (slot * mif->buffer_size);
	  ring->desc[j].buffer_length = mif->buffer_size;
	}
    }

  iov[0].iov_base = (void *) &msg;
  iov[0].iov_len = sizeof (memif_msg_t);
  mh.msg_iov = iov;
  mh.msg_iovlen = 1;

  vec_validate_init_empty_aligned (mif->rx_int_fd, memif_get_rx_queues (mif),
				   ~0, CLIB_CACHE_LINE_BYTES);
  vec_validate_init_empty_aligned (mif->tx_int_fd, memif_get_tx_queues (mif),
				   ~0, CLIB_CACHE_LINE_BYTES);
  vec_validate_init_empty (mif->rx_int_unix_file_index,
			   memif_get_rx_queues (mif), ~0);
  vec_validate_init_empty (mif->tx_int_unix_file_index,
			   memif_get_tx_queues (mif), ~0);

  /* create interrupt sockets */
  fd_array[0] = mfd;

  for (rid = 0; rid < memif_get_rx_queues (mif); rid++)
    if ((mif->rx_int_fd[rid] = eventfd (0, EFD_NONBLOCK)) < 0)
      {
	DBG_UNIX_LOG ("Failed to create a pair of connected sockets");
	goto error;
      }

  for (rid = 0; rid < memif_get_tx_queues (mif); rid++)
    if ((mif->tx_int_fd[rid] = eventfd (0, EFD_NONBLOCK)) < 0)
      {
	DBG_UNIX_LOG ("Failed to create a pair of connected sockets");
	goto error;
      }

  fd_array[1] = mif->rx_int_fd[0];
  fd_array[2] = mif->tx_int_fd[0];

  memset (&ctl, 0, sizeof (ctl));
  mh.msg_control = ctl;
  mh.msg_controllen = sizeof (ctl);
  cmsg = CMSG_FIRSTHDR (&mh);
  cmsg->cmsg_len = CMSG_LEN (sizeof (fd_array));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  memcpy (CMSG_DATA (cmsg), fd_array, sizeof (fd_array));

  mif->flags |= MEMIF_IF_FLAG_CONNECTING;
  rv = sendmsg (mif->conn_fd, &mh, 0);
  if (rv < 0)
    {
      DBG_UNIX_LOG ("Failed to send memif connection request");
      goto error;
    }

  /* No need to keep the descriptor open,
   * mmap creates an extra reference to the underlying file */
  close (mfd);
  mfd = -1;
  /* This FD is given to peer, so we can close it */
  return;

error:
  if (mfd > -1)
    close (mfd);
  if (fd_array[1] > -1)
    close (fd_array[1]);
  memif_disconnect (vm, mif);
}

static uword
memif_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  memif_main_t *mm = &memif_main;
  memif_if_t *mif;
  struct sockaddr_un sun;
  int sockfd;
  uword *event_data = 0, event_type;
  u8 enabled = 0;
  f64 start_time, last_run_duration = 0, now;

  sockfd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (sockfd < 0)
    {
      DBG_UNIX_LOG ("socket AF_UNIX");
      return 0;
    }
  sun.sun_family = AF_UNIX;

  while (1)
    {
      if (enabled)
	vlib_process_wait_for_event_or_clock (vm, (f64) 3 -
					      last_run_duration);
      else
	vlib_process_wait_for_event (vm);

      event_type = vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);

      switch (event_type)
	{
	case ~0:
	  break;
	case MEMIF_PROCESS_EVENT_START:
	  enabled = 1;
	  break;
	case MEMIF_PROCESS_EVENT_STOP:
	  enabled = 0;
	  continue;
	default:
	  ASSERT (0);
	}

      last_run_duration = start_time = vlib_time_now (vm);
      /* *INDENT-OFF* */
      pool_foreach (mif, mm->interfaces,
        ({
	  memif_socket_file_t * msf = vec_elt_at_index (mm->socket_files, mif->socket_file_index);
	  /* Allow no more than 10us without a pause */
	  now = vlib_time_now (vm);
	  if (now > start_time + 10e-6)
	    {
	      vlib_process_suspend (vm, 100e-6);	/* suspend for 100 us */
	      start_time = vlib_time_now (vm);
	    }

	  if ((mif->flags & MEMIF_IF_FLAG_ADMIN_UP) == 0)
	    continue;

	  if (mif->flags & MEMIF_IF_FLAG_CONNECTING)
	    continue;

	  if (mif->flags & MEMIF_IF_FLAG_CONNECTED)
	    continue;

	  if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
	    {
	      strncpy (sun.sun_path, (char *) msf->filename,
		       sizeof (sun.sun_path) - 1);

	      if (connect
		  (sockfd, (struct sockaddr *) &sun,
		   sizeof (struct sockaddr_un)) == 0)
	        {
		  mif->conn_fd = sockfd;
		  memif_connect_to_master (vm, mif);

		  /* grab another fd */
		  sockfd = socket (AF_UNIX, SOCK_STREAM, 0);
		  if (sockfd < 0)
		    {
		      DBG_UNIX_LOG ("socket AF_UNIX");
		      return 0;
		    }
	        }
	    }
        }));
      /* *INDENT-ON* */
      last_run_duration = vlib_time_now (vm) - last_run_duration;
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

int
memif_delete_if (vlib_main_t * vm, memif_if_t * mif)
{
  vnet_main_t *vnm = vnet_get_main ();
  memif_main_t *mm = &memif_main;
  memif_socket_file_t *msf =
    vec_elt_at_index (mm->socket_files, mif->socket_file_index);

  mif->flags |= MEMIF_IF_FLAG_DELETING;

  /* bring down the interface */
  vnet_hw_interface_set_flags (vnm, mif->hw_if_index, 0);
  vnet_sw_interface_set_flags (vnm, mif->sw_if_index, 0);

  memif_disconnect (vm, mif);

  /* remove the interface */
  ethernet_delete_interface (vnm, mif->hw_if_index);
  mif->hw_if_index = ~0;

  /* free interface data structures */
  clib_spinlock_free (&mif->lockp);
  vec_free (mif->ring_data);
  mhash_unset (&msf->dev_instance_by_key, &mif->key, 0);

  /* remove socket file */
  if (--(msf->ref_cnt) == 0)
    {
      DBG_LOG ("removing socket file %s", msf->filename);
      if (msf->is_listener)
	{
	  uword *x;
	  unix_file_del_by_index (&unix_main, msf->unix_file_index);
	  DBG_LOG ("unix_file_del idx %u", msf->unix_file_index);
	  vec_foreach (x, msf->pending_file_indices)
	  {
	    DBG_LOG ("removing pending funix file %u", *x);
	    unix_file_del_by_index (&unix_main, *x);
	  }
	  vec_free (msf->pending_file_indices);
	}
      mhash_free (&msf->dev_instance_by_key);
      hash_free (msf->dev_instance_by_fd);
      mhash_unset (&mm->socket_file_index_by_filename, msf->filename, 0);
      vec_free (msf->filename);
      pool_put (mm->socket_files, msf);
    }

  memset (mif, 0, sizeof (*mif));
  pool_put (mm->interfaces, mif);

  if (pool_elts (mm->interfaces) == 0)
    vlib_process_signal_event (vm, memif_process_node.index,
			       MEMIF_PROCESS_EVENT_STOP, 0);

  return 0;
}

int
memif_create_if (vlib_main_t * vm, memif_create_if_args_t * args)
{
  memif_main_t *mm = &memif_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vnet_main_t *vnm = vnet_get_main ();
  memif_if_t *mif = 0;
  vnet_sw_interface_t *sw;
  clib_error_t *error = 0;
  int ret = 0;
  uword *p;
  vnet_hw_interface_t *hw;
  memif_socket_file_t *msf = 0;
  u8 *socket_filename;
  int rv = 0;

  if (args->socket_filename == 0 || args->socket_filename[0] != '/')
    {
      rv = mkdir (MEMIF_DEFAULT_SOCKET_DIR, 0755);
      if (rv && errno != EEXIST)
	return VNET_API_ERROR_SYSCALL_ERROR_1;

      if (args->socket_filename == 0)
	socket_filename = format (0, "%s/%s%c", MEMIF_DEFAULT_SOCKET_DIR,
				  MEMIF_DEFAULT_SOCKET_FILENAME, 0);
      else
	socket_filename = format (0, "%s/%s%c", MEMIF_DEFAULT_SOCKET_DIR,
				  args->socket_filename, 0);

    }
  else
    socket_filename = vec_dup (args->socket_filename);

  p = mhash_get (&mm->socket_file_index_by_filename, socket_filename);

  if (p)
    {
      msf = vec_elt_at_index (mm->socket_files, p[0]);

      /* existing socket file can be either master or slave but cannot be both */
      if (!msf->is_listener != !args->is_master)
	{
	  rv = VNET_API_ERROR_SUBIF_ALREADY_EXISTS;
	  goto done;
	}

      p = mhash_get (&msf->dev_instance_by_key, &args->key);
      if (p)
	{
	  rv = VNET_API_ERROR_SUBIF_ALREADY_EXISTS;
	  goto done;
	}
    }

  /* Create new socket file */
  if (msf == 0)
    {
      struct stat file_stat;
      /* If we are creating listener make sure file doesn't exist or if it
       * exists thn delete it if it is old socket file */
      if (args->is_master &&
	  (stat ((char *) socket_filename, &file_stat) == 0))
	{
	  if (S_ISSOCK (file_stat.st_mode))
	    {
	      unlink ((char *) socket_filename);
	    }
	  else
	    {
	      ret = VNET_API_ERROR_SYSCALL_ERROR_3;
	      goto error;
	    }
	}
      pool_get (mm->socket_files, msf);
      memset (msf, 0, sizeof (memif_socket_file_t));
      mhash_init (&msf->dev_instance_by_key, sizeof (uword), sizeof (u64));
      msf->dev_instance_by_fd = hash_create (0, sizeof (uword));
      msf->filename = socket_filename;
      msf->fd = -1;
      msf->is_listener = (args->is_master != 0);
      socket_filename = 0;
      mhash_set (&mm->socket_file_index_by_filename, msf->filename,
		 msf - mm->socket_files, 0);
      DBG_LOG ("creating socket file %s", msf->filename);
    }

  pool_get (mm->interfaces, mif);
  memset (mif, 0, sizeof (*mif));
  mif->dev_instance = mif - mm->interfaces;
  mif->socket_file_index = msf - mm->socket_files;
  mif->key = args->key;
  mif->sw_if_index = mif->hw_if_index = mif->per_interface_next_index = ~0;
  mif->conn_unix_file_index = ~0;
  mif->conn_fd = -1;

  if (tm->n_vlib_mains > 1)
    clib_spinlock_init (&mif->lockp);

  if (!args->hw_addr_set)
    {
      f64 now = vlib_time_now (vm);
      u32 rnd;
      rnd = (u32) (now * 1e6);
      rnd = random_u32 (&rnd);

      memcpy (args->hw_addr + 2, &rnd, sizeof (rnd));
      args->hw_addr[0] = 2;
      args->hw_addr[1] = 0xfe;
    }

  error = ethernet_register_interface (vnm, memif_device_class.index,
				       mif->dev_instance, args->hw_addr,
				       &mif->hw_if_index,
				       memif_eth_flag_change);

  if (error)
    {
      clib_error_report (error);
      ret = VNET_API_ERROR_SYSCALL_ERROR_2;
      goto error;
    }

  sw = vnet_get_hw_sw_interface (vnm, mif->hw_if_index);
  mif->sw_if_index = sw->sw_if_index;

  mif->log2_ring_size = args->log2_ring_size;
  mif->buffer_size = args->buffer_size;

  /* TODO: make configurable */
  mif->num_s2m_rings = 1;
  mif->num_m2s_rings = 1;

  args->sw_if_index = mif->sw_if_index;

  /* If this is new one, start listening */
  if (msf->is_listener && msf->ref_cnt == 0)
    {
      struct sockaddr_un un = { 0 };
      struct stat file_stat;
      int on = 1;

      if ((msf->fd = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
	{
	  ret = VNET_API_ERROR_SYSCALL_ERROR_4;
	  goto error;
	}

      un.sun_family = AF_UNIX;
      strncpy ((char *) un.sun_path, (char *) msf->filename,
	       sizeof (un.sun_path) - 1);

      if (setsockopt (msf->fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof (on)) < 0)
	{
	  ret = VNET_API_ERROR_SYSCALL_ERROR_5;
	  goto error;
	}
      if (bind (msf->fd, (struct sockaddr *) &un, sizeof (un)) == -1)
	{
	  ret = VNET_API_ERROR_SYSCALL_ERROR_6;
	  goto error;
	}
      if (listen (msf->fd, 1) == -1)
	{
	  ret = VNET_API_ERROR_SYSCALL_ERROR_7;
	  goto error;
	}

      if (stat ((char *) msf->filename, &file_stat) == -1)
	{
	  ret = VNET_API_ERROR_SYSCALL_ERROR_8;
	  goto error;
	}

      unix_file_t template = { 0 };
      template.read_function = memif_conn_fd_accept_ready;
      template.file_descriptor = msf->fd;
      template.private_data = mif->socket_file_index;
      msf->unix_file_index = unix_file_add (&unix_main, &template);
      DBG_LOG ("unix_file_add fd %d pd %u idx %u", template.file_descriptor,
	       template.private_data, msf->unix_file_index);
    }

  msf->ref_cnt++;

  if (args->is_master == 0)
    mif->flags |= MEMIF_IF_FLAG_IS_SLAVE;

  hw = vnet_get_hw_interface (vnm, mif->hw_if_index);
  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
  vnet_hw_interface_set_input_node (vnm, mif->hw_if_index,
				    memif_input_node.index);

  mhash_set (&msf->dev_instance_by_key, &mif->key, mif->dev_instance, 0);

  if (pool_elts (mm->interfaces) == 1)
    {
      vlib_process_signal_event (vm, memif_process_node.index,
				 MEMIF_PROCESS_EVENT_START, 0);
    }
  goto done;

error:
  if (mif->hw_if_index != ~0)
    {
      ethernet_delete_interface (vnm, mif->hw_if_index);
      mif->hw_if_index = ~0;
    }
  memif_delete_if (vm, mif);
  return ret;

done:
  vec_free (socket_filename);
  return rv;
}


static clib_error_t *
memif_init (vlib_main_t * vm)
{
  memif_main_t *mm = &memif_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  memset (mm, 0, sizeof (memif_main_t));

  /* initialize binary API */
  memif_plugin_api_hookup (vm);

  mhash_init_c_string (&mm->socket_file_index_by_filename, sizeof (uword));

  vec_validate_aligned (mm->rx_buffers, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  return 0;
}

VLIB_INIT_FUNCTION (memif_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Packet Memory Interface (experimetal)",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
