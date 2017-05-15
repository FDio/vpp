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
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ethernet/ethernet.h>
#include <vpp/app/version.h>
#include <memif/memif.h>

#define MEMIF_DEBUG 1

#if MEMIF_DEBUG == 1
#define DEBUG_LOG(...) clib_warning(__VA_ARGS__)
#define DEBUG_UNIX_LOG(...) clib_unix_warning(__VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

memif_main_t memif_main;

static clib_error_t *memif_conn_fd_read_ready (unix_file_t * uf);
static clib_error_t *memif_int_fd_read_ready (unix_file_t * uf);

static u32
memif_eth_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hi, u32 flags)
{
  /* nothing for now */
  return 0;
}

static void
memif_remove_pending_conn (memif_pending_conn_t * pending_conn)
{
  memif_main_t *mm = &memif_main;

  unix_file_del (&unix_main,
		 unix_main.file_pool + pending_conn->connection.index);
  pool_put (mm->pending_conns, pending_conn);
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

  mif->flags &= ~MEMIF_IF_FLAG_CONNECTING;
  mif->flags |= MEMIF_IF_FLAG_CONNECTED;
  vnet_hw_interface_set_flags (vnm, mif->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);
}

void
memif_disconnect (vlib_main_t * vm, memif_if_t * mif)
{
  vnet_main_t *vnm = vnet_get_main ();

  mif->flags &= ~(MEMIF_IF_FLAG_CONNECTED | MEMIF_IF_FLAG_CONNECTING);
  if (mif->hw_if_index != ~0)
    vnet_hw_interface_set_flags (vnm, mif->hw_if_index, 0);

  if (mif->interrupt_line.index != ~0)
    {
      unix_file_del (&unix_main,
		     unix_main.file_pool + mif->interrupt_line.index);
      mif->interrupt_line.index = ~0;
      mif->interrupt_line.fd = -1;	/* closed in unix_file_del */
    }
  if (mif->connection.index != ~0)
    {
      unix_file_del (&unix_main, unix_main.file_pool + mif->connection.index);
      mif->connection.index = ~0;
      mif->connection.fd = -1;	/* closed in unix_file_del */
    }

  // TODO: properly munmap + close memif-owned shared memory segments
  vec_free (mif->regions);
}

static clib_error_t *
memif_process_connect_req (memif_pending_conn_t * pending_conn,
			   memif_msg_t * req, struct ucred *slave_cr,
			   int shm_fd, int int_fd)
{
  memif_main_t *mm = &memif_main;
  vlib_main_t *vm = vlib_get_main ();
  int fd = pending_conn->connection.fd;
  unix_file_t *uf = 0;
  memif_if_t *mif = 0;
  memif_msg_t resp = { 0 };
  unix_file_t template = { 0 };
  void *shm;
  uword *p;
  u8 retval = 0;
  static clib_error_t *error = 0;

  if (shm_fd == -1)
    {
      DEBUG_LOG
	("Connection request is missing shared memory file descriptor");
      retval = 1;
      goto response;
    }

  if (int_fd == -1)
    {
      DEBUG_LOG
	("Connection request is missing interrupt line file descriptor");
      retval = 2;
      goto response;
    }

  if (slave_cr == NULL)
    {
      DEBUG_LOG ("Connection request is missing slave credentials");
      retval = 3;
      goto response;
    }

  p = mhash_get (&mm->if_index_by_key, &req->key);
  if (!p)
    {
      DEBUG_LOG
	("Connection request with unmatched key (0x%" PRIx64 ")", req->key);
      retval = 4;
      goto response;
    }

  mif = vec_elt_at_index (mm->interfaces, *p);
  if (mif->listener_index != pending_conn->listener_index)
    {
      DEBUG_LOG
	("Connection request with non-matching listener (%d vs. %d)",
	 pending_conn->listener_index, mif->listener_index);
      retval = 5;
      goto response;
    }

  if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
    {
      DEBUG_LOG ("Memif slave does not accept connection requests");
      retval = 6;
      goto response;
    }

  if (mif->connection.fd != -1)
    {
      DEBUG_LOG
	("Memif with key 0x%" PRIx64 " is already connected", mif->key);
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
      DEBUG_LOG
	("Unexpectedly small shared memory segment received from slave.");
      retval = 9;
      goto response;
    }

  if ((shm =
       mmap (NULL, req->shared_mem_size, PROT_READ | PROT_WRITE, MAP_SHARED,
	     shm_fd, 0)) == MAP_FAILED)
    {
      DEBUG_UNIX_LOG
	("Failed to map shared memory segment received from slave memif");
      error = clib_error_return_unix (0, "mmap fd %d", shm_fd);
      retval = 10;
      goto response;
    }

  if (((memif_shm_t *) shm)->cookie != 0xdeadbeef)
    {
      DEBUG_LOG
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

  /* register interrupt line */
  mif->interrupt_line.fd = int_fd;
  template.read_function = memif_int_fd_read_ready;
  template.file_descriptor = int_fd;
  template.private_data = mif->if_index;
  mif->interrupt_line.index = unix_file_add (&unix_main, &template);

  /* change context for future messages */
  uf = vec_elt_at_index (unix_main.file_pool, pending_conn->connection.index);
  uf->private_data = mif->if_index << 1;
  mif->connection = pending_conn->connection;
  pool_put (mm->pending_conns, pending_conn);
  pending_conn = 0;

  memif_connect (vm, mif);

response:
  resp.version = MEMIF_VERSION;
  resp.type = MEMIF_MSG_TYPE_CONNECT_RESP;
  resp.retval = retval;
  if (send (fd, &resp, sizeof (resp), 0) < 0)
    {
      DEBUG_UNIX_LOG ("Failed to send connection response");
      error = clib_error_return_unix (0, "send fd %d", fd);
      if (pending_conn)
	memif_remove_pending_conn (pending_conn);
      else
	memif_disconnect (vm, mif);
    }
  if (retval > 0)
    {
      if (shm_fd >= 0)
	close (shm_fd);
      if (int_fd >= 0)
	close (int_fd);
    }
  return error;
}

static clib_error_t *
memif_process_connect_resp (memif_if_t * mif, memif_msg_t * resp)
{
  vlib_main_t *vm = vlib_get_main ();

  if ((mif->flags & MEMIF_IF_FLAG_IS_SLAVE) == 0)
    {
      DEBUG_LOG ("Memif master does not accept connection responses");
      return 0;
    }

  if ((mif->flags & MEMIF_IF_FLAG_CONNECTING) == 0)
    {
      DEBUG_LOG ("Unexpected connection response");
      return 0;
    }

  if (resp->retval == 0)
    memif_connect (vm, mif);
  else
    memif_disconnect (vm, mif);

  return 0;
}

static clib_error_t *
memif_conn_fd_read_ready (unix_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  vlib_main_t *vm = vlib_get_main ();
  memif_if_t *mif = 0;
  memif_pending_conn_t *pending_conn = 0;
  int fd_array[2] = { -1, -1 };
  char ctl[CMSG_SPACE (sizeof (fd_array)) +
	   CMSG_SPACE (sizeof (struct ucred))] = { 0 };
  struct msghdr mh = { 0 };
  struct iovec iov[1];
  struct ucred *cr = 0;
  memif_msg_t msg = { 0 };
  struct cmsghdr *cmsg;
  ssize_t size;
  static clib_error_t *error = 0;

  iov[0].iov_base = (void *) &msg;
  iov[0].iov_len = sizeof (memif_msg_t);
  mh.msg_iov = iov;
  mh.msg_iovlen = 1;
  mh.msg_control = ctl;
  mh.msg_controllen = sizeof (ctl);

  /* grab the appropriate context */
  if (uf->private_data & 1)
    pending_conn = vec_elt_at_index (mm->pending_conns,
				     uf->private_data >> 1);
  else
    mif = vec_elt_at_index (mm->interfaces, uf->private_data >> 1);

  /* receive the incoming message */
  size = recvmsg (uf->file_descriptor, &mh, 0);
  if (size != sizeof (memif_msg_t))
    {
      if (size != 0)
	{
	  DEBUG_UNIX_LOG ("Malformed message received on fd %d",
			  uf->file_descriptor);
	  error = clib_error_return_unix (0, "recvmsg fd %d",
					  uf->file_descriptor);
	}
      goto disconnect;
    }

  /* check version of the sender's memif plugin */
  if (msg.version != MEMIF_VERSION)
    {
      DEBUG_LOG ("Memif version mismatch");
      goto disconnect;
    }

  /* process the message based on its type */
  switch (msg.type)
    {
    case MEMIF_MSG_TYPE_CONNECT_REQ:
      if (pending_conn == 0)
	{
	  DEBUG_LOG ("Received unexpected connection request");
	  return 0;
	}

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

      return memif_process_connect_req (pending_conn, &msg, cr,
					fd_array[0], fd_array[1]);

    case MEMIF_MSG_TYPE_CONNECT_RESP:
      if (mif == 0)
	{
	  DEBUG_LOG ("Received unexpected connection response");
	  return 0;
	}
      return memif_process_connect_resp (mif, &msg);

    case MEMIF_MSG_TYPE_DISCONNECT:
      goto disconnect;

    default:
      DEBUG_LOG ("Received unknown message type");
      goto disconnect;
    }

  return 0;

disconnect:
  if (pending_conn)
    memif_remove_pending_conn (pending_conn);
  else
    memif_disconnect (vm, mif);
  return error;
}

static clib_error_t *
memif_int_fd_read_ready (unix_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  vnet_main_t *vnm = vnet_get_main ();
  memif_if_t *mif = vec_elt_at_index (mm->interfaces, uf->private_data);
  u8 b;
  ssize_t size;

  size = read (uf->file_descriptor, &b, sizeof (b));
  if (0 == size)
    {
      /* interrupt line was disconnected */
      unix_file_del (&unix_main,
		     unix_main.file_pool + mif->interrupt_line.index);
      mif->interrupt_line.index = ~0;
      mif->interrupt_line.fd = -1;
    }
  vnet_device_input_set_interrupt_pending (vnm, mif->hw_if_index, 0);
  return 0;
}

static clib_error_t *
memif_conn_fd_accept_ready (unix_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  memif_listener_t *listener = 0;
  memif_pending_conn_t *pending_conn = 0;
  int addr_len;
  struct sockaddr_un client;
  int conn_fd;
  unix_file_t template = { 0 };

  listener = pool_elt_at_index (mm->listeners, uf->private_data);

  addr_len = sizeof (client);
  conn_fd = accept (uf->file_descriptor,
		    (struct sockaddr *) &client, (socklen_t *) & addr_len);

  if (conn_fd < 0)
    return clib_error_return_unix (0, "accept fd %d", uf->file_descriptor);

  pool_get (mm->pending_conns, pending_conn);
  pending_conn->index = pending_conn - mm->pending_conns;
  pending_conn->listener_index = listener->index;
  pending_conn->connection.fd = conn_fd;

  template.read_function = memif_conn_fd_read_ready;
  template.file_descriptor = conn_fd;
  template.private_data = (pending_conn->index << 1) | 1;
  pending_conn->connection.index = unix_file_add (&unix_main, &template);

  return 0;
}

static void
memif_connect_master (vlib_main_t * vm, memif_if_t * mif)
{
  memif_msg_t msg;
  struct msghdr mh = { 0 };
  struct iovec iov[1];
  struct cmsghdr *cmsg;
  int mfd = -1;
  int rv;
  int fd_array[2] = { -1, -1 };
  char ctl[CMSG_SPACE (sizeof (fd_array))];
  memif_ring_t *ring = NULL;
  int i, j;
  void *shm = 0;
  u64 buffer_offset;
  unix_file_t template = { 0 };

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
      DEBUG_LOG ("Failed to create anonymous file");
      goto error;
    }

  if ((fcntl (mfd, F_ADD_SEALS, F_SEAL_SHRINK)) == -1)
    {
      DEBUG_UNIX_LOG ("Failed to seal an anonymous file off from truncating");
      goto error;
    }

  if ((ftruncate (mfd, msg.shared_mem_size)) == -1)
    {
      DEBUG_UNIX_LOG ("Failed to extend the size of an anonymous file");
      goto error;
    }

  if ((shm = mmap (NULL, msg.shared_mem_size, PROT_READ | PROT_WRITE,
		   MAP_SHARED, mfd, 0)) == MAP_FAILED)
    {
      DEBUG_UNIX_LOG ("Failed to map anonymous file into memory");
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

  /* create interrupt socket */
  if (socketpair (AF_UNIX, SOCK_STREAM, 0, fd_array) < 0)
    {
      DEBUG_UNIX_LOG ("Failed to create a pair of connected sockets");
      goto error;
    }

  mif->interrupt_line.fd = fd_array[0];
  template.read_function = memif_int_fd_read_ready;
  template.file_descriptor = mif->interrupt_line.fd;
  template.private_data = mif->if_index;
  mif->interrupt_line.index = unix_file_add (&unix_main, &template);

  memset (&ctl, 0, sizeof (ctl));
  mh.msg_control = ctl;
  mh.msg_controllen = sizeof (ctl);
  cmsg = CMSG_FIRSTHDR (&mh);
  cmsg->cmsg_len = CMSG_LEN (sizeof (fd_array));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  fd_array[0] = mfd;
  memcpy (CMSG_DATA (cmsg), fd_array, sizeof (fd_array));

  mif->flags |= MEMIF_IF_FLAG_CONNECTING;
  rv = sendmsg (mif->connection.fd, &mh, 0);
  if (rv < 0)
    {
      DEBUG_UNIX_LOG ("Failed to send memif connection request");
      goto error;
    }

  /* No need to keep the descriptor open,
   * mmap creates an extra reference to the underlying file */
  close (mfd);
  mfd = -1;
  /* This FD is given to peer, so we can close it */
  close (fd_array[1]);
  fd_array[1] = -1;
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
  unix_file_t template = { 0 };
  u8 enabled = 0;
  f64 start_time, last_run_duration = 0, now;

  sockfd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (sockfd < 0)
    {
      DEBUG_UNIX_LOG ("socket AF_UNIX");
      return 0;
    }
  sun.sun_family = AF_UNIX;
  template.read_function = memif_conn_fd_read_ready;

  while (1)
    {
      if (enabled)
	vlib_process_wait_for_event_or_clock (vm,
					      (f64) 3 - last_run_duration);
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
	      strncpy (sun.sun_path, (char *) mif->socket_filename,
		       sizeof (sun.sun_path) - 1);

	      if (connect
		  (sockfd, (struct sockaddr *) &sun,
		   sizeof (struct sockaddr_un)) == 0)
	        {
		  mif->connection.fd = sockfd;
		  template.file_descriptor = sockfd;
		  template.private_data = mif->if_index << 1;
		  mif->connection.index = unix_file_add (&unix_main, &template);
		  memif_connect_master (vm, mif);

		  /* grab another fd */
		  sockfd = socket (AF_UNIX, SOCK_STREAM, 0);
		  if (sockfd < 0)
		    {
		      DEBUG_UNIX_LOG ("socket AF_UNIX");
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

static void
memif_close_if (memif_main_t * mm, memif_if_t * mif)
{
  vlib_main_t *vm = vlib_get_main ();
  memif_listener_t *listener = 0;
  memif_pending_conn_t *pending_conn = 0;

  memif_disconnect (vm, mif);

  if (mif->listener_index != (uword) ~ 0)
    {
      listener = pool_elt_at_index (mm->listeners, mif->listener_index);
      if (--listener->usage_counter == 0)
	{
	  /* not used anymore -> remove the socket and pending connections */

	  /* *INDENT-OFF* */
	  pool_foreach (pending_conn, mm->pending_conns,
	    ({
	       if (pending_conn->listener_index == mif->listener_index)
	         {
		   memif_remove_pending_conn (pending_conn);
	         }
	     }));
          /* *INDENT-ON* */

	  unix_file_del (&unix_main,
			 unix_main.file_pool + listener->socket.index);
	  pool_put (mm->listeners, listener);
	  unlink ((char *) mif->socket_filename);
	}
    }

  clib_spinlock_free (&mif->lockp);

  mhash_unset (&mm->if_index_by_key, &mif->key, &mif->if_index);
  vec_free (mif->socket_filename);
  vec_free (mif->ring_data);

  memset (mif, 0, sizeof (*mif));
  pool_put (mm->interfaces, mif);
}

int
memif_worker_thread_enable ()
{
  /* if worker threads are enabled, switch to polling mode */
  /* *INDENT-OFF* */
  foreach_vlib_main ((
		       {
		       vlib_node_set_state (this_vlib_main,
					    memif_input_node.index,
					    VLIB_NODE_STATE_POLLING);
		       }));
  /* *INDENT-ON* */
  return 0;
}

int
memif_worker_thread_disable ()
{
  /* *INDENT-OFF* */
  foreach_vlib_main ((
		       {
		       vlib_node_set_state (this_vlib_main,
					    memif_input_node.index,
					    VLIB_NODE_STATE_INTERRUPT);
		       }));
  /* *INDENT-ON* */
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

  p = mhash_get (&mm->if_index_by_key, &args->key);
  if (p)
    return VNET_API_ERROR_SUBIF_ALREADY_EXISTS;

  pool_get (mm->interfaces, mif);
  memset (mif, 0, sizeof (*mif));
  mif->key = args->key;
  mif->if_index = mif - mm->interfaces;
  mif->sw_if_index = mif->hw_if_index = mif->per_interface_next_index = ~0;
  mif->listener_index = ~0;
  mif->connection.index = mif->interrupt_line.index = ~0;
  mif->connection.fd = mif->interrupt_line.fd = -1;

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
				       mif->if_index, args->hw_addr,
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

  mif->log2_ring_size = args->log2_ring_size;
  mif->buffer_size = args->buffer_size;

  /* TODO: make configurable */
  mif->num_s2m_rings = 1;
  mif->num_m2s_rings = 1;

  mhash_set_mem (&mm->if_index_by_key, &args->key, &mif->if_index, 0);

  if (args->socket_filename != 0)
    mif->socket_filename = args->socket_filename;
  else
    mif->socket_filename = vec_dup (mm->default_socket_filename);

  args->sw_if_index = mif->sw_if_index;

  if (args->is_master)
    {
      struct sockaddr_un un = { 0 };
      struct stat file_stat;
      int on = 1;
      memif_listener_t *listener = 0;

      if (stat ((char *) mif->socket_filename, &file_stat) == 0)
	{
	  if (!S_ISSOCK (file_stat.st_mode))
	    {
	      errno = ENOTSOCK;
	      ret = VNET_API_ERROR_SYSCALL_ERROR_2;
	      goto error;
	    }
	  /* *INDENT-OFF* */
	  pool_foreach (listener, mm->listeners,
	    ({
	       if (listener->sock_dev == file_stat.st_dev &&
		   listener->sock_ino == file_stat.st_ino)
	         {
		   /* attach memif to the existing listener */
		   mif->listener_index = listener->index;
		   ++listener->usage_counter;
		   goto signal;
	         }
	     }));
          /* *INDENT-ON* */
	  unlink ((char *) mif->socket_filename);
	}

      pool_get (mm->listeners, listener);
      memset (listener, 0, sizeof (*listener));
      listener->socket.fd = -1;
      listener->socket.index = ~0;
      listener->index = listener - mm->listeners;
      listener->usage_counter = 1;

      if ((listener->socket.fd = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
	{
	  ret = VNET_API_ERROR_SYSCALL_ERROR_3;
	  goto error;
	}

      un.sun_family = AF_UNIX;
      strncpy ((char *) un.sun_path, (char *) mif->socket_filename,
	       sizeof (un.sun_path) - 1);

      if (setsockopt (listener->socket.fd, SOL_SOCKET, SO_PASSCRED,
		      &on, sizeof (on)) < 0)
	{
	  ret = VNET_API_ERROR_SYSCALL_ERROR_4;
	  goto error;
	}
      if (bind (listener->socket.fd, (struct sockaddr *) &un,
		sizeof (un)) == -1)
	{
	  ret = VNET_API_ERROR_SYSCALL_ERROR_5;
	  goto error;
	}
      if (listen (listener->socket.fd, 1) == -1)
	{
	  ret = VNET_API_ERROR_SYSCALL_ERROR_6;
	  goto error;
	}

      if (stat ((char *) mif->socket_filename, &file_stat) == -1)
	{
	  ret = VNET_API_ERROR_SYSCALL_ERROR_7;
	  goto error;
	}

      listener->sock_dev = file_stat.st_dev;
      listener->sock_ino = file_stat.st_ino;

      unix_file_t template = { 0 };
      template.read_function = memif_conn_fd_accept_ready;
      template.file_descriptor = listener->socket.fd;
      template.private_data = listener->index;
      listener->socket.index = unix_file_add (&unix_main, &template);

      mif->listener_index = listener->index;
    }
  else
    {
      mif->flags |= MEMIF_IF_FLAG_IS_SLAVE;
    }

  hw = vnet_get_hw_interface (vnm, mif->hw_if_index);
  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
  vnet_hw_interface_set_input_node (vnm, mif->hw_if_index,
				    memif_input_node.index);
  vnet_hw_interface_assign_rx_thread (vnm, mif->hw_if_index, 0, ~0);
  ret = vnet_hw_interface_set_rx_mode (vnm, mif->hw_if_index, 0,
				       VNET_HW_INTERFACE_RX_MODE_INTERRUPT);
  if (ret)
    clib_warning ("Warning: unable to set rx mode for interface %d: "
		  "rc=%d", mif->hw_if_index, ret);

#if 0
  /* use configured or generate random MAC address */
  if (!args->hw_addr_set &&
      tm->n_vlib_mains > 1 && pool_elts (mm->interfaces) == 1)
    memif_worker_thread_enable ();
#endif

signal:
  if (pool_elts (mm->interfaces) == 1)
    {
      vlib_process_signal_event (vm, memif_process_node.index,
				 MEMIF_PROCESS_EVENT_START, 0);
    }
  return 0;

error:
  if (mif->hw_if_index != ~0)
    {
      ethernet_delete_interface (vnm, mif->hw_if_index);
      mif->hw_if_index = ~0;
    }
  memif_close_if (mm, mif);
  return ret;
}

int
memif_delete_if (vlib_main_t * vm, u64 key)
{
  vnet_main_t *vnm = vnet_get_main ();
  memif_main_t *mm = &memif_main;
  memif_if_t *mif;
  uword *p;
  int ret;

  p = mhash_get (&mm->if_index_by_key, &key);
  if (p == NULL)
    {
      clib_warning ("Memory interface with key 0x%" PRIx64 " does not exist",
		    key);
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }
  mif = pool_elt_at_index (mm->interfaces, p[0]);
  mif->flags |= MEMIF_IF_FLAG_DELETING;

  ret = vnet_hw_interface_unassign_rx_thread (vnm, mif->hw_if_index, 0);
  if (ret)
    clib_warning ("Warning: unable to unassign interface %d: rc=%d",
		  mif->hw_if_index, ret);

  /* bring down the interface */
  vnet_hw_interface_set_flags (vnm, mif->hw_if_index, 0);
  vnet_sw_interface_set_flags (vnm, mif->sw_if_index, 0);

  /* remove the interface */
  ethernet_delete_interface (vnm, mif->hw_if_index);
  mif->hw_if_index = ~0;
  memif_close_if (mm, mif);

  if (pool_elts (mm->interfaces) == 0)
    {
      vlib_process_signal_event (vm, memif_process_node.index,
				 MEMIF_PROCESS_EVENT_STOP, 0);
    }

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

  /* initialize binary API */
  memif_plugin_api_hookup (vm);

  /* find out which cpus will be used for input */
  p = hash_get_mem (tm->thread_registrations_by_name, "workers");
  tr = p ? (vlib_thread_registration_t *) p[0] : 0;

  if (tr && tr->count > 0)
    {
      mm->input_cpu_first_index = tr->first_index;
      mm->input_cpu_count = tr->count;
    }

  mhash_init (&mm->if_index_by_key, sizeof (uword), sizeof (u64));

  vec_validate_aligned (mm->rx_buffers, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  /* set default socket filename */
  vec_validate (mm->default_socket_filename,
		strlen (MEMIF_DEFAULT_SOCKET_FILENAME));
  strncpy ((char *) mm->default_socket_filename,
	   MEMIF_DEFAULT_SOCKET_FILENAME,
	   vec_len (mm->default_socket_filename) - 1);

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
