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

memif_main_t memif_main;

static u32
memif_eth_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hi, u32 flags)
{
  /* nothing for now */
  return 0;
}

static void
memif_queue_intfd_close (memif_queue_t * mq)
{
  if (mq->int_unix_file_index != ~0)
    {
      unix_file_del_by_index (&unix_main, mq->int_unix_file_index);
      DBG ("unix_file_del idx %u", mq->int_unix_file_index);
      mq->int_unix_file_index = ~0;
      mq->int_fd = -1;
    }
  else if (mq->int_fd > -1)
    {
      close (mq->int_fd);
      mq->int_fd = -1;
    }
}

static void
memif_disconnect (memif_if_t * mif)
{
  vnet_main_t *vnm = vnet_get_main ();
  memif_region_t *mr;
  memif_queue_t *mq;
  int i;

  if (mif == 0)
    return;

  DBG ("disconnect %u", mif->dev_instance);

  /* set interface down */
  mif->flags &= ~(MEMIF_IF_FLAG_CONNECTED | MEMIF_IF_FLAG_CONNECTING);
  if (mif->hw_if_index != ~0)
    vnet_hw_interface_set_flags (vnm, mif->hw_if_index, 0);

  /* close connection socket */
  if (mif->conn_unix_file_index != ~0)
    {
      unix_file_del_by_index (&unix_main, mif->conn_unix_file_index);
      mif->conn_unix_file_index = ~0;
    }
  else if (mif->conn_fd > -1)
    close (mif->conn_fd);
  mif->conn_fd = -1;

  vec_foreach_index (i, mif->rx_queues)
  {
    int rv;
    rv = vnet_hw_interface_unassign_rx_thread (vnm, mif->hw_if_index, i);
    if (rv)
      DBG ("Warning: unable to unassign interface %d, "
	   "queue %d: rc=%d", mif->hw_if_index, i, rv);
  }

  /* free tx and rx queues */
  vec_foreach (mq, mif->rx_queues) memif_queue_intfd_close (mq);
  vec_free (mif->rx_queues);

  vec_foreach (mq, mif->tx_queues) memif_queue_intfd_close (mq);
  vec_free (mif->tx_queues);

  /* free memory regions */
  vec_foreach (mr, mif->regions)
  {
    int rv;
    if ((rv = munmap (mr->shm, mr->region_size)))
      clib_warning ("munmap failed, rv = %d", rv);
    if (mr->fd > -1)
      close (mr->fd);
  }
  vec_free (mif->regions);

  mif->remote_pid = 0;
}

static clib_error_t *
memif_int_fd_read_ready (unix_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  vnet_main_t *vnm = vnet_get_main ();
  memif_if_t *mif =
    vec_elt_at_index (mm->interfaces, (uf->private_data >> 16));
  u64 b;
  ssize_t size;

  size = read (uf->file_descriptor, &b, sizeof (b));
#if 0
  if (size == 0)
    {
      /* interrupt line was disconnected */
      unix_file_del_by_index (&unix_main, mif->rx_int_unix_file_index[0]);	//FIXME
      DBG ("unix_file_del idx %u", mif->rx_int_unix_file_index[0]);	//FIXME
      mif->rx_int_unix_file_index[0] = ~0;
      mif->rx_int_fd[0] = -1;
    }
  else
#endif
  if (size < 0)
    DBG_UNIX_LOG ("Failed to read from socket");
  else
    vnet_device_input_set_interrupt_pending (vnm, mif->hw_if_index,
					     uf->private_data & 0xFFFF);

  return 0;
}


static clib_error_t *
memif_connect (memif_if_t * mif)
{
  vnet_main_t *vnm = vnet_get_main ();
  unix_file_t template = { 0 };
  memif_region_t *mr;
  int i;

  DBG ("connect %u", mif->dev_instance);

  vec_foreach (mr, mif->regions)
  {
    if (mr->shm)
      continue;

    if (mr->fd < 0)
      clib_error_return (0, "no memory region fd");

    if ((mr->shm = mmap (NULL, mr->region_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, mr->fd, 0)) == MAP_FAILED)
      return clib_error_return_unix (0, "mmap");

    if (((memif_shm_t *) mr->shm)->cookie != 0xdeadbeef)
      return clib_error_return (0, "bad cookie");
  }

  template.read_function = memif_int_fd_read_ready;

  vec_foreach_index (i, mif->rx_queues)
  {
    memif_queue_t *mq = vec_elt_at_index (mif->rx_queues, i);
    int rv;

    if (mq->int_fd > -1)
      {
	template.file_descriptor = mq->int_fd;
	template.private_data = (mif->dev_instance << 16) | (i & 0xFFFF);
	ASSERT (mq->int_unix_file_index == ~0);
	mq->int_unix_file_index = unix_file_add (&unix_main, &template);
	DBG ("unix_file_add fd %d pd %u idx %u",
	     template.file_descriptor, template.private_data,
	     mq->int_unix_file_index);
      }
    vnet_hw_interface_assign_rx_thread (vnm, mif->hw_if_index, i, ~0);
    rv = vnet_hw_interface_set_rx_mode (vnm, mif->hw_if_index, i,
					VNET_HW_INTERFACE_RX_MODE_INTERRUPT);
    if (rv)
      clib_warning
	("Warning: unable to set rx mode for interface %d queue %d: "
	 "rc=%d", mif->hw_if_index, i, rv);
  }

  mif->flags &= ~MEMIF_IF_FLAG_CONNECTING;
  mif->flags |= MEMIF_IF_FLAG_CONNECTED;

  vnet_hw_interface_set_flags (vnm, mif->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);
  return 0;
}

static clib_error_t *
memif_init_regions_and_queues (memif_if_t * mif)
{
  memif_ring_t *ring = NULL;
  int i, j;
  u64 buffer_offset;
  memif_region_t *r;

  vec_validate_aligned (mif->regions, 0, CLIB_CACHE_LINE_BYTES);
  r = vec_elt_at_index (mif->regions, 0);

  buffer_offset = sizeof (memif_shm_t) +
    (mif->num_s2m_rings + mif->num_m2s_rings) *
    (sizeof (memif_ring_t) +
     sizeof (memif_desc_t) * (1 << mif->log2_ring_size));

  r->region_size = buffer_offset +
    mif->buffer_size * (1 << mif->log2_ring_size) * (mif->num_s2m_rings +
						     mif->num_m2s_rings);

  if ((r->fd = memfd_create ("memif region 0", MFD_ALLOW_SEALING)) == -1)
    return clib_error_return_unix (0, "memfd_create");

  if ((fcntl (r->fd, F_ADD_SEALS, F_SEAL_SHRINK)) == -1)
    return clib_error_return_unix (0, "fcntl (F_ADD_SEALS, F_SEAL_SHRINK)");

  if ((ftruncate (r->fd, r->region_size)) == -1)
    return clib_error_return_unix (0, "ftruncate");

  if ((r->shm = mmap (NULL, r->region_size, PROT_READ | PROT_WRITE,
		      MAP_SHARED, r->fd, 0)) == MAP_FAILED)
    return clib_error_return_unix (0, "mmap");

  ((memif_shm_t *) r->shm)->cookie = 0xdeadbeef;

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

  ASSERT (mif->tx_queues == 0);
  vec_validate_aligned (mif->tx_queues, mif->num_s2m_rings - 1,
			CLIB_CACHE_LINE_BYTES);
  vec_foreach_index (i, mif->tx_queues)
  {
    memif_queue_t *mq = vec_elt_at_index (mif->tx_queues, i);
    if ((mq->int_fd = eventfd (0, EFD_NONBLOCK)) < 0)
      return clib_error_return_unix (0, "eventfd[tx queue %u]", i);
    mq->int_unix_file_index = ~0;
    mq->ring = memif_get_ring (mif, MEMIF_RING_S2M, i);
    mq->log2_ring_size = mif->log2_ring_size;
    mq->region = 0;
    mq->offset = (void *) mq->ring - (void *) mif->regions[mq->region].shm;
    mq->last_head = 0;
  }

  ASSERT (mif->rx_queues == 0);
  vec_validate_aligned (mif->rx_queues, mif->num_m2s_rings - 1,
			CLIB_CACHE_LINE_BYTES);
  vec_foreach_index (i, mif->rx_queues)
  {
    memif_queue_t *mq = vec_elt_at_index (mif->rx_queues, i);
    if ((mq->int_fd = eventfd (0, EFD_NONBLOCK)) < 0)
      return clib_error_return_unix (0, "eventfd[rx queue %u]", i);
    mq->int_unix_file_index = ~0;
    mq->ring = memif_get_ring (mif, MEMIF_RING_M2S, i);
    mq->log2_ring_size = mif->log2_ring_size;
    mq->region = 0;
    mq->offset = (void *) mq->ring - (void *) mif->regions[mq->region].shm;
    mq->last_head = 0;
  }

  return 0;
}

static clib_error_t *
memif_msg_receive_hello (memif_if_t * mif, memif_msg_t * msg)
{
  if (msg->hello.min_version > MEMIF_VERSION ||
      msg->hello.max_version < MEMIF_VERSION)
    {
      return clib_error_return (0, "incompatible protocol version");
    }

  return 0;
}

static clib_error_t *
memif_msg_receive_init (memif_if_t ** mifp, memif_msg_t * msg,
			unix_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  memif_socket_file_t *msf =
    vec_elt_at_index (mm->socket_files, uf->private_data);
  memif_msg_init_t *i = &msg->init;
  memif_if_t *mif;
  uword *p;

  p = mhash_get (&msf->dev_instance_by_key, &i->key);

  if (!p)
    return clib_error_return (0, "unmatched key");

  *mifp = mif = vec_elt_at_index (mm->interfaces, p[0]);

  if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
    return clib_error_return (0, "cannot connect to slave");

  if (mif->conn_fd != -1)
    return clib_error_return (0, "already connected");

  mif->conn_fd = uf->file_descriptor;
  mif->conn_unix_file_index = uf - unix_main.file_pool;
  hash_set (msf->dev_instance_by_fd, mif->conn_fd, mif->dev_instance);

  return 0;
}

static clib_error_t *
memif_msg_receive_add_region (memif_if_t * mif, memif_msg_t * msg, int fd)
{
  memif_msg_add_region_t *ar = &msg->add_region;
  memif_region_t *mr;
  if (fd < 0)
    return clib_error_return (0, "missing memory region fd");

  vec_validate_aligned (mif->regions, ar->index, CLIB_CACHE_LINE_BYTES);
  mr = vec_elt_at_index (mif->regions, ar->index);
  mr->fd = fd;
  mr->region_size = ar->size;

  return 0;
}

static clib_error_t *
memif_msg_receive_add_ring (memif_if_t * mif, memif_msg_t * msg, int fd)
{
  memif_msg_add_ring_t *ar = &msg->add_ring;
  memif_queue_t *mq;

  if (fd < 0)
    return clib_error_return (0, "missing ring interrupt fd");

  if (ar->flags & MEMIF_MSG_ADD_RING_FLAG_S2M)
    {
      vec_validate_aligned (mif->rx_queues, ar->index, CLIB_CACHE_LINE_BYTES);
      mq = vec_elt_at_index (mif->rx_queues, ar->index);
    }
  else
    {
      vec_validate_aligned (mif->tx_queues, ar->index, CLIB_CACHE_LINE_BYTES);
      mq = vec_elt_at_index (mif->tx_queues, ar->index);
    }
  mq->int_fd = fd;
  mq->int_unix_file_index = ~0;
  mq->log2_ring_size = ar->log2_ring_size;
  mq->region = ar->region;
  mq->offset = ar->offset;

  return 0;
}

static clib_error_t *
memif_msg_receive (memif_if_t * mif, unix_file_t * uf)
{
  char ctl[CMSG_SPACE (sizeof (int)) +
	   CMSG_SPACE (sizeof (struct ucred))] = { 0 };
  struct msghdr mh = { 0 };
  struct iovec iov[1];
  memif_msg_t msg = { 0 };
  ssize_t size;
  clib_error_t *err = 0;
  int fd = -1;
  int i;

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
      memif_disconnect (mif);
      return (size == 0) ? 0 :
	clib_error_return_unix (0,
				"recvmsg: malformed message received on fd %d",
				uf->file_descriptor);
    }

  if (mif == 0 && msg.type != MEMIF_MSG_TYPE_INIT)
    {
      unix_file_del (&unix_main, uf);
      return clib_error_return (0, "unexpected message received");
    }

  /* process anciliary data */
  struct ucred *cr = 0;
  struct cmsghdr *cmsg;

  cmsg = CMSG_FIRSTHDR (&mh);
  while (cmsg)
    {
      if (cmsg->cmsg_level == SOL_SOCKET
	  && cmsg->cmsg_type == SCM_CREDENTIALS)
	{
	  cr = (struct ucred *) CMSG_DATA (cmsg);
	  //clib_warning ("SCM_CREDENTIALS pid %d uid %d gid %d", cr->pid, cr->uid, cr->gid);
	}
      else if (cmsg->cmsg_level == SOL_SOCKET
	       && cmsg->cmsg_type == SCM_RIGHTS)
	{
	  fd = *(int *) CMSG_DATA (cmsg);
	  //clib_warning ("SCM_RIGHTS fd %u", fd);
	}
      cmsg = CMSG_NXTHDR (&mh, cmsg);
    }

  /* process the message based on its type */
  switch (msg.type)
    {
    case MEMIF_MSG_TYPE_HELLO:
      if ((err = memif_msg_receive_hello (mif, &msg)))
	goto error;

      if ((err = memif_init_regions_and_queues (mif)))
	goto error;

      if ((err = memif_msg_send_init (mif)))
	goto error;

      if ((err = memif_msg_send_add_region (mif, 0)))
	goto error;

      vec_foreach_index (i, mif->tx_queues)
	if ((err = memif_msg_send_add_ring (mif, i, MEMIF_RING_S2M)))
	goto error;

      vec_foreach_index (i, mif->rx_queues)
	if ((err = memif_msg_send_add_ring (mif, i, MEMIF_RING_M2S)))
	goto error;

      if ((err = memif_msg_send_connect (mif)))
	goto error;

      if ((err = memif_connect (mif)))
	goto error;
      break;

    case MEMIF_MSG_TYPE_INIT:
      if ((err = memif_msg_receive_init (&mif, &msg, uf)))
	goto error;
      mif->remote_pid = cr->pid;
      mif->remote_uid = cr->uid;
      mif->remote_gid = cr->gid;
      break;

    case MEMIF_MSG_TYPE_ADD_REGION:
      if ((err = memif_msg_receive_add_region (mif, &msg, fd)))
	goto error;
      break;

    case MEMIF_MSG_TYPE_ADD_RING:
      if ((err = memif_msg_receive_add_ring (mif, &msg, fd)))
	goto error;
      break;

    case MEMIF_MSG_TYPE_CONNECT:
      if ((err = memif_connect (mif)))
	goto error;
      break;

    case MEMIF_MSG_TYPE_CONNECTED:
      if (fd > 0)
	clib_warning ("fd %d", fd);
      break;

    default:
      err = clib_error_return (0, "unknown message type (0x%x)", msg.type);
      goto error;
    }

  return 0;

error:
  clib_error_report (err);
  if ((err = memif_msg_send_disconnect (mif)))
    clib_error_report (err);
  memif_disconnect (mif);
  return 0;
}


static clib_error_t *
memif_master_conn_fd_read_ready (unix_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  memif_socket_file_t *msf =
    pool_elt_at_index (mm->socket_files, uf->private_data);
  uword *p;
  memif_if_t *mif = 0;
  uword conn_unix_file_index = ~0;
  clib_error_t *err = 0;

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
  err = memif_msg_receive (mif, uf);
  if (err)
    clib_error_report (err);
  return 0;
}

static clib_error_t *
memif_slave_conn_fd_read_ready (unix_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  clib_error_t *err;
  memif_if_t *mif = vec_elt_at_index (mm->interfaces, uf->private_data);
  DBG ("fd %d", uf->file_descriptor);
  err = memif_msg_receive (mif, uf);
  if (err)
    {
      clib_error_report (err);
      memif_disconnect (mif);
    }
  return 0;
}

static clib_error_t *
memif_slave_conn_fd_error (unix_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  memif_if_t *mif = vec_elt_at_index (mm->interfaces, uf->private_data);

  DBG ("fd %d pd %u", uf->file_descriptor, uf->private_data);

  memif_disconnect (mif);
  return 0;
}

static clib_error_t *
memif_master_conn_fd_error (unix_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  memif_socket_file_t *msf =
    pool_elt_at_index (mm->socket_files, uf->private_data);
  uword *p;


  p = hash_get (msf->dev_instance_by_fd, uf->file_descriptor);
  if (p)
    {
      memif_if_t *mif;
      mif = vec_elt_at_index (mm->interfaces, p[0]);
      memif_disconnect (mif);
    }
  else
    {
      int i;
      vec_foreach_index (i, msf->pending_file_indices)
	if (msf->pending_file_indices[i] == uf - unix_main.file_pool)
	{
	  vec_del1 (msf->pending_file_indices, i);
	  unix_file_del (&unix_main, uf);
	  return 0;
	}
    }

  clib_warning ("Error on unknown file descriptor %d", uf->file_descriptor);
  unix_file_del (&unix_main, uf);
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
  clib_error_t *err;


  addr_len = sizeof (client);
  conn_fd = accept (uf->file_descriptor,
		    (struct sockaddr *) &client, (socklen_t *) & addr_len);

  if (conn_fd < 0)
    return clib_error_return_unix (0, "accept fd %d", uf->file_descriptor);

  template.read_function = memif_master_conn_fd_read_ready;
  template.error_function = memif_master_conn_fd_error;
  template.file_descriptor = conn_fd;
  template.private_data = uf->private_data;
  unix_file_index = unix_file_add (&unix_main, &template);
  DBG ("unix_file_add fd %d pd %u idx %u", template.file_descriptor,
       template.private_data, unix_file_index);


  err = memif_msg_send_hello (conn_fd);
  if (err)
    {
      clib_error_report (err);
      unix_file_del_by_index (&unix_main, unix_file_index);
    }
  else
    vec_add1 (msf->pending_file_indices, unix_file_index);

  return 0;
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
		  unix_file_t t = { 0 };

		  mif->conn_fd = sockfd;
		  t.read_function = memif_slave_conn_fd_read_ready;
		  t.error_function = memif_slave_conn_fd_error;
		  t.file_descriptor = mif->conn_fd;
		  t.private_data = mif->dev_instance;
		  ASSERT (mif->conn_unix_file_index == ~0);
		  mif->conn_unix_file_index = unix_file_add (&unix_main, &t);
		  DBG ("unix_file_add fd %d pd %u idx %u", t.file_descriptor,
			   t.private_data, mif->conn_unix_file_index);
		  hash_set (msf->dev_instance_by_fd, mif->conn_fd, mif->dev_instance);

		  mif->flags |= MEMIF_IF_FLAG_CONNECTING;

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

  memif_disconnect (mif);

  /* remove the interface */
  ethernet_delete_interface (vnm, mif->hw_if_index);
  mif->hw_if_index = ~0;

  /* free interface data structures */
  clib_spinlock_free (&mif->lockp);
  mhash_unset (&msf->dev_instance_by_key, &mif->key, 0);

  /* remove socket file */
  if (--(msf->ref_cnt) == 0)
    {
      DBG ("removing socket file %s", msf->filename);
      if (msf->is_listener)
	{
	  uword *x;
	  unix_file_del_by_index (&unix_main, msf->unix_file_index);
	  DBG ("unix_file_del idx %u", msf->unix_file_index);
	  vec_foreach (x, msf->pending_file_indices)
	  {
	    DBG ("removing pending funix file %u", *x);
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
      DBG ("creating socket file %s", msf->filename);
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
      DBG ("unix_file_add fd %d pd %u idx %u", template.file_descriptor,
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
