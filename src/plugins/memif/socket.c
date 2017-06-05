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
#include <memif/private.h>

static clib_error_t *
memif_msg_send (int fd, memif_msg_t * msg, int afd)
{
  struct msghdr mh = { 0 };
  struct iovec iov[1];
  char ctl[CMSG_SPACE (sizeof (int))];
  int rv;

  iov[0].iov_base = (void *) msg;
  iov[0].iov_len = sizeof (memif_msg_t);
  mh.msg_iov = iov;
  mh.msg_iovlen = 1;

  if (afd > 0)
    {
      struct cmsghdr *cmsg;
      memset (&ctl, 0, sizeof (ctl));
      mh.msg_control = ctl;
      mh.msg_controllen = sizeof (ctl);
      cmsg = CMSG_FIRSTHDR (&mh);
      cmsg->cmsg_len = CMSG_LEN (sizeof (int));
      cmsg->cmsg_level = SOL_SOCKET;
      cmsg->cmsg_type = SCM_RIGHTS;
      memcpy (CMSG_DATA (cmsg), &afd, sizeof (int));
    }
  rv = sendmsg (fd, &mh, 0);
  if (rv < 0)
    return clib_error_return_unix (0, "sendmsg");
  return 0;
}

static clib_error_t *
memif_msg_send_hello (int fd)
{
  memif_msg_t msg = { 0 };
  memif_msg_hello_t *h = &msg.hello;
  msg.type = MEMIF_MSG_TYPE_HELLO;
  h->min_version = MEMIF_VERSION;
  h->max_version = MEMIF_VERSION;
  h->max_m2s_rings = 1;
  h->max_s2m_rings = 1;
  h->max_regions = 1;
  h->max_log2_ring_size = 12;
  return memif_msg_send (fd, &msg, -1);
}

static clib_error_t *
memif_msg_send_init (memif_if_t * mif)
{
  memif_msg_t msg = { 0 };
  memif_msg_init_t *i = &msg.init;

  msg.type = MEMIF_MSG_TYPE_INIT;
  i->key = mif->key;

  //mif->flags |= MEMIF_IF_FLAG_CONNECTING;

  return memif_msg_send (mif->conn_fd, &msg, -1);
}

static clib_error_t *
memif_msg_send_add_region (memif_if_t * mif, u8 region)
{
  memif_msg_t msg = { 0 };
  memif_msg_add_region_t *ar = &msg.add_region;

  msg.type = MEMIF_MSG_TYPE_ADD_REGION;
  ar->index = region;
  ar->size = mif->regions[region].region_size;

  return memif_msg_send (mif->conn_fd, &msg, mif->regions[region].fd);
}

static clib_error_t *
memif_msg_send_add_ring (memif_if_t * mif, u8 index, u8 direction)
{
  memif_msg_t msg = { 0 };
  memif_msg_add_ring_t *ar = &msg.add_ring;
  memif_queue_t *mq;

  ASSERT ((mif->flags & MEMIF_IF_FLAG_IS_SLAVE) != 0);

  msg.type = MEMIF_MSG_TYPE_ADD_RING;

  if (direction == MEMIF_RING_M2S)
    mq = vec_elt_at_index (mif->rx_queues, index);
  else
    mq = vec_elt_at_index (mif->tx_queues, index);

  ar->index = index;
  ar->region = mq->region;
  ar->offset = mq->offset;
  ar->log2_ring_size = mq->log2_ring_size;
  ar->flags = (direction == MEMIF_RING_S2M) ? MEMIF_MSG_ADD_RING_FLAG_S2M : 0;

  return memif_msg_send (mif->conn_fd, &msg, mq->int_fd);
}

static clib_error_t *
memif_msg_send_connect (memif_if_t * mif)
{
  memif_msg_t msg = { 0 };
  msg.type = MEMIF_MSG_TYPE_CONNECT;
  return memif_msg_send (mif->conn_fd, &msg, -1);
}

static clib_error_t *
memif_msg_send_disconnect (memif_if_t * mif)
{
  memif_msg_t msg = { 0 };
  msg.type = MEMIF_MSG_TYPE_DISCONNECT;
  memif_msg_disconnect_t *d = &msg.disconnect;

  d->reason = ~0;
  strncpy ((char *) d->reason_string, "unknown", 8);

  return memif_msg_send (mif->conn_fd, &msg, -1);
}

static clib_error_t *
memif_msg_receive_hello (memif_if_t * mif, memif_msg_t * msg)
{
  if (msg->hello.min_version > MEMIF_VERSION ||
      msg->hello.max_version < MEMIF_VERSION)
    {
      return clib_error_return (0, "incompatible protocol version");
    }

  mif->run.num_s2m_rings = clib_min (msg->hello.max_s2m_rings,
				     mif->cfg.num_s2m_rings);
  mif->run.num_m2s_rings = clib_min (msg->hello.max_m2s_rings,
				     mif->cfg.num_m2s_rings);
  mif->run.log2_ring_size = clib_min (msg->hello.max_log2_ring_size,
				      mif->cfg.log2_ring_size);
  mif->run.buffer_size = mif->cfg.buffer_size;

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
	}
      else if (cmsg->cmsg_level == SOL_SOCKET
	       && cmsg->cmsg_type == SCM_RIGHTS)
	{
	  fd = *(int *) CMSG_DATA (cmsg);
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

clib_error_t *
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

clib_error_t *
memif_slave_conn_fd_read_ready (unix_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  clib_error_t *err;
  memif_if_t *mif = vec_elt_at_index (mm->interfaces, uf->private_data);
  err = memif_msg_receive (mif, uf);
  if (err)
    {
      clib_error_report (err);
      memif_disconnect (mif);
    }
  return 0;
}

clib_error_t *
memif_slave_conn_fd_error (unix_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  memif_if_t *mif = vec_elt_at_index (mm->interfaces, uf->private_data);

  memif_disconnect (mif);
  return 0;
}

clib_error_t *
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


clib_error_t *
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
