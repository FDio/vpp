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

static u8 *
memif_str2vec (uint8_t * str, int len)
{
  u8 *s = 0;
  int i;

  if (str[0] == 0)
    return s;

  for (i = 0; i < len; i++)
    {
      vec_add1 (s, str[i]);
      if (str[i] == 0)
	return s;
    }
  vec_add1 (s, 0);

  return s;
}

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
  DBG ("Message type %u sent (fd %d)", msg->type, afd);
  return 0;
}

static void
memif_msg_enq_ack (memif_if_t * mif)
{
  memif_msg_fifo_elt_t *e;
  clib_fifo_add2 (mif->msg_queue, e);

  e->msg.type = MEMIF_MSG_TYPE_ACK;
  e->fd = -1;
}

static clib_error_t *
memif_msg_enq_hello (int fd)
{
  u8 *s;
  memif_msg_t msg = { 0 };
  memif_msg_hello_t *h = &msg.hello;
  msg.type = MEMIF_MSG_TYPE_HELLO;
  h->min_version = MEMIF_VERSION;
  h->max_version = MEMIF_VERSION;
  h->max_m2s_ring = MEMIF_MAX_M2S_RING;
  h->max_s2m_ring = MEMIF_MAX_M2S_RING;
  h->max_region = MEMIF_MAX_REGION;
  h->max_log2_ring_size = MEMIF_MAX_LOG2_RING_SIZE;
  s = format (0, "VPP %s%c", VPP_BUILD_VER, 0);
  strncpy ((char *) h->name, (char *) s, sizeof (h->name) - 1);
  vec_free (s);
  return memif_msg_send (fd, &msg, -1);
}

static void
memif_msg_enq_init (memif_if_t * mif)
{
  u8 *s;
  memif_msg_fifo_elt_t *e;
  clib_fifo_add2 (mif->msg_queue, e);
  memif_msg_init_t *i = &e->msg.init;

  e->msg.type = MEMIF_MSG_TYPE_INIT;
  e->fd = -1;
  i->version = MEMIF_VERSION;
  i->id = mif->id;
  i->mode = mif->mode;
  s = format (0, "VPP %s%c", VPP_BUILD_VER, 0);
  strncpy ((char *) i->name, (char *) s, sizeof (i->name) - 1);
  if (mif->secret)
    strncpy ((char *) i->secret, (char *) mif->secret,
	     sizeof (i->secret) - 1);
  vec_free (s);
}

static void
memif_msg_enq_add_region (memif_if_t * mif, u8 region)
{
  memif_msg_fifo_elt_t *e;
  clib_fifo_add2 (mif->msg_queue, e);
  memif_msg_add_region_t *ar = &e->msg.add_region;

  e->msg.type = MEMIF_MSG_TYPE_ADD_REGION;
  e->fd = mif->regions[region].fd;
  ar->index = region;
  ar->size = mif->regions[region].region_size;
}

static void
memif_msg_enq_add_ring (memif_if_t * mif, u8 index, u8 direction)
{
  memif_msg_fifo_elt_t *e;
  clib_fifo_add2 (mif->msg_queue, e);
  memif_msg_add_ring_t *ar = &e->msg.add_ring;
  memif_queue_t *mq;

  ASSERT ((mif->flags & MEMIF_IF_FLAG_IS_SLAVE) != 0);

  e->msg.type = MEMIF_MSG_TYPE_ADD_RING;

  if (direction == MEMIF_RING_M2S)
    mq = vec_elt_at_index (mif->rx_queues, index);
  else
    mq = vec_elt_at_index (mif->tx_queues, index);

  e->fd = mq->int_fd;
  ar->index = index;
  ar->region = mq->region;
  ar->offset = mq->offset;
  ar->log2_ring_size = mq->log2_ring_size;
  ar->flags = (direction == MEMIF_RING_S2M) ? MEMIF_MSG_ADD_RING_FLAG_S2M : 0;
}

static void
memif_msg_enq_connect (memif_if_t * mif)
{
  memif_msg_fifo_elt_t *e;
  clib_fifo_add2 (mif->msg_queue, e);
  memif_msg_connect_t *c = &e->msg.connect;
  u8 *s;

  e->msg.type = MEMIF_MSG_TYPE_CONNECT;
  e->fd = -1;
  s = format (0, "%U%c", format_memif_device_name, mif->dev_instance, 0);
  strncpy ((char *) c->if_name, (char *) s, sizeof (c->if_name) - 1);
  vec_free (s);
}

static void
memif_msg_enq_connected (memif_if_t * mif)
{
  memif_msg_fifo_elt_t *e;
  clib_fifo_add2 (mif->msg_queue, e);
  memif_msg_connected_t *c = &e->msg.connected;
  u8 *s;

  e->msg.type = MEMIF_MSG_TYPE_CONNECTED;
  e->fd = -1;
  s = format (0, "%U%c", format_memif_device_name, mif->dev_instance, 0);
  strncpy ((char *) c->if_name, (char *) s, sizeof (c->if_name) - 1);
  vec_free (s);
}

clib_error_t *
memif_msg_send_disconnect (memif_if_t * mif, clib_error_t * err)
{
  memif_msg_t msg = { 0 };
  msg.type = MEMIF_MSG_TYPE_DISCONNECT;
  memif_msg_disconnect_t *d = &msg.disconnect;

  d->code = err->code;
  strncpy ((char *) d->string, (char *) err->what, sizeof (d->string) - 1);

  return memif_msg_send (mif->conn_fd, &msg, -1);
}

static clib_error_t *
memif_msg_receive_hello (memif_if_t * mif, memif_msg_t * msg)
{
  memif_msg_hello_t *h = &msg->hello;

  if (msg->hello.min_version > MEMIF_VERSION ||
      msg->hello.max_version < MEMIF_VERSION)
    return clib_error_return (0, "incompatible protocol version");

  mif->run.num_s2m_rings = clib_min (h->max_s2m_ring + 1,
				     mif->cfg.num_s2m_rings);
  mif->run.num_m2s_rings = clib_min (h->max_m2s_ring + 1,
				     mif->cfg.num_m2s_rings);
  mif->run.log2_ring_size = clib_min (h->max_log2_ring_size,
				      mif->cfg.log2_ring_size);
  mif->run.buffer_size = mif->cfg.buffer_size;

  mif->remote_name = memif_str2vec (h->name, sizeof (h->name));

  return 0;
}

static clib_error_t *
memif_msg_receive_init (memif_if_t ** mifp, memif_msg_t * msg,
			clib_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  memif_socket_file_t *msf =
    vec_elt_at_index (mm->socket_files, uf->private_data);
  memif_msg_init_t *i = &msg->init;
  memif_if_t *mif, tmp;
  clib_error_t *err;
  uword *p;

  if (i->version != MEMIF_VERSION)
    {
      memif_file_del_by_index (uf - file_main.file_pool);
      return clib_error_return (0, "unsupported version");
    }

  p = mhash_get (&msf->dev_instance_by_id, &i->id);

  if (!p)
    {
      err = clib_error_return (0, "unmatched interface id");
      goto error;
    }

  mif = vec_elt_at_index (mm->interfaces, p[0]);

  if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
    {
      err = clib_error_return (0, "cannot connect to slave");
      goto error;
    }

  if (mif->conn_fd != -1)
    {
      err = clib_error_return (0, "already connected");
      goto error;
    }

  if (i->mode != mif->mode)
    {
      err = clib_error_return (0, "mode mismatch");
      goto error;
    }

  mif->conn_fd = uf->file_descriptor;
  mif->conn_clib_file_index = uf - file_main.file_pool;
  hash_set (msf->dev_instance_by_fd, mif->conn_fd, mif->dev_instance);
  mif->remote_name = memif_str2vec (i->name, sizeof (i->name));
  *mifp = mif;

  if (mif->secret)
    {
      u8 *s;
      int r;
      s = memif_str2vec (i->secret, sizeof (i->secret));
      if (s == 0)
	return clib_error_return (0, "secret required");

      r = vec_cmp (s, mif->secret);
      vec_free (s);

      if (r)
	return clib_error_return (0, "incorrect secret");
    }

  return 0;

error:
  tmp.conn_fd = uf->file_descriptor;
  memif_msg_send_disconnect (&tmp, err);
  memif_file_del_by_index (uf - file_main.file_pool);
  return err;
}

static clib_error_t *
memif_msg_receive_add_region (memif_if_t * mif, memif_msg_t * msg, int fd)
{
  memif_msg_add_region_t *ar = &msg->add_region;
  memif_region_t *mr;
  if (fd < 0)
    return clib_error_return (0, "missing memory region fd");

  if (ar->index != vec_len (mif->regions))
    return clib_error_return (0, "unexpected region index");

  if (ar->index > MEMIF_MAX_REGION)
    return clib_error_return (0, "too many regions");

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
      if (ar->index != vec_len (mif->rx_queues))
	return clib_error_return (0, "unexpected ring index");

      if (ar->index > MEMIF_MAX_S2M_RING)
	return clib_error_return (0, "too many rings");

      vec_validate_aligned (mif->rx_queues, ar->index, CLIB_CACHE_LINE_BYTES);
      mq = vec_elt_at_index (mif->rx_queues, ar->index);
      mif->run.num_s2m_rings = vec_len (mif->rx_queues);
    }
  else
    {
      if (ar->index != vec_len (mif->tx_queues))
	return clib_error_return (0, "unexpected ring index");

      if (ar->index > MEMIF_MAX_M2S_RING)
	return clib_error_return (0, "too many rings");

      vec_validate_aligned (mif->tx_queues, ar->index, CLIB_CACHE_LINE_BYTES);
      mq = vec_elt_at_index (mif->tx_queues, ar->index);
      mif->run.num_m2s_rings = vec_len (mif->tx_queues);
    }

  mq->int_fd = fd;
  mq->int_clib_file_index = ~0;
  mq->log2_ring_size = ar->log2_ring_size;
  mq->region = ar->region;
  mq->offset = ar->offset;

  return 0;
}

static clib_error_t *
memif_msg_receive_connect (memif_if_t * mif, memif_msg_t * msg)
{
  clib_error_t *err;
  memif_msg_connect_t *c = &msg->connect;

  if ((err = memif_connect (mif)))
    return err;

  mif->remote_if_name = memif_str2vec (c->if_name, sizeof (c->if_name));

  return 0;
}

static clib_error_t *
memif_msg_receive_connected (memif_if_t * mif, memif_msg_t * msg)
{
  clib_error_t *err;
  memif_msg_connected_t *c = &msg->connected;

  if ((err = memif_connect (mif)))
    return err;

  mif->remote_if_name = memif_str2vec (c->if_name, sizeof (c->if_name));
  return 0;
}

static clib_error_t *
memif_msg_receive_disconnect (memif_if_t * mif, memif_msg_t * msg)
{
  memif_msg_disconnect_t *d = &msg->disconnect;

  mif->remote_disc_string = memif_str2vec (d->string, sizeof (d->string));
  return clib_error_return (0, "disconnect received");
}

static clib_error_t *
memif_msg_receive (memif_if_t ** mifp, clib_file_t * uf)
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
  memif_if_t *mif = *mifp;

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
      return (size == 0) ? clib_error_return (0, "disconnected") :
	clib_error_return_unix (0,
				"recvmsg: malformed message received on fd %d",
				uf->file_descriptor);
    }

  if (mif == 0 && msg.type != MEMIF_MSG_TYPE_INIT)
    {
      memif_file_del (uf);
      return clib_error_return (0, "unexpected message received");
    }

  /* process anciliary data */
  struct ucred *cr = 0;
  struct cmsghdr *cmsg;

  cmsg = CMSG_FIRSTHDR (&mh);
  while (cmsg)
    {
      if (cmsg->cmsg_level == SOL_SOCKET)
	{
	  if (cmsg->cmsg_type == SCM_CREDENTIALS)
	    {
	      cr = (struct ucred *) CMSG_DATA (cmsg);
	    }
	  else if (cmsg->cmsg_type == SCM_RIGHTS)
	    {
	      int *fdp = (int *) CMSG_DATA (cmsg);
	      fd = *fdp;
	    }
	}
      cmsg = CMSG_NXTHDR (&mh, cmsg);
    }

  DBG ("Message type %u received", msg.type);
  /* process the message based on its type */
  switch (msg.type)
    {
    case MEMIF_MSG_TYPE_ACK:
      break;

    case MEMIF_MSG_TYPE_HELLO:
      if ((err = memif_msg_receive_hello (mif, &msg)))
	return err;
      if ((err = memif_init_regions_and_queues (mif)))
	return err;
      memif_msg_enq_init (mif);
      memif_msg_enq_add_region (mif, 0);
      vec_foreach_index (i, mif->tx_queues)
	memif_msg_enq_add_ring (mif, i, MEMIF_RING_S2M);
      vec_foreach_index (i, mif->rx_queues)
	memif_msg_enq_add_ring (mif, i, MEMIF_RING_M2S);
      memif_msg_enq_connect (mif);
      break;

    case MEMIF_MSG_TYPE_INIT:
      if ((err = memif_msg_receive_init (mifp, &msg, uf)))
	return err;
      mif = *mifp;
      mif->remote_pid = cr->pid;
      mif->remote_uid = cr->uid;
      mif->remote_gid = cr->gid;
      memif_msg_enq_ack (mif);
      break;

    case MEMIF_MSG_TYPE_ADD_REGION:
      if ((err = memif_msg_receive_add_region (mif, &msg, fd)))
	return err;
      memif_msg_enq_ack (mif);
      break;

    case MEMIF_MSG_TYPE_ADD_RING:
      if ((err = memif_msg_receive_add_ring (mif, &msg, fd)))
	return err;
      memif_msg_enq_ack (mif);
      break;

    case MEMIF_MSG_TYPE_CONNECT:
      if ((err = memif_msg_receive_connect (mif, &msg)))
	return err;
      memif_msg_enq_connected (mif);
      break;

    case MEMIF_MSG_TYPE_CONNECTED:
      if ((err = memif_msg_receive_connected (mif, &msg)))
	return err;
      break;

    case MEMIF_MSG_TYPE_DISCONNECT:
      if ((err = memif_msg_receive_disconnect (mif, &msg)))
	return err;
      break;

    default:
      err = clib_error_return (0, "unknown message type (0x%x)", msg.type);
      return err;
    }

  if (clib_fifo_elts (mif->msg_queue) && mif->conn_clib_file_index != ~0)
    clib_file_set_data_available_to_write (&file_main,
					   mif->conn_clib_file_index, 1);
  return 0;
}

clib_error_t *
memif_master_conn_fd_read_ready (clib_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  memif_socket_file_t *msf =
    pool_elt_at_index (mm->socket_files, uf->private_data);
  uword *p;
  memif_if_t *mif = 0;
  uword conn_clib_file_index = ~0;
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
	if (msf->pending_file_indices[i] == uf - file_main.file_pool)
	{
	  conn_clib_file_index = msf->pending_file_indices[i];
	  vec_del1 (msf->pending_file_indices, i);
	  break;
	}
      ASSERT (conn_clib_file_index != ~0);
    }
  err = memif_msg_receive (&mif, uf);
  if (err)
    {
      memif_disconnect (mif, err);
      clib_error_free (err);
    }
  return 0;
}

clib_error_t *
memif_slave_conn_fd_read_ready (clib_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  clib_error_t *err;
  memif_if_t *mif = vec_elt_at_index (mm->interfaces, uf->private_data);
  err = memif_msg_receive (&mif, uf);
  if (err)
    {
      memif_disconnect (mif, err);
      clib_error_free (err);
    }
  return 0;
}

static clib_error_t *
memif_conn_fd_write_ready (clib_file_t * uf, memif_if_t * mif)
{
  memif_msg_fifo_elt_t *e;
  clib_fifo_sub2 (mif->msg_queue, e);
  clib_file_set_data_available_to_write (&file_main,
					 mif->conn_clib_file_index, 0);
  memif_msg_send (mif->conn_fd, &e->msg, e->fd);
  return 0;
}

clib_error_t *
memif_master_conn_fd_write_ready (clib_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  memif_socket_file_t *msf =
    pool_elt_at_index (mm->socket_files, uf->private_data);
  uword *p;
  memif_if_t *mif;

  p = hash_get (msf->dev_instance_by_fd, uf->file_descriptor);
  if (!p)
    return 0;

  mif = vec_elt_at_index (mm->interfaces, p[0]);
  return memif_conn_fd_write_ready (uf, mif);
}

clib_error_t *
memif_slave_conn_fd_write_ready (clib_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  memif_if_t *mif = vec_elt_at_index (mm->interfaces, uf->private_data);
  return memif_conn_fd_write_ready (uf, mif);
}

clib_error_t *
memif_slave_conn_fd_error (clib_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  memif_if_t *mif = vec_elt_at_index (mm->interfaces, uf->private_data);
  clib_error_t *err;

  err = clib_error_return (0, "connection fd error");
  memif_disconnect (mif, err);
  clib_error_free (err);

  return 0;
}

clib_error_t *
memif_master_conn_fd_error (clib_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  memif_socket_file_t *msf =
    pool_elt_at_index (mm->socket_files, uf->private_data);
  uword *p;


  p = hash_get (msf->dev_instance_by_fd, uf->file_descriptor);
  if (p)
    {
      memif_if_t *mif;
      clib_error_t *err;
      mif = vec_elt_at_index (mm->interfaces, p[0]);
      err = clib_error_return (0, "connection fd error");
      memif_disconnect (mif, err);
      clib_error_free (err);
    }
  else
    {
      int i;
      vec_foreach_index (i, msf->pending_file_indices)
	if (msf->pending_file_indices[i] == uf - file_main.file_pool)
	{
	  vec_del1 (msf->pending_file_indices, i);
	  memif_file_del (uf);
	  return 0;
	}
    }

  clib_warning ("Error on unknown file descriptor %d", uf->file_descriptor);
  memif_file_del (uf);
  return 0;
}


clib_error_t *
memif_conn_fd_accept_ready (clib_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  memif_socket_file_t *msf =
    pool_elt_at_index (mm->socket_files, uf->private_data);
  int addr_len;
  struct sockaddr_un client;
  int conn_fd;
  clib_file_t template = { 0 };
  uword clib_file_index = ~0;
  clib_error_t *err;


  addr_len = sizeof (client);
  conn_fd = accept (uf->file_descriptor,
		    (struct sockaddr *) &client, (socklen_t *) & addr_len);

  if (conn_fd < 0)
    return clib_error_return_unix (0, "accept fd %d", uf->file_descriptor);

  template.read_function = memif_master_conn_fd_read_ready;
  template.write_function = memif_master_conn_fd_write_ready;
  template.error_function = memif_master_conn_fd_error;
  template.file_descriptor = conn_fd;
  template.private_data = uf->private_data;

  memif_file_add (&clib_file_index, &template);

  err = memif_msg_enq_hello (conn_fd);
  if (err)
    {
      clib_error_report (err);
      memif_file_del_by_index (clib_file_index);
    }
  else
    vec_add1 (msf->pending_file_indices, clib_file_index);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
