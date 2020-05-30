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

void
memif_socket_close (clib_socket_t ** s)
{
  memif_file_del_by_index ((*s)->private_data);
  clib_mem_free (*s);
  *s = 0;
}

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

static void
memif_msg_enq_ack (memif_if_t * mif)
{
  memif_msg_fifo_elt_t *e;
  clib_fifo_add2 (mif->msg_queue, e);

  e->msg.type = MEMIF_MSG_TYPE_ACK;
  e->fd = -1;
}

static void
memif_msg_strlcpy (u8 * dest, u32 len, const u8 * src)
{
  len = clib_min (len - 1, vec_len (src));
  memcpy (dest, src, len);
  dest[len] = '\0';
}

static void
memif_msg_snprintf (u8 * dest, u32 len, const char *fmt, ...)
{
  va_list va;
  va_start (va, fmt);
  u8 *s = va_format (0, fmt, &va);
  va_end (va);
  memif_msg_strlcpy (dest, len, s);
  vec_free (s);
}

static clib_error_t *
memif_msg_enq_hello (clib_socket_t * sock)
{
  memif_msg_t msg = { 0 };
  memif_msg_hello_t *h = &msg.hello;
  msg.type = MEMIF_MSG_TYPE_HELLO;
  h->min_version = MEMIF_VERSION;
  h->max_version = MEMIF_VERSION;
  h->max_m2s_ring = MEMIF_MAX_M2S_RING;
  h->max_s2m_ring = MEMIF_MAX_S2M_RING;
  h->max_region = MEMIF_MAX_REGION;
  h->max_log2_ring_size = MEMIF_MAX_LOG2_RING_SIZE;
  memif_msg_snprintf (h->name, sizeof (h->name), "VPP %s", VPP_BUILD_VER);
  return clib_socket_sendmsg (sock, &msg, sizeof (memif_msg_t), 0, 0);
}

static void
memif_msg_enq_init (memif_if_t * mif)
{
  memif_msg_fifo_elt_t *e;
  clib_fifo_add2 (mif->msg_queue, e);
  memif_msg_init_t *i = &e->msg.init;

  e->msg.type = MEMIF_MSG_TYPE_INIT;
  e->fd = -1;
  i->version = MEMIF_VERSION;
  i->id = mif->id;
  i->mode = mif->mode;
  memif_msg_snprintf (i->name, sizeof (i->name), "VPP %s", VPP_BUILD_VER);
  if (mif->secret)
    memif_msg_strlcpy (i->secret, sizeof (i->secret), mif->secret);
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
  ar->private_hdr_size = 0;
}

static void
memif_msg_enq_connect (memif_if_t * mif)
{
  memif_msg_fifo_elt_t *e;
  clib_fifo_add2 (mif->msg_queue, e);
  memif_msg_connect_t *c = &e->msg.connect;

  e->msg.type = MEMIF_MSG_TYPE_CONNECT;
  e->fd = -1;
  memif_msg_snprintf (c->if_name, sizeof (c->if_name), "%U",
		      format_memif_device_name, mif->dev_instance);
}

static void
memif_msg_enq_connected (memif_if_t * mif)
{
  memif_msg_fifo_elt_t *e;
  clib_fifo_add2 (mif->msg_queue, e);
  memif_msg_connected_t *c = &e->msg.connected;

  e->msg.type = MEMIF_MSG_TYPE_CONNECTED;
  e->fd = -1;
  memif_msg_snprintf (c->if_name, sizeof (c->if_name), "%U",
		      format_memif_device_name, mif->dev_instance);
}

clib_error_t *
memif_msg_send_disconnect (memif_if_t * mif, clib_error_t * err)
{
  memif_msg_t msg = { 0 };
  msg.type = MEMIF_MSG_TYPE_DISCONNECT;
  memif_msg_disconnect_t *d = &msg.disconnect;

  d->code = err->code;
  memif_msg_strlcpy (d->string, sizeof (d->string), err->what);

  return clib_socket_sendmsg (mif->sock, &msg, sizeof (memif_msg_t), 0, 0);
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
			clib_socket_t * sock, uword socket_file_index)
{
  memif_main_t *mm = &memif_main;
  memif_socket_file_t *msf =
    vec_elt_at_index (mm->socket_files, socket_file_index);
  memif_msg_init_t *i = &msg->init;
  memif_if_t *mif, tmp;
  clib_error_t *err;
  uword *p;

  if (i->version != MEMIF_VERSION)
    {
      memif_file_del_by_index (sock->private_data);
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

  if (mif->sock)
    {
      err = clib_error_return (0, "already connected");
      goto error;
    }

  if (i->mode != mif->mode)
    {
      err = clib_error_return (0, "mode mismatch");
      goto error;
    }

  mif->sock = sock;
  hash_set (msf->dev_instance_by_fd, mif->sock->fd, mif->dev_instance);
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
  tmp.sock = sock;
  memif_msg_send_disconnect (&tmp, err);
  memif_socket_close (&sock);
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

  if (ar->private_hdr_size != 0)
    return clib_error_return (0, "private headers not supported");

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

  // clear previous cache data if interface reconnected
  clib_memset (mq, 0, sizeof (memif_queue_t));
  mq->int_fd = fd;
  mq->int_clib_file_index = ~0;
  mq->log2_ring_size = ar->log2_ring_size;
  mq->region = ar->region;
  mq->offset = ar->offset;
  mq->type =
    (ar->flags & MEMIF_MSG_ADD_RING_FLAG_S2M) ? MEMIF_RING_S2M :
    MEMIF_RING_M2S;

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
memif_msg_receive (memif_if_t ** mifp, clib_socket_t * sock, clib_file_t * uf)
{
  memif_msg_t msg = { 0 };
  clib_error_t *err = 0;
  int fd = -1;
  int i;
  memif_if_t *mif = *mifp;

  err = clib_socket_recvmsg (sock, &msg, sizeof (memif_msg_t), &fd, 1);
  if (err)
    goto error;

  if (mif == 0 && msg.type != MEMIF_MSG_TYPE_INIT)
    {
      memif_socket_close (&sock);
      err = clib_error_return (0, "unexpected message received");
      goto error;
    }

  memif_log_debug (mif, "Message type %u received", msg.type);
  /* process the message based on its type */
  switch (msg.type)
    {
    case MEMIF_MSG_TYPE_ACK:
      break;

    case MEMIF_MSG_TYPE_HELLO:
      if ((err = memif_msg_receive_hello (mif, &msg)))
	goto error;
      if ((err = memif_init_regions_and_queues (mif)))
	goto error;
      memif_msg_enq_init (mif);
      /* *INDENT-OFF* */
      vec_foreach_index (i, mif->regions)
	memif_msg_enq_add_region (mif, i);
      vec_foreach_index (i, mif->tx_queues)
	memif_msg_enq_add_ring (mif, i, MEMIF_RING_S2M);
      vec_foreach_index (i, mif->rx_queues)
	memif_msg_enq_add_ring (mif, i, MEMIF_RING_M2S);
      /* *INDENT-ON* */
      memif_msg_enq_connect (mif);
      break;

    case MEMIF_MSG_TYPE_INIT:
      if ((err = memif_msg_receive_init (mifp, &msg, sock, uf->private_data)))
	goto error;
      mif = *mifp;
      vec_reset_length (uf->description);
      uf->description = format (uf->description, "%U ctl",
				format_memif_device_name, mif->dev_instance);
      memif_msg_enq_ack (mif);
      break;

    case MEMIF_MSG_TYPE_ADD_REGION:
      if ((err = memif_msg_receive_add_region (mif, &msg, fd)))
	goto error;
      memif_msg_enq_ack (mif);
      break;

    case MEMIF_MSG_TYPE_ADD_RING:
      if ((err = memif_msg_receive_add_ring (mif, &msg, fd)))
	goto error;
      memif_msg_enq_ack (mif);
      break;

    case MEMIF_MSG_TYPE_CONNECT:
      if ((err = memif_msg_receive_connect (mif, &msg)))
	goto error;
      memif_msg_enq_connected (mif);
      break;

    case MEMIF_MSG_TYPE_CONNECTED:
      if ((err = memif_msg_receive_connected (mif, &msg)))
	goto error;
      break;

    case MEMIF_MSG_TYPE_DISCONNECT:
      if ((err = memif_msg_receive_disconnect (mif, &msg)))
	goto error;
      break;

    default:
      err = clib_error_return (0, "unknown message type (0x%x)", msg.type);
      goto error;
    }

  if (clib_fifo_elts (mif->msg_queue))
    clib_file_set_data_available_to_write (&file_main,
					   mif->sock->private_data, 1);
  return 0;

error:
  memif_log_err (mif, "%U", format_clib_error, err);
  return err;
}

clib_error_t *
memif_master_conn_fd_read_ready (clib_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  memif_socket_file_t *msf =
    pool_elt_at_index (mm->socket_files, uf->private_data);
  uword *p;
  memif_if_t *mif = 0;
  clib_socket_t *sock = 0;
  clib_error_t *err = 0;

  p = hash_get (msf->dev_instance_by_fd, uf->file_descriptor);
  if (p)
    {
      mif = vec_elt_at_index (mm->interfaces, p[0]);
      sock = mif->sock;
    }
  else
    {
      /* This is new connection, remove index from pending vector */
      int i;
      vec_foreach_index (i, msf->pending_clients)
	if (msf->pending_clients[i]->fd == uf->file_descriptor)
	{
	  sock = msf->pending_clients[i];
	  vec_del1 (msf->pending_clients, i);
	  break;
	}
      ASSERT (sock != 0);
    }
  err = memif_msg_receive (&mif, sock, uf);
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
  err = memif_msg_receive (&mif, mif->sock, uf);
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
					 mif->sock->private_data, 0);
  return clib_socket_sendmsg (mif->sock, &e->msg, sizeof (memif_msg_t),
			      &e->fd, e->fd > -1 ? 1 : 0);
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
      vec_foreach_index (i, msf->pending_clients)
	if (msf->pending_clients[i]->fd == uf->file_descriptor)
	{
	  clib_socket_t *s = msf->pending_clients[i];
	  memif_socket_close (&s);
	  vec_del1 (msf->pending_clients, i);
	  return 0;
	}
    }

  memif_log_warn (0, "Error on unknown file descriptor %d",
		  uf->file_descriptor);
  memif_file_del (uf);
  return 0;
}


clib_error_t *
memif_conn_fd_accept_ready (clib_file_t * uf)
{
  memif_main_t *mm = &memif_main;
  memif_socket_file_t *msf =
    pool_elt_at_index (mm->socket_files, uf->private_data);
  clib_file_t template = { 0 };
  clib_error_t *err;
  clib_socket_t *client;

  client = clib_mem_alloc (sizeof (clib_socket_t));
  clib_memset (client, 0, sizeof (clib_socket_t));
  err = clib_socket_accept (msf->sock, client);
  if (err)
    goto error;

  template.read_function = memif_master_conn_fd_read_ready;
  template.write_function = memif_master_conn_fd_write_ready;
  template.error_function = memif_master_conn_fd_error;
  template.file_descriptor = client->fd;
  template.private_data = uf->private_data;
  template.description = format (0, "memif in conn on %s", msf->filename);

  memif_file_add (&client->private_data, &template);

  err = memif_msg_enq_hello (client);
  if (err)
    {
      clib_socket_close (client);
      goto error;
    }

  vec_add1 (msf->pending_clients, client);

  return 0;

error:
  memif_log_err (0, "%U", format_clib_error, err);
  clib_mem_free (client);
  return err;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
