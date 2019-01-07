/*
 *------------------------------------------------------------------
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <errno.h>

#include <socket.h>
#include <memif.h>
#include <memif_private.h>

/* sends msg to socket */
static_fn int
memif_msg_send (int fd, memif_msg_t * msg, int afd)
{
  struct msghdr mh = { 0 };
  struct iovec iov[1];
  char ctl[CMSG_SPACE (sizeof (int))];
  int rv, err = MEMIF_ERR_SUCCESS;	/* 0 */

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
    err = memif_syscall_error_handler (errno);
  DBG ("Message type %u sent", msg->type);
  return err;
}

/* response from memif master - master is ready to handle next message */
static_fn int
memif_msg_enq_ack (memif_connection_t * c)
{
  libmemif_main_t *lm = &libmemif_main;
  memif_msg_queue_elt_t *e =
    (memif_msg_queue_elt_t *) lm->alloc (sizeof (memif_msg_queue_elt_t));
  if (e == NULL)
    return memif_syscall_error_handler (errno);

  memset (&e->msg, 0, sizeof (e->msg));
  e->msg.type = MEMIF_MSG_TYPE_ACK;
  e->fd = -1;

  e->next = NULL;
  if (c->msg_queue == NULL)
    {
      c->msg_queue = e;
      return MEMIF_ERR_SUCCESS;	/* 0 */
    }

  memif_msg_queue_elt_t *cur = c->msg_queue;
  while (cur->next != NULL)
    {
      cur = cur->next;
    }
  cur->next = e;

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

static_fn int
memif_msg_send_hello (int fd)
{
  libmemif_main_t *lm = &libmemif_main;
  memif_msg_t msg = { 0 };
  memif_msg_hello_t *h = &msg.hello;
  msg.type = MEMIF_MSG_TYPE_HELLO;
  h->min_version = MEMIF_VERSION;
  h->max_version = MEMIF_VERSION;
  h->max_s2m_ring = MEMIF_MAX_S2M_RING;
  h->max_m2s_ring = MEMIF_MAX_M2S_RING;
  h->max_region = MEMIF_MAX_REGION;
  h->max_log2_ring_size = MEMIF_MAX_LOG2_RING_SIZE;

  strncpy ((char *) h->name, (char *) lm->app_name,
	   strlen ((char *) lm->app_name));

  /* msg hello is not enqueued but sent directly,
     because it is the first msg to be sent */
  return memif_msg_send (fd, &msg, -1);
}

/* send id and secret (optional) for interface identification */
static_fn int
memif_msg_enq_init (memif_connection_t * c)
{
  libmemif_main_t *lm = &libmemif_main;
  memif_msg_queue_elt_t *e =
    (memif_msg_queue_elt_t *) lm->alloc (sizeof (memif_msg_queue_elt_t));
  if (e == NULL)
    return memif_syscall_error_handler (errno);
  memset (e, 0, sizeof (memif_msg_queue_elt_t));

  memset (&e->msg, 0, sizeof (e->msg));
  memif_msg_init_t *i = &e->msg.init;

  e->msg.type = MEMIF_MSG_TYPE_INIT;
  e->fd = -1;
  i->version = MEMIF_VERSION;
  i->id = c->args.interface_id;
  i->mode = c->args.mode;

  strncpy ((char *) i->name, (char *) lm->app_name,
	   strlen ((char *) lm->app_name));
  if (strlen ((char *) c->args.secret) > 0)
    strncpy ((char *) i->secret, (char *) c->args.secret, sizeof (i->secret));

  e->next = NULL;
  if (c->msg_queue == NULL)
    {
      c->msg_queue = e;
      return MEMIF_ERR_SUCCESS;	/* 0 */
    }

  memif_msg_queue_elt_t *cur = c->msg_queue;
  while (cur->next != NULL)
    {
      cur = cur->next;
    }
  cur->next = e;

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

/* send information about region specified by region_index */
static_fn int
memif_msg_enq_add_region (memif_connection_t * c, uint8_t region_index)
{
  libmemif_main_t *lm = &libmemif_main;
  memif_region_t *mr = &c->regions[region_index];

  memif_msg_queue_elt_t *e =
    (memif_msg_queue_elt_t *) lm->alloc (sizeof (memif_msg_queue_elt_t));
  if (e == NULL)
    return memif_syscall_error_handler (errno);

  memset (&e->msg, 0, sizeof (e->msg));
  memif_msg_add_region_t *ar = &e->msg.add_region;

  e->msg.type = MEMIF_MSG_TYPE_ADD_REGION;
  e->fd = mr->fd;
  ar->index = region_index;
  ar->size = mr->region_size;

  e->next = NULL;
  if (c->msg_queue == NULL)
    {
      c->msg_queue = e;
      return MEMIF_ERR_SUCCESS;	/* 0 */
    }

  memif_msg_queue_elt_t *cur = c->msg_queue;
  while (cur->next != NULL)
    {
      cur = cur->next;
    }
  cur->next = e;

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

/* send information about ring specified by direction (S2M | M2S) and index */
static_fn int
memif_msg_enq_add_ring (memif_connection_t * c, uint8_t index, uint8_t dir)
{
  libmemif_main_t *lm = &libmemif_main;
  memif_msg_queue_elt_t *e =
    (memif_msg_queue_elt_t *) lm->alloc (sizeof (memif_msg_queue_elt_t));
  if (e == NULL)
    return memif_syscall_error_handler (errno);

  memset (&e->msg, 0, sizeof (e->msg));
  memif_msg_add_ring_t *ar = &e->msg.add_ring;

  e->msg.type = MEMIF_MSG_TYPE_ADD_RING;

  /* TODO: support multiple rings */
  memif_queue_t *mq;
  if (dir == MEMIF_RING_M2S)
    mq = &c->rx_queues[index];
  else
    mq = &c->tx_queues[index];

  e->fd = mq->int_fd;
  ar->index = index;
  ar->offset = mq->offset;
  ar->region = mq->region;
  ar->log2_ring_size = mq->log2_ring_size;
  ar->flags = (dir == MEMIF_RING_S2M) ? MEMIF_MSG_ADD_RING_FLAG_S2M : 0;
  ar->private_hdr_size = 0;

  e->next = NULL;
  if (c->msg_queue == NULL)
    {
      c->msg_queue = e;
      return MEMIF_ERR_SUCCESS;	/* 0 */
    }

  memif_msg_queue_elt_t *cur = c->msg_queue;
  while (cur->next != NULL)
    {
      cur = cur->next;
    }
  cur->next = e;

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

/* used as connection request from slave */
static_fn int
memif_msg_enq_connect (memif_connection_t * c)
{
  libmemif_main_t *lm = &libmemif_main;
  memif_msg_queue_elt_t *e =
    (memif_msg_queue_elt_t *) lm->alloc (sizeof (memif_msg_queue_elt_t));
  if (e == NULL)
    return memif_syscall_error_handler (errno);

  memset (&e->msg, 0, sizeof (e->msg));
  memif_msg_connect_t *cm = &e->msg.connect;

  e->msg.type = MEMIF_MSG_TYPE_CONNECT;
  e->fd = -1;
  strncpy ((char *) cm->if_name, (char *) c->args.interface_name,
	   strlen ((char *) c->args.interface_name));

  e->next = NULL;
  if (c->msg_queue == NULL)
    {
      c->msg_queue = e;
      return MEMIF_ERR_SUCCESS;	/* 0 */
    }

  memif_msg_queue_elt_t *cur = c->msg_queue;
  while (cur->next != NULL)
    {
      cur = cur->next;
    }
  cur->next = e;

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

/* used as confirmation of connection by master */
static_fn int
memif_msg_enq_connected (memif_connection_t * c)
{
  libmemif_main_t *lm = &libmemif_main;
  memif_msg_queue_elt_t *e =
    (memif_msg_queue_elt_t *) lm->alloc (sizeof (memif_msg_queue_elt_t));
  if (e == NULL)
    return memif_syscall_error_handler (errno);

  memset (&e->msg, 0, sizeof (e->msg));
  memif_msg_connected_t *cm = &e->msg.connected;

  e->msg.type = MEMIF_MSG_TYPE_CONNECTED;
  e->fd = -1;
  strncpy ((char *) cm->if_name, (char *) c->args.interface_name,
	   strlen ((char *) c->args.interface_name));

  e->next = NULL;
  if (c->msg_queue == NULL)
    {
      c->msg_queue = e;
      return MEMIF_ERR_SUCCESS;	/* 0 */
    }

  memif_msg_queue_elt_t *cur = c->msg_queue;
  while (cur->next != NULL)
    {
      cur = cur->next;
    }
  cur->next = e;

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

/* immediately send disconnect msg */
    /* specifie protocol for disconnect msg err_code
       so that it will be compatible with VPP? (header/doc) */
int
memif_msg_send_disconnect (int fd, uint8_t * err_string, uint32_t err_code)
{
  memif_msg_t msg = { 0 };
  memif_msg_disconnect_t *d = &msg.disconnect;

  msg.type = MEMIF_MSG_TYPE_DISCONNECT;
  d->code = err_code;
  uint16_t l = strlen ((char *) err_string);
  if (l > 96)
    {
      DBG ("Disconnect string too long. Sending first 96 characters.");
      l = 96;
    }
  strncpy ((char *) d->string, (char *) err_string, l);

  return memif_msg_send (fd, &msg, -1);
}

static_fn int
memif_msg_receive_hello (memif_connection_t * c, memif_msg_t * msg)
{
  memif_msg_hello_t *h = &msg->hello;

  if (msg->hello.min_version > MEMIF_VERSION ||
      msg->hello.max_version < MEMIF_VERSION)
    {
      DBG ("incompatible protocol version");
      return MEMIF_ERR_PROTO;
    }

  c->run_args.num_s2m_rings = memif_min (h->max_s2m_ring + 1,
					 c->args.num_s2m_rings);
  c->run_args.num_m2s_rings = memif_min (h->max_m2s_ring + 1,
					 c->args.num_m2s_rings);
  c->run_args.log2_ring_size = memif_min (h->max_log2_ring_size,
					  c->args.log2_ring_size);
  c->run_args.buffer_size = c->args.buffer_size;
  strncpy ((char *) c->remote_name, (char *) h->name,
	   strlen ((char *) h->name));

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

/* handle interface identification (id, secret (optional)) */
static_fn int
memif_msg_receive_init (memif_socket_t * ms, int fd, memif_msg_t * msg)
{
  memif_msg_init_t *i = &msg->init;
  memif_list_elt_t *elt = NULL;
  memif_list_elt_t elt2;
  memif_connection_t *c = NULL;
  libmemif_main_t *lm = &libmemif_main;
  uint8_t err_string[96];
  memset (err_string, 0, sizeof (char) * 96);
  int err = MEMIF_ERR_SUCCESS;	/* 0 */
  if (i->version != MEMIF_VERSION)
    {
      DBG ("MEMIF_VER_ERR");
      strncpy ((char *) err_string, MEMIF_VER_ERR, strlen (MEMIF_VER_ERR));
      err = MEMIF_ERR_PROTO;
      goto error;
    }

  get_list_elt (&elt, ms->interface_list, ms->interface_list_len, i->id);
  if (elt == NULL)
    {
      DBG ("MEMIF_ID_ERR");
      strncpy ((char *) err_string, MEMIF_ID_ERR, strlen (MEMIF_ID_ERR));
      err = MEMIF_ERR_ID;
      goto error;
    }

  c = (memif_connection_t *) elt->data_struct;

  if (!(c->args.is_master))
    {
      DBG ("MEMIF_SLAVE_ERR");
      strncpy ((char *) err_string, MEMIF_SLAVE_ERR,
	       strlen (MEMIF_SLAVE_ERR));
      err = MEMIF_ERR_ACCSLAVE;
      goto error;
    }
  if (c->fd != -1)
    {
      DBG ("MEMIF_CONN_ERR");
      strncpy ((char *) err_string, MEMIF_CONN_ERR, strlen (MEMIF_CONN_ERR));
      err = MEMIF_ERR_ALRCONN;
      goto error;
    }

  c->fd = fd;

  if (i->mode != c->args.mode)
    {
      DBG ("MEMIF_MODE_ERR");
      strncpy ((char *) err_string, MEMIF_MODE_ERR, strlen (MEMIF_MODE_ERR));
      err = MEMIF_ERR_MODE;
      goto error;
    }

  strncpy ((char *) c->remote_name, (char *) i->name,
	   strlen ((char *) i->name));

  if (strlen ((char *) c->args.secret) > 0)
    {
      int r;
      if (strlen ((char *) i->secret) > 0)
	{
	  if (strlen ((char *) c->args.secret) != strlen ((char *) i->secret))
	    {
	      DBG ("MEMIF_SECRET_ERR");
	      strncpy ((char *) err_string,
		       MEMIF_SECRET_ERR, strlen (MEMIF_SECRET_ERR));
	      err = MEMIF_ERR_SECRET;
	      goto error;
	    }
	  r = strncmp ((char *) i->secret, (char *) c->args.secret,
		       strlen ((char *) c->args.secret));
	  if (r != 0)
	    {
	      DBG ("MEMIF_SECRET_ERR");
	      strncpy ((char *) err_string,
		       MEMIF_SECRET_ERR, strlen (MEMIF_SECRET_ERR));
	      err = MEMIF_ERR_SECRET;
	      goto error;
	    }
	}
      else
	{
	  DBG ("MEMIF_NOSECRET_ERR");
	  strncpy ((char *) err_string,
		   MEMIF_NOSECRET_ERR, strlen (MEMIF_NOSECRET_ERR));
	  err = MEMIF_ERR_NOSECRET;
	  goto error;
	}
    }

  c->read_fn = memif_conn_fd_read_ready;
  c->write_fn = memif_conn_fd_write_ready;
  c->error_fn = memif_conn_fd_error;

  elt2.key = c->fd;
  elt2.data_struct = c;

  add_list_elt (&elt2, &lm->control_list, &lm->control_list_len);
  free_list_elt (lm->pending_list, lm->pending_list_len, fd);

  return err;

error:
  memif_msg_send_disconnect (fd, err_string, 0);
  lm->control_fd_update (fd, MEMIF_FD_EVENT_DEL);
  free_list_elt (lm->pending_list, lm->pending_list_len, fd);
  close (fd);
  fd = -1;
  return err;
}

/* receive region information and add new region to connection (if possible) */
static_fn int
memif_msg_receive_add_region (memif_connection_t * c, memif_msg_t * msg,
			      int fd)
{
  libmemif_main_t *lm = &libmemif_main;

  memif_msg_add_region_t *ar = &msg->add_region;
  memif_region_t *mr;
  if (fd < 0)
    return MEMIF_ERR_NO_SHMFD;

  if (ar->index > MEMIF_MAX_REGION)
    return MEMIF_ERR_MAXREG;

  mr =
    (memif_region_t *) lm->realloc (c->regions,
				    sizeof (memif_region_t) *
				    (++c->regions_num));
  if (mr == NULL)
    return memif_syscall_error_handler (errno);
  memset (mr + ar->index, 0, sizeof (memif_region_t));
  c->regions = mr;
  c->regions[ar->index].fd = fd;
  c->regions[ar->index].region_size = ar->size;
  c->regions[ar->index].addr = NULL;

  /* region 0 is never external */
  if (lm->get_external_region_addr && (ar->index != 0))
    c->regions[ar->index].is_external = 1;

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

/* receive ring information and add new ring to connection queue
   (based on direction S2M | M2S) */
static_fn int
memif_msg_receive_add_ring (memif_connection_t * c, memif_msg_t * msg, int fd)
{
  libmemif_main_t *lm = &libmemif_main;

  memif_msg_add_ring_t *ar = &msg->add_ring;

  memif_queue_t *mq;

  if (fd < 0)
    return MEMIF_ERR_NO_INTFD;

  if (ar->private_hdr_size != 0)
    return MEMIF_ERR_PRIVHDR;

  if (ar->flags & MEMIF_MSG_ADD_RING_FLAG_S2M)
    {
      if (ar->index > MEMIF_MAX_S2M_RING)
	return MEMIF_ERR_MAXRING;
      if (ar->index >= c->args.num_s2m_rings)
	return MEMIF_ERR_MAXRING;

      mq =
	(memif_queue_t *) lm->realloc (c->rx_queues,
				       sizeof (memif_queue_t) *
				       (++c->rx_queues_num));
      memset (mq + ar->index, 0, sizeof (memif_queue_t));
      if (mq == NULL)
	return memif_syscall_error_handler (errno);
      c->rx_queues = mq;
      c->rx_queues[ar->index].int_fd = fd;
      c->rx_queues[ar->index].log2_ring_size = ar->log2_ring_size;
      c->rx_queues[ar->index].region = ar->region;
      c->rx_queues[ar->index].offset = ar->offset;
      c->run_args.num_s2m_rings++;
    }
  else
    {
      if (ar->index > MEMIF_MAX_M2S_RING)
	return MEMIF_ERR_MAXRING;
      if (ar->index >= c->args.num_m2s_rings)
	return MEMIF_ERR_MAXRING;

      mq =
	(memif_queue_t *) lm->realloc (c->tx_queues,
				       sizeof (memif_queue_t) *
				       (++c->tx_queues_num));
      memset (mq + ar->index, 0, sizeof (memif_queue_t));
      if (mq == NULL)
	return memif_syscall_error_handler (errno);
      c->tx_queues = mq;
      c->tx_queues[ar->index].int_fd = fd;
      c->tx_queues[ar->index].log2_ring_size = ar->log2_ring_size;
      c->tx_queues[ar->index].region = ar->region;
      c->tx_queues[ar->index].offset = ar->offset;
      c->run_args.num_m2s_rings++;
    }

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

/* slave -> master */
static_fn int
memif_msg_receive_connect (memif_connection_t * c, memif_msg_t * msg)
{
  memif_msg_connect_t *cm = &msg->connect;
  libmemif_main_t *lm = &libmemif_main;
  memif_list_elt_t elt;

  int err;
  err = memif_connect1 (c);
  if (err != MEMIF_ERR_SUCCESS)
    return err;

  strncpy ((char *) c->remote_if_name, (char *) cm->if_name,
	   strlen ((char *) cm->if_name));

  int i;
  if (c->on_interrupt != NULL)
    {
      for (i = 0; i < c->run_args.num_m2s_rings; i++)
	{
	  elt.key = c->rx_queues[i].int_fd;
	  elt.data_struct = c;
	  add_list_elt (&elt, &lm->interrupt_list, &lm->interrupt_list_len);

	  lm->control_fd_update (c->rx_queues[i].int_fd, MEMIF_FD_EVENT_READ);
	}

    }

  c->on_connect ((void *) c, c->private_ctx);

  return err;
}

/* master -> slave */
static_fn int
memif_msg_receive_connected (memif_connection_t * c, memif_msg_t * msg)
{
  memif_msg_connect_t *cm = &msg->connect;
  libmemif_main_t *lm = &libmemif_main;

  int err;
  err = memif_connect1 (c);
  if (err != MEMIF_ERR_SUCCESS)
    return err;

  strncpy ((char *) c->remote_if_name, (char *) cm->if_name,
	   strlen ((char *) cm->if_name));

  int i;
  if (c->on_interrupt != NULL)
    {
      for (i = 0; i < c->run_args.num_s2m_rings; i++)
	{
	  lm->control_fd_update (c->rx_queues[i].int_fd, MEMIF_FD_EVENT_READ);
	}
    }

  c->on_connect ((void *) c, c->private_ctx);

  return err;
}

static_fn int
memif_msg_receive_disconnect (memif_connection_t * c, memif_msg_t * msg)
{
  memif_msg_disconnect_t *d = &msg->disconnect;

  memset (c->remote_disconnect_string, 0,
	  sizeof (c->remote_disconnect_string));
  strncpy ((char *) c->remote_disconnect_string, (char *) d->string,
	   strlen ((char *) d->string));

  /* on returning error, handle function will call memif_disconnect () */
  DBG ("disconnect received: %s, mode: %d",
       c->remote_disconnect_string, c->args.mode);
  return MEMIF_ERR_DISCONNECT;
}

static_fn int
memif_msg_receive (int ifd)
{
  char ctl[CMSG_SPACE (sizeof (int)) +
	   CMSG_SPACE (sizeof (struct ucred))] = { 0 };
  struct msghdr mh = { 0 };
  struct iovec iov[1];
  memif_msg_t msg = { 0 };
  ssize_t size;
  int err = MEMIF_ERR_SUCCESS;	/* 0 */
  int fd = -1;
  int i;
  libmemif_main_t *lm = &libmemif_main;
  memif_connection_t *c = NULL;
  memif_socket_t *ms = NULL;
  memif_list_elt_t *elt = NULL;

  iov[0].iov_base = (void *) &msg;
  iov[0].iov_len = sizeof (memif_msg_t);
  mh.msg_iov = iov;
  mh.msg_iovlen = 1;
  mh.msg_control = ctl;
  mh.msg_controllen = sizeof (ctl);

  DBG ("recvmsg fd %d", ifd);
  size = recvmsg (ifd, &mh, 0);
  DBG ("done");
  if (size != sizeof (memif_msg_t))
    {
      if (size == 0)
	return MEMIF_ERR_DISCONNECTED;
      else
	return MEMIF_ERR_MFMSG;
    }

  struct cmsghdr *cmsg;

  cmsg = CMSG_FIRSTHDR (&mh);
  while (cmsg)
    {
      if (cmsg->cmsg_level == SOL_SOCKET)
	{
	  if (cmsg->cmsg_type == SCM_CREDENTIALS)
	    {
	      /* Do nothing */ ;
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

  get_list_elt (&elt, lm->control_list, lm->control_list_len, ifd);
  if (elt != NULL)
    c = (memif_connection_t *) elt->data_struct;

  switch (msg.type)
    {
    case MEMIF_MSG_TYPE_ACK:
      break;

    case MEMIF_MSG_TYPE_HELLO:
      if ((err = memif_msg_receive_hello (c, &msg)) != MEMIF_ERR_SUCCESS)
	return err;
      if ((err = memif_init_regions_and_queues (c)) != MEMIF_ERR_SUCCESS)
	return err;
      if ((err = memif_msg_enq_init (c)) != MEMIF_ERR_SUCCESS)
	return err;
      for (i = 0; i < c->regions_num; i++)
	{
	  if ((err = memif_msg_enq_add_region (c, i)) != MEMIF_ERR_SUCCESS)
	    return err;
	}
      for (i = 0; i < c->run_args.num_s2m_rings; i++)
	{
	  if ((err =
	       memif_msg_enq_add_ring (c, i,
				       MEMIF_RING_S2M)) != MEMIF_ERR_SUCCESS)
	    return err;
	}
      for (i = 0; i < c->run_args.num_m2s_rings; i++)
	{
	  if ((err =
	       memif_msg_enq_add_ring (c, i,
				       MEMIF_RING_M2S)) != MEMIF_ERR_SUCCESS)
	    return err;
	}
      if ((err = memif_msg_enq_connect (c)) != MEMIF_ERR_SUCCESS)
	return err;
      break;

    case MEMIF_MSG_TYPE_INIT:
      get_list_elt (&elt, lm->pending_list, lm->pending_list_len, ifd);
      if (elt == NULL)
	return -1;
      ms = (memif_socket_t *) elt->data_struct;
      if ((err = memif_msg_receive_init (ms, ifd, &msg)) != MEMIF_ERR_SUCCESS)
	return err;
      /* c->remote_pid = cr->pid */
      /* c->remote_uid = cr->uid */
      /* c->remote_gid = cr->gid */
      get_list_elt (&elt, lm->control_list, lm->control_list_len, ifd);
      if (elt == NULL)
	return -1;
      c = (memif_connection_t *) elt->data_struct;
      if ((err = memif_msg_enq_ack (c)) != MEMIF_ERR_SUCCESS)
	return err;
      break;

    case MEMIF_MSG_TYPE_ADD_REGION:
      if ((err =
	   memif_msg_receive_add_region (c, &msg, fd)) != MEMIF_ERR_SUCCESS)
	return err;
      if ((err = memif_msg_enq_ack (c)) != MEMIF_ERR_SUCCESS)
	return err;
      break;

    case MEMIF_MSG_TYPE_ADD_RING:
      if ((err =
	   memif_msg_receive_add_ring (c, &msg, fd)) != MEMIF_ERR_SUCCESS)
	return err;
      if ((err = memif_msg_enq_ack (c)) != MEMIF_ERR_SUCCESS)
	return err;
      break;

    case MEMIF_MSG_TYPE_CONNECT:
      if ((err = memif_msg_receive_connect (c, &msg)) != MEMIF_ERR_SUCCESS)
	return err;
      if ((err = memif_msg_enq_connected (c)) != MEMIF_ERR_SUCCESS)
	return err;
      break;

    case MEMIF_MSG_TYPE_CONNECTED:
      if ((err = memif_msg_receive_connected (c, &msg)) != MEMIF_ERR_SUCCESS)
	return err;
      break;

    case MEMIF_MSG_TYPE_DISCONNECT:
      if ((err = memif_msg_receive_disconnect (c, &msg)) != MEMIF_ERR_SUCCESS)
	return err;
      break;

    default:
      return MEMIF_ERR_UNKNOWN_MSG;;
      break;
    }

  if (c != NULL)
    c->flags |= MEMIF_CONNECTION_FLAG_WRITE;
/*    libmemif_main_t *lm = &libmemif_main;
    lm->control_fd_update (c->fd, MEMIF_FD_EVENT_READ | MEMIF_FD_EVENT_MOD); */
  return MEMIF_ERR_SUCCESS;	/* 0 */
}

int
memif_conn_fd_error (memif_connection_t * c)
{
  DBG ("connection fd error");
  strncpy ((char *) c->remote_disconnect_string, "connection fd error", 19);
  int err = memif_disconnect_internal (c);
  return err;
}

/* calls memif_msg_receive to handle pending messages on socket */
int
memif_conn_fd_read_ready (memif_connection_t * c)
{
  int err;
  err = memif_msg_receive (c->fd);
  if (err != 0)
    {
      err = memif_disconnect_internal (c);
    }
  return err;
}

/* get msg from msg queue buffer and send it to socket */
int
memif_conn_fd_write_ready (memif_connection_t * c)
{
  libmemif_main_t *lm = &libmemif_main;
  int err = MEMIF_ERR_SUCCESS;	/* 0 */


  if ((c->flags & MEMIF_CONNECTION_FLAG_WRITE) == 0)
    goto done;

  memif_msg_queue_elt_t *e = c->msg_queue;
  if (e == NULL)
    goto done;

  c->msg_queue = c->msg_queue->next;

  c->flags &= ~MEMIF_CONNECTION_FLAG_WRITE;
/*
    libmemif_main_t *lm = &libmemif_main;

    lm->control_fd_update (c->fd,
        MEMIF_FD_EVENT_READ | MEMIF_FD_EVENT_WRITE | MEMIF_FD_EVENT_MOD);
*/
  err = memif_msg_send (c->fd, &e->msg, e->fd);
  lm->free (e);
  goto done;

done:
  return err;
}

int
memif_conn_fd_accept_ready (memif_socket_t * ms)
{
  int addr_len;
  struct sockaddr_un client;
  int conn_fd;
  libmemif_main_t *lm = &libmemif_main;

  DBG ("accept called");

  addr_len = sizeof (client);
  conn_fd =
    accept (ms->fd, (struct sockaddr *) &client, (socklen_t *) & addr_len);

  if (conn_fd < 0)
    {
      return memif_syscall_error_handler (errno);
    }
  DBG ("accept fd %d", ms->fd);
  DBG ("conn fd %d", conn_fd);

  memif_list_elt_t elt;
  elt.key = conn_fd;
  elt.data_struct = ms;

  add_list_elt (&elt, &lm->pending_list, &lm->pending_list_len);
  lm->control_fd_update (conn_fd, MEMIF_FD_EVENT_READ | MEMIF_FD_EVENT_WRITE);

  return memif_msg_send_hello (conn_fd);
}

int
memif_read_ready (int fd)
{
  int err;
  DBG ("call recv");
  err = memif_msg_receive (fd);
  DBG ("recv finished");
  return err;
}
