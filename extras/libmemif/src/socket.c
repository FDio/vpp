/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
static int
memif_msg_send_from_queue (memif_control_channel_t *cc)
{
  struct msghdr mh = { 0 };
  struct iovec iov[1];
  char ctl[CMSG_SPACE (sizeof (int))];
  int rv, err = MEMIF_ERR_SUCCESS;	/* 0 */
  memif_msg_queue_elt_t *e;

  /* Pick the first message */
  e = TAILQ_FIRST (&cc->msg_queue);
  if (e == NULL)
    return MEMIF_ERR_SUCCESS;

  /* Construct the message */
  iov[0].iov_base = (void *) &e->msg;
  iov[0].iov_len = sizeof (memif_msg_t);
  mh.msg_iov = iov;
  mh.msg_iovlen = 1;

  if (e->fd > 0)
    {
      struct cmsghdr *cmsg;
      memset (&ctl, 0, sizeof (ctl));
      mh.msg_control = ctl;
      mh.msg_controllen = sizeof (ctl);
      cmsg = CMSG_FIRSTHDR (&mh);
      cmsg->cmsg_len = CMSG_LEN (sizeof (int));
      cmsg->cmsg_level = SOL_SOCKET;
      cmsg->cmsg_type = SCM_RIGHTS;
      memcpy (CMSG_DATA (cmsg), &e->fd, sizeof (int));
    }
  rv = sendmsg (cc->fd, &mh, 0);
  if (rv < 0)
    err = memif_syscall_error_handler (errno);
  DBG ("Message type %u sent", e->msg.type);

  /* If sent successfully, remove the msg from queue */
  if (err == MEMIF_ERR_SUCCESS)
    {
      TAILQ_REMOVE (&cc->msg_queue, e, next);
      cc->sock->args.free (e);
    }

  return err;
}

static memif_msg_queue_elt_t *
memif_msg_enq (memif_control_channel_t *cc)
{
  memif_msg_queue_elt_t *e;

  e = cc->sock->args.alloc (sizeof (*e));
  if (e == NULL)
    return NULL;

  e->fd = -1;
  TAILQ_INSERT_TAIL (&cc->msg_queue, e, next);

  return e;
}

static int
memif_msg_enq_hello (memif_control_channel_t *cc)
{
  memif_msg_hello_t *h;
  memif_msg_queue_elt_t *e = memif_msg_enq (cc);

  if (e == NULL)
    return MEMIF_ERR_NOMEM;

  e->msg.type = MEMIF_MSG_TYPE_HELLO;

  h = &e->msg.hello;
  h->min_version = MEMIF_VERSION;
  h->max_version = MEMIF_VERSION;
  h->max_s2m_ring = MEMIF_MAX_S2M_RING;
  h->max_m2s_ring = MEMIF_MAX_M2S_RING;
  h->max_region = MEMIF_MAX_REGION;
  h->max_log2_ring_size = MEMIF_MAX_LOG2_RING_SIZE;

  strlcpy ((char *) h->name, (char *) cc->sock->args.app_name,
	   sizeof (h->name));

  return MEMIF_ERR_SUCCESS;
}

/* response from memif master - master is ready to handle next message */
static int
memif_msg_enq_ack (memif_control_channel_t *cc)
{
  memif_msg_queue_elt_t *e = memif_msg_enq (cc);

  if (e == NULL)
    return MEMIF_ERR_NOMEM;

  e->msg.type = MEMIF_MSG_TYPE_ACK;
  e->fd = -1;

  return MEMIF_ERR_SUCCESS; /* 0 */
}

/* send id and secret (optional) for interface identification */
static int
memif_msg_enq_init (memif_control_channel_t *cc)
{
  memif_msg_queue_elt_t *e = memif_msg_enq (cc);

  if (e == NULL)
    return MEMIF_ERR_NOMEM;

  memif_msg_init_t *i = &e->msg.init;

  e->msg.type = MEMIF_MSG_TYPE_INIT;
  e->fd = -1;
  i->version = MEMIF_VERSION;
  i->id = cc->conn->args.interface_id;
  i->mode = cc->conn->args.mode;

  strlcpy ((char *) i->name, (char *) cc->sock->args.app_name,
	   sizeof (i->name));
  if (strlen ((char *) cc->conn->args.secret) > 0)
    strlcpy ((char *) i->secret, (char *) cc->conn->args.secret,
	     sizeof (i->secret));

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

/* send information about region specified by region_index */
static int
memif_msg_enq_add_region (memif_control_channel_t *cc, uint8_t region_index)
{
  memif_region_t *mr = &cc->conn->regions[region_index];
  memif_msg_queue_elt_t *e = memif_msg_enq (cc);

  if (e == NULL)
    return MEMIF_ERR_NOMEM;

  memif_msg_add_region_t *ar = &e->msg.add_region;

  e->msg.type = MEMIF_MSG_TYPE_ADD_REGION;
  e->fd = mr->fd;
  ar->index = region_index;
  ar->size = mr->region_size;

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

/* send information about ring specified by direction (S2M | M2S) and index */
static int
memif_msg_enq_add_ring (memif_control_channel_t *cc, uint8_t index,
			uint8_t dir)
{
  memif_msg_queue_elt_t *e = memif_msg_enq (cc);

  if (e == NULL)
    return MEMIF_ERR_NOMEM;

  memif_msg_add_ring_t *ar = &e->msg.add_ring;

  e->msg.type = MEMIF_MSG_TYPE_ADD_RING;

  /* TODO: support multiple rings */
  memif_queue_t *mq;
  if (dir == MEMIF_RING_M2S)
    mq = &cc->conn->rx_queues[index];
  else
    mq = &cc->conn->tx_queues[index];

  e->fd = mq->int_fd;
  ar->index = index;
  ar->offset = mq->offset;
  ar->region = mq->region;
  ar->log2_ring_size = mq->log2_ring_size;
  ar->flags = (dir == MEMIF_RING_S2M) ? MEMIF_MSG_ADD_RING_FLAG_S2M : 0;
  ar->private_hdr_size = 0;

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

/* used as connection request from slave */
static int
memif_msg_enq_connect (memif_control_channel_t *cc)
{
  memif_msg_queue_elt_t *e = memif_msg_enq (cc);

  if (e == NULL)
    return MEMIF_ERR_NOMEM;

  memif_msg_connect_t *cm = &e->msg.connect;

  e->msg.type = MEMIF_MSG_TYPE_CONNECT;
  e->fd = -1;
  strlcpy ((char *) cm->if_name, (char *) cc->conn->args.interface_name,
	   sizeof (cm->if_name));

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

/* used as confirmation of connection by master */
static int
memif_msg_enq_connected (memif_control_channel_t *cc)
{
  memif_msg_queue_elt_t *e = memif_msg_enq (cc);

  if (e == NULL)
    return MEMIF_ERR_NOMEM;

  memif_msg_connected_t *cm = &e->msg.connected;

  e->msg.type = MEMIF_MSG_TYPE_CONNECTED;
  e->fd = -1;
  strlcpy ((char *) cm->if_name, (char *) cc->conn->args.interface_name,
	   sizeof (cm->if_name));

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

int
memif_msg_enq_disconnect (memif_control_channel_t *cc, uint8_t *err_string,
			  uint32_t err_code)
{
  memif_msg_queue_elt_t *e;

  e = cc->sock->args.alloc (sizeof (*e));
  if (e == NULL)
    return MEMIF_ERR_NOMEM;

  e->fd = -1;
  /* Insert disconenct message at the top of the msg queue */
  TAILQ_INSERT_HEAD (&cc->msg_queue, e, next);

  memif_msg_disconnect_t *d = &e->msg.disconnect;

  e->msg.type = MEMIF_MSG_TYPE_DISCONNECT;
  d->code = err_code;
  uint16_t l = sizeof (d->string);
  if (l > 96)
    {
      DBG ("Disconnect string too long. Sending the first %ld characters.",
	   sizeof (d->string) - 1);
    }
  strlcpy ((char *) d->string, (char *) err_string, sizeof (d->string));

  return MEMIF_ERR_SUCCESS;
}

static int
memif_msg_parse_hello (memif_control_channel_t *cc, memif_msg_t *msg)
{
  memif_msg_hello_t *h = &msg->hello;
  memif_connection_t *c = cc->conn;

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
  strlcpy ((char *) c->remote_name, (char *) h->name, sizeof (c->remote_name));

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

/* handle interface identification (id, secret (optional)) */
static int
memif_msg_parse_init (memif_control_channel_t *cc, memif_msg_t *msg)
{
  memif_msg_init_t *i = &msg->init;
  memif_connection_t *c = NULL;
  uint8_t err_string[96];
  memset (err_string, 0, sizeof (char) * 96);
  int err = MEMIF_ERR_SUCCESS;	/* 0 */

  /* Check compatible meimf version */
  if (i->version != MEMIF_VERSION)
    {
      DBG ("MEMIF_VER_ERR");
      memif_msg_enq_disconnect (cc, MEMIF_VER_ERR, 0);
      return MEMIF_ERR_PROTO;
    }

  /* Find endpoint on the socket */
  TAILQ_FOREACH (c, &cc->sock->master_interfaces, next)
  {
    /* Match interface id */
    if (c->args.interface_id != i->id)
      continue;
    /* If control channel is present, interface is connected (or connecting) */
    if (c->control_channel != NULL)
      {
	memif_msg_enq_disconnect (cc, "Already connected", 0);
	return MEMIF_ERR_ALRCONN;
      }
    /* Verify secret */
    if (c->args.secret[0] != '\0')
      {
	if (strncmp ((char *) c->args.secret, (char *) i->secret, 24) != 0)
	  {
	    memif_msg_enq_disconnect (cc, "Incorrect secret", 0);
	    return MEMIF_ERR_SECRET;
	  }
      }

    /* Assign the control channel to this interface */
    c->control_channel = cc;
    cc->conn = c;

    strlcpy ((char *) c->remote_name, (char *) i->name,
	     sizeof (c->remote_name));
  }

  return err;
}

/* receive region information and add new region to connection (if possible) */
static int
memif_msg_parse_add_region (memif_control_channel_t *cc, memif_msg_t *msg,
			    int fd)
{
  memif_msg_add_region_t *ar = &msg->add_region;
  memif_region_t *mr;
  memif_connection_t *c = cc->conn;

  if (fd < 0)
    return MEMIF_ERR_NO_SHMFD;

  if (ar->index > MEMIF_MAX_REGION)
    return MEMIF_ERR_MAXREG;

  mr = (memif_region_t *) cc->sock->args.realloc (
    c->regions, sizeof (memif_region_t) * (++c->regions_num));
  if (mr == NULL)
    return memif_syscall_error_handler (errno);
  memset (mr + ar->index, 0, sizeof (memif_region_t));
  c->regions = mr;
  c->regions[ar->index].fd = fd;
  c->regions[ar->index].region_size = ar->size;
  c->regions[ar->index].addr = NULL;
  /* region 0 is never external */
  if (cc->sock->get_external_region_addr && (ar->index != 0))
    c->regions[ar->index].is_external = 1;

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

/* receive ring information and add new ring to connection queue
   (based on direction S2M | M2S) */
static int
memif_msg_parse_add_ring (memif_control_channel_t *cc, memif_msg_t *msg,
			  int fd)
{
  memif_msg_add_ring_t *ar = &msg->add_ring;
  memif_connection_t *c = cc->conn;

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

      mq = (memif_queue_t *) cc->sock->args.realloc (
	c->rx_queues, sizeof (memif_queue_t) * (++c->rx_queues_num));
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

      mq = (memif_queue_t *) cc->sock->args.realloc (
	c->tx_queues, sizeof (memif_queue_t) * (++c->tx_queues_num));
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

static int
memif_configure_rx_interrupt (memif_connection_t *c)
{
  memif_socket_t *ms = (memif_socket_t *) c->args.socket;
  memif_interrupt_t *idata;
  memif_fd_event_t fde;
  memif_fd_event_data_t *fdata;
  void *ctx;
  int i;

  if (c->on_interrupt != NULL)
    {
      for (i = 0; i < c->run_args.num_m2s_rings; i++)
	{
	  /* Allocate fd event data */
	  fdata = ms->args.alloc (sizeof (*fdata));
	  if (fdata == NULL)
	    {
	      memif_msg_enq_disconnect (c->control_channel, "Internal error",
					0);
	      return MEMIF_ERR_NOMEM;
	    }
	  /* Allocate interrupt data */
	  idata = ms->args.alloc (sizeof (*fdata));
	  if (idata == NULL)
	    {
	      ms->args.free (fdata);
	      memif_msg_enq_disconnect (c->control_channel, "Internal error",
					0);
	      return MEMIF_ERR_NOMEM;
	    }

	  /* configure interrupt data */
	  idata->c = c;
	  idata->qid = i;
	  /* configure fd event data */
	  fdata->event_handler = memif_interrupt_handler;
	  fdata->private_ctx = idata;
	  fde.fd = c->rx_queues[i].int_fd;
	  fde.type = MEMIF_FD_EVENT_READ;
	  fde.private_ctx = fdata;

	  /* Start listening for events */
	  ctx = ms->epfd != -1 ? ms : ms->private_ctx;
	  ms->args.on_control_fd_update (fde, ctx);
	}
    }

  return MEMIF_ERR_SUCCESS;
}

/* slave -> master */
static int
memif_msg_parse_connect (memif_control_channel_t *cc, memif_msg_t *msg)
{
  memif_msg_connect_t *cm = &msg->connect;
  memif_connection_t *c = cc->conn;
  int err;

  err = memif_connect1 (c);
  if (err != MEMIF_ERR_SUCCESS)
    return err;

  strlcpy ((char *) c->remote_if_name, (char *) cm->if_name,
	   sizeof (c->remote_if_name));

  err = memif_configure_rx_interrupt (c);
  if (err != MEMIF_ERR_SUCCESS)
    return err;

  c->on_connect ((void *) c, c->private_ctx);

  return err;
}

/* master -> slave */
static int
memif_msg_parse_connected (memif_control_channel_t *cc, memif_msg_t *msg)
{
  memif_msg_connect_t *cm = &msg->connect;
  memif_connection_t *c = cc->conn;

  int err;
  err = memif_connect1 (c);
  if (err != MEMIF_ERR_SUCCESS)
    return err;

  strlcpy ((char *) c->remote_if_name, (char *) cm->if_name,
	   sizeof (c->remote_if_name));

  err = memif_configure_rx_interrupt (c);
  if (err != MEMIF_ERR_SUCCESS)
    return err;

  c->on_connect ((void *) c, c->private_ctx);

  return err;
}

static int
memif_msg_parse_disconnect (memif_control_channel_t *cc, memif_msg_t *msg)
{
  memif_msg_disconnect_t *d = &msg->disconnect;
  memif_connection_t *c = cc->conn;

  memset (c->remote_disconnect_string, 0,
	  sizeof (c->remote_disconnect_string));
  strlcpy ((char *) c->remote_disconnect_string, (char *) d->string,
	   sizeof (c->remote_disconnect_string));

  /* on returning error, handle function will call memif_disconnect () */
  DBG ("disconnect received: %s, mode: %d",
       c->remote_disconnect_string, c->args.mode);
  return MEMIF_ERR_DISCONNECT;
}

static int
memif_msg_receive_and_parse (memif_control_channel_t *cc)
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
  memif_socket_t *ms = NULL;

  iov[0].iov_base = (void *) &msg;
  iov[0].iov_len = sizeof (memif_msg_t);
  mh.msg_iov = iov;
  mh.msg_iovlen = 1;
  mh.msg_control = ctl;
  mh.msg_controllen = sizeof (ctl);

  DBG ("recvmsg fd %d", cc->fd);
  size = recvmsg (cc->fd, &mh, 0);
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

  switch (msg.type)
    {
    case MEMIF_MSG_TYPE_ACK:
      break;

    case MEMIF_MSG_TYPE_HELLO:
      if ((err = memif_msg_parse_hello (cc, &msg)) != MEMIF_ERR_SUCCESS)
	return err;
      if ((err = memif_init_regions_and_queues (cc->conn)) !=
	  MEMIF_ERR_SUCCESS)
	return err;
      if ((err = memif_msg_enq_init (cc)) != MEMIF_ERR_SUCCESS)
	return err;
      for (i = 0; i < cc->conn->regions_num; i++)
	{
	  if ((err = memif_msg_enq_add_region (cc, i)) != MEMIF_ERR_SUCCESS)
	    return err;
	}
      for (i = 0; i < cc->conn->run_args.num_s2m_rings; i++)
	{
	  if ((err = memif_msg_enq_add_ring (cc, i, MEMIF_RING_S2M)) !=
	      MEMIF_ERR_SUCCESS)
	    return err;
	}
      for (i = 0; i < cc->conn->run_args.num_m2s_rings; i++)
	{
	  if ((err = memif_msg_enq_add_ring (cc, i, MEMIF_RING_M2S)) !=
	      MEMIF_ERR_SUCCESS)
	    return err;
	}
      if ((err = memif_msg_enq_connect (cc)) != MEMIF_ERR_SUCCESS)
	return err;
      break;

    case MEMIF_MSG_TYPE_INIT:
      if ((err = memif_msg_parse_init (cc, &msg)) != MEMIF_ERR_SUCCESS)
	return err;
      /* c->remote_pid = cr->pid */
      /* c->remote_uid = cr->uid */
      /* c->remote_gid = cr->gid */
      if ((err = memif_msg_enq_ack (cc)) != MEMIF_ERR_SUCCESS)
	return err;
      break;

    case MEMIF_MSG_TYPE_ADD_REGION:
      if ((err = memif_msg_parse_add_region (cc, &msg, fd)) !=
	  MEMIF_ERR_SUCCESS)
	return err;
      if ((err = memif_msg_enq_ack (cc)) != MEMIF_ERR_SUCCESS)
	return err;
      break;

    case MEMIF_MSG_TYPE_ADD_RING:
      if ((err = memif_msg_parse_add_ring (cc, &msg, fd)) != MEMIF_ERR_SUCCESS)
	return err;
      if ((err = memif_msg_enq_ack (cc)) != MEMIF_ERR_SUCCESS)
	return err;
      break;

    case MEMIF_MSG_TYPE_CONNECT:
      if ((err = memif_msg_parse_connect (cc, &msg)) != MEMIF_ERR_SUCCESS)
	return err;
      if ((err = memif_msg_enq_connected (cc)) != MEMIF_ERR_SUCCESS)
	return err;
      break;

    case MEMIF_MSG_TYPE_CONNECTED:
      if ((err = memif_msg_parse_connected (cc, &msg)) != MEMIF_ERR_SUCCESS)
	return err;
      break;

    case MEMIF_MSG_TYPE_DISCONNECT:
      if ((err = memif_msg_parse_disconnect (cc, &msg)) != MEMIF_ERR_SUCCESS)
	return err;
      break;

    default:
      return MEMIF_ERR_UNKNOWN_MSG;;
      break;
    }

  return MEMIF_ERR_SUCCESS;	/* 0 */
}

void
memif_delete_control_channel (memif_control_channel_t *cc)
{
  memif_msg_queue_elt_t *e, *next;
  memif_socket_t *ms = cc->sock;
  memif_fd_event_t fde;
  void *ctx;

  fde.fd = cc->fd;
  fde.type = MEMIF_FD_EVENT_DEL;
  ctx = ms->epfd != -1 ? ms : ms->private_ctx;
  cc->sock->args.on_control_fd_update (fde, ctx);

  if (cc->fd > 0)
    close (cc->fd);

  /* Clear control message queue */
  for (e = TAILQ_FIRST (&cc->msg_queue); e != NULL; e = next)
    {
      next = TAILQ_NEXT (e, next);
      TAILQ_REMOVE (&cc->msg_queue, e, next);
      cc->sock->args.free (e);
    }

  /* remove reference */
  if (cc->conn != NULL)
    cc->conn->control_channel = NULL;
  cc->conn = NULL;
  cc->sock->args.free (cc);

  return;
}

int
memif_control_channel_handler (memif_fd_event_type_t type, void *private_ctx)
{
  memif_control_channel_t *cc = (memif_control_channel_t *) private_ctx;
  int err;

  /* Receive the message, parse the message and
   * enqueue next message(s).
   */
  err = memif_msg_receive_and_parse (cc);
  /* Can't assign to endpoint */
  if (cc->conn == NULL)
    {
      /* A disconnect message is already in the queue */
      memif_msg_send_from_queue (cc);
      memif_delete_control_channel (cc);

      return MEMIF_ERR_SUCCESS;
    }
  /* error in memif_msg_receive */
  if (err != MEMIF_ERR_SUCCESS)
    goto disconnect;

  /* Continue connecting, send next message from the queue */
  err = memif_msg_send_from_queue (cc);
  if (err != MEMIF_ERR_SUCCESS)
    goto disconnect;

  return MEMIF_ERR_SUCCESS;

disconnect:
  memif_disconnect_internal (cc->conn);
  return MEMIF_ERR_SUCCESS;
}

int
memif_listener_handler (memif_fd_event_type_t type, void *private_ctx)
{
  memif_socket_t *ms = (memif_socket_t *) private_ctx;
  memif_control_channel_t *cc;
  memif_fd_event_t fde;
  memif_fd_event_data_t *fdata;
  struct sockaddr_un un;
  int err, sockfd, addr_len = sizeof (un);
  void *ctx;

  if (ms == NULL)
    return MEMIF_ERR_INVAL_ARG;

  if (type & MEMIF_FD_EVENT_READ)
    {
      /* Accept connection to the listener socket */
      sockfd = accept (ms->listener_fd, (struct sockaddr *) &un,
		       (socklen_t *) &addr_len);
      if (sockfd < 0)
	{
	  return memif_syscall_error_handler (errno);
	}

      /* Create new control channel */
      cc = ms->args.alloc (sizeof (*cc));
      if (cc == NULL)
	{
	  err = MEMIF_ERR_NOMEM;
	  goto error;
	}

      cc->fd = sockfd;
      /* The connection will be assigned after parsing MEMIF_MSG_TYPE_INIT msg
       */
      cc->conn = NULL;
      cc->sock = ms;
      TAILQ_INIT (&cc->msg_queue);

      /* Create memif fd event */
      fdata = ms->args.alloc (sizeof (*fdata));
      if (fdata == NULL)
	{
	  err = MEMIF_ERR_NOMEM;
	  goto error;
	}

      fdata->event_handler = memif_control_channel_handler;
      fdata->private_ctx = cc;

      fde.fd = sockfd;
      fde.type = MEMIF_FD_EVENT_READ;
      fde.private_ctx = fdata;

      /* Start listenning for events on the new control channel */
      ctx = ms->epfd != -1 ? ms : ms->private_ctx;
      ms->args.on_control_fd_update (fde, ctx);

      /* enqueue HELLO msg */
      err = memif_msg_enq_hello (cc);
      if (err != MEMIF_ERR_SUCCESS)
	goto error;

      /* send HELLO msg */
      err = memif_msg_send_from_queue (cc);
      if (err != MEMIF_ERR_SUCCESS)
	goto error;
    }

  return MEMIF_ERR_SUCCESS;

error:
  if (sockfd > 0)
    close (sockfd);
  if (cc != NULL)
    ms->args.free (cc);
  if (fdata != NULL)
    ms->args.free (fdata);

  return err;
}
