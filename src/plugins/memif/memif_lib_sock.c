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

#include "memif_lib.h"
#include "memif_lib_vec.h"
#include "memif_lib_priv.h"

static uint32_t
_min (uint32_t a, uint32_t b)
{
    return a < b ? a : b;
}

static int
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
    {
        DEBUG_LOG ("sendmsg error: %s", strerror (errno));
        return rv;
    }
    return 0;
}

static int
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

void
memif_msg_send_recv_mode (memif_if_t *mif)
{
    memif_main_t *mm = dump_memif_main ();
    memif_msg_t msg = { 0 };
    memif_msg_recv_mode_t *m = &msg.recv_mode;
    msg.type = MEMIF_MSG_TYPE_RECV_MODE;
    m->recv_mode = mm->recv_mode;
    m->qid = 0; /* queue id of peer memif tx_queue that is supposed to send interrupt */
                /* or other identification method... */
    int ret = memif_msg_send (mif->conn_fd, &msg, -1);
    if (ret < 0)
    {
        DEBUG_LOG ("send recv mode msg error on mif idx %lu", mif->dev_instance);
    }
}

static int
memif_msg_send_init (memif_if_t * mif)
{
  memif_msg_t msg = { 0 };
  memif_msg_init_t *i = &msg.init;

  msg.type = MEMIF_MSG_TYPE_INIT;
  i->key = mif->key;

  //mif->flags |= MEMIF_IF_FLAG_CONNECTING;

  return memif_msg_send (mif->conn_fd, &msg, -1);
}

static int
memif_msg_send_add_region (memif_if_t * mif, uint8_t region)
{
  memif_msg_t msg = { 0 };
  memif_msg_add_region_t *ar = &msg.add_region;

  msg.type = MEMIF_MSG_TYPE_ADD_REGION;
  ar->index = region;
  ar->size = mif->regions[region].region_size;

  return memif_msg_send (mif->conn_fd, &msg, mif->regions[region].fd);
}

static int
memif_msg_send_add_ring (memif_if_t * mif, uint8_t index, uint8_t direction)
{
  memif_msg_t msg = { 0 };
  memif_msg_add_ring_t *ar = &msg.add_ring;
  memif_queue_t *mq;

  //ASSERT ((mif->flags & MEMIF_IF_FLAG_IS_SLAVE) != 0);
  if ((mif->flags & MEMIF_IF_FLAG_IS_SLAVE) == 0)
    return -1;

  msg.type = MEMIF_MSG_TYPE_ADD_RING;

  if (direction == MEMIF_RING_M2S)
    mq = vec_get_at_index (index, mif->rx_queues);
  else
    mq = vec_get_at_index (index, mif->tx_queues);

  ar->index = index;
  ar->region = mq->region;
  ar->offset = mq->offset;
  ar->log2_ring_size = mq->log2_ring_size;
  ar->flags = (direction == MEMIF_RING_S2M) ? MEMIF_MSG_ADD_RING_FLAG_S2M : 0;

  return memif_msg_send (mif->conn_fd, &msg, mq->int_fd);
}

static int
memif_msg_send_connect (memif_if_t * mif)
{
  memif_msg_t msg = { 0 };
  msg.type = MEMIF_MSG_TYPE_CONNECT;
  return memif_msg_send (mif->conn_fd, &msg, -1);
}

static int
memif_msg_send_disconnect (memif_if_t * mif)
{
  memif_msg_t msg = { 0 };
  msg.type = MEMIF_MSG_TYPE_DISCONNECT;
  memif_msg_disconnect_t *d = &msg.disconnect;

  d->reason = ~0;
  strncpy ((char *) d->reason_string, "unknown", 8);

  return memif_msg_send (mif->conn_fd, &msg, -1);
}

static int
memif_msg_receive_hello (memif_if_t * mif, memif_msg_t * msg)
{
  if (msg->hello.min_version > MEMIF_VERSION ||
      msg->hello.max_version < MEMIF_VERSION)
    {
      DEBUG_LOG ("incompatible protocol version");
      return -1;
    }

  mif->run.num_s2m_rings = _min (msg->hello.max_s2m_rings,
                                 mif->cfg.num_s2m_rings);
  mif->run.num_m2s_rings = _min (msg->hello.max_m2s_rings,
                                 mif->cfg.num_m2s_rings);
  mif->run.log2_ring_size = _min (msg->hello.max_log2_ring_size,
                                  mif->cfg.log2_ring_size);
  mif->run.buffer_size = mif->cfg.buffer_size;

  return 0;
}

static int
memif_msg_receive_init (memif_if_t ** mifp, memif_msg_t * msg,
            memif_file_t * mf)
{
  memif_main_t *mm = dump_memif_main ();
  memif_socket_file_t *msf =
    (memif_socket_file_t *) vec_get_at_index (mf->data, mm->socket_files);

  memif_msg_init_t *i = &msg->init;
  memif_if_t *mif;

  mif = get_if_by_key (i->key);

  if (!mif)
    {
      DEBUG_LOG ("unmatched key");
      return -1;
    }

  *mifp = mif;

  if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
    {
      DEBUG_LOG ("cannot connect to slave");
      return -1;
    }

  if (mif->conn_fd != -1)
    {
      DEBUG_LOG ("already connected");
      return -1;
    }

  mif->conn_fd = mf->fd;
  mif->conn_memif_file_index = mf - mm->files;
  
  /*hash_set (msf->dev_instance_by_fd, mif->conn_fd, mif->dev_instance);*/
  vec_set_at_index (&mif->dev_instance, mif->conn_fd, (void **) &msf->dev_instance_by_fd);
  uint64_t *t = (uint64_t *) vec_get_at_index (mif->conn_fd, msf->dev_instance_by_fd);
  DEBUG_LOG ("mif->dev_instance: %lu", mif->dev_instance);
  DEBUG_LOG ("t: %lu", *t);

  return 0;
}

static int
memif_msg_receive_add_region (memif_if_t * mif, memif_msg_t * msg, int fd)
{
  memif_msg_add_region_t *ar = &msg->add_region;
  memif_region_t *mr;
  if (fd < 0)
    {
      DEBUG_LOG ("missing memory region fd");
      return -1;
    }

  if (mif->regions == NULL)
  {
    DEBUG_LOG ("mif->regions init");
    mif->regions = (memif_region_t *) vec_init (sizeof (memif_region_t));
  }

  mr = (memif_region_t *) vec_get ((void **) &mif->regions);
  mr->fd = fd;
  mr->region_size = ar->size;

  return 0;
}

static int
memif_msg_receive_add_ring (memif_if_t * mif, memif_msg_t * msg, int fd)
{
  memif_msg_add_ring_t *ar = &msg->add_ring;
  memif_queue_t *mq;

  if (fd < 0)
    {
      DEBUG_LOG ("missing ring interrupt fd");
      return -1;
    }

  if (ar->flags & MEMIF_MSG_ADD_RING_FLAG_S2M)
    {
      /*vec_validate_aligned (mif->rx_queues, ar->index, CLIB_CACHE_LINE_BYTES);*/
      if (mif->rx_queues == NULL)
      {
        DEBUG_LOG ("mif->rx_queues init");
        mif->rx_queues = (memif_queue_t *) vec_init (sizeof (memif_queue_t));
      }
      mq = (memif_queue_t *) vec_get ((void **) &mif->rx_queues);
      mif->run.num_s2m_rings = vec_get_len (mif->rx_queues);
    }
  else
    {
      /*vec_validate_aligned (mif->tx_queues, ar->index, CLIB_CACHE_LINE_BYTES);*/
      if (mif->tx_queues == NULL)
      {
        DEBUG_LOG ("mif->tx_queues init");
        mif->tx_queues = (memif_queue_t *) vec_init (sizeof (memif_queue_t));
      }
      mq = (memif_queue_t *) vec_get ((void **) &mif->tx_queues);
      mif->run.num_m2s_rings = vec_get_len (mif->tx_queues);
    }
  mq->int_fd = fd;
  mq->int_memif_file_index = ~0;
  mq->log2_ring_size = ar->log2_ring_size;
  mq->region = ar->region;
  mq->offset = ar->offset;
  mq->recv_mode = 0; /* TODO: pass with add_ring type */

  return 0;
}

static int
memif_update_recv_mode (memif_if_t *mif, memif_msg_t *msg)
{
    memif_msg_recv_mode_t *rm = &msg->recv_mode;
    memif_queue_t *mq = (memif_queue_t *) vec_get_at_index (rm->qid, mif->tx_queues);
    if (mq == NULL)
    {
        DEBUG_LOG ("no queue idx %u", rm->qid);
    }
    else
    {
        mq->recv_mode = rm->recv_mode;
    }
    return 0;
}

static int
memif_msg_receive (memif_if_t * mif, memif_file_t * mf)
{
  char ctl[CMSG_SPACE (sizeof (int)) +
       CMSG_SPACE (sizeof (struct ucred))] = { 0 };
  struct msghdr mh = { 0 };
  struct iovec iov[1];
  memif_msg_t msg = { 0 };
  ssize_t size;
  int err = 0;
  int fd = -1;
  long i = -1;

  iov[0].iov_base = (void *) &msg;
  iov[0].iov_len = sizeof (memif_msg_t);
  mh.msg_iov = iov;
  mh.msg_iovlen = 1;
  mh.msg_control = ctl;
  mh.msg_controllen = sizeof (ctl);

  /* receive the incoming message */
  size = recvmsg (mf->fd, &mh, 0);
  if (size != sizeof (memif_msg_t))
    {
      memif_disconnect (mif);
      if (size == 0)
        return 0;
      else
        {
            DEBUG_LOG ("recvmsg: malformed message received on fd %d", mf->fd);
            return -1;
        }
    }

  if (mif == 0 && msg.type != MEMIF_MSG_TYPE_INIT)
    {
      memif_file_del (mf);
      DEBUG_LOG ("unexpected message received");
      return -1;
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
      if ((err = memif_msg_receive_hello (mif, &msg)) < 0)
    goto error;

      if ((err = memif_init_regions_and_queues (mif)) < 0)
    goto error;

      if ((err = memif_msg_send_init (mif)) < 0)
    goto error;

      if ((err = memif_msg_send_add_region (mif, 0)) < 0)
    goto error;

      i = -1;
      while (vec_get_next (&i, mif->tx_queues) != NULL)
      {
    if ((err = memif_msg_send_add_ring (mif, i, MEMIF_RING_S2M)) < 0)
    goto error;
      }

      i = -1;
      while (vec_get_next (&i, mif->rx_queues) != NULL)
      {
    if ((err = memif_msg_send_add_ring (mif, i, MEMIF_RING_M2S)) < 0)
    goto error;
      }

      if ((err = memif_msg_send_connect (mif)) < 0)
    goto error;

      if ((err = memif_connect (mif)) < 0)
    goto error;
      break;

    case MEMIF_MSG_TYPE_INIT:
      if ((err = memif_msg_receive_init (&mif, &msg, mf)) < 0)
    goto error;
      mif->remote_pid = cr->pid;
      mif->remote_uid = cr->uid;
      mif->remote_gid = cr->gid;
      break;

    case MEMIF_MSG_TYPE_ADD_REGION:
      if ((err = memif_msg_receive_add_region (mif, &msg, fd)) < 0)
    goto error;
      break;

    case MEMIF_MSG_TYPE_ADD_RING:
      if ((err = memif_msg_receive_add_ring (mif, &msg, fd)) < 0)
    goto error;
      break;

    case MEMIF_MSG_TYPE_CONNECT:
      if ((err = memif_connect (mif)) < 0)
    goto error;
      break;

    case MEMIF_MSG_TYPE_CONNECTED:
      if (fd > 0)
    DEBUG_LOG ("fd %d", fd);
      break;

    case MEMIF_MSG_TYPE_RECV_MODE:
        if ((err = memif_update_recv_mode (mif, &msg)) < 0)
    goto error;
        break;

    default:
      DEBUG_LOG ("unknown message type (0x%x)", msg.type);
      err = -1;
      goto error;
    }

  return 0;

error:
  DEBUG_LOG ("RECV ERROR!");
  if ((err = memif_msg_send_disconnect (mif)) < 0)
  {
    DEBUG_LOG ("memif_msg_send_Disconnect error: %d", err);
  }
  memif_disconnect (mif);
  return 0;
}

void *
memif_master_conn_fd_read_ready (memif_file_t * mf)
{
  memif_main_t *mm = dump_memif_main ();
  memif_socket_file_t *msf =
    (memif_socket_file_t *) vec_get_at_index (mf->data, mm->socket_files);
  uint64_t *p;
  memif_if_t *mif = 0;
  /*uint64_t conn_memif_file_index = ~0;*/
  int err = 0;

  p = (uint64_t *) vec_get_at_index (mf->fd, msf->dev_instance_by_fd);
  if (p)
    {
      mif = vec_get_at_index (*p, mm->interfaces);
    }
  else
    {
      /* This is new connection, remove index from pending vector */
      long i = -1;
      while ((p = (uint64_t *) vec_get_next (&i, msf->pending_file_indices)) != NULL)
        {
    if (msf->pending_file_indices[i] == mf - mm->files)
    {
      /*conn_memif_file_index = msf->pending_file_indices[i];*/
      vec_free_at_index (i, msf->pending_file_indices);
      break;
    }
        }
      /*ASSERT (conn_memif_file_index != ~0);*/
    }
  err = memif_msg_receive (mif, mf);

  if (err < 0)
    {
      DEBUG_LOG ("memif_msg_receive return: %d", err);
    }
    
  return 0;
}

void *
memif_slave_conn_fd_read_ready (memif_file_t * mf)
{
  memif_main_t *mm = dump_memif_main ();
  int err;
  memif_if_t *mif = (memif_if_t *) vec_get_at_index (mf->data, mm->interfaces);
  err = memif_msg_receive (mif, mf);
  if (err < 0)
    {
      DEBUG_LOG ("memif_msg_receive return: %d", err);
      memif_disconnect (mif);
    }
  return 0;
}

void *
memif_slave_conn_fd_error (memif_file_t * mf)
{
  memif_main_t *mm = dump_memif_main ();
  memif_if_t *mif = (memif_if_t *) vec_get_at_index (mf->data, mm->interfaces);

  memif_disconnect (mif);
  return 0;
}

void *
memif_master_conn_fd_error (memif_file_t * mf)
{
/*  memif_main_t *mm = dump_memif_main ();
  memif_socket_file_t *msf =
    (memif_socket_file_t *) vec_get_at_index (mf->data, mm->interfaces);

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
    if (msf->pending_file_indices[i] == mf - memif_main.file_pool)
    {
      vec_del1 (msf->pending_file_indices, i);
      memif_file_del (mf);
      return 0;
    }
    }

  DEBUG_LOG ("Error on unknown file descriptor %d", mf->fd);
  memif_file_del (mf);
*/
  return 0;
}

void *
memif_conn_fd_accept_ready (memif_file_t * mf)
{
  memif_main_t *mm = dump_memif_main ();
  memif_socket_file_t *msf =
    (memif_socket_file_t *) vec_get_at_index (mf->data, mm->socket_files);
  int addr_len;
  struct sockaddr_un client;
  int conn_fd;
  memif_file_t template = { 0 };
  uint64_t memif_file_index;
  int err;


  addr_len = sizeof (client);
  conn_fd = accept (mf->fd,
            (struct sockaddr *) &client, (socklen_t *) & addr_len);

  if (conn_fd < 0)
    {
      DEBUG_LOG ("accept fd %d", mf->fd);
      return 0;
    }

  template.read_function = memif_master_conn_fd_read_ready;
  template.error_function = memif_master_conn_fd_error;
  template.fd = conn_fd;
  template.data = mf->data;
  memif_file_index = memif_file_add (&template);
  DEBUG_LOG ("memif_file_add fd %d pd %lu idx %lu", template.fd,
       template.data, memif_file_index);


  err = memif_msg_send_hello (conn_fd);
  if (err < 0)
    {
      DEBUG_LOG ("memif_msg_send_hello error: %d", err);
      memif_file_del_by_index (memif_file_index);
    }
  else
    {
      uint64_t *tmp =  (uint64_t *) vec_get ((void **) &msf->pending_file_indices);
      *tmp = memif_file_index;
    }

  return 0;
}
