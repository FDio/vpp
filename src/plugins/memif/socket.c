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

clib_error_t *
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

clib_error_t *
memif_msg_send_init (memif_if_t * mif)
{
  memif_msg_t msg = { 0 };
  memif_msg_init_t *i = &msg.init;

  msg.type = MEMIF_MSG_TYPE_INIT;
  i->key = mif->key;

  //mif->flags |= MEMIF_IF_FLAG_CONNECTING;

  return memif_msg_send (mif->conn_fd, &msg, -1);
}

clib_error_t *
memif_msg_send_add_region (memif_if_t * mif, u8 region)
{
  memif_msg_t msg = { 0 };
  memif_msg_add_region_t *ar = &msg.add_region;

  msg.type = MEMIF_MSG_TYPE_ADD_REGION;
  ar->index = region;
  ar->size = mif->regions[region].region_size;

  return memif_msg_send (mif->conn_fd, &msg, mif->regions[region].fd);
}

clib_error_t *
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

clib_error_t *
memif_msg_send_connect (memif_if_t * mif)
{
  memif_msg_t msg = { 0 };
  msg.type = MEMIF_MSG_TYPE_CONNECT;
  return memif_msg_send (mif->conn_fd, &msg, -1);
}

clib_error_t *
memif_msg_send_disconnect (memif_if_t * mif)
{
  memif_msg_t msg = { 0 };
  msg.type = MEMIF_MSG_TYPE_DISCONNECT;
  memif_msg_disconnect_t *d = &msg.disconnect;

  d->reason = ~0;
  strncpy ((char *) d->reason_string, "unknown", 8);

  return memif_msg_send (mif->conn_fd, &msg, -1);
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
