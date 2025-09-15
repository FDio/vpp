/*
** Copyright (C) 2025 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software Foundation, Inc.
** 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/epoll.h>

#include "daq.h"
#include "daq_vpp.h"

static daq_vpp_rv_t
daq_vpp_request (daq_vpp_msg_req_t *req, daq_vpp_msg_reply_t *reply, int n_fds,
		 int fds[])
{
  daq_vpp_main_t *vdm = &daq_vpp_main;
  const ssize_t req_msg_sz = sizeof (daq_vpp_msg_req_t);
  const int ctl_sz =
    CMSG_SPACE (sizeof (int) * n_fds) + CMSG_SPACE (sizeof (struct ucred));
  char ctl[ctl_sz];
  struct msghdr mh = {};
  struct iovec iov[1];
  struct cmsghdr *cmsg;
  ssize_t rv;

  if (send (vdm->socket_fd, req, req_msg_sz, 0) != req_msg_sz)
    return DAQ_VPP_ERR_SOCKET;

  iov[0].iov_base = (void *) reply;
  iov[0].iov_len = sizeof (daq_vpp_msg_reply_t);
  mh.msg_iov = iov;
  mh.msg_iovlen = 1;
  mh.msg_control = ctl;
  mh.msg_controllen = ctl_sz;

  memset (ctl, 0, ctl_sz);

  rv = recvmsg (vdm->socket_fd, &mh, 0);
  if (rv != sizeof (daq_vpp_msg_reply_t))
    return DAQ_VPP_ERR_SOCKET;

  cmsg = CMSG_FIRSTHDR (&mh);
  while (cmsg)
    {
      if (cmsg->cmsg_level == SOL_SOCKET)
	{
	  if (cmsg->cmsg_type == SCM_CREDENTIALS)
	    /* Do nothing */;
	  else if (cmsg->cmsg_type == SCM_RIGHTS)
	    memcpy (fds, CMSG_DATA (cmsg), n_fds * sizeof (int));
	}
      cmsg = CMSG_NXTHDR (&mh, cmsg);
    }

  return reply->err;
}

void
daq_vpp_socket_disconnect ()
{
  daq_vpp_main_t *vdm = &daq_vpp_main;

  if (vdm->bpools)
    free (vdm->bpools);

  if (vdm->socket_fd > -1)
    {
      close (vdm->socket_fd);
      vdm->socket_fd = -1;
    }
  vdm->connected = 1;
}

daq_vpp_rv_t
daq_vpp_socket_connect ()
{
  daq_vpp_main_t *vdm = &daq_vpp_main;

  struct sockaddr_un sun = { .sun_family = AF_UNIX };
  int fd;

  fd = socket (AF_UNIX, SOCK_SEQPACKET, 0);

  if (fd < 0)
    return DAQ_VPP_ERR_SOCKET;

  strncpy (sun.sun_path, vdm->socket_name, sizeof (sun.sun_path) - 1);

  if (connect (fd, (struct sockaddr *) &sun, sizeof (struct sockaddr_un)) != 0)
    {
      close (fd);
      return DAQ_VPP_ERR_SOCKET;
    }

  vdm->socket_fd = fd;
  return DAQ_VPP_OK;
}

int
daq_vpp_connect (daq_vpp_ctx_t *ctx, uint16_t num_instances, DAQ_Mode mode)
{
  daq_vpp_main_t *vdm = &daq_vpp_main;
  daq_vpp_msg_reply_t reply = {};
  daq_vpp_rv_t vrv;
  int rv, fd;

  vrv = daq_vpp_socket_connect ();
  if (vrv != DAQ_VPP_OK)
    return daq_vpp_err (ctx, "socket connect error");

  vrv = daq_vpp_request (
    &(daq_vpp_msg_req_t){
      .type = DAQ_VPP_MSG_TYPE_CONNECT,
      .connect = {
        .num_snort_instances = num_instances,
        .daq_version = daq_version_number(),
        .mode = (daq_vpp_mode_t)mode,
        },
    },
    &reply, 0, 0);

  if (vrv != DAQ_VPP_OK)
    {
      rv = daq_vpp_err (ctx, "CONNECT request failed, %s",
			daq_vpp_rv_string (vrv));
      goto err;
    }

  vdm->num_bpools = reply.connect.num_bpools;
  vdm->bpools = calloc (vdm->num_bpools, sizeof (daq_vpp_buffer_pool_t));

  if (vdm->bpools == NULL)
    {
      rv = daq_vpp_err (ctx, "buffer pool memory allocation error");
      goto err;
    }

  for (daq_vpp_buffer_pool_index_t i = 0; i < vdm->num_bpools; i++)
    {
      daq_vpp_buffer_pool_t *bp = vdm->bpools + i;

      vrv = daq_vpp_request (
	&(daq_vpp_msg_req_t){
	  .type = DAQ_VPP_MSG_TYPE_GET_BUFFER_POOL,
	  .get_buffer_pool = { .buffer_pool_index = i },
	},
	&reply, 1, &fd);

      if (vrv != DAQ_VPP_OK)
	{
	  rv = daq_vpp_err (ctx, "GET_BUFFER_POOL request failed, %s",
			    daq_vpp_rv_string (vrv));
	  goto err;
	}

      bp->base = mmap (0, reply.get_buffer_pool.size, PROT_READ | PROT_WRITE,
		       MAP_SHARED, fd, 0);

      if (bp->base == MAP_FAILED)
	{
	  rv = daq_vpp_err (ctx, "buffer pool mmap failed");
	  goto err;
	}

      bp->fd = fd;
      bp->size = reply.get_buffer_pool.size;
    }

  return DAQ_SUCCESS;

err:
  if (rv != DAQ_SUCCESS)
    daq_vpp_socket_disconnect ();
  return rv;
}

int
daq_vpp_find_or_add_input (daq_vpp_ctx_t *ctx, char *name,
			   daq_vpp_input_t **inp)
{
  daq_vpp_main_t *vdm = &daq_vpp_main;
  daq_vpp_input_t *in = 0;
  daq_vpp_msg_req_t req = {};
  daq_vpp_msg_reply_t reply;
  daq_vpp_input_index_t ii;
  daq_vpp_rv_t vrv;
  uint64_t shm_size;
  uint16_t n_qpairs;
  int rv, fd;
  uint8_t *base = 0;

  /* search for existing input */
  for (daq_vpp_input_index_t i = 0; i < vdm->n_inputs; i++)
    {
      daq_vpp_input_t *in = vdm->inputs[i];
      if (strcmp (in->name, name) == 0)
	{
	  *inp = in;
	  return DAQ_VPP_OK;
	}
    }

  req.type = DAQ_VPP_MSG_TYPE_GET_INPUT;
  strcpy (req.get_input.input_name, name);
  vrv = daq_vpp_request (&req, &reply, 1, &fd);

  if (vrv != DAQ_VPP_OK)
    {
      rv = daq_vpp_err (ctx, "GET_INPUT request failed, %s",
			daq_vpp_rv_string (vrv));
      goto err;
    }

  ii = reply.get_input.input_index;
  n_qpairs = reply.get_input.num_qpairs;
  shm_size = reply.get_input.shm_size;

  base = mmap (0, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

  if (base == MAP_FAILED)
    {
      rv = daq_vpp_err (ctx, "input shared memory mmap failed");
      goto err;
    }

  in =
    calloc (1, sizeof (daq_vpp_input_t) + n_qpairs * sizeof (daq_vpp_qpair_t));
  if (!in)
    {
      rv = daq_vpp_err (ctx, "input memory alloc failed");
      goto err;
    }

  strcpy (in->name, name);
  in->shm_size = shm_size;
  in->num_qpairs = n_qpairs;
  in->shm_fd = fd;
  in->shm_base = base;

  for (daq_vpp_qpair_index_t qi = 0; qi < in->num_qpairs; qi++)
    {
      daq_vpp_qpair_t *qp = in->qpairs + qi;
      daq_vpp_msg_reply_attach_qpair_t *g = &reply.attach_qpair;
      daq_vpp_msg_req_t req = {
        .type = DAQ_VPP_MSG_TYPE_ATTACH_QPAIR,
	.attach_qpair = {
          .input_index = ii,
          .qpair_index = qi,
        },
      };
      int fds[2];

      vrv = daq_vpp_request (&req, &reply, 2, fds);

      if (vrv != DAQ_VPP_OK)
	{
	  rv = daq_vpp_err (ctx, "ATTACH_QPAIR request failed, %s",
			    daq_vpp_rv_string (vrv));
	  goto err;
	}

      qp->qpair_id = g->qpair_id;
      qp->queue_size = 1 << g->log2_queue_size;
      qp->hdr = (daq_vpp_qpair_header_t *) (base + g->qpair_header_offset);
      qp->enq_ring = (daq_vpp_desc_index_t *) (base + g->enq_ring_offset);
      qp->deq_ring = (daq_vpp_desc_index_t *) (base + g->deq_ring_offset);
      qp->enq_fd = fds[0];
      qp->deq_fd = fds[1];
      qp->input_index = ii;

      if (qp->hdr->enq.cookie != DAQ_VPP_COOKIE)
	{
	  rv = daq_vpp_err (ctx, "invalid cookie for qpair %u.%u",
			    qp->qpair_id.thread_id, qp->qpair_id.queue_id);
	  goto err;
	}

      DEBUG ("qpair %u.%u added, size %u", qp->qpair_id.thread_id,
	     qp->qpair_id.queue_id, qp->queue_size);
    }

  vdm->inputs =
    reallocarray (vdm->inputs, vdm->n_inputs + 1, sizeof (daq_vpp_input_t *));
  vdm->inputs[vdm->n_inputs++] = in;

  *inp = in;

  return DAQ_VPP_OK;

err:
  if (base)
    munmap (base, shm_size);
  if (in)
    free (in);
  return rv;
}
