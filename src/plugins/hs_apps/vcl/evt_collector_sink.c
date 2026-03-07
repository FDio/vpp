/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

/**
 * VCL application: event collector sink.
 *
 * Listens on a TCP endpoint, accepts connections from VPP's app-evt-collector,
 * parses incoming app_evt_msg_t records, and prints per-protocol session stats
 * on exit.
 *
 * Usage:
 *   VCL_CONFIG=/path/to/vcl.conf evt_collector_sink <listen-addr> <port>
 */

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <vcl/vppcom.h>
#include <vnet/session/application_eventing.h>

#define ECS_MAX_CONNS 64
#define ECS_BUF_CAP   (4 << 20) /* 4 MB reassembly buffer per connection */

/* Per-connection reassembly buffer. */
typedef struct
{
  int fd;
  uint8_t *buf;
  uint32_t buf_len;
} ecs_conn_t;

typedef struct
{
  ecs_conn_t conns[ECS_MAX_CONNS];
  int nconns;
} ecs_main_t;

static ecs_main_t ecs_main;

static void
ecs_process_msg (app_evt_msg_t *msg)
{
  app_evt_msg_data_t *dm;
  app_evt_msg_data_session_stats_t *ss;

  if (msg->msg_type != APP_EVT_MSG_DATA)
    {
      fprintf (stderr, "unexpected msg_type %u\n", msg->msg_type);
      return;
    }

  dm = (app_evt_msg_data_t *) msg->data;
  if (dm->data_type != APP_EVT_MSG_DATA_SESSION_STATS)
    {
      fprintf (stderr, "unexpected data_type %u\n", dm->data_type);
      return;
    }

  ss = (app_evt_msg_data_session_stats_t *) dm->data;
  switch (ss->transport_proto_type)
    {
    case TRANSPORT_PROTO_TCP:
      {
	tcp_session_stats_t *ts = (tcp_session_stats_t *) ss->data;
	transport_connection_t *tc = (transport_connection_t *) ts->conn_id;
	printf ("[tcp] bytes_in=%lu bytes_out=%lu segs_in=%lu segs_out=%lu "
		"srtt=%u us is_ip4=%u proto=%u\n",
		(unsigned long) ts->bytes_in, (unsigned long) ts->bytes_out,
		(unsigned long) ts->segs_in, (unsigned long) ts->segs_out, ts->srtt, tc->is_ip4,
		tc->proto);
	fflush (stdout);
      }
      break;
    case TRANSPORT_PROTO_UDP:
      {
	udp_session_stats_t *us = (udp_session_stats_t *) ss->data;
	transport_connection_t *tc = (transport_connection_t *) us->conn_id;
	printf ("[udp] bytes_in=%lu bytes_out=%lu is_ip4=%u proto=%u\n",
		(unsigned long) us->bytes_in, (unsigned long) us->bytes_out, tc->is_ip4, tc->proto);
	fflush (stdout);
      }
      break;
    case TRANSPORT_PROTO_CT:
      {
	ct_session_stats_t *cs = (ct_session_stats_t *) ss->data;
	transport_connection_t *tc = (transport_connection_t *) cs->conn_id;
	if (cs->actual_proto == TRANSPORT_PROTO_UDP)
	  {
	    printf ("[udp] ct session is_ip4=%u proto=%u\n", tc->is_ip4, tc->proto);
	    fflush (stdout);
	  }
	else if (cs->actual_proto == TRANSPORT_PROTO_TCP)
	  {
	    printf ("[tcp] ct session is_ip4=%u proto=%u\n", tc->is_ip4, tc->proto);
	    fflush (stdout);
	  }
      }
      break;
    default:
      break;
    }
}

static void
ecs_consume (ecs_conn_t *c)
{
  uint32_t off = 0;

  while (off + sizeof (app_evt_msg_t) <= c->buf_len)
    {
      app_evt_msg_t *msg = (app_evt_msg_t *) (c->buf + off);
      if (off + msg->msg_len > c->buf_len)
	break;
      ecs_process_msg (msg);
      off += msg->msg_len;
    }

  if (off > 0)
    {
      uint32_t rem = c->buf_len - off;
      if (rem)
	memmove (c->buf, c->buf + off, rem);
      c->buf_len = rem;
    }
}

static ecs_conn_t *
ecs_conn_add (int fd)
{
  ecs_conn_t *c;
  if (ecs_main.nconns >= ECS_MAX_CONNS)
    {
      fprintf (stderr, "Too many connections\n");
      return NULL;
    }
  c = &ecs_main.conns[ecs_main.nconns++];
  c->fd = fd;
  c->buf = malloc (ECS_BUF_CAP);
  c->buf_len = 0;
  return c;
}

static ecs_conn_t *
ecs_conn_find (int fd)
{
  int i;
  for (i = 0; i < ecs_main.nconns; i++)
    if (ecs_main.conns[i].fd == fd)
      return &ecs_main.conns[i];
  return NULL;
}

static void
ecs_conn_del (int fd)
{
  int i;
  for (i = 0; i < ecs_main.nconns; i++)
    {
      if (ecs_main.conns[i].fd == fd)
	{
	  free (ecs_main.conns[i].buf);
	  ecs_main.conns[i] = ecs_main.conns[--ecs_main.nconns];
	  return;
	}
    }
}

int
main (int argc, char **argv)
{
  struct epoll_event events[ECS_MAX_CONNS + 1];
  struct epoll_event ev;
  uint8_t peer_ip[16] = {};
  vppcom_endpt_t peer = { .ip = peer_ip };
  vppcom_endpt_t endpt = {};
  struct in_addr listen_addr;
  uint8_t tmp[4096];
  int lfd, epfd, rv, i;

  if (argc < 3)
    {
      fprintf (stderr, "Usage: %s <listen-addr> <port>\n", argv[0]);
      return 1;
    }

  if (!inet_aton (argv[1], &listen_addr))
    {
      fprintf (stderr, "Invalid address: %s\n", argv[1]);
      return 1;
    }

  rv = vppcom_app_create ("evt-collector-sink");
  if (rv)
    {
      fprintf (stderr, "vppcom_app_create: %d\n", rv);
      return 1;
    }

  lfd = vppcom_session_create (VPPCOM_PROTO_TCP, 1 /* is_nonblocking */);
  if (lfd < 0)
    {
      fprintf (stderr, "vppcom_session_create: %d\n", lfd);
      return 1;
    }

  endpt.is_ip4 = 1;
  endpt.ip = (uint8_t *) &listen_addr;
  endpt.port = htons ((uint16_t) atoi (argv[2]));

  rv = vppcom_session_bind (lfd, &endpt);
  if (rv < 0)
    {
      fprintf (stderr, "vppcom_session_bind: %d\n", rv);
      return 1;
    }

  rv = vppcom_session_listen (lfd, 10);
  if (rv < 0)
    {
      fprintf (stderr, "vppcom_session_listen: %d\n", rv);
      return 1;
    }

  epfd = vppcom_epoll_create ();
  if (epfd < 0)
    {
      fprintf (stderr, "vppcom_epoll_create: %d\n", epfd);
      return 1;
    }

  memset (&ev, 0, sizeof (ev));
  ev.events = EPOLLIN;
  ev.data.u32 = (uint32_t) lfd;
  rv = vppcom_epoll_ctl (epfd, EPOLL_CTL_ADD, lfd, &ev);
  if (rv < 0)
    {
      fprintf (stderr, "vppcom_epoll_ctl lfd: %d\n", rv);
      return 1;
    }

  printf ("evt-collector-sink: listening on %s:%s\n", argv[1], argv[2]);
  fflush (stdout);

  for (;;)
    {
      int nev = vppcom_epoll_wait (epfd, events, ECS_MAX_CONNS + 1, 0.2 /* seconds */);
      if (nev < 0)
	{
	  fprintf (stderr, "vppcom_epoll_wait: %d\n", nev);
	  break;
	}

      for (i = 0; i < nev; i++)
	{
	  uint32_t fd = events[i].data.u32;
	  if (fd == (uint32_t) lfd)
	    {
	      int cfd = vppcom_session_accept (lfd, &peer, 0);
	      if (cfd < 0)
		{
		  fprintf (stderr, "vppcom_session_accept: %d\n", cfd);
		  continue;
		}
	      printf ("evt-collector-sink: accepted connection fd=%d\n", cfd);
	      fflush (stdout);
	      ecs_conn_t *c = ecs_conn_add (cfd);
	      if (!c)
		{
		  vppcom_session_close (cfd);
		  continue;
		}
	      memset (&ev, 0, sizeof (ev));
	      ev.events = EPOLLIN;
	      ev.data.u32 = (uint32_t) cfd;
	      if (vppcom_epoll_ctl (epfd, EPOLL_CTL_ADD, cfd, &ev) < 0)
		fprintf (stderr, "vppcom_epoll_ctl cfd: add failed\n");

	      continue;
	    }

	  ecs_conn_t *c = ecs_conn_find ((int) fd);
	  int n = vppcom_session_read ((int) fd, tmp, sizeof (tmp));
	  if (n <= 0)
	    {
	      if (n != VPPCOM_EAGAIN)
		{
		  vppcom_epoll_ctl (epfd, EPOLL_CTL_DEL, fd, NULL);
		  ecs_conn_del ((int) fd);
		  vppcom_session_close ((int) fd);
		}
	      continue;
	    }
	  if (!c)
	    continue;
	  if (c->buf_len + (uint32_t) n > ECS_BUF_CAP)
	    {
	      fprintf (stderr, "reassembly buffer full, dropping\n");
	      c->buf_len = 0;
	    }
	  else
	    {
	      memcpy (c->buf + c->buf_len, tmp, n);
	      c->buf_len += n;
	      ecs_consume (c);
	    }
	}
    }
}
