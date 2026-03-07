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
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
  uint64_t tcp_sessions;
  uint64_t udp_sessions;
  uint64_t other_sessions;
  uint64_t tcp_bytes_in;
  uint64_t tcp_bytes_out;
} ecs_stats_t;

typedef struct
{
  ecs_conn_t conns[ECS_MAX_CONNS];
  int nconns;
  volatile int quit;
  ecs_stats_t stats;
} ecs_main_t;

static ecs_main_t ecs_main;

static void
sig_handler (int sig)
{
  (void) sig;
  ecs_main.quit = 1;
}

static void
ecs_process_msg (app_evt_msg_t *msg)
{
  app_evt_msg_data_t *dm;
  app_evt_msg_data_session_stats_t *ss;

  if (msg->msg_type != APP_EVT_MSG_DATA)
    return;

  dm = (app_evt_msg_data_t *) msg->data;
  if (dm->data_type != APP_EVT_MSG_DATA_SESSION_STATS)
    return;

  ss = (app_evt_msg_data_session_stats_t *) dm->data;
  switch (ss->transport_proto_type)
    {
    case TRANSPORT_PROTO_TCP:
      {
	tcp_session_stats_t *ts = (tcp_session_stats_t *) ss->data;
	ecs_main.stats.tcp_sessions++;
	ecs_main.stats.tcp_bytes_in += ts->bytes_in;
	ecs_main.stats.tcp_bytes_out += ts->bytes_out;
	printf ("[tcp] bytes_in=%lu bytes_out=%lu segs_in=%lu segs_out=%lu "
		"srtt=%u us\n",
		(unsigned long) ts->bytes_in, (unsigned long) ts->bytes_out,
		(unsigned long) ts->segs_in, (unsigned long) ts->segs_out, ts->srtt);
	fflush (stdout);
      }
      break;
    case TRANSPORT_PROTO_UDP:
      ecs_main.stats.udp_sessions++;
      printf ("[udp] session closed\n");
      fflush (stdout);
      break;
    default:
      ecs_main.stats.other_sessions++;
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
  uint8_t peer_ip[16] = {};
  vppcom_endpt_t peer = { .ip = peer_ip };
  vppcom_endpt_t endpt = {};
  struct in_addr listen_addr;
  int lfd, cfd, rv;
  uint8_t tmp[4096];

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

  signal (SIGINT, sig_handler);
  signal (SIGTERM, sig_handler);

  rv = vppcom_app_create ("evt-collector-sink");
  if (rv)
    {
      fprintf (stderr, "vppcom_app_create: %d\n", rv);
      return 1;
    }

  /* Non-blocking listen session so accept() polls without blocking */
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

  printf ("evt-collector-sink: listening on %s:%s\n", argv[1], argv[2]);
  fflush (stdout);

  while (!ecs_main.quit)
    {
      /* Poll for a new connection */
      cfd = vppcom_session_accept (lfd, &peer, 0 /* blocking accepted session */);
      if (cfd == VPPCOM_EAGAIN)
	{
	  usleep (10 * 1000); /* 10 ms */
	  continue;
	}
      if (cfd < 0)
	{
	  fprintf (stderr, "vppcom_session_accept: %d\n", cfd);
	  break;
	}

      printf ("evt-collector-sink: accepted connection fd=%d\n", cfd);
      fflush (stdout);

      ecs_conn_t *c = ecs_conn_add (cfd);
      if (!c)
	{
	  vppcom_session_close (cfd);
	  continue;
	}

      /* Read until peer disconnects */
      while (!ecs_main.quit)
	{
	  int n = vppcom_session_read (cfd, tmp, sizeof (tmp));
	  if (n == VPPCOM_EAGAIN || n == 0)
	    {
	      usleep (1000); /* 1 ms */
	      continue;
	    }
	  if (n < 0)
	    break;

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

      ecs_conn_del (cfd);
      vppcom_session_close (cfd);
    }

  printf ("\n--- evt-collector-sink summary ---\n");
  printf ("TCP  sessions : %lu  (bytes_in=%lu  bytes_out=%lu)\n",
	  (unsigned long) ecs_main.stats.tcp_sessions, (unsigned long) ecs_main.stats.tcp_bytes_in,
	  (unsigned long) ecs_main.stats.tcp_bytes_out);
  printf ("UDP  sessions : %lu\n", (unsigned long) ecs_main.stats.udp_sessions);
  printf ("Other sessions: %lu\n", (unsigned long) ecs_main.stats.other_sessions);

  vppcom_session_close (lfd);
  vppcom_app_destroy ();

  return 0;
}
