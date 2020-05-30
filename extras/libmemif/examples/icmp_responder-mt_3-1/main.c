/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>

#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <libmemif.h>
#include <icmp_proto.h>


#define APP_NAME "ICMP_Responder_mt_v3.1"
#define IF_NAME  "memif_connection"

#ifdef ICMP_DBG
#define DBG(...) do {                                               \
                    printf (APP_NAME":%s:%d: ", __func__, __LINE__);         \
                    printf (__VA_ARGS__);                           \
                    printf ("\n");                                  \
                } while (0)
#else
#define DBG(...)
#endif

#define ICMPR_BUFFER_LENGTH		32
#define ICMPR_SOCKET_FILENAME_LEN	256
#define ICMPR_MEMIF_BUFFER_NUM		256

static struct option options[] = {
  {"threads", required_argument, 0, 't'},
  {"if_num", required_argument, 0, 'i'}
};

struct memif_connection
{
  uint16_t id;			/* unique interface id */
  bool connected;		/* is connected */
  struct per_thread_data *ptd;	/* per thread data */
  memif_conn_handle_t handle;	/* memif connection handle */
  uint8_t ip_addr[4];		/* ip4 address */
};

struct per_thread_data
{
  bool running;			/* is thread main loop running */
  uint8_t index;		/* thread index */
  int epfd;			/* epoll file descriptor */
  int pcfd;			/* poll cancel file descriptor */
  uint16_t if_num;		/* number of interfaces on this thread */
  struct memif_connection *conns;	/* memif connections pool */
  memif_per_thread_main_handle_t pt_main;	/* memif per thread main handle */
  memif_socket_handle_t socket_handle;		/* memif socket handle */
};

struct icmpr_main
{
  uint8_t threads;		/* number of threads */
  uint16_t per_thread_if_num;	/* number of interfaces per thread */
  struct per_thread_data *ptd;	/* per thread data pool */
  pthread_t *pthread;		/* thread pool */
};

struct icmpr_main icmpr_main;

int
add_epoll_fd (int epfd, int fd, uint32_t events)
{
  if (fd < 0)
    {
      DBG ("invalid fd %d", fd);
      return -1;
    }
  struct epoll_event evt;
  memset (&evt, 0, sizeof (evt));
  evt.events = events;
  evt.data.fd = fd;
  if (epoll_ctl (epfd, EPOLL_CTL_ADD, fd, &evt) < 0)
    {
      DBG ("epoll_ctl: %s fd %d", strerror (errno), fd);
      return -1;
    }
  DBG ("fd %d added to epoll", fd);
  return 0;
}

int
mod_epoll_fd (int epfd, int fd, uint32_t events)
{
  if (fd < 0)
    {
      DBG ("invalid fd %d", fd);
      return -1;
    }
  struct epoll_event evt;
  memset (&evt, 0, sizeof (evt));
  evt.events = events;
  evt.data.fd = fd;
  if (epoll_ctl (epfd, EPOLL_CTL_MOD, fd, &evt) < 0)
    {
      DBG ("epoll_ctl: %s fd %d", strerror (errno), fd);
      return -1;
    }
  DBG ("fd %d modified on epoll", fd);
  return 0;
}

int
del_epoll_fd (int epfd, int fd)
{
  if (fd < 0)
    {
      DBG ("invalid fd %d", fd);
      return -1;
    }
  struct epoll_event evt;
  memset (&evt, 0, sizeof (evt));
  if (epoll_ctl (epfd, EPOLL_CTL_DEL, fd, &evt) < 0)
    {
      DBG ("epoll_ctl: %s fd %d", strerror (errno), fd);
      return -1;
    }
  DBG ("fd %d removed from epoll", fd);
  return 0;
}

/* Called when libmemif requests an update on any of its file descriptors */
static int
control_fd_update (int fd, uint8_t events, void *private_ctx)
{
  struct per_thread_data *ptd = (struct per_thread_data *) private_ctx;
  uint32_t evt = 0;

  if (ptd == NULL)
    return -1;

  /* convert memif event definitions to epoll events */
  if (events & MEMIF_FD_EVENT_DEL)
    return del_epoll_fd (ptd->epfd, fd);

  if (events & MEMIF_FD_EVENT_READ)
    evt |= EPOLLIN;
  if (events & MEMIF_FD_EVENT_WRITE)
    evt |= EPOLLOUT;

  if (events & MEMIF_FD_EVENT_MOD)
    return mod_epoll_fd (ptd->epfd, fd, evt);

  return add_epoll_fd (ptd->epfd, fd, evt);
}

static int
on_connect (memif_conn_handle_t conn, void *private_ctx)
{
  struct per_thread_data *ptd = (struct per_thread_data *) private_ctx;
  struct memif_connection *c;
  int i = 0;

  while (i < ptd->if_num && ptd->conns[i].handle != conn)
    i++;
  c = &ptd->conns[i];

  c->connected = true;
  DBG ("Connected: %u", c->id);

  memif_refill_queue (conn, 0, -1, 0);

  return 0;
}

static int
on_disconnect (memif_conn_handle_t conn, void *private_ctx)
{
  struct per_thread_data *ptd = (struct per_thread_data *) private_ctx;
  struct memif_connection *c;
  int i = 0;

  while (i < ptd->if_num && ptd->conns[i].handle != conn)
    i++;
  c = &ptd->conns[i];

  c->connected = false;
  DBG ("Disconnected: %u", c->id);

  return 0;
}

static int
on_interrupt (memif_conn_handle_t conn, void *private_ctx, uint16_t qid)
{
  struct per_thread_data *ptd = (struct per_thread_data *) private_ctx;
  struct memif_connection *c;
  memif_buffer_t mbufs[ICMPR_MEMIF_BUFFER_NUM];
  uint16_t rx = 0;
  uint16_t tx = 0;
  uint16_t ret;
  memif_err_t err;
  int i = 0;

  memset (mbufs, 0, sizeof (memif_buffer_t) * ICMPR_MEMIF_BUFFER_NUM);

  while (i < ptd->if_num && ptd->conns[i].handle != conn)
    i++;
  c = &ptd->conns[i];

  /* receive data from shared memory buffers */
  err = memif_rx_burst (conn, qid, mbufs, ICMPR_MEMIF_BUFFER_NUM, &rx);
  if (err != MEMIF_ERR_SUCCESS)
  {
    printf ("memif_rx_burst: %s\n", memif_strerror (err));
    goto error;
  }

  /* resolve packet in place (zer-copy slave) */
  for (i = 0; i < rx; i++)
    resolve_packet2 (mbufs[i].data, &mbufs[i].len, c->ip_addr);

  /* enqueue received buffers */
  err = memif_buffer_enq_tx (conn, qid, mbufs, i, &tx);
  if (err != MEMIF_ERR_SUCCESS)
  {
    printf ("memif_rx_burst: %s\n", memif_strerror (err));
    goto error;
  }

  /* mark shared memory buffers as free */
  err = memif_refill_queue (conn, qid, rx, 0);
  if (err != MEMIF_ERR_SUCCESS)
  {
    printf ("memif_rx_burst: %s\n", memif_strerror (err));
    goto error;
  }

  err = memif_tx_burst (conn, qid, mbufs, tx, &ret);
  if (err != MEMIF_ERR_SUCCESS)
  {
    printf ("memif_rx_burst: %s\n", memif_strerror (err));
    goto error;
  }

  return 0;

error:
  memif_refill_queue (conn, qid, -1, 0);
  return -1;
}

int
poll_event (memif_per_thread_main_handle_t pt_main, int pcfd, int epfd,
	    int timeout)
{
  struct epoll_event evt;
  int en = 0;
  uint8_t events = 0;
  memset (&evt, 0, sizeof (evt));
  evt.events = EPOLLIN | EPOLLOUT;

  en = epoll_pwait (epfd, &evt, 1, timeout, NULL);
  if (en < 0)
    {
      printf ("epoll_pwait: %s\n", strerror (errno));
      return -1;
    }

  if (en > 0)
    {
      /* Cancel event polling */
      if (evt.data.fd == pcfd)
	return 1;

      if (evt.events & EPOLLIN)
	events |= MEMIF_FD_EVENT_READ;
      if (evt.events & EPOLLOUT)
	events |= MEMIF_FD_EVENT_WRITE;
      if (evt.events & EPOLLERR)
	events |= MEMIF_FD_EVENT_ERROR;

      /* No need to use locks, as the database is separated */
      memif_per_thread_control_fd_handler (pt_main, evt.data.fd, events);
    }

  return 0;
}

static void *
icmpr_thread_fn (void *data)
{
  struct per_thread_data *ptd = (struct per_thread_data *) data;
  int rv;
  uint16_t i;
  char socket_filename[ICMPR_SOCKET_FILENAME_LEN] = "/run/vpp/memif";
  memif_conn_args_t args;

  ptd->epfd = epoll_create (1);

  ptd->conns = malloc (sizeof (struct memif_connection) * ptd->if_num);
  if (ptd->conns == NULL)
    {
      printf ("%s\n", strerror (errno));
      return NULL;
    }

  memset (ptd->conns, 0, sizeof (struct memif_connection) * ptd->if_num);

  /* Initialize memif database (per thread). */
  rv =
    memif_per_thread_init (&ptd->pt_main, ptd, control_fd_update, APP_NAME,
			   NULL, NULL, NULL);
  if (rv != MEMIF_ERR_SUCCESS)
    {
      printf ("memif_per_thread_init: %s\n", memif_strerror (rv));
      return NULL;
    }

  /*  Create unique socket. Each thread requires a unique socket. Interfaces created
   *  on the same thread can share one socket.
   */
  socket_filename[strlen (socket_filename)] = '0' + ptd->index;
  strncpy (socket_filename + strlen (socket_filename), ".sock", 5);
  DBG ("socket_filename: %s", socket_filename);

  rv = memif_per_thread_create_socket (ptd->pt_main, &ptd->socket_handle,
				       socket_filename, ptd);
  if (rv != MEMIF_ERR_SUCCESS)
    {
      printf ("memif_per_thread_create_socket: %s\n", memif_strerror (rv));
      return NULL;
    }

  /* Create interfaces on this thread */
  for (i = 0; i < ptd->if_num; i++)
    {
      ptd->conns[i].ip_addr[0] = 192;
      ptd->conns[i].ip_addr[1] = 168;
      ptd->conns[i].ip_addr[2] = ptd->index + 1;
      ptd->conns[i].ip_addr[3] = i * 2 + 2;

      memset (&args, 0, sizeof (args));

      args.socket = ptd->socket_handle;
      ptd->conns[i].id = i;
      args.interface_id = i;

      rv = memif_create (&ptd->conns[i].handle, &args, on_connect,
			 on_disconnect, on_interrupt, ptd);
      if (rv < 0)
	{
	  printf ("%s\n", memif_strerror (rv));
	  return NULL;
	}
    }

  /* Poll cancel file descriptor. When an event is received on this fd, exit thread
   * loop in respective thread.
   */
  ptd->pcfd = eventfd (0, EFD_NONBLOCK);
  if (ptd->pcfd < 0)
    {
      printf ("eventfd: %s\n", strerror (errno));
      return NULL;
    }
  if (add_epoll_fd (ptd->epfd, ptd->pcfd, EPOLLIN) < 0)
    {
      printf ("Failed to add poll cancel fd to epfd.");
      return NULL;
    }

  /* Thread loop */
  ptd->running = true;
  while (ptd->running)
    {
      rv = poll_event (ptd->pt_main, ptd->pcfd, ptd->epfd, -1);
      if (rv != 0)
	ptd->running = false;
    }

  /* Clean up */
  for (i = 0; i < ptd->if_num; i++)
    memif_delete (&ptd->conns[i].handle);

  memif_delete_socket (&ptd->socket_handle);

  memif_per_thread_cleanup (&ptd->pt_main);

  free (ptd->conns);
  close (ptd->pcfd);

  return NULL;
}

static void
icmpr_print_help ()
{
  printf
    ("exit - Exits the application.\nhelp - Print this help.\nshow - Show memif interfaces\n");
}

static void
icmpr_show_memifs ()
{
  struct icmpr_main *im = &icmpr_main;
  int i, j;
  memif_socket_handle_t sh;

  printf ("%u Threads %u Memifs (per thread)\n", im->threads,
	  im->per_thread_if_num);
  printf ("=================================\n");

  for (i = 0; i < im->threads; i++)
    {
      sh = im->ptd[i].socket_handle;
      printf ("Thread %u %s\n", i, memif_get_socket_filename (sh));
      for (j = 0; j < im->per_thread_if_num; j++)
	{
	  printf ("\tMemif id %u\n\t%s\n", im->ptd[i].conns[j].id,
		  im->ptd[i].conns[j].connected ? "Link up" : "Link down");
	}
    }
}

int
main (int argc, char **argv)
{
  struct icmpr_main *im = &icmpr_main;
  int rv, i;
  int option_index = 0;
  bool running;
  char buffer[ICMPR_BUFFER_LENGTH];
  uint64_t b = 1;

  memset (im, 0, sizeof (struct icmpr_main));

  /* Default args */
  im->threads = 4;
  im->per_thread_if_num = 1;

  /* Parse args */
  while ((rv =
	  getopt_long (argc, argv, "t:i:", options, &option_index)) != (-1))
    {
      switch (rv)
	{
	case 't':
	  im->threads = strtoul (optarg, NULL, 10);
	  break;
	case 'i':
	  im->per_thread_if_num = strtoul (optarg, NULL, 10);
	  break;
	default:
	  break;
	}
    }

  /* Check args */
  if (im->threads < 1)
    {
      printf ("threads < 1\n");
      exit (EXIT_FAILURE);
    }

  if (im->per_thread_if_num < 1)
    {
      printf ("if_num < 1\n");
      exit (EXIT_FAILURE);
    }

  /* Allocate memory */
  im->ptd = malloc (sizeof (struct per_thread_data) * im->threads);
  if (im->ptd == NULL)
    {
      printf ("%s\n", strerror (errno));
      return -1;
    }
  im->pthread = malloc (sizeof (pthread_t) * im->threads);
  if (im->pthread == NULL)
    {
      printf ("%s\n", strerror (errno));
      return -1;
    }

  /* Initialize and create threads */
  for (i = 0; i < im->threads; i++)
    {
      im->ptd[i].index = i;
      im->ptd[i].if_num = im->per_thread_if_num;
      pthread_create (&im->pthread[i], NULL, icmpr_thread_fn, &im->ptd[i]);
    }

  icmpr_print_help ();

  /* Main loop */
  running = true;
  while (running)
    {
      printf ("cmd: ");
      memset (buffer, 0, ICMPR_BUFFER_LENGTH);
      if (fgets (buffer, ICMPR_BUFFER_LENGTH, stdin) != buffer)
	{
	  printf ("%s\n", strerror (errno));
	  running = false;
	}

      if (strncmp (buffer, "exit", 4) == 0)
	running = false;
      else if (strncmp (buffer, "help", 4) == 0)
	icmpr_print_help ();
      else if (strncmp (buffer, "show", 4) == 0)
	icmpr_show_memifs ();
    }

  for (i = 0; i < im->threads; i++)
    {
      /* Stop polling */
      rv = write (im->ptd[i].pcfd, &b, sizeof (b));
      if (rv < 0)
	{
	  printf ("Failed to cancel polling. %s\n", strerror (errno));
	  exit (EXIT_FAILURE);
	}
      pthread_join (im->pthread[i], NULL);
    }

  free (im->pthread);
  free (im->ptd);

  return 0;
}
