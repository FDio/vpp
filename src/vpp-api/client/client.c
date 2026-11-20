/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/hash.h>
#include <vppinfra/mem.h>

#include <vlibapi/api_types.h>
#include <vlibmemory/vl_memory_msg_enum.h>

#define vl_typedefs
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_typedefs

#include "vppapiclient.h"

#define VAC_DEFAULT_SOCKET "/run/vpp/api.sock"

/* Same layout as msgbuf_t, which prefixes every message on the socket */
typedef struct
{
  u64 q;
  u32 data_len;
  u32 gc_mark_timestamp;
} vac_msgbuf_t;

/*
 * Asynchronous mode:
 *  Client registers a callback. All messages are sent to the callback.
 * Synchronous mode:
 *  Client calls blocking vac_read().
 */

typedef struct
{
  int fd;
  int wake_fd;
  u32 client_index;
  uword *msg_index_by_name;
  u16 max_msg_index;
  vac_callback_t callback;
  pthread_t rx_thread;
  pthread_mutex_t lock;
  pthread_cond_t state_cv;
  u8 rx_thread_started;
  u8 suspend_requested;
  u8 suspended;
  u8 terminate;
} vac_main_t;

static vac_main_t vac_main = {
  .fd = -1,
  .wake_fd = -1,
  .lock = PTHREAD_MUTEX_INITIALIZER,
  .state_cv = PTHREAD_COND_INITIALIZER,
};

/* Only ever allocate one heap */
static bool mem_initialized = false;

void
vac_free (void *msg)
{
  free (msg);
}

static int
vac_write_all (int fd, const void *buf, size_t len)
{
  const u8 *p = buf;

  while (len)
    {
      ssize_t n = send (fd, p, len, MSG_NOSIGNAL);

      if (n < 0 && errno == EINTR)
	continue;
      if (n <= 0)
	return -1;
      p += n;
      len -= n;
    }

  return 0;
}

/* Wait for data, timeout in milliseconds, -1 is forever */
static int
vac_wait_readable (int fd, int wake_fd, int timeout_ms)
{
  struct pollfd pfd[2] = {
    {
      .fd = fd,
      .events = POLLIN,
    },
    {
      .fd = wake_fd,
      .events = POLLIN,
    },
  };
  int rv;

  do
    rv = poll (pfd, wake_fd < 0 ? 1 : 2, timeout_ms);
  while (rv < 0 && errno == EINTR);

  if (rv < 0)
    return -1;
  if (rv == 0)
    return VAC_TIMEOUT;
  if (pfd[0].revents)
    return 0;
  return 1;
}

static int
vac_read_all (int fd, void *buf, size_t len)
{
  u8 *p = buf;

  while (len)
    {
      ssize_t n = recv (fd, p, len, 0);

      if (n < 0 && errno == EINTR)
	continue;
      if (n <= 0)
	return -1;
      p += n;
      len -= n;
    }

  return 0;
}

/* Read one message, the caller owns the returned buffer */
static int
vac_read_msg (int fd, char **p, int *l)
{
  vac_msgbuf_t hdr;
  u32 len;
  char *msg;

  if (vac_read_all (fd, &hdr, sizeof (hdr)))
    return VAC_NOT_CONNECTED;

  len = ntohl (hdr.data_len);
  msg = malloc (len ? len : 1);
  if (!msg)
    return -1;

  if (vac_read_all (fd, msg, len))
    {
      free (msg);
      return VAC_NOT_CONNECTED;
    }

  *p = msg;
  *l = len;
  return 0;
}

static int
vac_send_msg (int fd, const char *p, int l)
{
  vac_msgbuf_t hdr = {
    .data_len = htonl (l),
  };

  if (vac_write_all (fd, &hdr, sizeof (hdr)))
    return -1;
  return vac_write_all (fd, p, l);
}

static void *
vac_rx_thread_fn (void *arg)
{
  vac_main_t *pm = &vac_main;

  while (1)
    {
      char *msg;
      int rv, l;

      pthread_mutex_lock (&pm->lock);
      while (pm->suspend_requested && !pm->terminate)
	{
	  uint64_t junk;

	  if (read (pm->wake_fd, &junk, sizeof (junk)) < 0 && errno != EAGAIN)
	    clib_warning ("wake fd read failed");
	  pm->suspended = 1;
	  pthread_cond_broadcast (&pm->state_cv);
	  pthread_cond_wait (&pm->state_cv, &pm->lock);
	}
      pm->suspended = 0;
      if (pm->terminate)
	{
	  pthread_mutex_unlock (&pm->lock);
	  return 0;
	}
      pthread_mutex_unlock (&pm->lock);

      rv = vac_wait_readable (pm->fd, pm->wake_fd, -1);
      if (rv < 0)
	return 0;
      if (rv == 1)
	{
	  uint64_t junk;

	  if (read (pm->wake_fd, &junk, sizeof (junk)) < 0 && errno != EAGAIN)
	    clib_warning ("wake fd read failed");
	  continue;
	}

      if (vac_read_msg (pm->fd, &msg, &l))
	return 0;
      if (l == 0)
	fprintf (stderr, "Unregistered API message of length 0\n");
      else
	pm->callback ((unsigned char *) msg, l);
      free (msg);
    }
}

void
vac_rx_suspend (void)
{
  vac_main_t *pm = &vac_main;
  uint64_t one = 1;

  if (!pm->rx_thread_started)
    return;

  pthread_mutex_lock (&pm->lock);
  if (!pm->suspend_requested)
    {
      pm->suspend_requested = 1;
      if (write (pm->wake_fd, &one, sizeof (one)) < 0)
	clib_warning ("wake fd write failed");
    }
  while (!pm->suspended)
    pthread_cond_wait (&pm->state_cv, &pm->lock);
  pthread_mutex_unlock (&pm->lock);
}

void
vac_rx_resume (void)
{
  vac_main_t *pm = &vac_main;

  if (!pm->rx_thread_started)
    return;

  pthread_mutex_lock (&pm->lock);
  pm->suspend_requested = 0;
  pthread_cond_broadcast (&pm->state_cv);
  pthread_mutex_unlock (&pm->lock);
}

int
vac_msg_table_size (void)
{
  return hash_elts (vac_main.msg_index_by_name);
}

int
vac_msg_table_max_index (void)
{
  return vac_main.max_msg_index;
}

int
vac_get_msg_index (char *name)
{
  uword *p = hash_get_mem (vac_main.msg_index_by_name, name);

  return p ? p[0] : ~0;
}

static void
vac_msg_table_free (vac_main_t *pm)
{
  hash_pair_t *hp;

  hash_foreach_pair (hp, pm->msg_index_by_name, ({ free ((void *) hp->key); }));
  hash_free (pm->msg_index_by_name);
  pm->msg_index_by_name = 0;
  pm->max_msg_index = 0;
}

static int
vac_create_client (vac_main_t *pm, char *name)
{
  vl_api_sockclnt_create_t mp = {
    ._vl_msg_id = htons (VL_API_SOCKCLNT_CREATE),
    .context = htonl (124),
  };
  vl_api_sockclnt_create_reply_t *rmp;
  char *reply;
  int l, rv;
  u16 count;

  strncpy ((char *) mp.name, name, sizeof (mp.name) - 1);
  if (vac_send_msg (pm->fd, (char *) &mp, sizeof (mp)))
    return -1;

  rv = vac_read_msg (pm->fd, &reply, &l);
  if (rv)
    return rv;

  rmp = (void *) reply;
  if (l < sizeof (*rmp) || ntohs (rmp->_vl_msg_id) != VL_API_SOCKCLNT_CREATE_REPLY ||
      ntohl (rmp->response) < 0)
    {
      free (reply);
      return -1;
    }

  count = ntohs (rmp->count);
  if (l < sizeof (*rmp) + count * sizeof (rmp->message_table[0]))
    {
      free (reply);
      return -1;
    }

  pm->client_index = ntohl (rmp->index);
  pm->msg_index_by_name = hash_create_string (0, sizeof (uword));
  for (int i = 0; i < count; i++)
    {
      u16 index = ntohs (rmp->message_table[i].index);
      char *key =
	strndup ((char *) rmp->message_table[i].name, sizeof (rmp->message_table[i].name));

      hash_set_mem (pm->msg_index_by_name, key, index);
      if (index > pm->max_msg_index)
	pm->max_msg_index = index;
    }

  free (reply);
  return 0;
}

int
vac_connect (char *name, char *socket_path, vac_callback_t cb, int rx_qlen)
{
  vac_main_t *pm = &vac_main;
  struct sockaddr_un addr = {
    .sun_family = AF_UNIX,
  };
  int rv;

  assert (clib_mem_get_heap ());

  if (pm->fd >= 0)
    return -1;

  if (!socket_path)
    socket_path = VAC_DEFAULT_SOCKET;
  if (strlen (socket_path) >= sizeof (addr.sun_path))
    return -1;
  strcpy (addr.sun_path, socket_path);

  pm->fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (pm->fd < 0)
    return -1;

  if (connect (pm->fd, (struct sockaddr *) &addr, sizeof (addr)) < 0)
    {
      clib_warning ("connect to %s failed: %s", socket_path, strerror (errno));
      goto error;
    }

  rv = vac_create_client (pm, name);
  if (rv)
    goto error;

  pm->callback = cb;
  pm->suspend_requested = pm->suspended = pm->terminate = 0;
  if (cb)
    {
      pm->wake_fd = eventfd (0, EFD_NONBLOCK);
      if (pm->wake_fd < 0)
	goto error;

      rv = pthread_create (&pm->rx_thread, NULL, vac_rx_thread_fn, 0);
      if (rv)
	{
	  clib_warning ("pthread_create returned %d", rv);
	  goto error;
	}
      pm->rx_thread_started = 1;
    }

  return 0;

error:
  if (pm->wake_fd >= 0)
    close (pm->wake_fd);
  pm->wake_fd = -1;
  close (pm->fd);
  pm->fd = -1;
  vac_msg_table_free (pm);
  return -1;
}

int
vac_disconnect (void)
{
  vac_main_t *pm = &vac_main;
  vl_api_sockclnt_delete_t mp = {
    ._vl_msg_id = htons (VL_API_SOCKCLNT_DELETE),
    .client_index = htonl (pm->client_index),
    .index = htonl (pm->client_index),
  };

  if (pm->fd < 0)
    return 0;

  /* Best effort, vpp also cleans up when the socket goes away */
  vac_send_msg (pm->fd, (char *) &mp, sizeof (mp));

  if (pm->rx_thread_started)
    {
      uint64_t one = 1;

      pthread_mutex_lock (&pm->lock);
      pm->terminate = 1;
      pthread_cond_broadcast (&pm->state_cv);
      pthread_mutex_unlock (&pm->lock);
      if (write (pm->wake_fd, &one, sizeof (one)) < 0)
	clib_warning ("wake fd write failed");
      shutdown (pm->fd, SHUT_RDWR);
      pthread_join (pm->rx_thread, 0);
      pm->rx_thread_started = 0;
    }

  close (pm->fd);
  pm->fd = -1;
  if (pm->wake_fd >= 0)
    close (pm->wake_fd);
  pm->wake_fd = -1;
  vac_msg_table_free (pm);

  return 0;
}

int
vac_read (char **p, int *l, u16 timeout)
{
  vac_main_t *pm = &vac_main;
  int rv;

  *l = 0;

  if (pm->fd < 0)
    return VAC_NOT_CONNECTED;

  while (1)
    {
      rv = vac_wait_readable (pm->fd, -1, timeout ? timeout * 1000 : -1);
      if (rv)
	{
	  vac_rx_resume ();
	  return rv < 0 ? VAC_NOT_CONNECTED : rv;
	}

      rv = vac_read_msg (pm->fd, p, l);
      if (rv)
	return rv;
      if (*l)
	return 0;

      fprintf (stderr, "Unregistered API message of length 0\n");
      free (*p);
    }
}

/*
 * XXX: Makes the assumption that client_index is the first member
 */
typedef struct _vl_api_header
{
  u16 _vl_msg_id;
  u32 client_index;
} __attribute__ ((packed)) vl_api_header_t;

int
vac_write (char *p, int l)
{
  vac_main_t *pm = &vac_main;
  vl_api_header_t *mp;
  char *copy;
  int rv;

  if (pm->fd < 0)
    return VAC_NOT_CONNECTED;

  copy = malloc (l);
  if (!copy)
    return -1;

  memcpy (copy, p, l);
  mp = (void *) copy;
  mp->client_index = htonl (pm->client_index);

  rv = vac_send_msg (pm->fd, copy, l);
  free (copy);
  if (rv)
    fprintf (stderr, "vpe_api_write fails: %d\n", rv);

  return rv;
}

void
vac_set_error_handler (vac_error_callback_t cb)
{
  assert (clib_mem_get_heap ());
  if (cb)
    clib_error_register_handler (cb, 0);
}

/*
 * Required if application doesn't use a VPP heap.
 */
void
vac_mem_init (size_t size)
{
  if (mem_initialized)
    return;
  if (size == 0)
    clib_mem_init (0, 1 << 30); /* default */
  else
    clib_mem_init (0, size);
  mem_initialized = true;
}
