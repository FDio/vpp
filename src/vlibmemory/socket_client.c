/*
 *------------------------------------------------------------------
 * socket_client.c - API message handling over sockets, client code.
 *
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

#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/fifo.h>
#include <vppinfra/time.h>
#include <vppinfra/mheap.h>
#include <vppinfra/heap.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibmemory/api.h>

#include <vlibmemory/vl_memory_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) clib_warning (__VA_ARGS__)
#define vl_printfun
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_printfun

socket_client_main_t socket_client_main;

/* Debug aid */
u32 vl (void *p) __attribute__ ((weak));
u32
vl (void *p)
{
  return vec_len (p);
}

void
vl_socket_client_read_reply (socket_client_main_t * scm)
{
  int n, current_rx_index;
  msgbuf_t *mbp;

  if (scm->socket_fd == 0 || scm->socket_enable == 0)
    return;

  mbp = 0;

  while (1)
    {
      current_rx_index = vec_len (scm->socket_rx_buffer);
      while (vec_len (scm->socket_rx_buffer) <
	     sizeof (*mbp) + 2 /* msg id */ )
	{
	  vec_validate (scm->socket_rx_buffer, current_rx_index
			+ scm->socket_buffer_size - 1);
	  _vec_len (scm->socket_rx_buffer) = current_rx_index;
	  n = read (scm->socket_fd, scm->socket_rx_buffer + current_rx_index,
		    scm->socket_buffer_size);
	  if (n < 0)
	    {
	      clib_unix_warning ("socket_read");
	      return;
	    }
	  _vec_len (scm->socket_rx_buffer) += n;
	}

#if CLIB_DEBUG > 1
      if (n > 0)
	clib_warning ("read %d bytes", n);
#endif

      if (mbp == 0)
	mbp = (msgbuf_t *) (scm->socket_rx_buffer);

      if (vec_len (scm->socket_rx_buffer) >= ntohl (mbp->data_len)
	  + sizeof (*mbp))
	{
	  vl_msg_api_socket_handler ((void *) (mbp->data));

	  if (vec_len (scm->socket_rx_buffer) == ntohl (mbp->data_len)
	      + sizeof (*mbp))
	    _vec_len (scm->socket_rx_buffer) = 0;
	  else
	    vec_delete (scm->socket_rx_buffer, ntohl (mbp->data_len)
			+ sizeof (*mbp), 0);
	  mbp = 0;

	  /* Quit if we're out of data, and not expecting a ping reply */
	  if (vec_len (scm->socket_rx_buffer) == 0
	      && scm->control_pings_outstanding == 0)
	    break;
	}
    }
}

int
vl_socket_client_connect (socket_client_main_t * scm, char *socket_path,
			  char *client_name, u32 socket_buffer_size)
{
  char buffer[256];
  char *rdptr;
  int n, total_bytes;
  vl_api_sockclnt_create_reply_t *rp;
  vl_api_sockclnt_create_t *mp;
  clib_socket_t *sock = &scm->client_socket;
  msgbuf_t *mbp;
  clib_error_t *error;

  /* Already connected? */
  if (scm->socket_fd)
    return (-2);

  /* bogus call? */
  if (socket_path == 0 || client_name == 0)
    return (-3);

  sock->config = socket_path;
  sock->flags = CLIB_SOCKET_F_IS_CLIENT | CLIB_SOCKET_F_SEQPACKET;

  error = clib_socket_init (sock);

  if (error)
    {
      clib_error_report (error);
      return (-1);
    }

  scm->socket_fd = sock->fd;

  mbp = (msgbuf_t *) buffer;
  mbp->q = 0;
  mbp->data_len = htonl (sizeof (*mp));
  mbp->gc_mark_timestamp = 0;

  mp = (vl_api_sockclnt_create_t *) mbp->data;
  mp->_vl_msg_id = htons (VL_API_SOCKCLNT_CREATE);
  strncpy ((char *) mp->name, client_name, sizeof (mp->name) - 1);
  mp->name[sizeof (mp->name) - 1] = 0;
  mp->context = 0xfeedface;

  n = write (scm->socket_fd, mbp, sizeof (*mbp) + sizeof (*mp));
  if (n < 0)
    {
      clib_unix_warning ("socket write (msg)");
      return (-1);
    }

  memset (buffer, 0, sizeof (buffer));

  total_bytes = 0;
  rdptr = buffer;
  do
    {
      n = read (scm->socket_fd, rdptr, sizeof (buffer) - (rdptr - buffer));
      if (n < 0)
	{
	  clib_unix_warning ("socket read");
	}
      total_bytes += n;
      rdptr += n;
    }
  while (total_bytes < sizeof (vl_api_sockclnt_create_reply_t)
	 + sizeof (msgbuf_t));

  rp = (vl_api_sockclnt_create_reply_t *) (buffer + sizeof (msgbuf_t));
  if (ntohs (rp->_vl_msg_id) != VL_API_SOCKCLNT_CREATE_REPLY)
    {
      clib_warning ("connect reply got msg id %d\n", ntohs (rp->_vl_msg_id));
      return (-1);
    }

  /* allocate tx, rx buffers */
  scm->socket_buffer_size = socket_buffer_size ? socket_buffer_size :
    SOCKET_CLIENT_DEFAULT_BUFFER_SIZE;
  vec_validate (scm->socket_tx_buffer, scm->socket_buffer_size - 1);
  vec_validate (scm->socket_rx_buffer, scm->socket_buffer_size - 1);
  _vec_len (scm->socket_rx_buffer) = 0;
  scm->socket_enable = 1;

  return (0);
}

void
vl_socket_client_disconnect (socket_client_main_t * scm)
{
  if (scm->socket_fd && (close (scm->socket_fd) < 0))
    clib_unix_warning ("close");
  scm->socket_fd = 0;
}

void
vl_socket_client_enable_disable (socket_client_main_t * scm, int enable)
{
  scm->socket_enable = enable;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
