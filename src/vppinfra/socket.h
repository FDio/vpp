/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
 */
/*
  Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef _clib_included_socket_h
#define _clib_included_socket_h

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <vppinfra/clib.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>

typedef struct _socket_t
{
  /* File descriptor. */
  i32 fd;

  /* Config string for socket HOST:PORT or just HOST. */
  char *config;

  u32 flags;
#define CLIB_SOCKET_F_IS_SERVER (1 << 0)
#define CLIB_SOCKET_F_IS_CLIENT (0 << 0)
#define CLIB_SOCKET_F_NON_BLOCKING_CONNECT (1 << 1)
#define CLIB_SOCKET_F_ALLOW_GROUP_WRITE (1 << 2)
#define CLIB_SOCKET_F_SEQPACKET (1 << 3)
#define CLIB_SOCKET_F_PASSCRED  (1 << 4)

  /* Read returned end-of-file. */
#define SOCKET_RX_END_OF_FILE (1 << 2)

  /* Transmit buffer.  Holds data waiting to be written. */
  u8 *tx_buffer;

  /* Receive buffer.  Holds data read from socket. */
  u8 *rx_buffer;

  /* Peer socket we are connected to. */
  struct sockaddr_in peer;

  /* Credentials, populated if CLIB_SOCKET_F_PASSCRED is set */
  pid_t pid;
  uid_t uid;
  gid_t gid;

  clib_error_t *(*write_func) (struct _socket_t * sock);
  clib_error_t *(*read_func) (struct _socket_t * sock, int min_bytes);
  clib_error_t *(*close_func) (struct _socket_t * sock);
  clib_error_t *(*recvmsg_func) (struct _socket_t * s, void *msg, int msglen,
				 int fds[], int num_fds);
  clib_error_t *(*sendmsg_func) (struct _socket_t * s, void *msg, int msglen,
				 int fds[], int num_fds);
  void *private_data;
} clib_socket_t;

/* socket config format is host:port.
   Unspecified port causes a free one to be chosen starting
   from IPPORT_USERRESERVED (5000). */
clib_error_t *clib_socket_init (clib_socket_t * socket);

clib_error_t *clib_socket_accept (clib_socket_t * server,
				  clib_socket_t * client);

always_inline uword
clib_socket_is_server (clib_socket_t * sock)
{
  return (sock->flags & CLIB_SOCKET_F_IS_SERVER) != 0;
}

always_inline uword
clib_socket_is_client (clib_socket_t * s)
{
  return !clib_socket_is_server (s);
}

always_inline int
clib_socket_rx_end_of_file (clib_socket_t * s)
{
  return s->flags & SOCKET_RX_END_OF_FILE;
}

always_inline void *
clib_socket_tx_add (clib_socket_t * s, int n_bytes)
{
  u8 *result;
  vec_add2 (s->tx_buffer, result, n_bytes);
  return result;
}

always_inline void
clib_socket_tx_add_va_formatted (clib_socket_t * s, char *fmt, va_list * va)
{
  s->tx_buffer = va_format (s->tx_buffer, fmt, va);
}

always_inline clib_error_t *
clib_socket_tx (clib_socket_t * s)
{
  return s->write_func (s);
}

always_inline clib_error_t *
clib_socket_rx (clib_socket_t * s, int n_bytes)
{
  return s->read_func (s, n_bytes);
}

always_inline clib_error_t *
clib_socket_sendmsg (clib_socket_t * s, void *msg, int msglen,
		     int fds[], int num_fds)
{
  return s->sendmsg_func (s, msg, msglen, fds, num_fds);
}

always_inline clib_error_t *
clib_socket_recvmsg (clib_socket_t * s, void *msg, int msglen,
		     int fds[], int num_fds)
{
  return s->recvmsg_func (s, msg, msglen, fds, num_fds);
}

always_inline void
clib_socket_free (clib_socket_t * s)
{
  vec_free (s->tx_buffer);
  vec_free (s->rx_buffer);
  if (clib_mem_is_heap_object (s->config))
    vec_free (s->config);
  memset (s, 0, sizeof (s[0]));
}

always_inline clib_error_t *
clib_socket_close (clib_socket_t * sock)
{
  clib_error_t *err;
  err = (*sock->close_func) (sock);
  return err;
}

void clib_socket_tx_add_formatted (clib_socket_t * s, char *fmt, ...);

#endif /* _clib_included_socket_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
