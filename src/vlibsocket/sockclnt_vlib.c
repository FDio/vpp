/*
 *------------------------------------------------------------------
 * sockclnt_vlib.c
 *
 * Copyright (c) 2009 Cisco and/or its affiliates.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <vppinfra/byte_order.h>
#include <netdb.h>

#include <fcntl.h>
#include <sys/stat.h>

#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

#include <vlibmemory/vl_memory_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_typedefs

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_printfun

/* instantiate all the endian swap functions we know about */
#define vl_endianfun
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_endianfun

static void
vl_api_sockclnt_create_reply_t_handler (vl_api_sockclnt_create_reply_t * mp)
{
  vl_api_registration_t *rp = socket_main.current_rp;

  rp->server_handle = mp->handle;
  rp->server_index = mp->index;
}

static void
vl_api_sockclnt_delete_reply_t_handler (vl_api_sockclnt_delete_reply_t * mp)
{
  unix_main_t *um = &unix_main;
  unix_file_t *uf = socket_main.current_uf;
  vl_api_registration_t *rp = socket_main.current_rp;

  unix_file_del (um, uf);
  vl_free_socket_registration_index (rp->vl_api_registration_pool_index);
}

u32
sockclnt_open_index (char *client_name, char *hostname, int port)
{
  vl_api_registration_t *rp;
  unix_main_t *um = &unix_main;
  unix_file_t template = { 0 };
  int sockfd;
  int one = 1;
  int rv;
  struct sockaddr_in serv_addr;
  struct hostent *server;
  vl_api_sockclnt_create_t *mp;
  char my_hostname[64];

  server = gethostbyname (hostname);
  if (server == NULL)
    {
      clib_warning ("Couldn't translate server name %s", hostname);
      return ~0;
    }

  /* Set up non-blocking server socket on CLIENT_API_SERVER_PORT */
  sockfd = socket (AF_INET, SOCK_STREAM, 0);

  if (sockfd < 0)
    {
      clib_unix_warning ("socket");
      return ~0;
    }

  bzero ((char *) &serv_addr, sizeof (serv_addr));
  serv_addr.sin_family = AF_INET;
  bcopy ((char *) server->h_addr,
	 (char *) &serv_addr.sin_addr.s_addr, server->h_length);
  serv_addr.sin_port = htons (port);

  if (connect (sockfd, (const void *) &serv_addr, sizeof (serv_addr)) < 0)
    {
      clib_unix_warning ("Connect failure to (%s, %d)", hostname, port);
      close (sockfd);
      return ~0;
    }

  rv = ioctl (sockfd, FIONBIO, &one);
  if (rv < 0)
    {
      clib_unix_warning ("FIONBIO");
      close (sockfd);
      return ~0;
    }

  pool_get (socket_main.registration_pool, rp);
  memset (rp, 0, sizeof (*rp));
  rp->registration_type = REGISTRATION_TYPE_SOCKET_CLIENT;
  rp->vl_api_registration_pool_index = rp - socket_main.registration_pool;

  template.read_function = vl_socket_read_ready;
  template.write_function = vl_socket_write_ready;
  template.file_descriptor = sockfd;
  template.private_data = rp - socket_main.registration_pool;

  rp->unix_file_index = unix_file_add (um, &template);
  rp->name = format (0, "%s:%d", hostname, port);

  mp = vl_msg_api_alloc (sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SOCKCLNT_CREATE);
  mp->context = rp - socket_main.registration_pool;

  if (gethostname (my_hostname, sizeof (my_hostname)) < 0)
    {
      clib_unix_warning ("gethostname");
      strncpy (my_hostname, "unknown!", sizeof (my_hostname) - 1);
    }
  strncpy ((char *) mp->name, my_hostname, sizeof (mp->name) - 1);

  vl_msg_api_send (rp, (u8 *) mp);
  return rp - socket_main.registration_pool;
}

void
sockclnt_close_index (u32 index)
{
  vl_api_sockclnt_delete_t *mp;
  vl_api_registration_t *rp;

  /* Don't crash / assert if fed garbage */
  if (pool_is_free_index (socket_main.registration_pool, index))
    {
      clib_warning ("registration_pool index %d already free", index);
      return;
    }
  rp = pool_elt_at_index (socket_main.registration_pool, index);

  mp = vl_msg_api_alloc (sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SOCKCLNT_DELETE);
  mp->handle = rp->server_handle;
  mp->index = rp->server_index;
  vl_msg_api_send (rp, (u8 *) mp);
}

vl_api_registration_t *
sockclnt_get_registration (u32 index)
{
  return pool_elt_at_index (socket_main.registration_pool, index);
}

/*
 * Both rx and tx msgs MUST be initialized, or we'll have
 * precisely no idea how many bytes to write into the API trace...
 */
#define foreach_sockclnt_api_msg                        \
_(SOCKCLNT_CREATE_REPLY, sockclnt_create_reply)         \
_(SOCKCLNT_DELETE_REPLY, sockclnt_delete_reply)


static clib_error_t *
sockclnt_vlib_api_init (vlib_main_t * vm)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_sockclnt_api_msg;
#undef _
  return 0;
}

VLIB_API_INIT_FUNCTION (sockclnt_vlib_api_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
