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

#include <lina/shared.h>
#include <lina/lina.h>

static void
lina_client_disconnect (lina_instance_t * lin)
{
  lina_main_t *lm = &lina_main;
  clib_socket_close (&lin->client);
  lin->flags &= ~LINA_INSTANCE_F_CONNECTED;
  lm->n_connected--;
  if (lm->n_connected == 0)
    {
      u32 i;
      for (i = 0; i < vec_len (vlib_mains); i++)
	vlib_node_set_state (vlib_mains[i], lina_dequeue_node.index,
			     VLIB_NODE_STATE_DISABLED);
    }
}

clib_error_t *
lina_conn_fd_read_ready (clib_file_t * uf)
{
  lina_main_t *lm = &lina_main;
  lina_instance_t *lin = pool_elt_at_index (lm->instances, uf->private_data);
  clib_error_t *err;
  lina_msg_t msg;

  if ((err = clib_socket_recvmsg (&lin->client, &msg, sizeof (lina_msg_t),
				  0, 0)))
    {
      lina_log_debug (lin, "%U", format_clib_error, err);
      clib_error_free (err);
      lina_client_disconnect (lin);
    }
  return 0;
}

clib_error_t *
lina_conn_fd_err_ready (clib_file_t * uf)
{
  lina_main_t *lm = &lina_main;
  lina_instance_t *lin = pool_elt_at_index (lm->instances, uf->private_data);

  lina_log_debug (lin, "socket error");
  lina_client_disconnect (lin);
  return 0;
}


clib_error_t *
lina_conn_fd_accept_ready (clib_file_t * uf)
{
  vlib_main_t *vm = vlib_get_main ();
  clib_error_t *err = 0;
  lina_main_t *lm = &lina_main;
  clib_file_t t = { 0 };
  clib_socket_t _sock = { 0 };
  clib_socket_t *s = &_sock;
  lina_instance_t *lin = pool_elt_at_index (lm->instances, uf->private_data);
  lina_msg_t msg = { 0 };
  int i, fds[LINA_SHM_MAX_REGIONS];

  lina_log_debug (lin, "connection received");

  if ((err = clib_socket_accept (&lin->listener, s)))
    return err;

  if (lin->flags & LINA_INSTANCE_F_CONNECTED)
    {
      lina_log_debug (lin, "already connected, new connectoin closed");
      clib_socket_close (s);
      return 0;
    }

  clib_memcpy (&lin->client, s, sizeof (clib_socket_t));

  lina_log_debug (lin, "connection accepted, fd %d", lin->client.fd);

  t.private_data = lin->index;
  t.file_descriptor = lin->client.fd;
  t.read_function = lina_conn_fd_read_ready;
  t.description = format (0, "lina instance %u '%s'", lin->index,
			  lin->listener_filename);
  lin->client.private_data = clib_file_add (&file_main, &t);

  msg.instance = lin->index;
  msg.n_regions = 1;
  msg.region_size[0] = lin->shm_size;

  fds[0] = lin->fd;

  vec_foreach_index (i, buffer_main.buffer_pools)
  {
    vlib_physmem_map_t *pm;
    vlib_buffer_pool_t *bp = vec_elt_at_index (buffer_main.buffer_pools, i);
    pm = vlib_physmem_get_map (vm, bp->physmem_map_index);
    msg.n_regions++;
    fds[i + 1] = pm->fd;
    msg.region_size[i + 1] = pm->n_pages << pm->log2_page_size;
  }

  err = clib_socket_sendmsg (&lin->client, &msg, sizeof (lina_msg_t), fds,
			     msg.n_regions);

  if (err)
    clib_socket_close (&lin->client);

  lin->flags |= LINA_INSTANCE_F_CONNECTED;
  lm->n_connected++;

  if (lm->n_connected == 1)
    {
      u32 i;
      for (i = 0; i < vec_len (vlib_mains); i++)
	vlib_node_set_state (vlib_mains[i], lina_dequeue_node.index,
			     VLIB_NODE_STATE_POLLING);
    }

  return err;
}

clib_error_t *
lina_socket_listener_create (vlib_main_t * vm, lina_instance_t * lin)
{
  clib_error_t *err = 0;
  struct stat file_stat;
  clib_file_t t = { 0 };
  clib_socket_t *sock = &lin->listener;

  if (stat ((char *) lin->listener_filename, &file_stat) == 0)
    {
      if (S_ISSOCK (file_stat.st_mode))
	unlink ((char *) lin->listener_filename);
      else
	return clib_error_return (0, "file '%s' already exists",
				  lin->listener_filename);
    }

  clib_memset (sock, 0, sizeof (clib_socket_t));
  sock->config = (char *) lin->listener_filename;
  sock->flags = CLIB_SOCKET_F_IS_SERVER |
    CLIB_SOCKET_F_ALLOW_GROUP_WRITE |
    CLIB_SOCKET_F_SEQPACKET | CLIB_SOCKET_F_PASSCRED;

  if ((err = clib_socket_init (sock)))
    return err;

  lina_log_debug (lin, "socket listener created, fd %d", sock->fd);

  t.read_function = lina_conn_fd_accept_ready;
  t.file_descriptor = sock->fd;
  t.private_data = lin->index;
  t.description = format (0, "lina listener %s", sock->config);
  sock->private_data = clib_file_add (&file_main, &t);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
