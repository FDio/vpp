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
#define __USE_GNU
#include <sys/socket.h>

#include <svm/ssvm.h>
#include <vlibmemory/socket_client.h>
#include <vlibmemory/memory_client.h>

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

int
vl_socket_client_read (int wait)
{
  socket_client_main_t *scm = &socket_client_main;
  u32 data_len = 0, msg_size;
  int n, current_rx_index;
  msgbuf_t *mbp = 0;
  f64 timeout;

  if (scm->socket_fd == 0)
    return -1;

  if (wait)
    timeout = clib_time_now (&scm->clib_time) + wait;

  while (1)
    {
      while (vec_len (scm->socket_rx_buffer) < sizeof (*mbp))
	{
	  current_rx_index = vec_len (scm->socket_rx_buffer);
	  vec_validate (scm->socket_rx_buffer, current_rx_index
			+ scm->socket_buffer_size - 1);
	  _vec_len (scm->socket_rx_buffer) = current_rx_index;
	  n = read (scm->socket_fd, scm->socket_rx_buffer + current_rx_index,
		    scm->socket_buffer_size);
	  if (n < 0)
	    {
	      clib_unix_warning ("socket_read");
	      return -1;
	    }
	  _vec_len (scm->socket_rx_buffer) += n;
	}

#if CLIB_DEBUG > 1
      if (n > 0)
	clib_warning ("read %d bytes", n);
#endif

      mbp = (msgbuf_t *) (scm->socket_rx_buffer);
      data_len = ntohl (mbp->data_len);
      current_rx_index = vec_len (scm->socket_rx_buffer);
      vec_validate (scm->socket_rx_buffer, current_rx_index + data_len);
      _vec_len (scm->socket_rx_buffer) = current_rx_index;
      mbp = (msgbuf_t *) (scm->socket_rx_buffer);
      msg_size = data_len + sizeof (*mbp);

      while (vec_len (scm->socket_rx_buffer) < msg_size)
	{
	  n = read (scm->socket_fd,
		    scm->socket_rx_buffer + vec_len (scm->socket_rx_buffer),
		    msg_size - vec_len (scm->socket_rx_buffer));
	  if (n < 0 && errno != EAGAIN)
	    {
	      clib_unix_warning ("socket_read");
	      return -1;
	    }
	  _vec_len (scm->socket_rx_buffer) += n;
	}

      if (vec_len (scm->socket_rx_buffer) >= data_len + sizeof (*mbp))
	{
	  vl_msg_api_socket_handler ((void *) (mbp->data));

	  if (vec_len (scm->socket_rx_buffer) == data_len + sizeof (*mbp))
	    _vec_len (scm->socket_rx_buffer) = 0;
	  else
	    vec_delete (scm->socket_rx_buffer, data_len + sizeof (*mbp), 0);
	  mbp = 0;

	  /* Quit if we're out of data, and not expecting a ping reply */
	  if (vec_len (scm->socket_rx_buffer) == 0
	      && scm->control_pings_outstanding == 0)
	    break;
	}
      if (wait && clib_time_now (&scm->clib_time) >= timeout)
	return -1;
    }
  return 0;
}

int
vl_socket_client_write (void)
{
  socket_client_main_t *scm = &socket_client_main;
  int n;

  msgbuf_t msgbuf = {
    .q = 0,
    .gc_mark_timestamp = 0,
    .data_len = htonl (scm->socket_tx_nbytes),
  };

  n = write (scm->socket_fd, &msgbuf, sizeof (msgbuf));
  if (n < sizeof (msgbuf))
    {
      clib_unix_warning ("socket write (msgbuf)");
      return -1;
    }

  n = write (scm->socket_fd, scm->socket_tx_buffer, scm->socket_tx_nbytes);
  if (n < scm->socket_tx_nbytes)
    {
      clib_unix_warning ("socket write (msg)");
      return -1;
    }

  return n;
}

void *
vl_socket_client_msg_alloc (int nbytes)
{
  socket_client_main.socket_tx_nbytes = nbytes;
  return ((void *) socket_client_main.socket_tx_buffer);
}

void
vl_socket_client_disconnect (void)
{
  socket_client_main_t *scm = &socket_client_main;

  if (vl_mem_client_is_connected ())
    {
      vl_client_disconnect_from_vlib_no_unmap ();
      ssvm_delete_memfd (&scm->memfd_segment);
    }
  if (scm->socket_fd && (close (scm->socket_fd) < 0))
    clib_unix_warning ("close");
  scm->socket_fd = 0;
}

void
vl_socket_client_enable_disable (int enable)
{
  socket_client_main_t *scm = &socket_client_main;
  scm->socket_enable = enable;
}

clib_error_t *
vl_sock_api_recv_fd_msg (int socket_fd, int fds[], int n_fds, u32 wait)
{
  socket_client_main_t *scm = &socket_client_main;
  char msgbuf[16];
  char ctl[CMSG_SPACE (sizeof (int) * n_fds)
	   + CMSG_SPACE (sizeof (struct ucred))];
  struct msghdr mh = { 0 };
  struct iovec iov[1];
  ssize_t size = 0;
  struct ucred *cr = 0;
  struct cmsghdr *cmsg;
  pid_t pid __attribute__ ((unused));
  uid_t uid __attribute__ ((unused));
  gid_t gid __attribute__ ((unused));
  f64 timeout;

  iov[0].iov_base = msgbuf;
  iov[0].iov_len = 5;
  mh.msg_iov = iov;
  mh.msg_iovlen = 1;
  mh.msg_control = ctl;
  mh.msg_controllen = sizeof (ctl);

  clib_memset (ctl, 0, sizeof (ctl));

  if (wait != ~0)
    {
      timeout = clib_time_now (&scm->clib_time) + wait;
      while (size != 5 && clib_time_now (&scm->clib_time) < timeout)
	size = recvmsg (socket_fd, &mh, MSG_DONTWAIT);
    }
  else
    size = recvmsg (socket_fd, &mh, 0);

  if (size != 5)
    {
      return (size == 0) ? clib_error_return (0, "disconnected") :
	clib_error_return_unix (0, "recvmsg: malformed message (fd %d)",
				socket_fd);
    }

  cmsg = CMSG_FIRSTHDR (&mh);
  while (cmsg)
    {
      if (cmsg->cmsg_level == SOL_SOCKET)
	{
	  if (cmsg->cmsg_type == SCM_CREDENTIALS)
	    {
	      cr = (struct ucred *) CMSG_DATA (cmsg);
	      uid = cr->uid;
	      gid = cr->gid;
	      pid = cr->pid;
	    }
	  else if (cmsg->cmsg_type == SCM_RIGHTS)
	    {
	      clib_memcpy (fds, CMSG_DATA (cmsg), sizeof (int) * n_fds);
	    }
	}
      cmsg = CMSG_NXTHDR (&mh, cmsg);
    }
  return 0;
}

static void vl_api_sock_init_shm_reply_t_handler
  (vl_api_sock_init_shm_reply_t * mp)
{
  socket_client_main_t *scm = &socket_client_main;
  ssvm_private_t *memfd = &scm->memfd_segment;
  i32 retval = ntohl (mp->retval);
  api_main_t *am = &api_main;
  clib_error_t *error;
  int my_fd = -1;
  u8 *new_name;

  if (retval)
    {
      clib_warning ("failed to init shmem");
      return;
    }

  /*
   * Check the socket for the magic fd
   */
  error = vl_sock_api_recv_fd_msg (scm->socket_fd, &my_fd, 1, 5);
  if (error)
    {
      clib_error_report (error);
      retval = -99;
      return;
    }

  clib_memset (memfd, 0, sizeof (*memfd));
  memfd->fd = my_fd;

  /* Note: this closes memfd.fd */
  retval = ssvm_slave_init_memfd (memfd);
  if (retval)
    clib_warning ("WARNING: segment map returned %d", retval);

  /*
   * Pivot to the memory client segment that vpp just created
   */
  am->vlib_rp = (void *) (memfd->requested_va + MMAP_PAGESIZE);
  am->shmem_hdr = (void *) am->vlib_rp->user_ctx;

  new_name = format (0, "%v[shm]%c", scm->name, 0);
  vl_client_install_client_message_handlers ();
  vl_client_connect_to_vlib_no_map ("pvt", (char *) new_name,
				    32 /* input_queue_length */ );
  vl_socket_client_enable_disable (0);
  vec_free (new_name);
}

static void
vl_api_sockclnt_create_reply_t_handler (vl_api_sockclnt_create_reply_t * mp)
{
  socket_client_main_t *scm = &socket_client_main;
  if (!mp->response)
    {
      scm->socket_enable = 1;
      scm->client_index = clib_net_to_host_u32 (mp->index);
    }
}

#define foreach_sock_client_api_msg             		\
_(SOCKCLNT_CREATE_REPLY, sockclnt_create_reply)			\
_(SOCK_INIT_SHM_REPLY, sock_init_shm_reply)     		\

static void
noop_handler (void *notused)
{
}

void
vl_sock_client_install_message_handlers (void)
{

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                            vl_api_##n##_t_handler,             \
                            noop_handler,                       \
                            vl_api_##n##_t_endian,              \
                            vl_api_##n##_t_print,               \
                            sizeof(vl_api_##n##_t), 1);
  foreach_sock_client_api_msg;
#undef _
}

int
vl_socket_client_connect (char *socket_path, char *client_name,
			  u32 socket_buffer_size)
{
  socket_client_main_t *scm = &socket_client_main;
  vl_api_sockclnt_create_t *mp;
  clib_socket_t *sock;
  clib_error_t *error;

  /* Already connected? */
  if (scm->socket_fd)
    return (-2);

  /* bogus call? */
  if (socket_path == 0 || client_name == 0)
    return (-3);

  sock = &scm->client_socket;
  sock->config = socket_path;
  sock->flags = CLIB_SOCKET_F_IS_CLIENT | CLIB_SOCKET_F_SEQPACKET;

  if ((error = clib_socket_init (sock)))
    {
      clib_error_report (error);
      return (-1);
    }

  vl_sock_client_install_message_handlers ();

  scm->socket_fd = sock->fd;
  scm->socket_buffer_size = socket_buffer_size ? socket_buffer_size :
    SOCKET_CLIENT_DEFAULT_BUFFER_SIZE;
  vec_validate (scm->socket_tx_buffer, scm->socket_buffer_size - 1);
  vec_validate (scm->socket_rx_buffer, scm->socket_buffer_size - 1);
  _vec_len (scm->socket_rx_buffer) = 0;
  _vec_len (scm->socket_tx_buffer) = 0;
  scm->name = format (0, "%s", client_name);

  mp = vl_socket_client_msg_alloc (sizeof (*mp));
  mp->_vl_msg_id = htons (VL_API_SOCKCLNT_CREATE);
  strncpy ((char *) mp->name, client_name, sizeof (mp->name) - 1);
  mp->name[sizeof (mp->name) - 1] = 0;
  mp->context = 0xfeedface;

  clib_time_init (&scm->clib_time);

  if (vl_socket_client_write () <= 0)
    return (-1);

  if (vl_socket_client_read (5))
    return (-1);

  return (0);
}

int
vl_socket_client_init_shm (vl_api_shm_elem_config_t * config)
{
  socket_client_main_t *scm = &socket_client_main;
  vl_api_sock_init_shm_t *mp;
  int rv, i;
  u64 *cfg;

  mp = vl_socket_client_msg_alloc (sizeof (*mp) +
				   vec_len (config) * sizeof (u64));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_SOCK_INIT_SHM);
  mp->client_index = clib_host_to_net_u32 (scm->client_index);
  mp->requested_size = 64 << 20;

  if (config)
    {
      for (i = 0; i < vec_len (config); i++)
	{
	  cfg = (u64 *) & config[i];
	  mp->configs[i] = *cfg;
	}
      mp->nitems = vec_len (config);
    }
  rv = vl_socket_client_write ();
  if (rv <= 0)
    return rv;

  if (vl_socket_client_read (1))
    return -1;

  return 0;
}

clib_error_t *
vl_socket_client_recv_fd_msg (int fds[], int n_fds, u32 wait)
{
  socket_client_main_t *scm = &socket_client_main;
  if (!scm->socket_fd)
    return clib_error_return (0, "no socket");
  return vl_sock_api_recv_fd_msg (scm->client_socket.fd, fds, n_fds, wait);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
