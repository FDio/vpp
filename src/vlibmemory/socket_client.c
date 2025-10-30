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
#define _GNU_SOURCE
#include <sys/socket.h>

#ifdef __FreeBSD__
#define _WANT_UCRED
#include <sys/types.h>
#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/un.h>
#endif /* __FreeBSD__ */

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

#define vl_calcsizefun
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_calcsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_printfun

socket_client_main_t socket_client_main;
__thread socket_client_main_t *socket_client_ctx = &socket_client_main;

/* Debug aid */
u32 vl (void *p) __attribute__ ((weak));

u32
vl (void *p)
{
  return vec_len (p);
}

static socket_client_main_t *
vl_socket_client_ctx_push (socket_client_main_t * ctx)
{
  socket_client_main_t *old = socket_client_ctx;
  socket_client_ctx = ctx;
  return old;
}

static void
vl_socket_client_ctx_pop (socket_client_main_t * old_ctx)
{
  socket_client_ctx = old_ctx;
}

static int
vl_socket_client_read_internal (socket_client_main_t * scm, int wait)
{
  u32 data_len = 0, msg_size;
  int n, current_rx_index;
  msgbuf_t *mbp = 0;
  f64 timeout = 0;

  if (scm->socket_fd == 0)
    return -1;

  if (wait)
    timeout = clib_time_now (&scm->clib_time) + wait;

  while (1)
    {
      current_rx_index = vec_len (scm->socket_rx_buffer);
      while (current_rx_index < sizeof (*mbp))
	{
	  vec_validate (scm->socket_rx_buffer, current_rx_index
			+ scm->socket_buffer_size - 1);
	  n = read (scm->socket_fd, scm->socket_rx_buffer + current_rx_index,
		    scm->socket_buffer_size);
	  if (n < 0)
	    {
	      if (errno == EAGAIN)
		continue;

	      clib_unix_warning ("socket_read");
	      vec_set_len (scm->socket_rx_buffer, current_rx_index);
	      return -1;
	    }
	  current_rx_index += n;
	}
      vec_set_len (scm->socket_rx_buffer, current_rx_index);

#if CLIB_DEBUG > 1
      if (n > 0)
	clib_warning ("read %d bytes", n);
#endif

      mbp = (msgbuf_t *) (scm->socket_rx_buffer);
      data_len = ntohl (mbp->data_len);
      current_rx_index = vec_len (scm->socket_rx_buffer);
      vec_validate (scm->socket_rx_buffer, current_rx_index + data_len);
      mbp = (msgbuf_t *) (scm->socket_rx_buffer);
      msg_size = data_len + sizeof (*mbp);

      while (current_rx_index < msg_size)
	{
	  n = read (scm->socket_fd, scm->socket_rx_buffer + current_rx_index,
		    msg_size - current_rx_index);
	  if (n < 0)
	    {
	      if (errno == EAGAIN)
		continue;

	      clib_unix_warning ("socket_read");
	      vec_set_len (scm->socket_rx_buffer, current_rx_index);
	      return -1;
	    }
	  current_rx_index += n;
	}
      vec_set_len (scm->socket_rx_buffer, current_rx_index);

      if (vec_len (scm->socket_rx_buffer) >= data_len + sizeof (*mbp))
	{
	  vl_msg_api_socket_handler ((void *) (mbp->data), data_len);

	  if (vec_len (scm->socket_rx_buffer) == data_len + sizeof (*mbp))
	    vec_set_len (scm->socket_rx_buffer, 0);
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
vl_socket_client_read (int wait)
{
  return vl_socket_client_read_internal (socket_client_ctx, wait);
}

int
vl_socket_client_read2 (socket_client_main_t * scm, int wait)
{
  socket_client_main_t *old_ctx;
  int rv;

  old_ctx = vl_socket_client_ctx_push (scm);
  rv = vl_socket_client_read_internal (scm, wait);
  vl_socket_client_ctx_pop (old_ctx);
  return rv;
}

static int
vl_socket_client_write_internal (socket_client_main_t * scm)
{
  int n;
  int len = vec_len (scm->socket_tx_buffer);
  msgbuf_t msgbuf = {
    .q = 0,
    .gc_mark_timestamp = 0,
    .data_len = htonl (len),
  };

  n = write (scm->socket_fd, &msgbuf, sizeof (msgbuf));
  if (n < sizeof (msgbuf))
    {
      clib_unix_warning ("socket write (msgbuf)");
      return -1;
    }

  n = write (scm->socket_fd, scm->socket_tx_buffer, len);

  vec_set_len (scm->socket_tx_buffer, 0);

  if (n < len)
    {
      clib_unix_warning ("socket write (msg)");
      return -1;
    }

  return n;
}

int
vl_socket_client_write (void)
{
  return vl_socket_client_write_internal (socket_client_ctx);
}

int
vl_socket_client_write2 (socket_client_main_t * scm)
{
  socket_client_main_t *old_ctx;
  int rv;

  old_ctx = vl_socket_client_ctx_push (scm);
  rv = vl_socket_client_write_internal (scm);
  vl_socket_client_ctx_pop (old_ctx);
  return rv;
}

void *
vl_socket_client_msg_alloc2 (socket_client_main_t * scm, int nbytes)
{
  vec_set_len (scm->socket_tx_buffer, nbytes);
  return ((void *) scm->socket_tx_buffer);
}

void *
vl_socket_client_msg_alloc (int nbytes)
{
  return vl_socket_client_msg_alloc2 (socket_client_ctx, nbytes);
}

void
vl_socket_client_disconnect2 (socket_client_main_t * scm)
{
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
vl_socket_client_disconnect (void)
{
  vl_socket_client_disconnect2 (socket_client_ctx);
}

void
vl_socket_client_enable_disable2 (socket_client_main_t * scm, int enable)
{
  scm->socket_enable = enable;
}

void
vl_socket_client_enable_disable (int enable)
{
  vl_socket_client_enable_disable2 (socket_client_ctx, enable);
}

static clib_error_t *
vl_sock_api_recv_fd_msg_internal (socket_client_main_t * scm, int fds[],
				  int n_fds, u32 wait)
{
  char msgbuf[16];
  char ctl[CMSG_SPACE (sizeof (int) * n_fds)
	   + CMSG_SPACE (sizeof (struct ucred))];
  struct msghdr mh = { 0 };
  struct iovec iov[1];
  ssize_t size = 0;
#ifdef __linux__
  struct ucred *cr = 0;
#elif __FreeBSD__
  struct cmsgcred *cr = 0;
#endif /* __linux__ */
  struct cmsghdr *cmsg;
  pid_t pid __attribute__ ((unused));
  uid_t uid __attribute__ ((unused));
  gid_t gid __attribute__ ((unused));
  int socket_fd;
  f64 timeout;

  socket_fd = scm->client_socket.fd;

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
#ifdef __linux__
	  if (cmsg->cmsg_type == SCM_CREDENTIALS)
	    {
	      cr = (struct ucred *) CMSG_DATA (cmsg);
	      uid = cr->uid;
	      gid = cr->gid;
	      pid = cr->pid;
	    }
#elif __FreeBSD__
	  if (cmsg->cmsg_type == SCM_CREDS)
	    {
	      cr = (struct cmsgcred *) CMSG_DATA (cmsg);
	      uid = cr->cmcred_uid;
	      gid = cr->cmcred_gid;
	      pid = cr->cmcred_pid;
	    }
#endif /* __linux__ */
	  else if (cmsg->cmsg_type == SCM_RIGHTS)
	    {
	      clib_memcpy_fast (fds, CMSG_DATA (cmsg), sizeof (int) * n_fds);
	    }
	}
      cmsg = CMSG_NXTHDR (&mh, cmsg);
    }
  return 0;
}

clib_error_t *
vl_sock_api_recv_fd_msg (int socket_fd, int fds[], int n_fds, u32 wait)
{
  return vl_sock_api_recv_fd_msg_internal (socket_client_ctx, fds, n_fds,
					   wait);
}

clib_error_t *
vl_sock_api_recv_fd_msg2 (socket_client_main_t * scm, int socket_fd,
			  int fds[], int n_fds, u32 wait)
{
  socket_client_main_t *old_ctx;
  clib_error_t *error;

  old_ctx = vl_socket_client_ctx_push (scm);
  error = vl_sock_api_recv_fd_msg_internal (scm, fds, n_fds, wait);
  vl_socket_client_ctx_pop (old_ctx);
  return error;
}

static void vl_api_sock_init_shm_reply_t_handler
  (vl_api_sock_init_shm_reply_t * mp)
{
  socket_client_main_t *scm = socket_client_ctx;
  ssvm_private_t *memfd = &scm->memfd_segment;
  i32 retval = ntohl (mp->retval);
  api_main_t *am = vlibapi_get_main ();
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
  retval = ssvm_client_init_memfd (memfd);
  if (retval)
    clib_warning ("WARNING: segment map returned %d", retval);

  /*
   * Pivot to the memory client segment that vpp just created
   */
  am->vlib_rp = (void *) (memfd->requested_va + MMAP_PAGESIZE);
  am->shmem_hdr = (void *) am->vlib_rp->user_ctx;

  new_name = format (0, "%v[shm]%c", scm->name, 0);
  vl_client_install_client_message_handlers ();
  if (scm->want_shm_pthread)
    {
      vl_client_connect_to_vlib_no_map ("pvt", (char *) new_name,
					32 /* input_queue_length */ );
    }
  else
    {
      vl_client_connect_to_vlib_no_rx_pthread_no_map ("pvt",
						      (char *) new_name, 32
						      /* input_queue_length */
	);
    }
  vl_socket_client_enable_disable (0);
  vec_free (new_name);
}

static void
vl_api_sockclnt_create_reply_t_handler (vl_api_sockclnt_create_reply_t * mp)
{
  socket_client_main_t *scm = socket_client_ctx;
  if (!mp->response)
    {
      scm->socket_enable = 1;
      scm->client_index = clib_net_to_host_u32 (mp->index);
    }
}

#define foreach_sock_client_api_msg             		\
_(SOCKCLNT_CREATE_REPLY, sockclnt_create_reply)			\
_(SOCK_INIT_SHM_REPLY, sock_init_shm_reply)     		\

void
vl_sock_client_install_message_handlers (void)
{

#define _(N, n)                                                               \
  vl_msg_api_config (&(vl_msg_api_msg_config_t){                              \
    .id = VL_API_##N,                                                         \
    .name = #n,                                                               \
    .handler = vl_api_##n##_t_handler,                                        \
    .endian = vl_api_##n##_t_endian,                                          \
    .format_fn = vl_api_##n##_t_format,                                       \
    .size = sizeof (vl_api_##n##_t),                                          \
    .traced = 0,                                                              \
    .tojson = vl_api_##n##_t_tojson,                                          \
    .fromjson = vl_api_##n##_t_fromjson,                                      \
    .calc_size = vl_api_##n##_t_calc_size,                                    \
  });
  foreach_sock_client_api_msg;
#undef _
}

int
vl_socket_client_connect_internal (socket_client_main_t * scm,
				   char *socket_path, char *client_name,
				   u32 socket_buffer_size)
{
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
  sock->flags = CLIB_SOCKET_F_IS_CLIENT;

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
  vec_set_len (scm->socket_rx_buffer, 0);
  vec_set_len (scm->socket_tx_buffer, 0);
  scm->name = format (0, "%s", client_name);

  mp = vl_socket_client_msg_alloc2 (scm, sizeof (*mp));
  mp->_vl_msg_id = htons (VL_API_SOCKCLNT_CREATE);
  strncpy ((char *) mp->name, client_name, sizeof (mp->name) - 1);
  mp->name[sizeof (mp->name) - 1] = 0;
  mp->context = 0xfeedface;

  clib_time_init (&scm->clib_time);

  if (vl_socket_client_write_internal (scm) <= 0)
    return (-1);

  if (vl_socket_client_read_internal (scm, 5))
    return (-1);

  return (0);
}

int
vl_socket_client_connect (char *socket_path, char *client_name,
			  u32 socket_buffer_size)
{
  return vl_socket_client_connect_internal (socket_client_ctx, socket_path,
					    client_name, socket_buffer_size);
}

int
vl_socket_client_connect2 (socket_client_main_t * scm, char *socket_path,
			   char *client_name, u32 socket_buffer_size)
{
  socket_client_main_t *old_ctx;
  int rv;

  old_ctx = vl_socket_client_ctx_push (scm);
  rv = vl_socket_client_connect_internal (socket_client_ctx, socket_path,
					  client_name, socket_buffer_size);
  vl_socket_client_ctx_pop (old_ctx);
  return rv;
}

int
vl_socket_client_init_shm_internal (socket_client_main_t * scm,
				    vl_api_shm_elem_config_t * config,
				    int want_pthread)
{
  vl_api_sock_init_shm_t *mp;
  int rv, i;
  u64 *cfg;

  scm->want_shm_pthread = want_pthread;

  mp = vl_socket_client_msg_alloc2 (scm, sizeof (*mp) +
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
  rv = vl_socket_client_write_internal (scm);
  if (rv <= 0)
    return rv;

  if (vl_socket_client_read_internal (scm, 1))
    return -1;

  return 0;
}

int
vl_socket_client_init_shm (vl_api_shm_elem_config_t * config,
			   int want_pthread)
{
  return vl_socket_client_init_shm_internal (socket_client_ctx, config,
					     want_pthread);
}

int
vl_socket_client_init_shm2 (socket_client_main_t * scm,
			    vl_api_shm_elem_config_t * config,
			    int want_pthread)
{
  socket_client_main_t *old_ctx;
  int rv;

  old_ctx = vl_socket_client_ctx_push (scm);
  rv = vl_socket_client_init_shm_internal (socket_client_ctx, config,
					   want_pthread);
  vl_socket_client_ctx_pop (old_ctx);
  return rv;
}

clib_error_t *
vl_socket_client_recv_fd_msg2 (socket_client_main_t * scm, int fds[],
			       int n_fds, u32 wait)
{
  if (!scm->socket_fd)
    return clib_error_return (0, "no socket");
  return vl_sock_api_recv_fd_msg_internal (scm, fds, n_fds, wait);
}

clib_error_t *
vl_socket_client_recv_fd_msg (int fds[], int n_fds, u32 wait)
{
  return vl_socket_client_recv_fd_msg2 (socket_client_ctx, fds, n_fds, wait);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
