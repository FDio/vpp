/*
 *------------------------------------------------------------------
 * socksvr_vlib.c
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
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <vppinfra/byte_order.h>
#include <svm/memfd.h>

#include <fcntl.h>
#include <sys/stat.h>

#include <vlibmemory/api.h>

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

void
dump_socket_clients (vlib_main_t * vm, api_main_t * am)
{
  vl_api_registration_t *reg;
  socket_main_t *sm = &socket_main;
  clib_file_main_t *fm = &file_main;
  clib_file_t *f;

  /*
   * Must have at least one active client, not counting the
   * REGISTRATION_TYPE_SOCKET_LISTEN bind/accept socket
   */
  if (pool_elts (sm->registration_pool) < 2)
    return;

  vlib_cli_output (vm, "Socket clients");
  vlib_cli_output (vm, "%16s %8s", "Name", "Fildesc");
    /* *INDENT-OFF* */
    pool_foreach (reg, sm->registration_pool,
    ({
        if (reg->registration_type == REGISTRATION_TYPE_SOCKET_SERVER) {
            f = pool_elt_at_index (fm->file_pool, reg->clib_file_index);
            vlib_cli_output (vm, "%16s %8d",
                             reg->name, f->file_descriptor);
        }
    }));
/* *INDENT-ON* */
}

void
vl_socket_api_send (vl_api_registration_t * rp, u8 * elem)
{
  u16 msg_id = ntohs (*(u16 *) elem);
  api_main_t *am = &api_main;
  msgbuf_t *mb = (msgbuf_t *) (elem - offsetof (msgbuf_t, data));
#if CLIB_DEBUG > 1
  u32 output_length;
#endif
  clib_file_t *cf = rp->clib_file_index + file_main.file_pool;

  ASSERT (rp->registration_type > REGISTRATION_TYPE_SHMEM);

  if (msg_id >= vec_len (am->api_trace_cfg))
    {
      clib_warning ("id out of range: %d", msg_id);
      vl_msg_api_free ((void *) elem);
      return;
    }

  /* Add the msgbuf_t to the output vector */
  vl_socket_add_pending_output_no_flush (cf,
					 rp->vl_api_registration_pool_index +
					 socket_main.registration_pool,
					 (u8 *) mb, sizeof (*mb));
  /* Send the message */
  vl_socket_add_pending_output (cf,
				rp->vl_api_registration_pool_index
				+ socket_main.registration_pool,
				elem, ntohl (mb->data_len));

#if CLIB_DEBUG > 1
  output_length = sizeof (*mb) + ntohl (mb->data_len);
  clib_warning ("wrote %u bytes to fd %d", output_length,
		cf->file_descriptor);
#endif

  vl_msg_api_free ((void *) elem);
}

void
vl_free_socket_registration_index (u32 pool_index)
{
  int i;
  vl_api_registration_t *rp;
  if (pool_is_free_index (socket_main.registration_pool, pool_index))
    {
      clib_warning ("main pool index %d already free", pool_index);
      return;
    }
  rp = pool_elt_at_index (socket_main.registration_pool, pool_index);

  ASSERT (rp->registration_type != REGISTRATION_TYPE_FREE);
  for (i = 0; i < vec_len (rp->additional_fds_to_close); i++)
    if (close (rp->additional_fds_to_close[i]) < 0)
      clib_unix_warning ("close");
  vec_free (rp->additional_fds_to_close);
  vec_free (rp->name);
  vec_free (rp->unprocessed_input);
  vec_free (rp->output_vector);
  rp->registration_type = REGISTRATION_TYPE_FREE;
  pool_put (socket_main.registration_pool, rp);
}

void
vl_api_socket_process_msg (clib_file_t * uf, vl_api_registration_t * rp,
			   i8 * input_v)
{
  msgbuf_t *mbp = (msgbuf_t *) input_v;

  u8 *the_msg = (u8 *) (mbp->data);
  socket_main.current_uf = uf;
  socket_main.current_rp = rp;
  vl_msg_api_socket_handler (the_msg);
  socket_main.current_uf = 0;
  socket_main.current_rp = 0;
}

clib_error_t *
vl_socket_read_ready (clib_file_t * uf)
{
  clib_file_main_t *fm = &file_main;
  vlib_main_t *vm = vlib_get_main ();
  vl_api_registration_t *rp;
  int n;
  i8 *msg_buffer = 0;
  u8 *data_for_process;
  u32 msg_len;
  u32 save_input_buffer_length = vec_len (socket_main.input_buffer);
  vl_socket_args_for_process_t *a;
  msgbuf_t *mbp;
  int mbp_set = 0;

  rp = pool_elt_at_index (socket_main.registration_pool, uf->private_data);

  n = read (uf->file_descriptor, socket_main.input_buffer,
	    vec_len (socket_main.input_buffer));

  if (n <= 0 && errno != EAGAIN)
    {
      clib_file_del (fm, uf);

      if (!pool_is_free (socket_main.registration_pool, rp))
	{
	  u32 index = rp - socket_main.registration_pool;
	  vl_free_socket_registration_index (index);
	}
      else
	{
	  clib_warning ("client index %d already free?",
			rp->vl_api_registration_pool_index);
	}
      return 0;
    }

  _vec_len (socket_main.input_buffer) = n;

  /*
   * Look for bugs here. This code is tricky because
   * data read from a stream socket does not honor message
   * boundaries. In the case of a long message (>4K bytes)
   * we have to do (at least) 2 reads, etc.
   */
  do
    {
      if (vec_len (rp->unprocessed_input))
	{
	  vec_append (rp->unprocessed_input, socket_main.input_buffer);
	  msg_buffer = rp->unprocessed_input;
	}
      else
	{
	  msg_buffer = socket_main.input_buffer;
	  mbp_set = 0;
	}

      if (mbp_set == 0)
	{
	  /* Any chance that we have a complete message? */
	  if (vec_len (msg_buffer) <= sizeof (msgbuf_t))
	    goto save_and_split;

	  mbp = (msgbuf_t *) msg_buffer;
	  msg_len = ntohl (mbp->data_len);
	  mbp_set = 1;
	}

      /* We don't have the entire message yet. */
      if (mbp_set == 0
	  || (msg_len + sizeof (msgbuf_t)) > vec_len (msg_buffer))
	{
	save_and_split:
	  /* if we were using the input buffer save the fragment */
	  if (msg_buffer == socket_main.input_buffer)
	    {
	      ASSERT (vec_len (rp->unprocessed_input) == 0);
	      vec_validate (rp->unprocessed_input, vec_len (msg_buffer) - 1);
	      clib_memcpy (rp->unprocessed_input, msg_buffer,
			   vec_len (msg_buffer));
	      _vec_len (rp->unprocessed_input) = vec_len (msg_buffer);
	    }
	  _vec_len (socket_main.input_buffer) = save_input_buffer_length;
	  return 0;
	}

      data_for_process = (u8 *) vec_dup (msg_buffer);
      _vec_len (data_for_process) = (msg_len + sizeof (msgbuf_t));
      pool_get (socket_main.process_args, a);
      a->clib_file = uf;
      a->regp = rp;
      a->data = data_for_process;

      vlib_process_signal_event (vm, memclnt_node.index,
				 SOCKET_READ_EVENT,
				 a - socket_main.process_args);
      if (n > (msg_len + sizeof (*mbp)))
	vec_delete (msg_buffer, msg_len + sizeof (*mbp), 0);
      else
	_vec_len (msg_buffer) = 0;
      n -= msg_len + sizeof (msgbuf_t);
      msg_len = 0;
      mbp_set = 0;
    }
  while (n > 0);

  _vec_len (socket_main.input_buffer) = save_input_buffer_length;

  return 0;
}

void
vl_socket_add_pending_output (clib_file_t * uf,
			      vl_api_registration_t * rp,
			      u8 * buffer, uword buffer_bytes)
{
  clib_file_main_t *fm = &file_main;

  vec_add (rp->output_vector, buffer, buffer_bytes);
  if (vec_len (rp->output_vector) > 0)
    {
      int skip_update = 0 != (uf->flags & UNIX_FILE_DATA_AVAILABLE_TO_WRITE);
      uf->flags |= UNIX_FILE_DATA_AVAILABLE_TO_WRITE;
      if (!skip_update)
	fm->file_update (uf, UNIX_FILE_UPDATE_MODIFY);
    }
}

void
vl_socket_add_pending_output_no_flush (clib_file_t * uf,
				       vl_api_registration_t * rp,
				       u8 * buffer, uword buffer_bytes)
{
  vec_add (rp->output_vector, buffer, buffer_bytes);
}

static void
socket_del_pending_output (clib_file_t * uf,
			   vl_api_registration_t * rp, uword n_bytes)
{
  clib_file_main_t *fm = &file_main;

  vec_delete (rp->output_vector, n_bytes, 0);
  if (vec_len (rp->output_vector) <= 0)
    {
      int skip_update = 0 == (uf->flags & UNIX_FILE_DATA_AVAILABLE_TO_WRITE);
      uf->flags &= ~UNIX_FILE_DATA_AVAILABLE_TO_WRITE;
      if (!skip_update)
	fm->file_update (uf, UNIX_FILE_UPDATE_MODIFY);
    }
}

clib_error_t *
vl_socket_write_ready (clib_file_t * uf)
{
  clib_file_main_t *fm = &file_main;
  vl_api_registration_t *rp;
  int n;

  rp = pool_elt_at_index (socket_main.registration_pool, uf->private_data);

  /* Flush output vector. */
  n = write (uf->file_descriptor,
	     rp->output_vector, vec_len (rp->output_vector));

  if (n < 0)
    {
#if DEBUG > 2
      clib_warning ("write error, close the file...\n");
#endif
      clib_file_del (fm, uf);

      vl_free_socket_registration_index (rp - socket_main.registration_pool);
      return 0;
    }

  else if (n > 0)
    socket_del_pending_output (uf, rp, n);

  return 0;
}

clib_error_t *
vl_socket_error_ready (clib_file_t * uf)
{
  vl_api_registration_t *rp;
  clib_file_main_t *fm = &file_main;

  rp = pool_elt_at_index (socket_main.registration_pool, uf->private_data);
  clib_file_del (fm, uf);
  vl_free_socket_registration_index (rp - socket_main.registration_pool);

  return 0;
}

void
socksvr_file_add (clib_file_main_t * fm, int fd)
{
  vl_api_registration_t *rp;
  clib_file_t template = { 0 };

  pool_get (socket_main.registration_pool, rp);
  memset (rp, 0, sizeof (*rp));

  template.read_function = vl_socket_read_ready;
  template.write_function = vl_socket_write_ready;
  template.error_function = vl_socket_error_ready;
  template.file_descriptor = fd;
  template.private_data = rp - socket_main.registration_pool;

  rp->registration_type = REGISTRATION_TYPE_SOCKET_SERVER;
  rp->vl_api_registration_pool_index = rp - socket_main.registration_pool;
  rp->clib_file_index = clib_file_add (fm, &template);
}

static clib_error_t *
socksvr_accept_ready (clib_file_t * uf)
{
  clib_file_main_t *fm = &file_main;
  socket_main_t *sm = &socket_main;
  clib_socket_t *sock = &sm->socksvr_listen_socket;
  clib_socket_t client;
  clib_error_t *error;

  error = clib_socket_accept (sock, &client);

  if (error)
    return error;

  socksvr_file_add (fm, client.fd);
  return 0;
}

static clib_error_t *
socksvr_bogus_write (clib_file_t * uf)
{
  clib_warning ("why am I here?");
  return 0;
}

/*
 * vl_api_sockclnt_create_t_handler
 */
void
vl_api_sockclnt_create_t_handler (vl_api_sockclnt_create_t * mp)
{
  vl_api_registration_t *regp;
  vl_api_sockclnt_create_reply_t *rp;
  int rv = 1;

  regp = socket_main.current_rp;

  ASSERT (regp->registration_type == REGISTRATION_TYPE_SOCKET_SERVER);

  regp->name = format (0, "%s%c", mp->name, 0);

  rp = vl_msg_api_alloc (sizeof (*rp));
  rp->_vl_msg_id = htons (VL_API_SOCKCLNT_CREATE_REPLY);
  rp->handle = (uword) regp;
  rp->index = (uword) regp->vl_api_registration_pool_index;
  rp->context = mp->context;
  rp->response = htonl (rv);

  vl_msg_api_send (regp, (u8 *) rp);
}

/*
 * vl_api_sockclnt_delete_t_handler
 */
void
vl_api_sockclnt_delete_t_handler (vl_api_sockclnt_delete_t * mp)
{
  vl_api_registration_t *regp;
  vl_api_sockclnt_delete_reply_t *rp;

  if (!pool_is_free_index (socket_main.registration_pool, mp->index))
    {
      regp = pool_elt_at_index (socket_main.registration_pool, mp->index);

      rp = vl_msg_api_alloc (sizeof (*rp));
      rp->_vl_msg_id = htons (VL_API_SOCKCLNT_DELETE_REPLY);
      rp->handle = mp->handle;
      rp->response = htonl (1);

      vl_msg_api_send (regp, (u8 *) rp);

      clib_file_del (&file_main, file_main.file_pool + regp->clib_file_index);

      vl_free_socket_registration_index (mp->index);
    }
  else
    {
      clib_warning ("unknown client ID %d", mp->index);
    }
}

static clib_error_t *
send_fd_msg (int socket_fd, int fd_to_share)
{
  struct msghdr mh = { 0 };
  struct iovec iov[1];
  char ctl[CMSG_SPACE (sizeof (int))];
  char *msg = "memfd";
  int rv;

  iov[0].iov_base = msg;
  iov[0].iov_len = strlen (msg);
  mh.msg_iov = iov;
  mh.msg_iovlen = 1;

  struct cmsghdr *cmsg;
  memset (&ctl, 0, sizeof (ctl));
  mh.msg_control = ctl;
  mh.msg_controllen = sizeof (ctl);
  cmsg = CMSG_FIRSTHDR (&mh);
  cmsg->cmsg_len = CMSG_LEN (sizeof (int));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  memcpy (CMSG_DATA (cmsg), &fd_to_share, sizeof (int));

  rv = sendmsg (socket_fd, &mh, 0);
  if (rv < 0)
    return clib_error_return_unix (0, "sendmsg");
  return 0;
}

/*
 * Create a memory-fd segment.
 */
void
vl_api_memfd_segment_create_t_handler (vl_api_memfd_segment_create_t * mp)
{
  vl_api_memfd_segment_create_reply_t *rmp;
  api_main_t *am = &api_main;
  clib_file_t *cf;
  memfd_private_t _memfd_private, *memfd = &_memfd_private;
  vl_api_registration_t *regp;
  vlib_main_t *vm = vlib_get_main ();
  svm_map_region_args_t _args, *a = &_args;
  svm_region_t *vlib_rp;
  int rv;

  regp = vl_api_client_index_to_registration (mp->client_index);

  if (regp == 0)
    {
      clib_warning ("API client disconnected");
      return;
    }

  if (regp->registration_type != REGISTRATION_TYPE_SOCKET_SERVER)
    {
      rv = -31;			/* VNET_API_ERROR_INVALID_REGISTRATION */
      goto reply;
    }

  memset (memfd, 0, sizeof (*memfd));

  /* Embed in api_main_t */
  memfd->memfd_size = mp->requested_size;
  memfd->requested_va = 0ULL;
  memfd->i_am_master = 1;
  memfd->name = format (0, "%s%c", regp->name, 0);

  /* Set up a memfd segment of the requested size */
  rv = memfd_master_init (memfd, mp->client_index);

  if (rv)
    goto reply;

  /* Remember to close this fd when the socket connection goes away */
  vec_add1 (regp->additional_fds_to_close, memfd->fd);

  /* And create a plausible svm_region in it */
  memset (a, 0, sizeof (*a));
  a->baseva = memfd->sh->memfd_va + MMAP_PAGESIZE;
  a->size = memfd->memfd_size - MMAP_PAGESIZE;
  /* $$$$ might want a different config parameter */
  a->pvt_heap_size = am->api_pvt_heap_size;
  a->flags = SVM_FLAGS_MHEAP;
  svm_region_init_mapped_region (a, (svm_region_t *) a->baseva);

  vlib_rp = (svm_region_t *) a->baseva;

  /*
   * Part deux, initialize the svm_region_t shared-memory header
   * api allocation rings, and so on.
   */
  vl_init_shmem (vlib_rp, 1 /* is_vlib (dont-care) */ , 1 /* is_private */ );

  vec_add1 (am->vlib_private_rps, vlib_rp);

  memfd->sh->ready = 1;

  /* Recompute the set of input queues to poll in memclnt_process */
  vec_reset_length (vl_api_queue_cursizes);

reply:

  /* send the reply message */

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = htons (VL_API_MEMFD_SEGMENT_CREATE_REPLY);
  rmp->context = mp->context;
  rmp->retval = htonl (rv);

  vl_msg_api_send (regp, (u8 *) rmp);

  if (rv != 0)
    return;

  /*
   * We need the reply message to make it out the back door
   * before we send the magic fd message.
   */
  vlib_process_suspend (vm, 11e-6);

  cf = file_main.file_pool + regp->clib_file_index;

  /* send the magic "here's your sign (aka fd)" socket message */
  send_fd_msg (cf->file_descriptor, memfd->fd);
}

#define foreach_vlib_api_msg                    \
_(SOCKCLNT_CREATE, sockclnt_create)             \
_(SOCKCLNT_DELETE, sockclnt_delete)		\
_(MEMFD_SEGMENT_CREATE, memfd_segment_create)

clib_error_t *
socksvr_api_init (vlib_main_t * vm)
{
  clib_file_main_t *fm = &file_main;
  clib_file_t template = { 0 };
  vl_api_registration_t *rp;
  vl_msg_api_msg_config_t cfg;
  vl_msg_api_msg_config_t *c = &cfg;
  socket_main_t *sm = &socket_main;
  clib_socket_t *sock = &sm->socksvr_listen_socket;
  clib_error_t *error;

  /* If not explicitly configured, do not bind/enable, etc. */
  if (sm->socket_name == 0)
    return 0;

#define _(N,n) do {                                             \
    c->id = VL_API_##N;                                         \
    c->name = #n;                                               \
    c->handler = vl_api_##n##_t_handler;                        \
    c->cleanup = vl_noop_handler;                               \
    c->endian = vl_api_##n##_t_endian;                          \
    c->print = vl_api_##n##_t_print;                            \
    c->size = sizeof(vl_api_##n##_t);                           \
    c->traced = 1; /* trace, so these msgs print */             \
    c->replay = 0; /* don't replay client create/delete msgs */ \
    c->message_bounce = 0; /* don't bounce this message */	\
    vl_msg_api_config(c);} while (0);

  foreach_vlib_api_msg;
#undef _

  vec_resize (sm->input_buffer, 4096);

  sock->config = (char *) sm->socket_name;

  /* mkdir of file socket, only under /run  */
  if (strncmp (sock->config, "/run", 4) == 0)
    {
      u8 *tmp = format (0, "%s", sock->config);
      int i = vec_len (tmp);
      while (i && tmp[--i] != '/')
	;

      tmp[i] = 0;

      if (i)
	vlib_unix_recursive_mkdir ((char *) tmp);
      vec_free (tmp);
    }

  sock->flags = CLIB_SOCKET_F_IS_SERVER | CLIB_SOCKET_F_SEQPACKET |
    CLIB_SOCKET_F_ALLOW_GROUP_WRITE;
  error = clib_socket_init (sock);
  if (error)
    return error;

  pool_get (sm->registration_pool, rp);
  memset (rp, 0, sizeof (*rp));

  rp->registration_type = REGISTRATION_TYPE_SOCKET_LISTEN;

  template.read_function = socksvr_accept_ready;
  template.write_function = socksvr_bogus_write;
  template.file_descriptor = sock->fd;
  template.private_data = rp - sm->registration_pool;

  rp->clib_file_index = clib_file_add (fm, &template);
  return 0;
}

static clib_error_t *
socket_exit (vlib_main_t * vm)
{
  clib_file_main_t *fm = &file_main;
  socket_main_t *sm = &socket_main;
  vl_api_registration_t *rp;

  /* Defensive driving in case something wipes out early */
  if (sm->registration_pool)
    {
      u32 index;
        /* *INDENT-OFF* */
        pool_foreach (rp, sm->registration_pool, ({
            clib_file_del (fm, fm->file_pool + rp->clib_file_index);
            index = rp->vl_api_registration_pool_index;
            vl_free_socket_registration_index (index);
        }));
/* *INDENT-ON* */
    }

  return 0;
}

VLIB_MAIN_LOOP_EXIT_FUNCTION (socket_exit);

static clib_error_t *
socksvr_config (vlib_main_t * vm, unformat_input_t * input)
{
  socket_main_t *sm = &socket_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "socket-name %s", &sm->socket_name))
	;
      else if (unformat (input, "default"))
	{
	  sm->socket_name = format (0, "%s%c", API_SOCKET_FILE, 0);
	}
      else
	{
	  return clib_error_return (0, "unknown input '%U'",
				    format_unformat_error, input);
	}
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (socksvr_config, "socksvr");

clib_error_t *
vlibsocket_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (vlibsocket_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
