/*
 *------------------------------------------------------------------
 * socket_api.c
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
#include <fcntl.h>
#include <sys/stat.h>

#include <vppinfra/byte_order.h>
#include <svm/ssvm.h>
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

socket_main_t socket_main;

#define SOCK_API_REG_HANDLE_BIT (1<<31)

static u32
sock_api_registration_handle (vl_api_registration_t * regp)
{
  ASSERT (regp->vl_api_registration_pool_index < SOCK_API_REG_HANDLE_BIT);
  return regp->vl_api_registration_pool_index | SOCK_API_REG_HANDLE_BIT;
}

static u32
socket_api_registration_handle_to_index (u32 reg_index)
{
  return (reg_index & ~SOCK_API_REG_HANDLE_BIT);
}

u8
vl_socket_api_registration_handle_is_valid (u32 reg_handle)
{
  return ((reg_handle & SOCK_API_REG_HANDLE_BIT) != 0);
}

void
vl_sock_api_dump_clients (vlib_main_t * vm, api_main_t * am)
{
  vl_api_registration_t *reg;
  socket_main_t *sm = &socket_main;
  clib_file_t *f;

  /*
   * Must have at least one active client, not counting the
   * REGISTRATION_TYPE_SOCKET_LISTEN bind/accept socket
   */
  if (pool_elts (sm->registration_pool) < 2)
    return;

  vlib_cli_output (vm, "Socket clients");
  vlib_cli_output (vm, "%20s %8s", "Name", "Fildesc");
    /* *INDENT-OFF* */
    pool_foreach (reg, sm->registration_pool,
    ({
        if (reg->registration_type == REGISTRATION_TYPE_SOCKET_SERVER) {
            f = vl_api_registration_file (reg);
            vlib_cli_output (vm, "%20s %8d", reg->name, f->file_descriptor);
        }
    }));
/* *INDENT-ON* */
}

vl_api_registration_t *
vl_socket_api_client_handle_to_registration (u32 handle)
{
  socket_main_t *sm = &socket_main;
  u32 index = socket_api_registration_handle_to_index (handle);
  if (pool_is_free_index (sm->registration_pool, index))
    {
#if DEBUG > 2
      clib_warning ("Invalid index %d\n", index);
#endif
      return 0;
    }
  return pool_elt_at_index (sm->registration_pool, index);
}

void
vl_socket_api_send (vl_api_registration_t * rp, u8 * elem)
{
#if CLIB_DEBUG > 1
  u32 output_length;
#endif
  socket_main_t *sm = &socket_main;
  u16 msg_id = ntohs (*(u16 *) elem);
  api_main_t *am = vlibapi_get_main ();
  msgbuf_t *mb = (msgbuf_t *) (elem - offsetof (msgbuf_t, data));
  vl_api_registration_t *sock_rp;
  clib_file_main_t *fm = &file_main;
  clib_error_t *error;
  clib_file_t *cf;

  cf = vl_api_registration_file (rp);
  ASSERT (rp->registration_type > REGISTRATION_TYPE_SHMEM);

  if (msg_id >= vec_len (am->api_trace_cfg))
    {
      clib_warning ("id out of range: %d", msg_id);
      vl_msg_api_free ((void *) elem);
      return;
    }

  sock_rp = pool_elt_at_index (sm->registration_pool,
			       rp->vl_api_registration_pool_index);
  ASSERT (sock_rp);

  /* Add the msgbuf_t to the output vector */
  vec_add (sock_rp->output_vector, (u8 *) mb, sizeof (*mb));

  /* Try to send the message and save any error like
   * we do in the input epoll loop */
  vec_add (sock_rp->output_vector, elem, ntohl (mb->data_len));
  error = clib_file_write (cf);
  unix_save_error (&unix_main, error);

  /* If we didn't finish sending everything, wait for tx space */
  if (vec_len (sock_rp->output_vector) > 0
      && !(cf->flags & UNIX_FILE_DATA_AVAILABLE_TO_WRITE))
    {
      cf->flags |= UNIX_FILE_DATA_AVAILABLE_TO_WRITE;
      fm->file_update (cf, UNIX_FILE_UPDATE_MODIFY);
    }

#if CLIB_DEBUG > 1
  output_length = sizeof (*mb) + ntohl (mb->data_len);
  clib_warning ("wrote %u bytes to fd %d", output_length,
		cf->file_descriptor);
#endif

  vl_msg_api_free ((void *) elem);
}

void
vl_socket_free_registration_index (u32 pool_index)
{
  int i;
  vl_api_registration_t *rp;
  void vl_api_call_reaper_functions (u32 client_index);

  if (pool_is_free_index (socket_main.registration_pool, pool_index))
    {
      clib_warning ("main pool index %d already free", pool_index);
      return;
    }
  rp = pool_elt_at_index (socket_main.registration_pool, pool_index);

  vl_api_call_reaper_functions (pool_index);

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
vl_socket_process_api_msg (vl_api_registration_t * rp, i8 * input_v)
{
  msgbuf_t *mbp = (msgbuf_t *) input_v;

  u8 *the_msg = (u8 *) (mbp->data);
  socket_main.current_rp = rp;
  vl_msg_api_socket_handler (the_msg);
  socket_main.current_rp = 0;
}

/*
 * Read function for API socket.
 *
 * Read data from socket, invoke SOCKET_READ_EVENT
 * for each fully read API message, return 0.
 * Store incomplete data for next invocation to continue.
 *
 * On severe read error, the file is closed.
 *
 * As reading is single threaded,
 * socket_main.input_buffer is used temporarily.
 * Even its length is modified, but always restored before return.
 *
 * Incomplete data is copied into a vector,
 * pointer saved in registration's unprocessed_input.
 */
clib_error_t *
vl_socket_read_ready (clib_file_t * uf)
{
  clib_file_main_t *fm = &file_main;
  vlib_main_t *vm = vlib_get_main ();
  vl_api_registration_t *rp;
  /* n is the size of data read to input_buffer */
  int n;
  /* msg_buffer vector can point to input_buffer or unprocessed_input */
  i8 *msg_buffer = 0;
  /* data_for_process is a vector containing one full message, incl msgbuf_t */
  u8 *data_for_process;
  /* msgbuf_len is the size of one message, including sizeof (msgbuf_t) */
  u32 msgbuf_len;
  u32 save_input_buffer_length = vec_len (socket_main.input_buffer);
  vl_socket_args_for_process_t *a;
  u32 reg_index = uf->private_data;

  rp = vl_socket_get_registration (reg_index);

  /* Ignore unprocessed_input for now, n describes input_buffer for now. */
  n = read (uf->file_descriptor, socket_main.input_buffer,
	    vec_len (socket_main.input_buffer));

  if (n <= 0)
    {
      if (errno != EAGAIN)
	{
	  /* Severe error, close the file. */
	  clib_file_del (fm, uf);
	  vl_socket_free_registration_index (reg_index);
	}
      /* EAGAIN means we do not close the file, but no data to process anyway. */
      return 0;
    }

  /* Fake smaller length teporarily, so input_buffer can be used as msg_buffer. */
  _vec_len (socket_main.input_buffer) = n;

  /*
   * Look for bugs here. This code is tricky because
   * data read from a stream socket does not honor message
   * boundaries. In the case of a long message (>4K bytes)
   * we have to do (at least) 2 reads, etc.
   */
  /* Determine msg_buffer. */
  if (vec_len (rp->unprocessed_input))
    {
      vec_append (rp->unprocessed_input, socket_main.input_buffer);
      msg_buffer = rp->unprocessed_input;
    }
  else
    {
      msg_buffer = socket_main.input_buffer;
    }
  /* Loop to process any full messages. */
  ASSERT (vec_len (msg_buffer) > 0);
  do
    {
      /* Here, we are not sure how big a chunk of message we have left. */
      /* Do we at least know how big the full message will be? */
      if (vec_len (msg_buffer) <= sizeof (msgbuf_t))
	/* No, so fragment is not a full message. */
	goto save_and_split;

      /* Now we know how big the full message will be. */
      msgbuf_len =
	ntohl (((msgbuf_t *) msg_buffer)->data_len) + sizeof (msgbuf_t);

      /* But do we have a full message? */
      if (msgbuf_len > vec_len (msg_buffer))
	{
	save_and_split:
	  /* We don't have the entire message yet. */
	  /* If msg_buffer is unprocessed_input, nothing needs to be done. */
	  if (msg_buffer == socket_main.input_buffer)
	    /* But if we were using the input buffer, save the fragment. */
	    {
	      ASSERT (vec_len (rp->unprocessed_input) == 0);
	      vec_validate (rp->unprocessed_input, vec_len (msg_buffer) - 1);
	      clib_memcpy_fast (rp->unprocessed_input, msg_buffer,
				vec_len (msg_buffer));
	      _vec_len (rp->unprocessed_input) = vec_len (msg_buffer);
	    }
	  /* No more full messages, restore original input_buffer length. */
	  _vec_len (socket_main.input_buffer) = save_input_buffer_length;
	  return 0;
	}

      /*
       * We have at least one full message.
       * But msg_buffer can contain more data, so copy one message data
       * so we can overwrite its length to what single message has.
       */
      data_for_process = (u8 *) vec_dup (msg_buffer);
      _vec_len (data_for_process) = msgbuf_len;
      /* Everything is ready to signal the SOCKET_READ_EVENT. */
      pool_get (socket_main.process_args, a);
      a->reg_index = reg_index;
      a->data = data_for_process;

      vlib_process_signal_event (vm, vl_api_clnt_node.index,
				 SOCKET_READ_EVENT,
				 a - socket_main.process_args);
      if (vec_len (msg_buffer) > msgbuf_len)
	/* There are some fragments left. Shrink the msg_buffer to simplify logic. */
	vec_delete (msg_buffer, msgbuf_len, 0);
      else
	/* We are done with msg_buffer. */
	_vec_len (msg_buffer) = 0;
    }
  while (vec_len (msg_buffer) > 0);

  /* Restore input_buffer, it could have been msg_buffer. */
  _vec_len (socket_main.input_buffer) = save_input_buffer_length;
  return 0;
}

clib_error_t *
vl_socket_write_ready (clib_file_t * uf)
{
  clib_file_main_t *fm = &file_main;
  vl_api_registration_t *rp;
  int n;

  rp = pool_elt_at_index (socket_main.registration_pool, uf->private_data);

  /* Flush output vector. */
  size_t total_bytes = vec_len (rp->output_vector);
  size_t bytes_to_send, remaining_bytes = total_bytes;
  void *p = rp->output_vector;
  while (remaining_bytes > 0)
    {
      bytes_to_send = remaining_bytes > 4096 ? 4096 : remaining_bytes;
      n = write (uf->file_descriptor, p, bytes_to_send);
      if (n < 0)
	{
	  if (errno == EAGAIN)
	    {
	      break;
	    }
#if DEBUG > 2
	  clib_warning ("write error, close the file...\n");
#endif
	  clib_file_del (fm, uf);
	  vl_socket_free_registration_index (rp -
					     socket_main.registration_pool);
	  return 0;
	}
      remaining_bytes -= bytes_to_send;
      p += bytes_to_send;
    }

  vec_delete (rp->output_vector, total_bytes - remaining_bytes, 0);
  if (vec_len (rp->output_vector) <= 0
      && (uf->flags & UNIX_FILE_DATA_AVAILABLE_TO_WRITE))
    {
      uf->flags &= ~UNIX_FILE_DATA_AVAILABLE_TO_WRITE;
      fm->file_update (uf, UNIX_FILE_UPDATE_MODIFY);
    }

  return 0;
}

clib_error_t *
vl_socket_error_ready (clib_file_t * uf)
{
  vl_api_registration_t *rp;
  clib_file_main_t *fm = &file_main;

  rp = pool_elt_at_index (socket_main.registration_pool, uf->private_data);
  clib_file_del (fm, uf);
  vl_socket_free_registration_index (rp - socket_main.registration_pool);

  return 0;
}

void
socksvr_file_add (clib_file_main_t * fm, int fd)
{
  vl_api_registration_t *rp;
  clib_file_t template = { 0 };

  pool_get (socket_main.registration_pool, rp);
  clib_memset (rp, 0, sizeof (*rp));

  template.read_function = vl_socket_read_ready;
  template.write_function = vl_socket_write_ready;
  template.error_function = vl_socket_error_ready;
  template.file_descriptor = fd;
  template.description = format (0, "socksrv");
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
  api_main_t *am = vlibapi_get_main ();
  hash_pair_t *hp;
  int rv = 0;
  u32 nmsg = hash_elts (am->msg_index_by_name_and_crc);
  u32 i = 0;

  regp = socket_main.current_rp;

  ASSERT (regp->registration_type == REGISTRATION_TYPE_SOCKET_SERVER);

  regp->name = format (0, "%s%c", mp->name, 0);

  u32 size = sizeof (*rp) + (nmsg * sizeof (vl_api_message_table_entry_t));
  rp = vl_msg_api_alloc_zero (size);
  rp->_vl_msg_id = htons (VL_API_SOCKCLNT_CREATE_REPLY);
  rp->index = htonl (sock_api_registration_handle (regp));
  rp->context = mp->context;
  rp->response = htonl (rv);
  rp->count = htons (nmsg);

  /* *INDENT-OFF* */
  hash_foreach_pair (hp, am->msg_index_by_name_and_crc,
  ({
    rp->message_table[i].index = htons(hp->value[0]);
    (void) strncpy_s((char *)rp->message_table[i].name,
                     64 /* bytes of space at dst */,
                     (char *)hp->key,
                     64-1 /* chars to copy, without zero byte. */);
    i++;
  }));
  /* *INDENT-ON* */
  vl_api_send_msg (regp, (u8 *) rp);
}

/*
 * vl_api_sockclnt_delete_t_handler
 */
void
vl_api_sockclnt_delete_t_handler (vl_api_sockclnt_delete_t * mp)
{
  vl_api_registration_t *regp;
  vl_api_sockclnt_delete_reply_t *rp;

  regp = vl_api_client_index_to_registration (mp->client_index);
  if (!regp)
    return;

  u32 reg_index = socket_api_registration_handle_to_index (ntohl (mp->index));
  rp = vl_msg_api_alloc (sizeof (*rp));
  rp->_vl_msg_id = htons (VL_API_SOCKCLNT_DELETE_REPLY);
  rp->context = mp->context;

  if (!pool_is_free_index (socket_main.registration_pool, reg_index))
    {
      rp->response = htonl (1);
      vl_api_send_msg (regp, (u8 *) rp);

      vl_api_registration_del_file (regp);
      vl_socket_free_registration_index (reg_index);
    }
  else
    {
      clib_warning ("unknown client ID %d", reg_index);
      rp->response = htonl (-1);
      vl_api_send_msg (regp, (u8 *) rp);
    }
}

clib_error_t *
vl_sock_api_send_fd_msg (int socket_fd, int fds[], int n_fds)
{
  struct msghdr mh = { 0 };
  struct iovec iov[1];
  char ctl[CMSG_SPACE (sizeof (int) * n_fds)];
  struct cmsghdr *cmsg;
  char *msg = "fdmsg";
  int rv;

  iov[0].iov_base = msg;
  iov[0].iov_len = strlen (msg);
  mh.msg_iov = iov;
  mh.msg_iovlen = 1;

  clib_memset (&ctl, 0, sizeof (ctl));
  mh.msg_control = ctl;
  mh.msg_controllen = sizeof (ctl);
  cmsg = CMSG_FIRSTHDR (&mh);
  cmsg->cmsg_len = CMSG_LEN (sizeof (int) * n_fds);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  clib_memcpy_fast (CMSG_DATA (cmsg), fds, sizeof (int) * n_fds);

  while ((rv = sendmsg (socket_fd, &mh, 0)) < 0 && errno == EAGAIN)
    ;
  if (rv < 0)
    return clib_error_return_unix (0, "sendmsg");
  return 0;
}

vl_api_shm_elem_config_t *
vl_api_make_shm_config (vl_api_sock_init_shm_t * mp)
{
  vl_api_shm_elem_config_t *config = 0, *c;
  u64 cfg;
  int i;

  if (!mp->nitems)
    {
      vec_validate (config, 6);
      config[0].type = VL_API_VLIB_RING;
      config[0].size = 256;
      config[0].count = 32;

      config[1].type = VL_API_VLIB_RING;
      config[1].size = 1024;
      config[1].count = 16;

      config[2].type = VL_API_VLIB_RING;
      config[2].size = 4096;
      config[2].count = 2;

      config[3].type = VL_API_CLIENT_RING;
      config[3].size = 256;
      config[3].count = 32;

      config[4].type = VL_API_CLIENT_RING;
      config[4].size = 1024;
      config[4].count = 16;

      config[5].type = VL_API_CLIENT_RING;
      config[5].size = 4096;
      config[5].count = 2;

      config[6].type = VL_API_QUEUE;
      config[6].count = 128;
      config[6].size = sizeof (uword);
    }
  else
    {
      vec_validate (config, mp->nitems - 1);
      for (i = 0; i < mp->nitems; i++)
	{
	  cfg = mp->configs[i];
	  /* Pretty much a hack but it avoids defining our own api type
	   * in memclnt.api */
	  c = (vl_api_shm_elem_config_t *) & cfg;
	  config[i].type = c->type;
	  config[i].count = c->count;
	  config[i].size = c->size;
	}
    }
  return config;
}

/*
 * Bootstrap shm api using the socket api
 */
void
vl_api_sock_init_shm_t_handler (vl_api_sock_init_shm_t * mp)
{
  vl_api_sock_init_shm_reply_t *rmp;
  ssvm_private_t _memfd_private, *memfd = &_memfd_private;
  svm_map_region_args_t _args, *a = &_args;
  vl_api_registration_t *regp;
  api_main_t *am = vlibapi_get_main ();
  svm_region_t *vlib_rp;
  clib_file_t *cf;
  vl_api_shm_elem_config_t *config = 0;
  vl_shmem_hdr_t *shmem_hdr;
  int rv, tries = 1000;

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

  /*
   * Set up a memfd segment of the requested size wherein the
   * shmem data structures will be initialized
   */
  clib_memset (memfd, 0, sizeof (*memfd));
  memfd->ssvm_size = mp->requested_size;
  memfd->requested_va = 0ULL;
  memfd->is_server = 1;
  memfd->name = format (0, "%s%c", regp->name, 0);

  if ((rv = ssvm_server_init_memfd (memfd)))
    goto reply;

  /* delete the unused heap created in ssvm_server_init_memfd and mark it
   * accessible again for ASAN */
  clib_mem_destroy_heap (memfd->sh->heap);
  CLIB_MEM_UNPOISON ((void *) memfd->sh->ssvm_va, memfd->ssvm_size);

  /* Remember to close this fd when the socket connection goes away */
  vec_add1 (regp->additional_fds_to_close, memfd->fd);

  /*
   * Create a plausible svm_region in the memfd backed segment
   */
  clib_memset (a, 0, sizeof (*a));
  a->baseva = memfd->sh->ssvm_va + MMAP_PAGESIZE;
  a->size = memfd->ssvm_size - MMAP_PAGESIZE;
  /* $$$$ might want a different config parameter */
  a->pvt_heap_size = am->api_pvt_heap_size;
  a->flags = SVM_FLAGS_MHEAP;
  svm_region_init_mapped_region (a, (svm_region_t *) a->baseva);

  /*
   * Part deux, initialize the svm_region_t shared-memory header
   * api allocation rings, and so on.
   */
  config = vl_api_make_shm_config (mp);
  vlib_rp = (svm_region_t *) a->baseva;
  vl_init_shmem (vlib_rp, config, 1 /* is_vlib (dont-care) */ ,
		 1 /* is_private */ );

  /* Remember who created this. Needs to be post vl_init_shmem */
  shmem_hdr = (vl_shmem_hdr_t *) vlib_rp->user_ctx;
  shmem_hdr->clib_file_index = vl_api_registration_file_index (regp);

  vec_add1 (am->vlib_private_rps, vlib_rp);
  memfd->sh->ready = 1;
  vec_free (config);

  /* Recompute the set of input queues to poll in memclnt_process */
  vec_reset_length (vl_api_queue_cursizes);

reply:

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = htons (VL_API_SOCK_INIT_SHM_REPLY);
  rmp->context = mp->context;
  rmp->retval = htonl (rv);

  /*
   * Note: The reply message needs to make it out the back door
   * before we send the magic fd message. That's taken care of by
   * the send function.
   */
  vl_socket_api_send (regp, (u8 *) rmp);

  if (rv != 0)
    return;

  /* Send the magic "here's your sign (aka fd)" socket message */
  cf = vl_api_registration_file (regp);

  /* Wait for reply to be consumed before sending the fd */
  while (tries-- > 0)
    {
      int bytes;
      rv = ioctl (cf->file_descriptor, TIOCOUTQ, &bytes);
      if (rv < 0)
	{
	  clib_unix_warning ("ioctl returned");
	  break;
	}
      if (bytes == 0)
	break;
      usleep (1e3);
    }

  vl_sock_api_send_fd_msg (cf->file_descriptor, &memfd->fd, 1);
}

#define foreach_vlib_api_msg                    	\
  _(SOCKCLNT_CREATE, sockclnt_create, 1)             	\
  _(SOCKCLNT_DELETE, sockclnt_delete, 1)		\
  _(SOCK_INIT_SHM, sock_init_shm, 1)

clib_error_t *
vl_sock_api_init (vlib_main_t * vm)
{
  clib_file_main_t *fm = &file_main;
  clib_file_t template = { 0 };
  vl_api_registration_t *rp;
  socket_main_t *sm = &socket_main;
  clib_socket_t *sock = &sm->socksvr_listen_socket;
  clib_error_t *error;

  /* If not explicitly configured, do not bind/enable, etc. */
  if (sm->socket_name == 0)
    return 0;

#define _(N,n,t)						\
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), t);
  foreach_vlib_api_msg;
#undef _

  vec_resize (sm->input_buffer, 4096);

  sock->config = (char *) sm->socket_name;
  sock->flags = CLIB_SOCKET_F_IS_SERVER | CLIB_SOCKET_F_ALLOW_GROUP_WRITE;
  error = clib_socket_init (sock);
  if (error)
    return error;

  pool_get (sm->registration_pool, rp);
  clib_memset (rp, 0, sizeof (*rp));

  rp->registration_type = REGISTRATION_TYPE_SOCKET_LISTEN;

  template.read_function = socksvr_accept_ready;
  template.write_function = socksvr_bogus_write;
  template.file_descriptor = sock->fd;
  template.description = format (0, "socksvr %s", sock->config);
  template.private_data = rp - sm->registration_pool;

  rp->clib_file_index = clib_file_add (fm, &template);
  return 0;
}

static clib_error_t *
socket_exit (vlib_main_t * vm)
{
  socket_main_t *sm = &socket_main;
  vl_api_registration_t *rp;

  /* Defensive driving in case something wipes out early */
  if (sm->registration_pool)
    {
      u32 index;
        /* *INDENT-OFF* */
        pool_foreach (rp, sm->registration_pool, ({
          vl_api_registration_del_file (rp);
          index = rp->vl_api_registration_pool_index;
          vl_socket_free_registration_index (index);
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
      /* DEPRECATE: default keyword is ignored */
      else if (unformat (input, "default"))
	;
      else
	{
	  return clib_error_return (0, "unknown input '%U'",
				    format_unformat_error, input);
	}
    }

  if (!vec_len (sm->socket_name))
    sm->socket_name = format (0, "%s/%s", vlib_unix_get_runtime_dir (),
			      API_SOCKET_FILENAME);
  vec_terminate_c_string (sm->socket_name);

  return 0;
}

VLIB_CONFIG_FUNCTION (socksvr_config, "socksvr");

void
vlibsocket_reference ()
{
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
