/*
 * mc_socket.c: socket based multicast for vlib mc
 *
 * Copyright (c) 2010 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vlib/unix/mc_socket.h>

#include <sys/ioctl.h>		/* for FIONBIO */
#include <netinet/tcp.h>	/* for TCP_NODELAY */
#include <net/if.h>		/* for struct ifreq */

static u8 *
format_socket_peer_id (u8 * s, va_list * args)
{
  u64 peer_id_as_u64 = va_arg (*args, u64);
  mc_peer_id_t peer_id;
  peer_id.as_u64 = peer_id_as_u64;
  u32 a = mc_socket_peer_id_get_address (peer_id);
  u32 p = mc_socket_peer_id_get_port (peer_id);

  s = format (s, "%U:%04x", format_network_address, AF_INET, &a, ntohs (p));

  return s;
}

typedef void (mc_msg_handler_t) (mc_main_t * mcm, void *msg,
				 u32 buffer_index);

always_inline void
msg_handler (mc_main_t * mcm,
	     u32 buffer_index, u32 handler_frees_buffer, void *_h)
{
  vlib_main_t *vm = mcm->vlib_main;
  mc_msg_handler_t *h = _h;
  vlib_buffer_t *b = vlib_get_buffer (vm, buffer_index);
  void *the_msg = vlib_buffer_get_current (b);

  h (mcm, the_msg, buffer_index);
  if (!handler_frees_buffer)
    vlib_buffer_free_one (vm, buffer_index);
}

static uword
append_buffer_index_to_iovec (vlib_main_t * vm,
			      u32 buffer_index, struct iovec **iovs_return)
{
  struct iovec *i;
  vlib_buffer_t *b;
  u32 bi = buffer_index;
  u32 l = 0;

  while (1)
    {
      b = vlib_get_buffer (vm, bi);
      vec_add2 (*iovs_return, i, 1);
      i->iov_base = vlib_buffer_get_current (b);
      i->iov_len = b->current_length;
      l += i->iov_len;
      if (!(b->flags & VLIB_BUFFER_NEXT_PRESENT))
	break;
      bi = b->next_buffer;
    }

  return l;
}

static clib_error_t *
sendmsg_helper (mc_socket_main_t * msm,
		int socket, struct sockaddr_in *tx_addr, u32 buffer_index)
{
  vlib_main_t *vm = msm->mc_main.vlib_main;
  struct msghdr h;
  word n_bytes, n_bytes_tx, n_retries;

  clib_memset (&h, 0, sizeof (h));
  h.msg_name = tx_addr;
  h.msg_namelen = sizeof (tx_addr[0]);

  if (msm->iovecs)
    _vec_len (msm->iovecs) = 0;

  n_bytes = append_buffer_index_to_iovec (vm, buffer_index, &msm->iovecs);
  ASSERT (n_bytes <= msm->mc_main.transport.max_packet_size);
  if (n_bytes > msm->mc_main.transport.max_packet_size)
    clib_error ("sending packet larger than interface MTU %d bytes", n_bytes);

  h.msg_iov = msm->iovecs;
  h.msg_iovlen = vec_len (msm->iovecs);

  n_retries = 0;
  while ((n_bytes_tx = sendmsg (socket, &h, /* flags */ 0)) != n_bytes
	 && errno == EAGAIN)
    n_retries++;
  if (n_bytes_tx != n_bytes)
    {
      clib_unix_warning ("sendmsg");
      return 0;
    }
  if (n_retries)
    {
      ELOG_TYPE_DECLARE (e) =
      {
      .format = "sendmsg-helper: %d retries",.format_args = "i4",};
      struct
      {
	u32 retries;
      } *ed = 0;

      ed = ELOG_DATA (&vm->elog_main, e);
      ed->retries = n_retries;
    }
  return 0;
}

static clib_error_t *
tx_buffer (void *transport, mc_transport_type_t type, u32 buffer_index)
{
  mc_socket_main_t *msm = (mc_socket_main_t *) transport;
  vlib_main_t *vm = msm->mc_main.vlib_main;
  mc_multicast_socket_t *ms = &msm->multicast_sockets[type];
  clib_error_t *error;
  error = sendmsg_helper (msm, ms->socket, &ms->tx_addr, buffer_index);
  if (type != MC_TRANSPORT_USER_REQUEST_TO_RELAY)
    vlib_buffer_free_one (vm, buffer_index);
  return error;
}

static clib_error_t *
tx_ack (void *transport, mc_peer_id_t dest_peer_id, u32 buffer_index)
{
  struct sockaddr_in tx_addr;
  mc_socket_main_t *msm = (mc_socket_main_t *) transport;
  vlib_main_t *vm = msm->mc_main.vlib_main;
  clib_error_t *error;

  clib_memset (&tx_addr, 0, sizeof (tx_addr));
  tx_addr.sin_family = AF_INET;
  tx_addr.sin_addr.s_addr = mc_socket_peer_id_get_address (dest_peer_id);
  tx_addr.sin_port = mc_socket_peer_id_get_port (dest_peer_id);

  error = sendmsg_helper (msm, msm->ack_socket, &tx_addr, buffer_index);
  vlib_buffer_free_one (vm, buffer_index);
  return error;
}

static clib_error_t *
recvmsg_helper (mc_socket_main_t * msm,
		int socket,
		struct sockaddr_in *rx_addr,
		u32 * buffer_index, u32 drop_message)
{
  vlib_main_t *vm = msm->mc_main.vlib_main;
  vlib_buffer_t *b;
  uword n_left, n_alloc, n_mtu, i, i_rx;
  const uword buffer_size = vlib_buffer_get_default_data_size (vm);
  word n_bytes_left;

  /* Make sure we have at least a MTU worth of buffers. */
  n_mtu = msm->rx_mtu_n_buffers;
  n_left = vec_len (msm->rx_buffers);
  if (n_left < n_mtu)
    {
      uword max_alloc = 8 * n_mtu;
      vec_validate (msm->rx_buffers, max_alloc - 1);
      n_alloc =
	vlib_buffer_alloc (vm, msm->rx_buffers + n_left, max_alloc - n_left);
      _vec_len (msm->rx_buffers) = n_left + n_alloc;
    }

  ASSERT (vec_len (msm->rx_buffers) >= n_mtu);
  vec_validate (msm->iovecs, n_mtu - 1);

  /* Allocate RX buffers from end of rx_buffers.
     Turn them into iovecs to pass to readv. */
  i_rx = vec_len (msm->rx_buffers) - 1;
  for (i = 0; i < n_mtu; i++)
    {
      b = vlib_get_buffer (vm, msm->rx_buffers[i_rx - i]);
      msm->iovecs[i].iov_base = b->data;
      msm->iovecs[i].iov_len = buffer_size;
    }
  _vec_len (msm->iovecs) = n_mtu;

  {
    struct msghdr h;

    clib_memset (&h, 0, sizeof (h));
    if (rx_addr)
      {
	h.msg_name = rx_addr;
	h.msg_namelen = sizeof (rx_addr[0]);
      }
    h.msg_iov = msm->iovecs;
    h.msg_iovlen = vec_len (msm->iovecs);

    n_bytes_left = recvmsg (socket, &h, 0);
    if (n_bytes_left < 0)
      return clib_error_return_unix (0, "recvmsg");
  }

  if (drop_message)
    {
      *buffer_index = ~0;
      return 0;
    }

  *buffer_index = msm->rx_buffers[i_rx];
  while (1)
    {
      b = vlib_get_buffer (vm, msm->rx_buffers[i_rx]);

      b->flags = 0;
      b->current_data = 0;
      b->current_length =
	n_bytes_left < buffer_size ? n_bytes_left : buffer_size;

      n_bytes_left -= buffer_size;

      if (n_bytes_left <= 0)
	break;

      i_rx--;
      b->flags |= VLIB_BUFFER_NEXT_PRESENT;
      b->next_buffer = msm->rx_buffers[i_rx];
    }

  _vec_len (msm->rx_buffers) = i_rx;

  return 0 /* no error */ ;
}

static clib_error_t *
mastership_socket_read_ready (clib_file_t * uf)
{
  mc_socket_main_t *msm = (mc_socket_main_t *) uf->private_data;
  mc_main_t *mcm = &msm->mc_main;
  mc_multicast_socket_t *ms =
    &msm->multicast_sockets[MC_TRANSPORT_MASTERSHIP];
  clib_error_t *error;
  u32 bi = 0;

  error = recvmsg_helper (msm, ms->socket, /* rx_addr */ 0, &bi,	/* drop_message */
			  0);
  if (!error)
    msg_handler (mcm, bi,
		 /* handler_frees_buffer */ 0,
		 mc_msg_master_assert_handler);

  return error;
}

static clib_error_t *
to_relay_socket_read_ready (clib_file_t * uf)
{
  mc_socket_main_t *msm = (mc_socket_main_t *) uf->private_data;
  mc_main_t *mcm = &msm->mc_main;
  vlib_main_t *vm = msm->mc_main.vlib_main;
  mc_multicast_socket_t *ms_to_relay =
    &msm->multicast_sockets[MC_TRANSPORT_USER_REQUEST_TO_RELAY];
  mc_multicast_socket_t *ms_from_relay =
    &msm->multicast_sockets[MC_TRANSPORT_USER_REQUEST_FROM_RELAY];
  clib_error_t *error;
  u32 bi = 0;
  u32 is_master = mcm->relay_state == MC_RELAY_STATE_MASTER;

  /* Not the ordering master? Turf the msg */
  error = recvmsg_helper (msm, ms_to_relay->socket, /* rx_addr */ 0, &bi,
			  /* drop_message */ !is_master);

  /* If we are the master, number and rebroadcast the msg. */
  if (!error && is_master)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
      mc_msg_user_request_t *mp = vlib_buffer_get_current (b);
      mp->global_sequence = clib_host_to_net_u32 (mcm->relay_global_sequence);
      mcm->relay_global_sequence++;
      error =
	sendmsg_helper (msm, ms_from_relay->socket, &ms_from_relay->tx_addr,
			bi);
      vlib_buffer_free_one (vm, bi);
    }

  return error;
}

static clib_error_t *
from_relay_socket_read_ready (clib_file_t * uf)
{
  mc_socket_main_t *msm = (mc_socket_main_t *) uf->private_data;
  mc_main_t *mcm = &msm->mc_main;
  mc_multicast_socket_t *ms =
    &msm->multicast_sockets[MC_TRANSPORT_USER_REQUEST_FROM_RELAY];
  clib_error_t *error;
  u32 bi = 0;

  error = recvmsg_helper (msm, ms->socket, /* rx_addr */ 0, &bi,	/* drop_message */
			  0);
  if (!error)
    {
      msg_handler (mcm, bi, /* handler_frees_buffer */ 1,
		   mc_msg_user_request_handler);
    }
  return error;
}

static clib_error_t *
join_socket_read_ready (clib_file_t * uf)
{
  mc_socket_main_t *msm = (mc_socket_main_t *) uf->private_data;
  mc_main_t *mcm = &msm->mc_main;
  vlib_main_t *vm = mcm->vlib_main;
  mc_multicast_socket_t *ms = &msm->multicast_sockets[MC_TRANSPORT_JOIN];
  clib_error_t *error;
  u32 bi = 0;

  error = recvmsg_helper (msm, ms->socket, /* rx_addr */ 0, &bi,	/* drop_message */
			  0);
  if (!error)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
      mc_msg_join_or_leave_request_t *mp = vlib_buffer_get_current (b);

      switch (clib_host_to_net_u32 (mp->type))
	{
	case MC_MSG_TYPE_join_or_leave_request:
	  msg_handler (mcm, bi, /* handler_frees_buffer */ 0,
		       mc_msg_join_or_leave_request_handler);
	  break;

	case MC_MSG_TYPE_join_reply:
	  msg_handler (mcm, bi, /* handler_frees_buffer */ 0,
		       mc_msg_join_reply_handler);
	  break;

	default:
	  ASSERT (0);
	  break;
	}
    }
  return error;
}

static clib_error_t *
ack_socket_read_ready (clib_file_t * uf)
{
  mc_socket_main_t *msm = (mc_socket_main_t *) uf->private_data;
  mc_main_t *mcm = &msm->mc_main;
  clib_error_t *error;
  u32 bi = 0;

  error = recvmsg_helper (msm, msm->ack_socket, /* rx_addr */ 0, &bi,
			  /* drop_message */ 0);
  if (!error)
    msg_handler (mcm, bi, /* handler_frees_buffer */ 0,
		 mc_msg_user_ack_handler);
  return error;
}

static void
catchup_cleanup (mc_socket_main_t * msm,
		 mc_socket_catchup_t * c, clib_file_main_t * um,
		 clib_file_t * uf)
{
  hash_unset (msm->catchup_index_by_file_descriptor, uf->file_descriptor);
  clib_file_del (um, uf);
  vec_free (c->input_vector);
  vec_free (c->output_vector);
  pool_put (msm->catchups, c);
}

static mc_socket_catchup_t *
find_catchup_from_file_descriptor (mc_socket_main_t * msm,
				   int file_descriptor)
{
  uword *p =
    hash_get (msm->catchup_index_by_file_descriptor, file_descriptor);
  return p ? pool_elt_at_index (msm->catchups, p[0]) : 0;
}

static clib_error_t *
catchup_socket_read_ready (clib_file_t * uf, int is_server)
{
  clib_file_main_t *um = &file_main;
  mc_socket_main_t *msm = (mc_socket_main_t *) uf->private_data;
  mc_main_t *mcm = &msm->mc_main;
  mc_socket_catchup_t *c =
    find_catchup_from_file_descriptor (msm, uf->file_descriptor);
  word l, n, is_eof;

  l = vec_len (c->input_vector);
  vec_resize (c->input_vector, 4096);
  n =
    read (uf->file_descriptor, c->input_vector + l,
	  vec_len (c->input_vector) - l);
  is_eof = n == 0;

  if (n < 0)
    {
      if (errno == EAGAIN)
	n = 0;
      else
	{
	  catchup_cleanup (msm, c, um, uf);
	  return clib_error_return_unix (0, "read");
	}
    }

  _vec_len (c->input_vector) = l + n;

  if (is_eof && vec_len (c->input_vector) > 0)
    {
      if (is_server)
	{
	  mc_msg_catchup_request_handler (mcm, (void *) c->input_vector,
					  c - msm->catchups);
	  _vec_len (c->input_vector) = 0;
	}
      else
	{
	  mc_msg_catchup_reply_handler (mcm, (void *) c->input_vector,
					c - msm->catchups);
	  c->input_vector = 0;	/* reply handler is responsible for freeing vector */
	  catchup_cleanup (msm, c, um, uf);
	}
    }

  return 0 /* no error */ ;
}

static clib_error_t *
catchup_server_read_ready (clib_file_t * uf)
{
  return catchup_socket_read_ready (uf, /* is_server */ 1);
}

static clib_error_t *
catchup_client_read_ready (clib_file_t * uf)
{
  if (MC_EVENT_LOGGING)
    {
      mc_socket_main_t *msm = (mc_socket_main_t *) uf->private_data;
      vlib_main_t *vm = msm->mc_main.vlib_main;

      ELOG_TYPE (e, "catchup_client_read_ready");
      ELOG (&vm->elog_main, e, 0);
    }
  return catchup_socket_read_ready (uf, /* is_server */ 0);
}

static clib_error_t *
catchup_socket_write_ready (clib_file_t * uf, int is_server)
{
  clib_file_main_t *um = &file_main;
  mc_socket_main_t *msm = (mc_socket_main_t *) uf->private_data;
  mc_socket_catchup_t *c =
    find_catchup_from_file_descriptor (msm, uf->file_descriptor);
  clib_error_t *error = 0;
  int n;

  if (c->connect_in_progress)
    {
      u32 len, value;

      c->connect_in_progress = 0;
      len = sizeof (value);
      if (getsockopt (c->socket, SOL_SOCKET, SO_ERROR, &value, &len) < 0)
	{
	  error = clib_error_return_unix (0, "getsockopt SO_ERROR");
	  goto error_quit;
	}
      if (value != 0)
	{
	  error =
	    clib_error_return_code (0, value, CLIB_ERROR_ERRNO_VALID,
				    "connect fails");
	  goto error_quit;
	}
    }

  while (1)
    {
      u32 n_this_write;

      n_this_write =
	clib_min (vec_len (c->output_vector) - c->output_vector_n_written,
		  msm->rx_mtu_n_bytes -
		  64 /* ip + tcp + option allowance */ );

      if (n_this_write <= 0)
	break;

      do
	{
	  n = write (uf->file_descriptor,
		     c->output_vector + c->output_vector_n_written,
		     n_this_write);
	}
      while (n < 0 && errno == EAGAIN);

      if (n < 0)
	{
	  error = clib_error_return_unix (0, "write");
	  goto error_quit;
	}
      c->output_vector_n_written += n;
    }

  if (c->output_vector_n_written >= vec_len (c->output_vector))
    {
      if (!is_server)
	{
	  uf->flags &= ~UNIX_FILE_DATA_AVAILABLE_TO_WRITE;
	  file_main.file_update (uf, UNIX_FILE_UPDATE_MODIFY);
	  /* Send EOF to other side. */
	  shutdown (uf->file_descriptor, SHUT_WR);
	  return error;
	}
      else
	{
	error_quit:
	  catchup_cleanup (msm, c, um, uf);
	}
    }
  return error;
}

static clib_error_t *
catchup_server_write_ready (clib_file_t * uf)
{
  return catchup_socket_write_ready (uf, /* is_server */ 1);
}

static clib_error_t *
catchup_client_write_ready (clib_file_t * uf)
{
  return catchup_socket_write_ready (uf, /* is_server */ 0);
}

static clib_error_t *
catchup_socket_error_ready (clib_file_t * uf)
{
  clib_file_main_t *um = &file_main;
  mc_socket_main_t *msm = (mc_socket_main_t *) uf->private_data;
  mc_socket_catchup_t *c =
    find_catchup_from_file_descriptor (msm, uf->file_descriptor);
  catchup_cleanup (msm, c, um, uf);
  return clib_error_return (0, "error");
}

static clib_error_t *
catchup_listen_read_ready (clib_file_t * uf)
{
  mc_socket_main_t *msm = (mc_socket_main_t *) uf->private_data;
  struct sockaddr_in client_addr;
  int client_len;
  mc_socket_catchup_t *c;
  clib_file_t template = { 0 };

  pool_get (msm->catchups, c);
  clib_memset (c, 0, sizeof (c[0]));

  client_len = sizeof (client_addr);

  /* Acquires the non-blocking attrib from the server socket. */
  c->socket = accept (uf->file_descriptor,
		      (struct sockaddr *) &client_addr,
		      (socklen_t *) & client_len);

  if (c->socket < 0)
    {
      pool_put (msm->catchups, c);
      return clib_error_return_unix (0, "accept");
    }

  if (MC_EVENT_LOGGING)
    {
      mc_main_t *mcm = &msm->mc_main;
      vlib_main_t *vm = mcm->vlib_main;

      ELOG_TYPE_DECLARE (e) =
      {
      .format = "catchup accepted from 0x%lx",.format_args = "i4",};
      struct
      {
	u32 addr;
      } *ed = 0;

      ed = ELOG_DATA (&vm->elog_main, e);
      ed->addr = ntohl (client_addr.sin_addr.s_addr);
    }

  /* Disable the Nagle algorithm, ship catchup pkts immediately */
  {
    int one = 1;
    if ((setsockopt (c->socket, IPPROTO_TCP,
		     TCP_NODELAY, (void *) &one, sizeof (one))) < 0)
      {
	clib_unix_warning ("catchup socket: set TCP_NODELAY");
      }
  }

  template.read_function = catchup_server_read_ready;
  template.write_function = catchup_server_write_ready;
  template.error_function = catchup_socket_error_ready;
  template.file_descriptor = c->socket;
  template.description = format (0, "multicast catchup socket");
  template.private_data = pointer_to_uword (msm);
  c->clib_file_index = clib_file_add (&file_main, &template);
  hash_set (msm->catchup_index_by_file_descriptor, c->socket,
	    c - msm->catchups);

  return 0;
}

/* Return and bind to an unused port. */
static word
find_and_bind_to_free_port (word sock, word port)
{
  for (; port < 1 << 16; port++)
    {
      struct sockaddr_in a;

      clib_memset (&a, 0, sizeof (a));	/* Warnings be gone */

      a.sin_family = PF_INET;
      a.sin_addr.s_addr = INADDR_ANY;
      a.sin_port = htons (port);

      if (bind (sock, (struct sockaddr *) &a, sizeof (a)) >= 0)
	break;
    }

  return port < 1 << 16 ? port : -1;
}

static clib_error_t *
setup_mutlicast_socket (mc_socket_main_t * msm,
			mc_multicast_socket_t * ms,
			char *type, uword udp_port)
{
  int one = 1;
  struct ip_mreq mcast_req;

  if (!msm->multicast_ttl)
    msm->multicast_ttl = 1;

  /* mastership (multicast) TX socket */
  if ((ms->socket = socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    return clib_error_return_unix (0, "%s socket", type);

  {
    u8 ttl = msm->multicast_ttl;

    if ((setsockopt (ms->socket, IPPROTO_IP,
		     IP_MULTICAST_TTL, (void *) &ttl, sizeof (ttl))) < 0)
      return clib_error_return_unix (0, "%s set multicast ttl", type);
  }

  if (setsockopt (ms->socket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one)) <
      0)
    return clib_error_return_unix (0, "%s setsockopt SO_REUSEADDR", type);

  clib_memset (&ms->tx_addr, 0, sizeof (ms->tx_addr));
  ms->tx_addr.sin_family = AF_INET;
  ms->tx_addr.sin_addr.s_addr =
    htonl (msm->multicast_tx_ip4_address_host_byte_order);
  ms->tx_addr.sin_port = htons (udp_port);

  if (bind (ms->socket, (struct sockaddr *) &ms->tx_addr,
	    sizeof (ms->tx_addr)) < 0)
    return clib_error_return_unix (0, "%s bind", type);

  clib_memset (&mcast_req, 0, sizeof (mcast_req));
  mcast_req.imr_multiaddr.s_addr =
    htonl (msm->multicast_tx_ip4_address_host_byte_order);
  mcast_req.imr_interface.s_addr = msm->if_ip4_address_net_byte_order;

  if ((setsockopt (ms->socket, IPPROTO_IP,
		   IP_ADD_MEMBERSHIP, (void *) &mcast_req,
		   sizeof (mcast_req))) < 0)
    return clib_error_return_unix (0, "%s IP_ADD_MEMBERSHIP setsockopt",
				   type);

  if (ioctl (ms->socket, FIONBIO, &one) < 0)
    return clib_error_return_unix (0, "%s set FIONBIO", type);

  /* FIXME remove this when we support tx_ready. */
  {
    u32 len = 1 << 20;
    socklen_t sl = sizeof (len);
    if (setsockopt (ms->socket, SOL_SOCKET, SO_SNDBUF, &len, sl) < 0)
      clib_unix_error ("setsockopt");
  }

  return 0;
}

static clib_error_t *
socket_setup (mc_socket_main_t * msm)
{
  int one = 1;
  clib_error_t *error;
  u32 port;

  if (!msm->base_multicast_udp_port_host_byte_order)
    msm->base_multicast_udp_port_host_byte_order =
      0xffff - ((MC_N_TRANSPORT_TYPE + 2 /* ack socket, catchup socket */ )
		- 1);

  port = msm->base_multicast_udp_port_host_byte_order;

  error = setup_mutlicast_socket (msm,
				  &msm->multicast_sockets
				  [MC_TRANSPORT_MASTERSHIP], "mastership",
				  port++);
  if (error)
    return error;

  error = setup_mutlicast_socket (msm,
				  &msm->multicast_sockets[MC_TRANSPORT_JOIN],
				  "join", port++);
  if (error)
    return error;

  error = setup_mutlicast_socket (msm,
				  &msm->multicast_sockets
				  [MC_TRANSPORT_USER_REQUEST_TO_RELAY],
				  "to relay", port++);
  if (error)
    return error;

  error = setup_mutlicast_socket (msm,
				  &msm->multicast_sockets
				  [MC_TRANSPORT_USER_REQUEST_FROM_RELAY],
				  "from relay", port++);
  if (error)
    return error;

  /* ACK rx socket */
  msm->ack_socket = socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (msm->ack_socket < 0)
    return clib_error_return_unix (0, "ack socket");

  msm->ack_udp_port = find_and_bind_to_free_port (msm->ack_socket, port++);

  if (ioctl (msm->ack_socket, FIONBIO, &one) < 0)
    return clib_error_return_unix (0, "ack socket FIONBIO");

  msm->catchup_server_socket = socket (AF_INET, SOCK_STREAM, 0);
  if (msm->catchup_server_socket < 0)
    return clib_error_return_unix (0, "catchup server socket");

  msm->catchup_tcp_port =
    find_and_bind_to_free_port (msm->catchup_server_socket, port++);

  if (ioctl (msm->catchup_server_socket, FIONBIO, &one) < 0)
    return clib_error_return_unix (0, "catchup server socket FIONBIO");

  if (listen (msm->catchup_server_socket, 5) < 0)
    return clib_error_return_unix (0, "catchup server socket listen");

  /* epoll setup for multicast mastership socket */
  {
    clib_file_t template = { 0 };

    template.read_function = mastership_socket_read_ready;
    template.file_descriptor =
      msm->multicast_sockets[MC_TRANSPORT_MASTERSHIP].socket;
    template.private_data = (uword) msm;
    clib_file_add (&file_main, &template);

    /* epoll setup for multicast to_relay socket */
    template.read_function = to_relay_socket_read_ready;
    template.file_descriptor =
      msm->multicast_sockets[MC_TRANSPORT_USER_REQUEST_TO_RELAY].socket;
    template.private_data = (uword) msm;
    template.description = format (0, "multicast to_relay socket");
    clib_file_add (&file_main, &template);

    /* epoll setup for multicast from_relay socket */
    template.read_function = from_relay_socket_read_ready;
    template.file_descriptor =
      msm->multicast_sockets[MC_TRANSPORT_USER_REQUEST_FROM_RELAY].socket;
    template.private_data = (uword) msm;
    template.description = format (0, "multicast from_relay socket");
    clib_file_add (&file_main, &template);

    template.read_function = join_socket_read_ready;
    template.file_descriptor =
      msm->multicast_sockets[MC_TRANSPORT_JOIN].socket;
    template.private_data = (uword) msm;
    template.description = format (0, "multicast join socket");
    clib_file_add (&file_main, &template);

    /* epoll setup for ack rx socket */
    template.read_function = ack_socket_read_ready;
    template.file_descriptor = msm->ack_socket;
    template.private_data = (uword) msm;
    template.description = format (0, "multicast ack rx socket");
    clib_file_add (&file_main, &template);

    /* epoll setup for TCP catchup server */
    template.read_function = catchup_listen_read_ready;
    template.file_descriptor = msm->catchup_server_socket;
    template.private_data = (uword) msm;
    template.description = format (0, "multicast tcp catchup socket");
    clib_file_add (&file_main, &template);
  }

  return 0;
}

static void *
catchup_add_pending_output (mc_socket_catchup_t * c, uword n_bytes,
			    u8 * set_output_vector)
{
  clib_file_t *uf = pool_elt_at_index (file_main.file_pool,
				       c->clib_file_index);
  u8 *result = 0;

  if (set_output_vector)
    c->output_vector = set_output_vector;
  else
    vec_add2 (c->output_vector, result, n_bytes);
  if (vec_len (c->output_vector) > 0)
    {
      int skip_update = 0 != (uf->flags & UNIX_FILE_DATA_AVAILABLE_TO_WRITE);
      uf->flags |= UNIX_FILE_DATA_AVAILABLE_TO_WRITE;
      if (!skip_update)
	file_main.file_update (uf, UNIX_FILE_UPDATE_MODIFY);
    }
  return result;
}

static uword
catchup_request_fun (void *transport_main,
		     u32 stream_index, mc_peer_id_t catchup_peer_id)
{
  mc_socket_main_t *msm = (mc_socket_main_t *) transport_main;
  mc_main_t *mcm = &msm->mc_main;
  vlib_main_t *vm = mcm->vlib_main;
  mc_socket_catchup_t *c;
  struct sockaddr_in addr;
  clib_file_main_t *um = &file_main;
  int one = 1;

  pool_get (msm->catchups, c);
  clib_memset (c, 0, sizeof (*c));

  c->socket = socket (AF_INET, SOCK_STREAM, 0);
  if (c->socket < 0)
    {
      clib_unix_warning ("socket");
      return 0;
    }

  if (ioctl (c->socket, FIONBIO, &one) < 0)
    {
      clib_unix_warning ("FIONBIO");
      return 0;
    }

  clib_memset (&addr, 0, sizeof (addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = mc_socket_peer_id_get_address (catchup_peer_id);
  addr.sin_port = mc_socket_peer_id_get_port (catchup_peer_id);

  c->connect_in_progress = 1;

  if (MC_EVENT_LOGGING)
    {
      ELOG_TYPE_DECLARE (e) =
      {
      .format = "connecting to peer 0x%Lx",.format_args = "i8",};
      struct
      {
	u64 peer;
      } *ed;
      ed = ELOG_DATA (&vm->elog_main, e);
      ed->peer = catchup_peer_id.as_u64;
    }

  if (connect (c->socket, (const void *) &addr, sizeof (addr))
      < 0 && errno != EINPROGRESS)
    {
      clib_unix_warning ("connect to %U fails",
			 format_socket_peer_id, catchup_peer_id);
      return 0;
    }

  {
    clib_file_t template = { 0 };

    template.read_function = catchup_client_read_ready;
    template.write_function = catchup_client_write_ready;
    template.error_function = catchup_socket_error_ready;
    template.file_descriptor = c->socket;
    template.private_data = (uword) msm;
    template.description = format (0, "multicast socket");
    c->clib_file_index = clib_file_add (um, &template);

    hash_set (msm->catchup_index_by_file_descriptor, c->socket,
	      c - msm->catchups);
  }

  {
    mc_msg_catchup_request_t *mp;
    mp = catchup_add_pending_output (c, sizeof (mp[0]),	/* set_output_vector */
				     0);
    mp->peer_id = msm->mc_main.transport.our_catchup_peer_id;
    mp->stream_index = stream_index;
    mc_byte_swap_msg_catchup_request (mp);
  }

  return c - msm->catchups;
}

static void
catchup_send_fun (void *transport_main, uword opaque, u8 * data)
{
  mc_socket_main_t *msm = (mc_socket_main_t *) transport_main;
  mc_socket_catchup_t *c = pool_elt_at_index (msm->catchups, opaque);
  catchup_add_pending_output (c, 0, data);
}

static int
find_interface_ip4_address (char *if_name, u32 * ip4_address, u32 * mtu)
{
  int fd;
  struct ifreq ifr;
  struct sockaddr_in *sa;

  /* Dig up our IP address */
  fd = socket (PF_INET, AF_INET, 0);
  if (fd < 0)
    {
      clib_unix_error ("socket");
      return -1;
    }

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy (ifr.ifr_name, if_name, sizeof (ifr.ifr_name) - 1);
  if (ioctl (fd, SIOCGIFADDR, &ifr) < 0)
    {
      clib_unix_error ("ioctl(SIOCFIGADDR)");
      close (fd);
      return -1;
    }

  sa = (void *) &ifr.ifr_addr;
  clib_memcpy (ip4_address, &sa->sin_addr.s_addr, sizeof (ip4_address[0]));

  if (ioctl (fd, SIOCGIFMTU, &ifr) < 0)
    {
      close (fd);
      return -1;
    }
  if (mtu)
    *mtu = ifr.ifr_mtu - ( /* IP4 header */ 20 + /* UDP header */ 8);

  close (fd);

  return 0;
}

clib_error_t *
mc_socket_main_init (mc_socket_main_t * msm, char **intfc_probe_list,
		     int n_intfcs_to_probe)
{
  clib_error_t *error;
  mc_main_t *mcm;
  u32 mtu;

  mcm = &msm->mc_main;

  /* 239.255.0.7 */
  if (!msm->multicast_tx_ip4_address_host_byte_order)
    msm->multicast_tx_ip4_address_host_byte_order = 0xefff0007;

  {
    u32 i, a, win;

    win = 0;
    if (msm->multicast_interface_name)
      {
	win =
	  !find_interface_ip4_address (msm->multicast_interface_name, &a,
				       &mtu);
      }
    else
      {
	for (i = 0; i < n_intfcs_to_probe; i++)
	  if (!find_interface_ip4_address (intfc_probe_list[i], &a, &mtu))
	    {
	      win = 1;
	      msm->multicast_interface_name = intfc_probe_list[i];
	      break;
	    }
      }

    if (!win)
      return clib_error_return (0, "can't find interface ip4 address");

    msm->if_ip4_address_net_byte_order = a;
  }

  msm->rx_mtu_n_bytes = mtu;
  msm->rx_mtu_n_buffers =
    msm->rx_mtu_n_bytes / vlib_buffer_get_default_data_size (vm);
  msm->rx_mtu_n_buffers +=
    (msm->rx_mtu_n_bytes % vlib_buffer_get_default_data_size (vm)) != 0;

  error = socket_setup (msm);
  if (error)
    return error;

  mcm->transport.our_ack_peer_id =
    mc_socket_set_peer_id (msm->if_ip4_address_net_byte_order,
			   msm->ack_udp_port);

  mcm->transport.our_catchup_peer_id =
    mc_socket_set_peer_id (msm->if_ip4_address_net_byte_order,
			   msm->catchup_tcp_port);

  mcm->transport.tx_buffer = tx_buffer;
  mcm->transport.tx_ack = tx_ack;
  mcm->transport.catchup_request_fun = catchup_request_fun;
  mcm->transport.catchup_send_fun = catchup_send_fun;
  mcm->transport.format_peer_id = format_socket_peer_id;
  mcm->transport.opaque = msm;
  mcm->transport.max_packet_size = mtu;

  mc_main_init (mcm, "socket");

  return error;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
