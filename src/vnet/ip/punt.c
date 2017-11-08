/*
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
 */

/**
 * @file
 * @brief Local TCP/IP stack punt infrastructure.
 *
 * Provides a set of VPP nodes together with the relevant APIs and CLI
 * commands in order to adjust and dispatch packets from the VPP data plane
 * to the local TCP/IP stack
 */

#include <vnet/ip/ip.h>
#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <vnet/udp/udp.h>
#include <vnet/tcp/tcp.h>
#include <vnet/ip/punt.h>
#include <vppinfra/sparse_vec.h>
#include <vlib/unix/unix.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <stdbool.h>

#define foreach_punt_next			\
  _ (PUNT, "error-punt")

typedef enum
{
#define _(s,n) PUNT_NEXT_##s,
  foreach_punt_next
#undef _
    PUNT_N_NEXT,
} punt_next_t;

enum punt_socket_rx_next_e
{
  PUNT_SOCKET_RX_NEXT_INTERFACE_OUTPUT,
  PUNT_SOCKET_RX_NEXT_IP4_LOOKUP,
  PUNT_SOCKET_RX_NEXT_IP6_LOOKUP,
  PUNT_SOCKET_RX_N_NEXT
};

vlib_node_registration_t udp4_punt_node;
vlib_node_registration_t udp6_punt_node;
vlib_node_registration_t udp4_punt_socket_node;
vlib_node_registration_t udp6_punt_socket_node;
static vlib_node_registration_t punt_socket_rx_node;

punt_main_t punt_main;

char *
vnet_punt_get_server_pathname (void)
{
  punt_main_t *pm = &punt_main;
  return pm->sun_path;
}

/** @brief IPv4/IPv6 UDP punt node main loop.

    This is the main loop inline function for IPv4/IPv6 UDP punt
    transition node.

    @param vm vlib_main_t corresponding to the current thread
    @param node vlib_node_runtime_t
    @param frame vlib_frame_t whose contents should be dispatched
    @param is_ipv4 indicates if called for IPv4 or IPv6 node
*/
always_inline uword
udp46_punt_inline (vlib_main_t * vm,
		   vlib_node_runtime_t * node,
		   vlib_frame_t * from_frame, int is_ip4)
{
  u32 n_left_from, *from, *to_next;
  word advance;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  /* udp[46]_lookup hands us the data payload, not the IP header */
  if (is_ip4)
    advance = -(sizeof (ip4_header_t) + sizeof (udp_header_t));
  else
    advance = -(sizeof (ip6_header_t) + sizeof (udp_header_t));

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, PUNT_NEXT_PUNT, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  vlib_buffer_advance (b0, advance);
	  b0->error = node->errors[PUNT_ERROR_UDP_PORT];
	}

      vlib_put_next_frame (vm, node, PUNT_NEXT_PUNT, n_left_to_next);
    }

  return from_frame->n_vectors;
}

static char *punt_error_strings[] = {
#define punt_error(n,s) s,
#include "punt_error.def"
#undef punt_error
};

/** @brief IPv4 UDP punt node.
    @node ip4-udp-punt

    This is the IPv4 UDP punt transition node. It is registered as a next
    node for the "ip4-udp-lookup" handling UDP port(s) requested for punt.
    The buffer's current data pointer is adjusted to the original packet
    IPv4 header. All buffers are dispatched to "error-punt".

    @param vm vlib_main_t corresponding to the current thread
    @param node vlib_node_runtime_t
    @param frame vlib_frame_t whose contents should be dispatched

    @par Graph mechanics: next index usage

    @em Sets:
    - <code>vnet_buffer(b)->current_data</code>
    - <code>vnet_buffer(b)->current_len</code>

    <em>Next Index:</em>
    - Dispatches the packet to the "error-punt" node
*/
static uword
udp4_punt (vlib_main_t * vm,
	   vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return udp46_punt_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}

/** @brief IPv6 UDP punt node.
    @node ip6-udp-punt

    This is the IPv6 UDP punt transition node. It is registered as a next
    node for the "ip6-udp-lookup" handling UDP port(s) requested for punt.
    The buffer's current data pointer is adjusted to the original packet
    IPv6 header. All buffers are dispatched to "error-punt".

    @param vm vlib_main_t corresponding to the current thread
    @param node vlib_node_runtime_t
    @param frame vlib_frame_t whose contents should be dispatched

    @par Graph mechanics: next index usage

    @em Sets:
    - <code>vnet_buffer(b)->current_data</code>
    - <code>vnet_buffer(b)->current_len</code>

    <em>Next Index:</em>
    - Dispatches the packet to the "error-punt" node
*/
static uword
udp6_punt (vlib_main_t * vm,
	   vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return udp46_punt_inline (vm, node, from_frame, 0 /* is_ip4 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (udp4_punt_node) = {
  .function = udp4_punt,
  .name = "ip4-udp-punt",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = PUNT_N_ERROR,
  .error_strings = punt_error_strings,

  .n_next_nodes = PUNT_N_NEXT,
  .next_nodes = {
#define _(s,n) [PUNT_NEXT_##s] = n,
     foreach_punt_next
#undef _
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (udp4_punt_node, udp4_punt);

VLIB_REGISTER_NODE (udp6_punt_node) = {
  .function = udp6_punt,
  .name = "ip6-udp-punt",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = PUNT_N_ERROR,
  .error_strings = punt_error_strings,

  .n_next_nodes = PUNT_N_NEXT,
  .next_nodes = {
#define _(s,n) [PUNT_NEXT_##s] = n,
     foreach_punt_next
#undef _
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (udp6_punt_node, udp6_punt);;

/* *INDENT-ON* */

static punt_client_t *
punt_client_get (bool is_ip4, u16 port)
{
  punt_main_t *pm = &punt_main;
  punt_client_t *v =
    is_ip4 ? pm->clients_by_dst_port4 : pm->clients_by_dst_port6;

  u16 i = sparse_vec_index (v, port);
  if (i == SPARSE_VEC_INVALID_INDEX)
    return 0;

  return &vec_elt (v, i);
}

static struct sockaddr_un *
punt_socket_get (bool is_ip4, u16 port)
{
  punt_client_t *v = punt_client_get (is_ip4, port);
  if (v)
    return &v->caddr;

  return NULL;
}

static void
punt_socket_register (bool is_ip4, u8 protocol, u16 port,
		      char *client_pathname)
{
  punt_main_t *pm = &punt_main;
  punt_client_t c, *n;
  punt_client_t *v = is_ip4 ? pm->clients_by_dst_port4 :
    pm->clients_by_dst_port6;

  memset (&c, 0, sizeof (c));
  memcpy (c.caddr.sun_path, client_pathname, sizeof (c.caddr.sun_path));
  c.caddr.sun_family = AF_UNIX;
  c.port = port;
  n = sparse_vec_validate (v, port);
  n[0] = c;
}

/* $$$$ Just leaves the mapping in place for now */
static void
punt_socket_unregister (bool is_ip4, u8 protocol, u16 port)
{
  return;
}

typedef struct
{
  punt_client_t client;
  u8 is_midchain;
} udp_punt_trace_t;

u8 *
format_udp_punt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  udp_punt_trace_t *t = va_arg (*args, udp_punt_trace_t *);
  u32 indent = format_get_indent (s);
  s = format (s, "to: %s", t->client.caddr.sun_path);
  if (t->is_midchain)
    {
      s = format (s, "\n%U(buffer is part of chain)", format_white_space,
		  indent);
    }
  return s;
}

always_inline uword
udp46_punt_socket_inline (vlib_main_t * vm,
			  vlib_node_runtime_t * node,
			  vlib_frame_t * frame, bool is_ip4)
{
  u32 *buffers = vlib_frame_args (frame);
  uword n_packets = frame->n_vectors;
  struct iovec *iovecs = 0;
  punt_main_t *pm = &punt_main;
  int i;

  u32 node_index = is_ip4 ? udp4_punt_socket_node.index :
    udp6_punt_socket_node.index;

  for (i = 0; i < n_packets; i++)
    {
      struct iovec *iov;
      vlib_buffer_t *b;
      uword l;
      punt_packetdesc_t packetdesc;

      b = vlib_get_buffer (vm, buffers[i]);

      /* Reverse UDP Punt advance */
      udp_header_t *udp;
      if (is_ip4)
	{
	  vlib_buffer_advance (b, -(sizeof (ip4_header_t) +
				    sizeof (udp_header_t)));
	  ip4_header_t *ip = vlib_buffer_get_current (b);
	  udp = (udp_header_t *) (ip + 1);
	}
      else
	{
	  vlib_buffer_advance (b, -(sizeof (ip6_header_t) +
				    sizeof (udp_header_t)));
	  ip6_header_t *ip = vlib_buffer_get_current (b);
	  udp = (udp_header_t *) (ip + 1);
	}

      u16 port = clib_net_to_host_u16 (udp->dst_port);

      /*
       * Find registerered client
       * If no registered client, drop packet and count
       */
      struct sockaddr_un *caddr;
      caddr = punt_socket_get (is_ip4, port);
      if (!caddr)
	{
	  vlib_node_increment_counter (vm, node_index,
				       PUNT_ERROR_SOCKET_TX_ERROR, 1);
	  goto error;
	}

      punt_client_t *c = NULL;
      if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	{
	  if (!c)
	    {
	      c = punt_client_get (is_ip4, port);
	    }
	  udp_punt_trace_t *t;
	  t = vlib_add_trace (vm, node, b, sizeof (t[0]));
	  clib_memcpy (&t->client, c, sizeof (t->client));
	}

      /* Re-set iovecs if present. */
      if (iovecs)
	_vec_len (iovecs) = 0;

      /* Add packet descriptor */
      packetdesc.sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
      packetdesc.action = 0;
      vec_add2 (iovecs, iov, 1);
      iov->iov_base = &packetdesc;
      iov->iov_len = sizeof (packetdesc);

      /** VLIB buffer chain -> Unix iovec(s). */
      vlib_buffer_advance (b, -(sizeof (ethernet_header_t)));
      vec_add2 (iovecs, iov, 1);
      iov->iov_base = b->data + b->current_data;
      iov->iov_len = l = b->current_length;

      if (PREDICT_FALSE (b->flags & VLIB_BUFFER_NEXT_PRESENT))
	{
	  do
	    {
	      b = vlib_get_buffer (vm, b->next_buffer);
	      if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
		{
		  udp_punt_trace_t *t;
		  t = vlib_add_trace (vm, node, b, sizeof (t[0]));
		  clib_memcpy (&t->client, c, sizeof (t->client));
		  t->is_midchain = 1;
		}

	      vec_add2 (iovecs, iov, 1);

	      iov->iov_base = b->data + b->current_data;
	      iov->iov_len = b->current_length;
	      l += b->current_length;
	    }
	  while (b->flags & VLIB_BUFFER_NEXT_PRESENT);
	}

      struct msghdr msg = {
	.msg_name = caddr,
	.msg_namelen = sizeof (*caddr),
	.msg_iov = iovecs,
	.msg_iovlen = vec_len (iovecs),
      };

      if (sendmsg (pm->socket_fd, &msg, 0) < (ssize_t) l)
	vlib_node_increment_counter (vm, node_index,
				     PUNT_ERROR_SOCKET_TX_ERROR, 1);
    }

error:
  vlib_buffer_free (vm, buffers, n_packets);

  return n_packets;
}

static uword
udp4_punt_socket (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return udp46_punt_socket_inline (vm, node, from_frame, true /* is_ip4 */ );
}

static uword
udp6_punt_socket (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return udp46_punt_socket_inline (vm, node, from_frame, false /* is_ip4 */ );
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (udp4_punt_socket_node) = {
  .function = udp4_punt_socket,
  .name = "ip4-udp-punt-socket",
  .format_trace = format_udp_punt_trace,
  .flags = VLIB_NODE_FLAG_IS_DROP,
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = PUNT_N_ERROR,
  .error_strings = punt_error_strings,
};
VLIB_REGISTER_NODE (udp6_punt_socket_node) = {
  .function = udp6_punt_socket,
  .name = "ip6-udp-punt-socket",
  .format_trace = format_udp_punt_trace,
  .flags = VLIB_NODE_FLAG_IS_DROP,
  .vector_size = sizeof (u32),
  .n_errors = PUNT_N_ERROR,
  .error_strings = punt_error_strings,
};
/* *INDENT-ON* */

typedef struct
{
  enum punt_action_e action;
  u32 sw_if_index;
} punt_trace_t;

static u8 *
format_punt_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  vnet_main_t *vnm = vnet_get_main ();
  punt_trace_t *t = va_arg (*va, punt_trace_t *);
  s = format (s, "%U Action: %d", format_vnet_sw_if_index_name,
	      vnm, t->sw_if_index, t->action);
  return s;
}

static uword
punt_socket_rx_fd (vlib_main_t * vm, vlib_node_runtime_t * node, u32 fd)
{
  const uword buffer_size = VLIB_BUFFER_DATA_SIZE;
  u32 n_trace = vlib_get_trace_count (vm, node);
  u32 next = node->cached_next_index;
  u32 n_left_to_next, next_index;
  u32 *to_next;
  u32 error = PUNT_ERROR_NONE;
  vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);

  /* $$$$ Only dealing with one buffer at the time for now */

  u32 bi;
  vlib_buffer_t *b;
  punt_packetdesc_t packetdesc;
  ssize_t size;
  struct iovec io[2];

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    {
      error = PUNT_ERROR_NOBUFFER;
      goto error;
    }

  b = vlib_get_buffer (vm, bi);
  io[0].iov_base = &packetdesc;
  io[0].iov_len = sizeof (packetdesc);
  io[1].iov_base = b->data;
  io[1].iov_len = buffer_size;

  size = readv (fd, io, 2);
  /* We need at least the packet descriptor plus a header */
  if (size <= (int) (sizeof (packetdesc) + sizeof (ip4_header_t)))
    {
      vlib_buffer_free (vm, &bi, 1);
      error = PUNT_ERROR_READV;
      goto error;
    }

  b->flags = VNET_BUFFER_F_LOCALLY_ORIGINATED;
  b->current_length = size - sizeof (packetdesc);

  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);

  switch (packetdesc.action)
    {
    case PUNT_L2:
      vnet_buffer (b)->sw_if_index[VLIB_TX] = packetdesc.sw_if_index;
      next_index = PUNT_SOCKET_RX_NEXT_INTERFACE_OUTPUT;
      break;

    case PUNT_IP4_ROUTED:
      vnet_buffer (b)->sw_if_index[VLIB_RX] = packetdesc.sw_if_index;
      vnet_buffer (b)->sw_if_index[VLIB_TX] = ~0;
      next_index = PUNT_SOCKET_RX_NEXT_IP4_LOOKUP;
      break;

    case PUNT_IP6_ROUTED:
      vnet_buffer (b)->sw_if_index[VLIB_RX] = packetdesc.sw_if_index;
      vnet_buffer (b)->sw_if_index[VLIB_TX] = ~0;
      next_index = PUNT_SOCKET_RX_NEXT_IP6_LOOKUP;
      break;

    default:
      error = PUNT_ERROR_ACTION;
      vlib_buffer_free (vm, &bi, 1);
      goto error;
    }

  if (PREDICT_FALSE (n_trace > 0))
    {
      punt_trace_t *t;
      vlib_trace_buffer (vm, node, next_index, b, 1 /* follow_chain */ );
      vlib_set_trace_count (vm, node, --n_trace);
      t = vlib_add_trace (vm, node, b, sizeof (*t));
      t->sw_if_index = packetdesc.sw_if_index;
      t->action = packetdesc.action;
    }

  to_next[0] = bi;
  to_next++;
  n_left_to_next--;

  vlib_validate_buffer_enqueue_x1 (vm, node, next, to_next, n_left_to_next,
				   bi, next_index);
  vlib_put_next_frame (vm, node, next, n_left_to_next);
  return 1;

error:
  vlib_node_increment_counter (vm, punt_socket_rx_node.index, error, 1);
  return 0;
}

static uword
punt_socket_rx (vlib_main_t * vm,
		vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  punt_main_t *pm = &punt_main;
  u32 total_count = 0;
  int i;

  for (i = 0; i < vec_len (pm->ready_fds); i++)
    {
      total_count += punt_socket_rx_fd (vm, node, pm->ready_fds[i]);
      vec_del1 (pm->ready_fds, i);
    }
  return total_count;
}

VLIB_REGISTER_NODE (punt_socket_rx_node, static) =
{
  .function = punt_socket_rx,.name = "punt-socket-rx",.type =
    VLIB_NODE_TYPE_INPUT,.state = VLIB_NODE_STATE_INTERRUPT,.vector_size =
    1,.n_errors = PUNT_N_ERROR,.error_strings =
    punt_error_strings,.n_next_nodes = PUNT_SOCKET_RX_N_NEXT,.next_nodes =
  {
[PUNT_SOCKET_RX_NEXT_INTERFACE_OUTPUT] = "interface-output",
      [PUNT_SOCKET_RX_NEXT_IP4_LOOKUP] = "ip4-lookup",
      [PUNT_SOCKET_RX_NEXT_IP6_LOOKUP] = "ip6-lookup",},.format_trace =
    format_punt_trace,};

static clib_error_t *
punt_socket_read_ready (clib_file_t * uf)
{
  vlib_main_t *vm = vlib_get_main ();
  punt_main_t *pm = &punt_main;

  /** Schedule the rx node */
  vlib_node_set_interrupt_pending (vm, punt_socket_rx_node.index);
  vec_add1 (pm->ready_fds, uf->file_descriptor);

  return 0;
}

clib_error_t *
vnet_punt_socket_add (vlib_main_t * vm, u32 header_version,
		      bool is_ip4, u8 protocol, u16 port,
		      char *client_pathname)
{
  punt_main_t *pm = &punt_main;

  if (!pm->is_configured)
    return clib_error_return (0, "socket is not configured");

  if (header_version != PUNT_PACKETDESC_VERSION)
    return clib_error_return (0, "Invalid packet descriptor version");

  /* For now we only support UDP punt */
  if (protocol != IP_PROTOCOL_UDP)
    return clib_error_return (0,
			      "only UDP protocol (%d) is supported, got %d",
			      IP_PROTOCOL_UDP, protocol);

  if (port == (u16) ~ 0)
    return clib_error_return (0, "UDP port number required");

  /* Register client */
  punt_socket_register (is_ip4, protocol, port, client_pathname);

  u32 node_index = is_ip4 ? udp4_punt_socket_node.index :
    udp6_punt_socket_node.index;

  udp_register_dst_port (vm, port, node_index, is_ip4);

  return 0;
}

clib_error_t *
vnet_punt_socket_del (vlib_main_t * vm, bool is_ip4, u8 l4_protocol, u16 port)
{
  punt_main_t *pm = &punt_main;

  if (!pm->is_configured)
    return clib_error_return (0, "socket is not configured");

  punt_socket_unregister (is_ip4, l4_protocol, port);
  udp_unregister_dst_port (vm, port, is_ip4);

  return 0;
}

/**
 * @brief Request IP traffic punt to the local TCP/IP stack.
 *
 * @em Note
 * - UDP and TCP are the only protocols supported in the current implementation
 *
 * @param vm       vlib_main_t corresponding to the current thread
 * @param ipv      IP protcol version.
 *                 4 - IPv4, 6 - IPv6, ~0 for both IPv6 and IPv4
 * @param protocol 8-bits L4 protocol value
 *                 UDP is 17
 *                 TCP is 1
 * @param port     16-bits L4 (TCP/IP) port number when applicable (UDP only)
 *
 * @returns 0 on success, non-zero value otherwise
 */
clib_error_t *
vnet_punt_add_del (vlib_main_t * vm, u8 ipv, u8 protocol, u16 port,
		   bool is_add)
{

  /* For now we only support UDP punt */
  if (protocol != IP_PROTOCOL_UDP && protocol != IP_PROTOCOL_TCP)
    return clib_error_return (0,
			      "only UDP (%d) and TCP (%d) protocols are supported, got %d",
			      IP_PROTOCOL_UDP, IP_PROTOCOL_TCP, protocol);

  if (ipv != (u8) ~ 0 && ipv != 4 && ipv != 6)
    return clib_error_return (0, "IP version must be 4 or 6, got %d", ipv);

  if (port == (u16) ~ 0)
    {
      if ((ipv == 4) || (ipv == (u8) ~ 0))
	{
	  if (protocol == IP_PROTOCOL_UDP)
	    udp_punt_unknown (vm, 1, is_add);
	  else if (protocol == IP_PROTOCOL_TCP)
	    tcp_punt_unknown (vm, 1, is_add);
	}

      if ((ipv == 6) || (ipv == (u8) ~ 0))
	{
	  if (protocol == IP_PROTOCOL_UDP)
	    udp_punt_unknown (vm, 0, is_add);
	  else if (protocol == IP_PROTOCOL_TCP)
	    tcp_punt_unknown (vm, 0, is_add);
	}

      return 0;
    }

  else if (is_add)
    {
      if (protocol == IP_PROTOCOL_TCP)
	return clib_error_return (0, "punt TCP ports is not supported yet");

      if (ipv == 4 || ipv == (u8) ~ 0)
	udp_register_dst_port (vm, port, udp4_punt_node.index, 1);

      if (ipv == 6 || ipv == (u8) ~ 0)
	udp_register_dst_port (vm, port, udp6_punt_node.index, 0);

      return 0;
    }
  else
    return clib_error_return (0, "punt delete is not supported yet");
}

static clib_error_t *
punt_cli (vlib_main_t * vm,
	  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 port;
  bool is_add = true;
  u32 protocol = ~0;
  clib_error_t *error;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = false;
      else if (unformat (input, "all"))
	{
	  /* punt both IPv6 and IPv4 when used in CLI */
	  error = vnet_punt_add_del (vm, ~0, protocol, ~0, is_add);
	  if (error)
	    clib_error_report (error);
	}
      else if (unformat (input, "%d", &port))
	{
	  /* punt both IPv6 and IPv4 when used in CLI */
	  error = vnet_punt_add_del (vm, ~0, protocol, port, is_add);
	  if (error)
	    clib_error_report (error);
	}
      else if (unformat (input, "udp"))
	protocol = IP_PROTOCOL_UDP;
      else if (unformat (input, "tcp"))
	protocol = IP_PROTOCOL_TCP;
    }

  return 0;
}

/*?
 * The set of '<em>set punt</em>' commands allows specific IP traffic to
 * be punted to the host TCP/IP stack
 *
 * @em Note
 * - UDP is the only protocol supported in the current implementation
 * - All TCP traffic is currently punted to the host by default
 *
 * @cliexpar
 * @parblock
 * Example of how to request NTP traffic to be punted
 * @cliexcmd{set punt udp 125}
 *
 * Example of how to request all 'unknown' UDP traffic to be punted
 * @cliexcmd{set punt udp all}
 *
 * Example of how to stop all 'unknown' UDP traffic to be punted
 * @cliexcmd{set punt udp del all}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (punt_command, static) = {
  .path = "set punt",
  .short_help = "set punt [udp|tcp] [del] <all | port-num1 [port-num2 ...]>",
  .function = punt_cli,
};
/* *INDENT-ON* */

clib_error_t *
punt_init (vlib_main_t * vm)
{
  punt_main_t *pm = &punt_main;

  pm->clients_by_dst_port6 = sparse_vec_new
    (sizeof (pm->clients_by_dst_port6[0]),
     BITS (((udp_header_t *) 0)->dst_port));
  pm->clients_by_dst_port4 = sparse_vec_new
    (sizeof (pm->clients_by_dst_port4[0]),
     BITS (((udp_header_t *) 0)->dst_port));

  pm->is_configured = false;
  pm->interface_output_node = vlib_get_node_by_name (vm,
						     (u8 *)
						     "interface-output");
  return 0;
}

VLIB_INIT_FUNCTION (punt_init);

static clib_error_t *
punt_config (vlib_main_t * vm, unformat_input_t * input)
{
  punt_main_t *pm = &punt_main;
  char *socket_path = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "socket %s", &socket_path))
	strncpy (pm->sun_path, socket_path, 108 - 1);
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (socket_path == 0)
    return 0;

  /* UNIX domain socket */
  struct sockaddr_un addr;
  if ((pm->socket_fd = socket (AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0)) == -1)
    {
      return clib_error_return (0, "socket error");
    }

  memset (&addr, 0, sizeof (addr));
  addr.sun_family = AF_UNIX;
  if (*socket_path == '\0')
    {
      *addr.sun_path = '\0';
      strncpy (addr.sun_path + 1, socket_path + 1,
	       sizeof (addr.sun_path) - 2);
    }
  else
    {
      strncpy (addr.sun_path, socket_path, sizeof (addr.sun_path) - 1);
      unlink (socket_path);
    }

  if (bind (pm->socket_fd, (struct sockaddr *) &addr, sizeof (addr)) == -1)
    {
      return clib_error_return (0, "bind error");
    }

  /* Register socket */
  clib_file_main_t *fm = &file_main;
  clib_file_t template = { 0 };
  template.read_function = punt_socket_read_ready;
  template.file_descriptor = pm->socket_fd;
  pm->clib_file_index = clib_file_add (fm, &template);

  pm->is_configured = true;

  return 0;
}

VLIB_CONFIG_FUNCTION (punt_config, "punt");

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
