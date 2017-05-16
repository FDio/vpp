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
 * Provides a set of VPP nodes togather with the relevant APIs and CLI
 * commands in order to adjust and dispatch packets from the VPP data plane
 * to the local TCP/IP stack
 */
#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <vnet/udp/udp.h>
#include <vnet/ip/punt.h>
#include <vppinfra/sparse_vec.h>
#include <vlib/unix/unix.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>

#define foreach_punt_next			\
  _ (PUNT, "error-punt")

typedef enum
{
#define _(s,n) PUNT_NEXT_##s,
  foreach_punt_next
#undef _
    PUNT_N_NEXT,
} punt_next_t;

vlib_node_registration_t udp4_punt_node;
vlib_node_registration_t udp6_punt_node;
vlib_node_registration_t udp4_punt_socket_node;
vlib_node_registration_t udp6_punt_socket_node;

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

static struct sockaddr_un *
punt_socket_get (u8 ipv, u16 port)
{
  punt_main_t *pm = &punt_main;
  u16 i;
  punt_client_t *v = ipv == 6 ? pm->client_by_dst_port6 :
    pm->client_by_dst_port4;

  i = sparse_vec_index (v, port);
  if (i == SPARSE_VEC_INVALID_INDEX)
    return 0;
  clib_warning("Got an index: %d\n", i);
  return &vec_elt(v, i).caddr;
}

static void
punt_socket_register (u8 ipv, u8 protocol, u16 port, char *client_pathname)
{
  punt_main_t *pm = &punt_main;
  punt_client_t client = { 0 }, *n;

  memcpy(client.caddr.sun_path, client_pathname, sizeof(struct sockaddr_un));
  client.caddr.sun_family = AF_UNIX;
  n = sparse_vec_validate (pm->client_by_dst_port6, port);
  n[0] = client;
}

always_inline uword
udp46_punt_socket_inline (vlib_main_t * vm,
			  vlib_node_runtime_t * node,
			  vlib_frame_t * frame, int is_ip4)
{
  u32 * buffers = vlib_frame_args (frame);
  uword n_packets = frame->n_vectors;
  struct iovec * iovecs = 0;
  punt_main_t * pm = &punt_main;
  int i;

  u32 node_index = is_ip4 ? udp4_punt_socket_node.index :
    udp6_punt_socket_node.index;

  for (i = 0; i < n_packets; i++)
    {
      struct iovec * iov;
      vlib_buffer_t * b;
      uword l;
      punt_packetdesc_t packetdesc;

      b = vlib_get_buffer (vm, buffers[i]);

      /* Reverse UDP Punt advance */
      udp_header_t *udp;
      if (is_ip4)
	{
	  vlib_buffer_advance (b, -(sizeof (ip4_header_t) +
				    sizeof (udp_header_t)));
	  ip4_header_t *ip = vlib_buffer_get_current(b);
	  udp = (udp_header_t *) (ip + 1);
	}
      else
	{
	  vlib_buffer_advance (b, -(sizeof (ip6_header_t) +
				    sizeof (udp_header_t)));
	  ip6_header_t *ip = vlib_buffer_get_current(b);
	  udp = (udp_header_t *) (ip + 1);
	}

      u16 port = clib_net_to_host_u16(udp->dst_port);

      /*
       * Find registerered client
       * If no registered client, drop packet and count
       */
      struct sockaddr_un *caddr;
      if (is_ip4)
	caddr = punt_socket_get(4 , port);
      else
	caddr = punt_socket_get(4 , port);
      if (!caddr)
	{
	  vlib_node_increment_counter (vm, node_index,
				       PUNT_ERROR_SOCKET_TX_ERROR, 1);
	  goto error;
	}

      /* Re-set iovecs if present. */
      if (iovecs)
	_vec_len (iovecs) = 0;

      /* Add packet descriptor */
      packetdesc.sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
      packetdesc.action = 0;
      vec_add2 (iovecs, iov, 1);
      iov->iov_base = &packetdesc;
      iov->iov_len = sizeof(packetdesc);

      /** VLIB buffer chain -> Unix iovec(s). */
      vlib_buffer_advance (b, -(sizeof (ethernet_header_t)));
      vec_add2 (iovecs, iov, 1);
      iov->iov_base = b->data + b->current_data;
      iov->iov_len = l = b->current_length;

      if (PREDICT_FALSE (b->flags & VLIB_BUFFER_NEXT_PRESENT))
	{
	  do {
	    b = vlib_get_buffer (vm, b->next_buffer);

	    vec_add2 (iovecs, iov, 1);

	    iov->iov_base = b->data + b->current_data;
	    iov->iov_len = b->current_length;
	    l += b->current_length;
	  } while (b->flags & VLIB_BUFFER_NEXT_PRESENT);
	}

      struct msghdr msg = {
	.msg_name = caddr,
	.msg_namelen = sizeof(*caddr),
	.msg_iov = iovecs,
	.msg_iovlen = vec_len (iovecs),
      };

      if (sendmsg(pm->socket_fd, &msg, 0) < l)
	vlib_node_increment_counter (vm, node_index,
				     PUNT_ERROR_SOCKET_TX_ERROR, 1);
      else
	{
	  vlib_node_increment_counter (vm, node_index,
				       PUNT_ERROR_SOCKET_TX, 1);

	}
    }

 error:
  vlib_buffer_free_no_next (vm, buffers, n_packets);

  return n_packets;
}

static uword
udp4_punt_socket (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return udp46_punt_socket_inline (vm, node, from_frame, 1 /* is_ip4 */ );
}
static uword
udp6_punt_socket (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return udp46_punt_socket_inline (vm, node, from_frame, 0 /* is_ip4 */ );
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (udp4_punt_socket_node) = {
  .function = udp4_punt_socket,
  .name = "ip4-udp-punt-socket",
  .flags = VLIB_NODE_FLAG_IS_DROP,
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = PUNT_N_ERROR,
  .error_strings = punt_error_strings,
};
VLIB_REGISTER_NODE (udp6_punt_socket_node) = {
  .function = udp6_punt_socket,
  .name = "ip6-udp-punt-socket",
  .flags = VLIB_NODE_FLAG_IS_DROP,
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = PUNT_N_ERROR,
  .error_strings = punt_error_strings,
};
/* *INDENT-ON* */

static inline void
punt_frame_to_next_node (vlib_main_t * vm, u32 bi, u32 next_node)
{
  vlib_frame_t *f = vlib_get_frame_to_node (vm, next_node);
  u32 *to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, next_node, f);
}

static clib_error_t *
punt_read_ready (unix_file_t * uf)
{
  punt_main_t *pm = &punt_main;
  vlib_main_t *vm = vlib_get_main();
  ssize_t size;
  punt_packetdesc_t packetdesc;
  struct iovec io[2];
  u32 bi;
  vlib_buffer_t *b;
  const uword buffer_size = VLIB_BUFFER_DATA_SIZE;

  /* $$$$: Empty socket even if we cannot get a buffer! */
  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
      return 0;

  b = vlib_get_buffer (vm, bi);
  b->flags = 0;
  b->flags |= VNET_BUFFER_LOCALLY_ORIGINATED;
  b->current_data = 0;

  io[0].iov_base = &packetdesc;
  io[0].iov_len = sizeof(packetdesc);
  io[1].iov_base = b->data;
  io[1].iov_len = buffer_size;

  size = readv(uf->file_descriptor, io, 2);

  b->current_length = size - sizeof(packetdesc);

  switch (packetdesc.action)
    {
    case PUNT_L2:
      vnet_buffer (b)->sw_if_index[VLIB_TX] = packetdesc.sw_if_index;
      punt_frame_to_next_node (vm, bi, pm->interface_output_node->index);
      break;

    case PUNT_IP4_ROUTED:
      punt_frame_to_next_node (vm, bi, ip4_lookup_node.index);
      break;

    case PUNT_IP6_ROUTED:
      punt_frame_to_next_node (vm, bi, ip6_lookup_node.index);
      break;

    default:
      /* $$$$ Error */
      break;
    }

  vlib_node_increment_counter (vm, udp6_punt_socket_node.index,
			       PUNT_ERROR_SOCKET_RX, 1);

  return 0;
}

clib_error_t *
vnet_punt_socket_add_del (vlib_main_t * vm, u8 ipv, u8 protocol, u16 port,
			  bool is_add, char *client_pathname)
{
  punt_main_t *pm = &punt_main;

  if (!pm->is_configured)
    return clib_error_return(0,
			     "socket is not configured");

  /* For now we only support UDP punt */
  if (protocol != IP_PROTOCOL_UDP)
    return clib_error_return (0,
			      "only UDP protocol (%d) is supported, got %d",
			      IP_PROTOCOL_UDP, protocol);

  if (ipv != (u8) ~ 0 && ipv != 4 && ipv != 6)
    return clib_error_return (0, "IP version must be 4 or 6, got %d", ipv);

  if (port == (u16) ~ 0)
    return clib_error_return (0, "UDP port number required");

  if (is_add)
    {
      /* Register client */
      punt_socket_register (ipv, protocol, port, client_pathname);

      if (ipv == 4 || ipv == (u8) ~ 0)
	udp_register_dst_port (vm, port, udp4_punt_socket_node.index, 1);
      else if (ipv == 6 || ipv == (u8) ~ 0)
	udp_register_dst_port (vm, port, udp6_punt_socket_node.index, 0);

      return 0;
    }
  else
    return clib_error_return (0, "punt delete is not supported yet");
}

/**
 * @brief Request IP traffic punt to the local TCP/IP stack.
 *
 * @em Note
 * - UDP is the only protocol supported in the current implementation
 * - When requesting UDP punt port number(s) must be specified
 * - All TCP traffic is currently punted to the host by default
 *
 * @param vm       vlib_main_t corresponding to the current thread
 * @param ipv      IP protcol version.
 *                 4 - IPv4, 6 - IPv6, ~0 for both IPv6 and IPv4
 * @param protocol 8-bits L4 protocol value
 *                 Only value of 17 (UDP) is currently supported
 * @param port     16-bits L4 (TCP/IP) port number when applicable
 *
 * @returns 0 on success, non-zero value otherwise
 */
clib_error_t *
vnet_punt_add_del (vlib_main_t * vm, u8 ipv, u8 protocol, u16 port,
		   bool is_add)
{
  /* For now we only support UDP punt */
  if (protocol != IP_PROTOCOL_UDP)
    return clib_error_return (0,
			      "only UDP protocol (%d) is supported, got %d",
			      IP_PROTOCOL_UDP, protocol);

  if (ipv != (u8) ~ 0 && ipv != 4 && ipv != 6)
    return clib_error_return (0, "IP version must be 4 or 6, got %d", ipv);

  if (port == (u16) ~ 0)
    {
      if (ipv == 4 || ipv == (u8) ~ 0)
	udp_punt_unknown (vm, 1, is_add);

      if (ipv == 6 || ipv == (u8) ~ 0)
	udp_punt_unknown (vm, 0, is_add);

      return 0;
    }

  else if (is_add)
    {
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
udp_punt_cli (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 udp_port;
  bool is_add = true;
  clib_error_t *error;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = false;
      if (unformat (input, "all"))
	{
	  /* punt both IPv6 and IPv4 when used in CLI */
	  error = vnet_punt_add_del (vm, ~0, IP_PROTOCOL_UDP, ~0, is_add);
	  if (error)
	    clib_error_report (error);
	}
      else if (unformat (input, "%d", &udp_port))
	{
	  /* punt both IPv6 and IPv4 when used in CLI */
	  error = vnet_punt_add_del (vm, ~0, IP_PROTOCOL_UDP, udp_port, is_add);
	  if (error)
	    clib_error_report (error);
	}
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
VLIB_CLI_COMMAND (punt_udp_command, static) = {
  .path = "set punt udp",
  .short_help = "set punt udp [del] <all | port-num1 [port-num2 ...]>",
  .function = udp_punt_cli,
};
/* *INDENT-ON* */

clib_error_t *
punt_init (vlib_main_t * vm)
{
  punt_main_t *pm = &punt_main;

  pm->client_by_dst_port6 = sparse_vec_new
    (sizeof(pm->client_by_dst_port6[0]),
     BITS(((udp_header_t *) 0)->dst_port));
  pm->client_by_dst_port4 = sparse_vec_new
    (sizeof(pm->client_by_dst_port4[0]),
     BITS(((udp_header_t *) 0)->dst_port));
  pm->is_configured = false;
  pm->interface_output_node = vlib_get_node_by_name (vm,
						     (u8 *) "interface-output");
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
  if ((pm->socket_fd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
    return clib_error_return (0, "socket error");
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (*socket_path == '\0')
    {
      *addr.sun_path = '\0';
      strncpy(addr.sun_path + 1, socket_path + 1, sizeof(addr.sun_path) - 2);
    }
  else
    {
      strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
      unlink(socket_path);
    }

  if (bind(pm->socket_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    return clib_error_return (0, "bind error");
  }

  /* Register socket */
  unix_main_t *um = &unix_main;
  unix_file_t template = { 0 };
  template.read_function = punt_read_ready;
  template.file_descriptor = pm->socket_fd;
  pm->unix_file_index = unix_file_add (um, &template);

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
