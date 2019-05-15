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
#include <vnet/sctp/sctp.h>
#include <vnet/ip/punt.h>
#include <vlib/unix/unix.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <stdlib.h>

#define foreach_punt_next			\
  _ (PUNT4, "ip4-punt")                         \
  _ (PUNT6, "ip6-punt")

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

#define punt_next_punt(is_ip4) (is_ip4 ? PUNT_NEXT_PUNT4 : PUNT_NEXT_PUNT6)

extern vlib_node_registration_t udp4_punt_node;
extern vlib_node_registration_t udp6_punt_node;
extern vlib_node_registration_t udp4_punt_socket_node;
extern vlib_node_registration_t udp6_punt_socket_node;
static vlib_node_registration_t punt_socket_rx_node;

extern punt_main_t punt_main;

#ifndef CLIB_MARCH_VARIANT
punt_main_t punt_main;

char *
vnet_punt_get_server_pathname (void)
{
  punt_main_t *pm = &punt_main;
  return pm->sun_path;
}
#endif /* CLIB_MARCH_VARIANT */

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

      vlib_get_next_frame (vm, node, punt_next_punt (is_ip4), to_next,
			   n_left_to_next);

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

      vlib_put_next_frame (vm, node, punt_next_punt (is_ip4), n_left_to_next);
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
VLIB_NODE_FN (udp4_punt_node) (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
			       vlib_frame_t * from_frame)
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
VLIB_NODE_FN (udp6_punt_node) (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
			       vlib_frame_t * from_frame)
{
  return udp46_punt_inline (vm, node, from_frame, 0 /* is_ip4 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (udp4_punt_node) = {
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

VLIB_REGISTER_NODE (udp6_punt_node) = {
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

/* *INDENT-ON* */

static void *
punt_client_l4_get_db (ip_address_family_t af)
{
  punt_main_t *pm = &punt_main;

  return (af == AF_IP4 ?
	  pm->db.clients_by_l4_port4 : pm->db.clients_by_l4_port6);
}

static punt_client_t *
punt_client_l4_get (ip_address_family_t af, u16 port)
{
  punt_main_t *pm = &punt_main;
  uword *p;

  p = hash_get (punt_client_l4_get_db (af), port);

  if (p)
    return (pool_elt_at_index (pm->punt_client_pool, p[0]));

  return (NULL);
}


#ifndef CLIB_MARCH_VARIANT

static punt_client_t *
punt_client_exception_get (vlib_punt_reason_t reason)
{
  punt_main_t *pm = &punt_main;
  u32 pci;

  if (reason >= vec_len (pm->db.clients_by_exception))
    return (NULL);

  pci = pm->db.clients_by_exception[reason];

  if (~0 != pci)
    return (pool_elt_at_index (pm->punt_client_pool, pci));

  return (NULL);
}

static void
punt_client_l4_db_add (ip_address_family_t af, u16 port, u32 index)
{
  punt_main_t *pm = &punt_main;

  if (af == AF_IP4)
    hash_set (pm->db.clients_by_l4_port4, port, index);
  else
    hash_set (pm->db.clients_by_l4_port6, port, index);
}

static u32
punt_client_l4_db_remove (ip_address_family_t af, u16 port)
{
  u32 index = ~0;
  uword *p;
  void *h;

  h = punt_client_l4_get_db (af);
  p = hash_get (h, port);

  if (p)
    index = p[0];

  hash_unset (h, port);

  return (index);
}

static void
punt_client_exception_db_add (vlib_punt_reason_t reason, u32 pci)
{
  punt_main_t *pm = &punt_main;

  vec_validate_init_empty (pm->db.clients_by_exception, reason, ~0);

  pm->db.clients_by_exception[reason] = pci;
}

static u32
punt_client_exception_db_remove (vlib_punt_reason_t reason)
{
  punt_main_t *pm = &punt_main;
  u32 pci = ~0;

  if (punt_client_exception_get (reason))
    {
      pci = pm->db.clients_by_exception[reason];
      pm->db.clients_by_exception[reason] = ~0;
    }

  return pci;
}

#endif /* CLIB_MARCH_VARIANT */

typedef struct
{
  punt_client_t client;
  u8 is_midchain;
} udp_punt_trace_t;

static u8 *
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
punt_socket_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * frame,
		    punt_type_t pt, ip_address_family_t af)
{
  u32 *buffers = vlib_frame_vector_args (frame);
  uword n_packets = frame->n_vectors;
  struct iovec *iovecs = 0;
  punt_main_t *pm = &punt_main;
  int i;

  u32 node_index = AF_IP4 == af ? udp4_punt_socket_node.index :
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
      if (AF_IP4 == af)
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
      punt_client_t *c = punt_client_l4_get (af, port);

      if (PREDICT_FALSE (NULL == c))
	{
	  vlib_node_increment_counter (vm, node_index,
				       PUNT_ERROR_SOCKET_TX_ERROR, 1);
	  goto error;
	}

      struct sockaddr_un *caddr = &c->caddr;

      if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	{
	  udp_punt_trace_t *t;
	  t = vlib_add_trace (vm, node, b, sizeof (t[0]));
	  clib_memcpy_fast (&t->client, c, sizeof (t->client));
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
		  clib_memcpy_fast (&t->client, c, sizeof (t->client));
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
      else
	vlib_node_increment_counter (vm, node_index, PUNT_ERROR_SOCKET_TX, 1);

    }

error:
  vlib_buffer_free (vm, buffers, n_packets);

  return n_packets;
}

static uword
udp4_punt_socket (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return punt_socket_inline (vm, node, from_frame, PUNT_TYPE_L4, AF_IP4);
}

static uword
udp6_punt_socket (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return punt_socket_inline (vm, node, from_frame, PUNT_TYPE_L4, AF_IP6);
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
  const uword buffer_size = vlib_buffer_get_default_data_size (vm);
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

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (punt_socket_rx_node, static) =
{
 .function = punt_socket_rx,
 .name = "punt-socket-rx",
 .type = VLIB_NODE_TYPE_INPUT,
 .state = VLIB_NODE_STATE_INTERRUPT,
 .vector_size = 1,
 .n_errors = PUNT_N_ERROR,
 .error_strings = punt_error_strings,
 .n_next_nodes = PUNT_SOCKET_RX_N_NEXT,
 .next_nodes = {
		[PUNT_SOCKET_RX_NEXT_INTERFACE_OUTPUT] = "interface-output",
		[PUNT_SOCKET_RX_NEXT_IP4_LOOKUP] = "ip4-lookup",
		[PUNT_SOCKET_RX_NEXT_IP6_LOOKUP] = "ip6-lookup",
		},
 .format_trace = format_punt_trace,
};
/* *INDENT-ON* */

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

#ifndef CLIB_MARCH_VARIANT

static clib_error_t *
punt_socket_register_l4 (vlib_main_t * vm,
			 ip_address_family_t af,
			 u8 protocol, u16 port, char *client_pathname)
{
  punt_main_t *pm = &punt_main;
  punt_client_t *c;

  /* For now we only support UDP punt */
  if (protocol != IP_PROTOCOL_UDP)
    return clib_error_return (0,
			      "only UDP protocol (%d) is supported, got %d",
			      IP_PROTOCOL_UDP, protocol);

  if (port == (u16) ~ 0)
    return clib_error_return (0, "UDP port number required");

  if (strncmp (client_pathname, vnet_punt_get_server_pathname (),
	       UNIX_PATH_MAX) == 0)
    return clib_error_return (0,
			      "Punt socket: Invalid client path: %s",
			      client_pathname);

  c = punt_client_l4_get (af, port);

  if (NULL == c)
    {
      pool_get_zero (pm->punt_client_pool, c);
      punt_client_l4_db_add (af, port, c - pm->punt_client_pool);
    }

  memcpy (c->caddr.sun_path, client_pathname, sizeof (c->caddr.sun_path));
  c->caddr.sun_family = AF_UNIX;
  c->reg.type = PUNT_TYPE_L4;
  c->reg.punt.l4.port = port;
  c->reg.punt.l4.protocol = protocol;

  u32 node_index = (af == AF_IP4 ?
		    udp4_punt_socket_node.index :
		    udp6_punt_socket_node.index);

  udp_register_dst_port (vm, port, node_index, af == AF_IP4);

  return (NULL);
}

static clib_error_t *
punt_socket_register_exception (vlib_main_t * vm,
				vlib_punt_reason_t reason,
				char *client_pathname)
{
  punt_main_t *pm = &punt_main;
  punt_client_t *pc;

  pc = punt_client_exception_get (reason);

  if (NULL == pc)
    {
      pool_get_zero (pm->punt_client_pool, pc);
      punt_client_exception_db_add (reason, pc - pm->punt_client_pool);
    }

  memcpy (pc->caddr.sun_path, client_pathname, sizeof (pc->caddr.sun_path));
  pc->caddr.sun_family = AF_UNIX;
  pc->reg.type = PUNT_TYPE_EXCEPTION;
  pc->reg.punt.exception.reason = reason;

  return (NULL);
}

static clib_error_t *
punt_socket_unregister_l4 (ip_address_family_t af,
			   ip_protocol_t protocol, u16 port)
{
  u32 pci;

  udp_unregister_dst_port (vlib_get_main (), port, af == AF_IP4);

  pci = punt_client_l4_db_remove (af, port);

  if (~0 != pci)
    pool_put_index (punt_main.punt_client_pool, pci);

  return (NULL);
}

static clib_error_t *
punt_socket_unregister_exception (vlib_punt_reason_t reason)
{
  u32 pci;

  pci = punt_client_exception_db_remove (reason);

  if (~0 != pci)
    pool_put_index (punt_main.punt_client_pool, pci);

  return (NULL);
}

clib_error_t *
vnet_punt_socket_add (vlib_main_t * vm, u32 header_version,
		      const punt_reg_t * pr, char *client_pathname)
{
  punt_main_t *pm = &punt_main;

  if (!pm->is_configured)
    return clib_error_return (0, "socket is not configured");

  if (header_version != PUNT_PACKETDESC_VERSION)
    return clib_error_return (0, "Invalid packet descriptor version");

  /* Register client */
  switch (pr->type)
    {
    case PUNT_TYPE_L4:
      return (punt_socket_register_l4 (vm,
				       pr->punt.l4.af,
				       pr->punt.l4.protocol,
				       pr->punt.l4.port, client_pathname));
    case PUNT_TYPE_EXCEPTION:
      return (punt_socket_register_exception (vm,
					      pr->punt.exception.reason,
					      client_pathname));
    }

  return 0;
}

clib_error_t *
vnet_punt_socket_del (vlib_main_t * vm, const punt_reg_t * pr)
{
  punt_main_t *pm = &punt_main;

  if (!pm->is_configured)
    return clib_error_return (0, "socket is not configured");

  switch (pr->type)
    {
    case PUNT_TYPE_L4:
      return (punt_socket_unregister_l4 (pr->punt.l4.af,
					 pr->punt.l4.protocol,
					 pr->punt.l4.port));
    case PUNT_TYPE_EXCEPTION:
      return (punt_socket_unregister_exception (pr->punt.exception.reason));
    }

  return 0;
}

/**
 * @brief Request IP traffic punt to the local TCP/IP stack.
 *
 * @em Note
 * - UDP, TCP and SCTP are the only protocols supported in the current implementation
 *
 * @param vm       vlib_main_t corresponding to the current thread
 * @param af       IP address family.
 * @param protocol 8-bits L4 protocol value
 *                 UDP is 17
 *                 TCP is 1
 * @param port     16-bits L4 (TCP/IP) port number when applicable (UDP only)
 *
 * @returns 0 on success, non-zero value otherwise
 */
static clib_error_t *
punt_l4_add_del (vlib_main_t * vm,
		 ip_address_family_t af,
		 ip_protocol_t protocol, u16 port, bool is_add)
{
  /* For now we only support TCP, UDP and SCTP punt */
  if (protocol != IP_PROTOCOL_UDP &&
      protocol != IP_PROTOCOL_TCP && protocol != IP_PROTOCOL_SCTP)
    return clib_error_return (0,
			      "only UDP (%d), TCP (%d) and SCTP (%d) protocols are supported, got %d",
			      IP_PROTOCOL_UDP, IP_PROTOCOL_TCP,
			      IP_PROTOCOL_SCTP, protocol);

  if (port == (u16) ~ 0)
    {
      if (protocol == IP_PROTOCOL_UDP)
	udp_punt_unknown (vm, af == AF_IP4, is_add);
      else if (protocol == IP_PROTOCOL_TCP)
	tcp_punt_unknown (vm, af == AF_IP4, is_add);
      else if (protocol == IP_PROTOCOL_SCTP)
	sctp_punt_unknown (vm, af == AF_IP4, is_add);

      return 0;
    }

  else if (is_add)
    {
      if (protocol == IP_PROTOCOL_TCP || protocol == IP_PROTOCOL_SCTP)
	return clib_error_return (0,
				  "punt TCP/SCTP ports is not supported yet");

      if (!udp_is_valid_dst_port (port, af == AF_IP4))
	return clib_error_return (0, "invalid port: %d", port);

      udp_register_dst_port (vm, port, udp4_punt_node.index, af == AF_IP4);

      return 0;
    }
  else
    {
      if (protocol == IP_PROTOCOL_TCP || protocol == IP_PROTOCOL_SCTP)
	return clib_error_return (0,
				  "punt TCP/SCTP ports is not supported yet");

      udp_unregister_dst_port (vm, port, af == AF_IP4);

      return 0;
    }
}

static clib_error_t *
punt_exception_add_del (vlib_main_t * vm,
			vlib_punt_reason_t reason, bool is_add)
{
  return (NULL);
}

clib_error_t *
vnet_punt_add_del (vlib_main_t * vm, const punt_reg_t * pr, bool is_add)
{
  switch (pr->type)
    {
    case PUNT_TYPE_L4:
      return (punt_l4_add_del (vm, pr->punt.l4.af, pr->punt.l4.protocol,
			       pr->punt.l4.port, is_add));
    case PUNT_TYPE_EXCEPTION:
      return (punt_exception_add_del (vm, pr->punt.exception.reason, is_add));
    }

  return (clib_error_return (0, "Unsupported punt type: %d", pr->type));
}
#endif /* CLIB_MARCH_VARIANT */

static clib_error_t *
punt_cli (vlib_main_t * vm,
	  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = NULL;
  bool is_add = true;
  punt_reg_t pr = {
    .punt = {
	     .l4 = {
		    .af = AF_IP4,
		    .port = ~0,
		    .protocol = ~0,
		    },
	     },
    .type = PUNT_TYPE_L4,
  };

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = false;
      else if (unformat (input, "ipv6"))
	pr.punt.l4.af = AF_IP6;
      else if (unformat (input, "ip6"))
	pr.punt.l4.af = AF_IP6;
      else if (unformat (input, "%d", &pr.punt.l4.port))
	;
      else if (unformat (input, "udp"))
	pr.punt.l4.protocol = IP_PROTOCOL_UDP;
      else if (unformat (input, "tcp"))
	pr.punt.l4.protocol = IP_PROTOCOL_TCP;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  /* punt both IPv6 and IPv4 when used in CLI */
  error = vnet_punt_add_del (vm, &pr, is_add);
  if (error)
    {
      clib_error_report (error);
    }

done:
  return error;
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

#ifndef CLIB_MARCH_VARIANT
static clib_error_t *
punt_socket_register_cmd (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u8 *socket_name = 0;
  clib_error_t *error = NULL;
  /* *INDENT-OFF* */
  punt_reg_t pr = {
    .punt = {
      .l4 = {
        .af = AF_IP4,
        .port = ~0,
        .protocol = ~0,
      },
    },
    .type = PUNT_TYPE_L4,
  };
  /* *INDENT-ON* */

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "ipv4"))
	;
      else if (unformat (input, "ipv6"))
	pr.punt.l4.af = AF_IP6;
      else if (unformat (input, "udp"))
	pr.punt.l4.protocol = IP_PROTOCOL_UDP;
      else if (unformat (input, "tcp"))
	pr.punt.l4.protocol = IP_PROTOCOL_TCP;
      else if (unformat (input, "%d", &pr.punt.l4.port))
	;
      else if (unformat (input, "socket %s", &socket_name))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  error = vnet_punt_socket_add (vm, 1, &pr, (char *) socket_name);

done:
  return error;
}

/*?
 *
 * @cliexpar
 * @cliexcmd{punt socket register}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (punt_socket_register_command, static) =
{
  .path = "punt socket register",
  .function = punt_socket_register_cmd,
  .short_help = "punt socket register [ipv4|ipv6] [udp|tcp]> <all | port-num1 [port-num2 ...]> <socket>",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static clib_error_t *
punt_socket_deregister_cmd (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  clib_error_t *error = NULL;
  /* *INDENT-OFF* */
  punt_reg_t pr = {
    .punt = {
      .l4 = {
        .af = AF_IP4,
        .port = ~0,
        .protocol = ~0,
      },
    },
    .type = PUNT_TYPE_L4,
  };
  /* *INDENT-ON* */

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "ipv4"))
	;
      else if (unformat (input, "ipv6"))
	pr.punt.l4.af = AF_IP6;
      else if (unformat (input, "udp"))
	pr.punt.l4.protocol = IP_PROTOCOL_UDP;
      else if (unformat (input, "tcp"))
	pr.punt.l4.protocol = IP_PROTOCOL_TCP;
      else if (unformat (input, "%d", &pr.punt.l4.port))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  error = vnet_punt_socket_del (vm, &pr);
done:
  return error;
}

/*?
 *
 * @cliexpar
 * @cliexcmd{punt socket register}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (punt_socket_deregister_command, static) =
{
  .path = "punt socket deregister",
  .function = punt_socket_deregister_cmd,
  .short_help = "punt socket deregister [ipv4|ipv6] [udp|tcp]> <all | port-num1 [port-num2 ...]>",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

void
punt_client_walk (punt_type_t pt, punt_client_walk_cb_t cb, void *ctx)
{
  punt_main_t *pm = &punt_main;

  switch (pt)
    {
    case PUNT_TYPE_L4:
      {
	u32 pci;
	u16 port;

        /* *INDENT-OFF* */
        hash_foreach(port, pci, pm->db.clients_by_l4_port4,
        ({
          cb (pool_elt_at_index(pm->punt_client_pool, pci), ctx);
        }));
        hash_foreach(port, pci, pm->db.clients_by_l4_port6,
        ({
          cb (pool_elt_at_index(pm->punt_client_pool, pci), ctx);
        }));
        /* *INDENT-ON* */
	break;
      }
    case PUNT_TYPE_EXCEPTION:
      {
	u32 *pci;

	vec_foreach (pci, pm->db.clients_by_exception)
	{
	  if (~0 != *pci)
	    cb (pool_elt_at_index (pm->punt_client_pool, *pci), ctx);
	}

	break;
      }
    }
}

u8 *
format_punt_client (u8 * s, va_list * args)
{
  punt_client_t *pc = va_arg (*args, punt_client_t *);

  s = format (s, " punt ");

  switch (pc->reg.type)
    {
    case PUNT_TYPE_L4:
      s = format (s, "%U %U port %d",
		  format_ip_address_family, pc->reg.punt.l4.af,
		  format_ip_protocol, pc->reg.punt.l4.protocol,
		  pc->reg.punt.l4.port);
      break;
    case PUNT_TYPE_EXCEPTION:
      s = format (s, " %U", format_vlib_punt_reason,
		  pc->reg.punt.exception.reason);
      break;
    }

  s = format (s, " to socket %s \n", pc->caddr.sun_path);

  return (s);
}

static walk_rc_t
punt_client_show_one (const punt_client_t * pc, void *ctx)
{
  vlib_cli_output (ctx, "%U", format_punt_client, pc);

  return (WALK_CONTINUE);
}

static clib_error_t *
punt_socket_show_cmd (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = NULL;
  punt_type_t pt;

  pt = PUNT_TYPE_L4;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "exception"))
	pt = PUNT_TYPE_EXCEPTION;
      else if (unformat (input, "l4"))
	pt = PUNT_TYPE_L4;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  punt_client_walk (pt, punt_client_show_one, vm);

done:
  return (error);
}

/*?
 *
 * @cliexpar
 * @cliexcmd{show punt socket ipv4}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_punt_socket_registration_command, static) =
{
  .path = "show punt socket registrations",
  .function = punt_socket_show_cmd,
  .short_help = "show punt socket registrations [l4|exception]",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

clib_error_t *
ip_punt_init (vlib_main_t * vm)
{
  punt_main_t *pm = &punt_main;

  pm->is_configured = false;
  pm->interface_output_node =
    vlib_get_node_by_name (vm, (u8 *) "interface-output");

  return (NULL);
}

VLIB_INIT_FUNCTION (ip_punt_init);
#endif /* CLIB_MARCH_VARIANT */

static clib_error_t *
punt_config (vlib_main_t * vm, unformat_input_t * input)
{
  punt_main_t *pm = &punt_main;
  char *socket_path = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "socket %s", &socket_path))
	strncpy (pm->sun_path, socket_path, UNIX_PATH_MAX - 1);
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

  clib_memset (&addr, 0, sizeof (addr));
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
  template.description = format (0, "%s", socket_path);
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
