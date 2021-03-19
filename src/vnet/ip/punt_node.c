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
#include <vnet/ip/punt.h>
#include <vlib/unix/unix.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <stdlib.h>

typedef enum
{
#define punt_error(n,s) PUNT_ERROR_##n,
#include <vnet/ip/punt_error.def>
#undef punt_error
  PUNT_N_ERROR,
} punt_error_t;

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

typedef struct
{
  punt_client_t client;
  u8 is_midchain;
  u8 packet_data[64];
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
  s = format (s, "\n%U%U", format_white_space, indent,
	      format_hex_bytes, t->packet_data, sizeof (t->packet_data));

  return s;
}

always_inline uword
punt_socket_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * frame,
		    punt_type_t pt, ip_address_family_t af)
{
  u32 *buffers = vlib_frame_vector_args (frame);
  u32 thread_index = vm->thread_index;
  uword n_packets = frame->n_vectors;
  punt_main_t *pm = &punt_main;
  int i;

  punt_thread_data_t *ptd = &pm->thread_data[thread_index];
  u32 node_index = (AF_IP4 == af ?
		    udp4_punt_socket_node.index :
		    udp6_punt_socket_node.index);

  for (i = 0; i < n_packets; i++)
    {
      struct iovec *iov;
      vlib_buffer_t *b;
      uword l;
      punt_packetdesc_t packetdesc;
      punt_client_t *c;

      b = vlib_get_buffer (vm, buffers[i]);

      if (PUNT_TYPE_L4 == pt)
	{
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

	  /*
	   * Find registerered client
	   * If no registered client, drop packet and count
	   */
	  c = punt_client_l4_get (af, clib_net_to_host_u16 (udp->dst_port));
	}
      else if (PUNT_TYPE_IP_PROTO == pt)
	{
	  /* Reverse UDP Punt advance */
	  ip_protocol_t proto;

	  if (AF_IP4 == af)
	    {
	      ip4_header_t *ip = vlib_buffer_get_current (b);
	      proto = ip->protocol;
	    }
	  else
	    {
	      ip6_header_t *ip = vlib_buffer_get_current (b);
	      proto = ip->protocol;
	    }

	  c = punt_client_ip_proto_get (af, proto);
	}
      else if (PUNT_TYPE_EXCEPTION == pt)
	{
	  c = punt_client_exception_get (b->punt_reason);
	}
      else
	c = NULL;

      if (PREDICT_FALSE (NULL == c))
	{
	  vlib_node_increment_counter (vm, node_index,
				       PUNT_ERROR_SOCKET_TX_ERROR, 1);
	  goto error;
	}

      struct sockaddr_un *caddr = &c->caddr;

      /* Re-set iovecs */
      vec_reset_length (ptd->iovecs);

      /* Add packet descriptor */
      packetdesc.sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
      packetdesc.action = 0;
      vec_add2 (ptd->iovecs, iov, 1);
      iov->iov_base = &packetdesc;
      iov->iov_len = sizeof (packetdesc);

      /** VLIB buffer chain -> Unix iovec(s). */
      vlib_buffer_advance (b, -(sizeof (ethernet_header_t)));
      vec_add2 (ptd->iovecs, iov, 1);
      iov->iov_base = b->data + b->current_data;
      iov->iov_len = l = b->current_length;

      if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	{
	  udp_punt_trace_t *t;
	  t = vlib_add_trace (vm, node, b, sizeof (t[0]));
	  clib_memcpy_fast (&t->client, c, sizeof (t->client));
	  clib_memcpy_fast (t->packet_data,
			    vlib_buffer_get_current (b),
			    sizeof (t->packet_data));
	}

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

	      vec_add2 (ptd->iovecs, iov, 1);

	      iov->iov_base = b->data + b->current_data;
	      iov->iov_len = b->current_length;
	      l += b->current_length;
	    }
	  while (b->flags & VLIB_BUFFER_NEXT_PRESENT);
	}

      struct msghdr msg = {
	.msg_name = caddr,
	.msg_namelen = sizeof (*caddr),
	.msg_iov = ptd->iovecs,
	.msg_iovlen = vec_len (ptd->iovecs),
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

static uword
ip4_proto_punt_socket (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return punt_socket_inline (vm, node, from_frame,
			     PUNT_TYPE_IP_PROTO, AF_IP4);
}

static uword
ip6_proto_punt_socket (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return punt_socket_inline (vm, node, from_frame,
			     PUNT_TYPE_IP_PROTO, AF_IP6);
}

static uword
exception_punt_socket (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  return punt_socket_inline (vm, node, from_frame,
			     PUNT_TYPE_EXCEPTION, AF_IP4);
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
VLIB_REGISTER_NODE (ip4_proto_punt_socket_node) = {
  .function = ip4_proto_punt_socket,
  .name = "ip4-proto-punt-socket",
  .format_trace = format_udp_punt_trace,
  .flags = VLIB_NODE_FLAG_IS_DROP,
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = PUNT_N_ERROR,
  .error_strings = punt_error_strings,
};
VLIB_REGISTER_NODE (ip6_proto_punt_socket_node) = {
  .function = ip6_proto_punt_socket,
  .name = "ip6-proto-punt-socket",
  .format_trace = format_udp_punt_trace,
  .flags = VLIB_NODE_FLAG_IS_DROP,
  .vector_size = sizeof (u32),
  .n_errors = PUNT_N_ERROR,
  .error_strings = punt_error_strings,
};
VLIB_REGISTER_NODE (exception_punt_socket_node) = {
  .function = exception_punt_socket,
  .name = "exception-punt-socket",
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

  if (PREDICT_FALSE
      (n_trace > 0
       && vlib_trace_buffer (vm, node, next_index, b, 1 /* follow_chain */ )))
    {
      punt_trace_t *t;
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
  vlib_put_next_frame (vm, node, next, n_left_to_next);
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
VLIB_REGISTER_NODE (punt_socket_rx_node) =
{
 .function = punt_socket_rx,
 .name = "punt-socket-rx",
 .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED | VLIB_NODE_FLAG_ADAPTIVE_MODE,
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
