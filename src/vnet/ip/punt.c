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

#define foreach_punt_next \
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
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (udp6_punt_node, udp6_punt);;

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
		   int is_add)
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
  int is_add = 1;
  clib_error_t *error;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = 0;
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
	  error = vnet_punt_add_del (vm, ~0, IP_PROTOCOL_UDP,
				     udp_port, is_add);
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
