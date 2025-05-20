/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/lookup.h>
#include <vnet/ip/ip6.h>
#include <vnet/ipip/ipip.h>
#include <vlib/vlib.h>

static char *ip6_destination_options_node_error_strings[] = {
  [0] = "Unknown or unsupported extension header - dropped",
};

typedef enum
{
  IP6_DEST_OPT_ERROR_UNKNOWN_PROTOCOL,
  IP6_DEST_OPT_N_ERROR,
} ip6_dest_opt_error_t;

typedef struct
{
  u8 next_by_ip_protocol[256];
} ip6_destination_options_main_t;

ip6_destination_options_main_t ip6_destination_options_main;

VLIB_NODE_FN (ip6_destination_options_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  ip6_destination_options_main_t *idom = &ip6_destination_options_main;
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from)
    {

      ip6_header_t *ip0 = vlib_buffer_get_current (b[0]);

      u8 next_hdr = ip0->protocol;
      u8 *payload = (u8 *) (ip0 + 1);

      if (next_hdr == IP_PROTOCOL_IP6_DESTINATION_OPTIONS)
	{
	  // Parse destination options extension header
	  ip6_ext_header_t *dest_opts = (ip6_ext_header_t *) payload;
	  // u8 ext_len =
	  // ip6_ext_header_len_s(IP_PROTOCOL_IP6_DESTINATION_OPTIONS,
	  // payload);

	  u8 final_next_hdr = dest_opts->next_hdr;

	  if (final_next_hdr == IP_PROTOCOL_IPV6)
	    {
	      // Chain to ipip6-input
	      next[0] = idom->next_by_ip_protocol[IP_PROTOCOL_IPV6];
	    }
	  else
	    {
	      // Drop - unsupported inner protocol
	      next[0] = 0;
	      b[0]->error = node->errors[IP6_DEST_OPT_ERROR_UNKNOWN_PROTOCOL];
	    }
	}
      else
	{
	  // Not a destination option - drop
	  next[0] = 0;
	  b[0]->error = node->errors[IP6_DEST_OPT_ERROR_UNKNOWN_PROTOCOL];
	}

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE(ip6_destination_options_node) = {
    .name = "ip6-destination-options",
    .vector_size = sizeof(u32),
    .format_trace = NULL,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = ARRAY_LEN(ip6_destination_options_node_error_strings),
    .error_strings = ip6_destination_options_node_error_strings,
    .n_next_nodes = 1,
    .next_nodes = 
    { 
        [0] = "ip6-drop", // Default drop if unknown
    },
};

static clib_error_t *
ipv6_destination_options_init (vlib_main_t *vm)
{
  ip6_destination_options_main_t *idom = &ip6_destination_options_main;
  ip6_register_protocol (IP_PROTOCOL_IP6_DESTINATION_OPTIONS,
			 ip6_destination_options_node.index);
  idom->next_by_ip_protocol[IP_PROTOCOL_IPV6] = vlib_node_add_next (
    vm, ip6_destination_options_node.index, ipip6_input_node.index);
  return 0;
}

VLIB_INIT_FUNCTION (ipv6_destination_options_init);
