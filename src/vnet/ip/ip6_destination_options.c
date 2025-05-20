/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */
#include <vnet/vnet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/lookup.h>
#include <vnet/ip/ip6.h>
#include <vnet/ipip/ipip.h>
#include <vlib/vlib.h>

typedef enum
{
  IP6_DEST_OPT_ERROR_UNKNOWN_PROTOCOL,
  IP6_DEST_OPT_N_ERROR,
} ip6_dest_opt_error_t;

static char *ip6_destination_options_node_error_strings[] = {
  [IP6_DEST_OPT_ERROR_UNKNOWN_PROTOCOL] =
    "Unknown or unsupported extension header - dropped",
};

typedef enum
{
  IP6_DEST_OPT_NEXT_DROP,
  IP6_DEST_OPT_N_NEXT,
} ip6_destination_options_next_t;

typedef struct
{
  u8 next_by_ip_protocol[256];
} ip6_destination_options_main_t;

ip6_destination_options_main_t ip6_destination_options_main;

typedef struct
{
  u32 next_index;
  u8 eh_protocol;
  u8 next_hdr;
  u8 hdr_ext_len;
  u8 packet_data[128 - 2 * sizeof (u32)]; // Capture initial portion of packet
} ip6_dest_opts_trace_t;

static u8 *
format_ip6_destination_options_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_dest_opts_trace_t *t = va_arg (*args, ip6_dest_opts_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "%U: next index %d\n", format_ip_protocol, t->eh_protocol,
	      t->next_index);
  s = format (s, "%Unext header: %U", format_white_space, indent,
	      format_ip_protocol, t->next_hdr);
  s = format (s, "%Uextension header length: %u\n", format_white_space, indent,
	      t->hdr_ext_len);
  s = format (s, "%U%U\n", format_white_space, indent, format_ip6_header,
	      t->packet_data, sizeof (t->packet_data));
  s = format (s, "%U%U\n", format_white_space, indent,
	      format_ip6_destination_option_header,
	      t->packet_data + sizeof (ip6_header_t),
	      sizeof (t->packet_data) - sizeof (ip6_header_t));

  return s;
}

VLIB_NODE_FN (ip6_destination_options_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  ip6_destination_options_main_t *idom = &ip6_destination_options_main;
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);

  while (n_left_from)
    {

      ip6_header_t *ip0 = vlib_buffer_get_current (b[0]);

      u8 next_hdr = ip0->protocol;
      u8 *payload = (u8 *) (ip0 + 1);

      if (next_hdr == IP_PROTOCOL_IP6_DESTINATION_OPTIONS)
	{
	  // Parse destination options extension header
	  ip6_ext_header_t *dest_opts = (ip6_ext_header_t *) payload;
	  u8 final_next_hdr = dest_opts->next_hdr;

	  if (final_next_hdr == IP_PROTOCOL_IPV6)
	    {
	      next[0] = idom->next_by_ip_protocol[IP_PROTOCOL_IPV6];
	    }
	  else if (final_next_hdr == IP_PROTOCOL_IP_IN_IP)
	    {
	      next[0] = idom->next_by_ip_protocol[IP_PROTOCOL_IP_IN_IP];
	    }
	  else
	    {
	      // Drop - unsupported inner protocol
	      next[0] = IP6_DEST_OPT_NEXT_DROP;
	      b[0]->error = node->errors[IP6_DEST_OPT_ERROR_UNKNOWN_PROTOCOL];
	    }
	}
      else
	{
	  // Not a destination option - drop
	  next[0] = IP6_DEST_OPT_NEXT_DROP;
	  b[0]->error = node->errors[IP6_DEST_OPT_ERROR_UNKNOWN_PROTOCOL];
	}

      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ip6_dest_opts_trace_t *tr =
	    vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  ip6_ext_header_t *eh = (ip6_ext_header_t *) payload;

	  tr->next_index = next[0];
	  tr->eh_protocol = next_hdr;
	  tr->next_hdr = eh->next_hdr;
	  tr->hdr_ext_len = ip6_ext_header_len (payload);
	  clib_memcpy_fast (tr->packet_data, ip0, sizeof (tr->packet_data));
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
    .format_trace = format_ip6_destination_options_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = ARRAY_LEN(ip6_destination_options_node_error_strings),
    .error_strings = ip6_destination_options_node_error_strings,
    .n_next_nodes = IP6_DEST_OPT_N_NEXT,
    .next_nodes = 
    { 
        [IP6_DEST_OPT_NEXT_DROP] = "ip6-drop", // Default drop if unknown
    },
};

static clib_error_t *
ip6_destination_options_init (vlib_main_t *vm)
{
  ip_main_t *im = &ip_main;
  ip_protocol_info_t *pi;
  ip6_destination_options_main_t *idom = &ip6_destination_options_main;

  clib_error_t *error;

  error = vlib_call_init_function (vm, ip_main_init);

  if (error)
    return error;

  ip6_register_protocol (IP_PROTOCOL_IP6_DESTINATION_OPTIONS,
			 ip6_destination_options_node.index);

  pi = ip_get_protocol_info (im, IP_PROTOCOL_IP6_DESTINATION_OPTIONS);
  pi->format_header = format_ip6_destination_option_header;

  idom->next_by_ip_protocol[IP_PROTOCOL_IPV6] = vlib_node_add_next (
    vm, ip6_destination_options_node.index, ipip6_input_node.index);
  idom->next_by_ip_protocol[IP_PROTOCOL_IP_IN_IP] = vlib_node_add_next (
    vm, ip6_destination_options_node.index, ipip6_input_node.index);
  return 0;
}

VLIB_INIT_FUNCTION (ip6_destination_options_init);
