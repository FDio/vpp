/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 * @brief Handle IPv4 header options in the data-path
 */

#include <vnet/ip/ip.h>

typedef enum ip4_options_next_t_
{
  IP4_OPTIONS_NEXT_PUNT,
  IP4_OPTIONS_NEXT_LOCAL,
  IP4_OPTIONS_N_NEXT,
} ip4_options_next_t;

typedef struct ip4_options_trace_t_
{
  u8 option[4];
} ip4_options_trace_t;

VLIB_NODE_FN (ip4_options_node) (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * frame)
{
  uword n_left_from, n_left_to_next, next_index;
  u32 *from, *to_next;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = 0;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /*
       * IP options packets, when properly used, are very low rate,
       * so this code is not dual-looped for extra performance.
       */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  ip4_options_next_t next;
	  ip4_header_t *ip4;
	  vlib_buffer_t *b;
	  u8 *options;
	  u32 bi;

	  bi = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next[0] = bi;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b = vlib_get_buffer (vm, bi);
	  ip4 = vlib_buffer_get_current (b);
	  next = IP4_OPTIONS_NEXT_PUNT;

	  options = (u8 *) (ip4 + 1);

	  /*
	   * mask out the copy flag to leave the option type
	   */
	  switch (options[0] & 0x7f)
	    {
	    case IP4_ROUTER_ALERT_OPTION:
	      /*
	       * if it's an IGMP packet, pass up the local stack
	       */
	      if (IP_PROTOCOL_IGMP == ip4->protocol)
		{
		  next = IP4_OPTIONS_NEXT_LOCAL;
		}
	      break;
	    default:
	      break;
	    }

	  if (b->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      ip4_options_trace_t *t =
		vlib_add_trace (vm, node, b, sizeof (*t));

	      clib_memcpy_fast (t->option, options, 4);
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi, next);

	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

u8 *
format_ip4_options_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip4_options_trace_t *t = va_arg (*args, ip4_options_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "%Uoption:[0x%x,0x%x,0x%x,0x%x]",
	      format_white_space, indent,
	      t->option[0], t->option[1], t->option[2], t->option[3]);
  return s;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_options_node) = {
  .name = "ip4-options",
  .vector_size = sizeof (u32),

  .n_next_nodes = IP4_OPTIONS_N_NEXT,
  .next_nodes = {
    [IP4_OPTIONS_NEXT_PUNT] = "ip4-punt",
    [IP4_OPTIONS_NEXT_LOCAL] = "ip4-local",
  },
  .format_buffer = format_ip4_header,
  .format_trace = format_ip4_options_trace,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
