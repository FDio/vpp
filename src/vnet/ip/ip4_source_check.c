/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
 * ip/ip4_source_check.c: IP v4 check source address (unicast RPF check)
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vnet/ip/ip.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/fib_urpf_list.h>
#include <vnet/dpo/load_balance.h>

/**
 * @file
 * @brief IPv4 Unicast Source Check.
 *
 * This file contains the IPv4 interface unicast source check.
 */


typedef struct
{
  u8 packet_data[64];
  index_t urpf;
} ip4_source_check_trace_t;

static u8 *
format_ip4_source_check_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  ip4_source_check_trace_t *t = va_arg (*va, ip4_source_check_trace_t *);

  s = format (s, "%U",
	      format_ip4_header, t->packet_data, sizeof (t->packet_data));

  return s;
}

typedef enum
{
  IP4_SOURCE_CHECK_NEXT_DROP,
  IP4_SOURCE_CHECK_N_NEXT,
} ip4_source_check_next_t;

typedef enum
{
  IP4_SOURCE_CHECK_REACHABLE_VIA_RX,
  IP4_SOURCE_CHECK_REACHABLE_VIA_ANY,
} ip4_source_check_type_t;

typedef union
{
  u32 fib_index;
} ip4_source_check_config_t;

always_inline uword
ip4_source_check_inline (vlib_main_t * vm,
			 vlib_node_runtime_t * node,
			 vlib_frame_t * frame,
			 ip4_source_check_type_t source_check_type)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip4_input_node.index);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (ip4_source_check_trace_t));

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t *p0, *p1;
	  ip4_header_t *ip0, *ip1;
	  ip4_fib_mtrie_t *mtrie0, *mtrie1;
	  ip4_fib_mtrie_leaf_t leaf0, leaf1;
	  ip4_source_check_config_t *c0, *c1;
	  const load_balance_t *lb0, *lb1;
	  u32 pi0, next0, pass0, lb_index0;
	  u32 pi1, next1, pass1, lb_index1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, sizeof (ip0[0]), LOAD);
	    CLIB_PREFETCH (p3->data, sizeof (ip1[0]), LOAD);
	  }

	  pi0 = to_next[0] = from[0];
	  pi1 = to_next[1] = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);

	  ip0 = vlib_buffer_get_current (p0);
	  ip1 = vlib_buffer_get_current (p1);

	  c0 =
	    vnet_feature_next_with_data (vnet_buffer (p0)->sw_if_index
					 [VLIB_RX], &next0, p0,
					 sizeof (c0[0]));
	  c1 =
	    vnet_feature_next_with_data (vnet_buffer (p1)->sw_if_index
					 [VLIB_RX], &next1, p1,
					 sizeof (c1[0]));

	  mtrie0 = &ip4_fib_get (c0->fib_index)->mtrie;
	  mtrie1 = &ip4_fib_get (c1->fib_index)->mtrie;

	  leaf0 = ip4_fib_mtrie_lookup_step_one (mtrie0, &ip0->src_address);
	  leaf1 = ip4_fib_mtrie_lookup_step_one (mtrie1, &ip1->src_address);

	  leaf0 =
	    ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address, 2);
	  leaf1 =
	    ip4_fib_mtrie_lookup_step (mtrie1, leaf1, &ip1->src_address, 2);

	  leaf0 =
	    ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address, 3);
	  leaf1 =
	    ip4_fib_mtrie_lookup_step (mtrie1, leaf1, &ip1->src_address, 3);

	  lb_index0 = ip4_fib_mtrie_leaf_get_adj_index (leaf0);
	  lb_index1 = ip4_fib_mtrie_leaf_get_adj_index (leaf1);

	  lb0 = load_balance_get (lb_index0);
	  lb1 = load_balance_get (lb_index1);

	  /* Pass multicast. */
	  pass0 = ip4_address_is_multicast (&ip0->src_address)
	    || ip0->src_address.as_u32 == clib_host_to_net_u32 (0xFFFFFFFF);
	  pass1 = ip4_address_is_multicast (&ip1->src_address)
	    || ip1->src_address.as_u32 == clib_host_to_net_u32 (0xFFFFFFFF);

	  if (IP4_SOURCE_CHECK_REACHABLE_VIA_RX == source_check_type)
	    {
	      pass0 |= fib_urpf_check (lb0->lb_urpf,
				       vnet_buffer (p0)->sw_if_index
				       [VLIB_RX]);
	      pass1 |=
		fib_urpf_check (lb1->lb_urpf,
				vnet_buffer (p1)->sw_if_index[VLIB_RX]);
	    }
	  else
	    {
	      pass0 |= fib_urpf_check_size (lb0->lb_urpf);
	      pass1 |= fib_urpf_check_size (lb1->lb_urpf);
	    }
	  next0 = (pass0 ? next0 : IP4_SOURCE_CHECK_NEXT_DROP);
	  next1 = (pass1 ? next1 : IP4_SOURCE_CHECK_NEXT_DROP);

	  p0->error =
	    error_node->errors[IP4_ERROR_UNICAST_SOURCE_CHECK_FAILS];
	  p1->error =
	    error_node->errors[IP4_ERROR_UNICAST_SOURCE_CHECK_FAILS];

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, pi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ip4_header_t *ip0;
	  ip4_fib_mtrie_t *mtrie0;
	  ip4_fib_mtrie_leaf_t leaf0;
	  ip4_source_check_config_t *c0;
	  u32 pi0, next0, pass0, lb_index0;
	  const load_balance_t *lb0;

	  pi0 = from[0];
	  to_next[0] = pi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip0 = vlib_buffer_get_current (p0);

	  c0 =
	    vnet_feature_next_with_data (vnet_buffer (p0)->sw_if_index
					 [VLIB_RX], &next0, p0,
					 sizeof (c0[0]));

	  mtrie0 = &ip4_fib_get (c0->fib_index)->mtrie;

	  leaf0 = ip4_fib_mtrie_lookup_step_one (mtrie0, &ip0->src_address);

	  leaf0 =
	    ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address, 2);

	  leaf0 =
	    ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address, 3);

	  lb_index0 = ip4_fib_mtrie_leaf_get_adj_index (leaf0);

	  lb0 = load_balance_get (lb_index0);

	  /* Pass multicast. */
	  pass0 = ip4_address_is_multicast (&ip0->src_address)
	    || ip0->src_address.as_u32 == clib_host_to_net_u32 (0xFFFFFFFF);

	  if (IP4_SOURCE_CHECK_REACHABLE_VIA_RX == source_check_type)
	    {
	      pass0 |= fib_urpf_check (lb0->lb_urpf,
				       vnet_buffer (p0)->sw_if_index
				       [VLIB_RX]);
	    }
	  else
	    {
	      pass0 |= fib_urpf_check_size (lb0->lb_urpf);
	    }

	  next0 = (pass0 ? next0 : IP4_SOURCE_CHECK_NEXT_DROP);
	  p0->error =
	    error_node->errors[IP4_ERROR_UNICAST_SOURCE_CHECK_FAILS];

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static uword
ip4_source_check_reachable_via_any (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return ip4_source_check_inline (vm, node, frame,
				  IP4_SOURCE_CHECK_REACHABLE_VIA_ANY);
}

static uword
ip4_source_check_reachable_via_rx (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return ip4_source_check_inline (vm, node, frame,
				  IP4_SOURCE_CHECK_REACHABLE_VIA_RX);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_check_source_reachable_via_any) = {
  .function = ip4_source_check_reachable_via_any,
  .name = "ip4-source-check-via-any",
  .vector_size = sizeof (u32),

  .n_next_nodes = IP4_SOURCE_CHECK_N_NEXT,
  .next_nodes = {
    [IP4_SOURCE_CHECK_NEXT_DROP] = "error-drop",
  },

  .format_buffer = format_ip4_header,
  .format_trace = format_ip4_source_check_trace,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (ip4_check_source_reachable_via_any,
			      ip4_source_check_reachable_via_any);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_check_source_reachable_via_rx) = {
  .function = ip4_source_check_reachable_via_rx,
  .name = "ip4-source-check-via-rx",
  .vector_size = sizeof (u32),

  .n_next_nodes = IP4_SOURCE_CHECK_N_NEXT,
  .next_nodes = {
    [IP4_SOURCE_CHECK_NEXT_DROP] = "error-drop",
  },

  .format_buffer = format_ip4_header,
  .format_trace = format_ip4_source_check_trace,
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (ip4_check_source_reachable_via_rx,
			      ip4_source_check_reachable_via_rx);

static clib_error_t *
set_ip_source_check (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  ip4_main_t *im = &ip4_main;
  clib_error_t *error = 0;
  u32 sw_if_index, is_del;
  ip4_source_check_config_t config;
  char *feature_name = "ip4-source-check-via-rx";

  sw_if_index = ~0;
  is_del = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat_user
	  (line_input, unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (line_input, "del"))
	is_del = 1;
      else if (unformat (line_input, "loose"))
	feature_name = "ip4-source-check-via-any";
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (~0 == sw_if_index)
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, line_input);
      goto done;
    }

  config.fib_index = im->fib_index_by_sw_if_index[sw_if_index];
  vnet_feature_enable_disable ("ip4-unicast", feature_name, sw_if_index,
			       is_del == 0, &config, sizeof (config));
done:
  unformat_free (line_input);

  return error;
}

/*?
 * This command adds the 'ip4-source-check-via-rx' graph node for
 * a given interface. By adding the IPv4 source check graph node to
 * an interface, the code verifies that the source address of incoming
 * unicast packets are reachable over the incoming interface. Two flavours
 * are supported (the default is strict):
 * - loose: accept ingress packet if there is a route to reach the source
 * - strict: accept ingress packet if it arrived on an interface which
 *          the route to the source uses. i.e. an interface that the source
 *          is reachable via.
 *
 * @cliexpar
 * @parblock
 * Example of graph node before range checking is enabled:
 * @cliexstart{show vlib graph ip4-source-check-via-rx}
 *            Name                      Next                    Previous
 * ip4-source-check-via-rx         error-drop [0]
 * @cliexend
 *
 * Example of how to enable unicast source checking on an interface:
 * @cliexcmd{set interface ip source-check GigabitEthernet2/0/0 loose}
 *
 * Example of graph node after range checking is enabled:
 * @cliexstart{show vlib graph ip4-source-check-via-rx}
 *            Name                      Next                    Previous
 * ip4-source-check-via-rx         error-drop [0]         ip4-input-no-checksum
 *                           ip4-source-and-port-range-         ip4-input
 * @cliexend
 *
 * Example of how to display the feature enabed on an interface:
 * @cliexstart{show ip interface features GigabitEthernet2/0/0}
 * IP feature paths configured on GigabitEthernet2/0/0...
 *
 * ipv4 unicast:
 *   ip4-source-check-via-rx
 *   ip4-lookup
 *
 * ipv4 multicast:
 *   ip4-lookup-multicast
 *
 * ipv4 multicast:
 *   interface-output
 *
 * ipv6 unicast:
 *   ip6-lookup
 *
 * ipv6 multicast:
 *   ip6-lookup
 *
 * ipv6 multicast:
 *   interface-output
 * @cliexend
 *
 * Example of how to disable unicast source checking on an interface:
 * @cliexcmd{set interface ip source-check GigabitEthernet2/0/0 del}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_ip_source_check_command, static) = {
  .path = "set interface ip source-check",
  .function = set_ip_source_check,
  .short_help = "set interface ip source-check <interface> [strict|loose] [del]",
};
/* *INDENT-ON* */

static clib_error_t *
ip_source_check_accept (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
  };
  clib_error_t *error = NULL;
  u32 table_id, is_add, fib_index;

  is_add = 1;
  table_id = ~0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "table %d", &table_id))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "add"))
	is_add = 1;
      else if (unformat (line_input, "%U/%d",
			 unformat_ip4_address, &pfx.fp_addr.ip4, &pfx.fp_len))
	pfx.fp_proto = FIB_PROTOCOL_IP4;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (~0 != table_id)
    {
      fib_index = fib_table_find (pfx.fp_proto, table_id);
      if (~0 == fib_index)
	{
	  error = clib_error_return (0, "Nonexistent table id %d", table_id);
	  goto done;
	}
    }
  else
    {
      fib_index = 0;
    }

  if (is_add)
    {
      fib_table_entry_special_add (fib_index,
				   &pfx,
				   FIB_SOURCE_URPF_EXEMPT,
				   FIB_ENTRY_FLAG_DROP);
    }
  else
    {
      fib_table_entry_special_remove (fib_index,
				      &pfx, FIB_SOURCE_URPF_EXEMPT);
    }

done:
  unformat_free (line_input);

  return error;
}

/*?
 * Add an exemption for a prefix to pass the Unicast Reverse Path
 * Forwarding (uRPF) loose check. This is for testing purposes only.
 * If the '<em>table</em>' is not enter it is defaulted to 0. Default
 * is to '<em>add</em>'. VPP always performs a loose uRPF check for
 * for-us traffic.
 *
 * @cliexpar
 * Example of how to add a uRPF exception to a FIB table to pass the
 * loose RPF tests:
 * @cliexcmd{ip urpf-accept table 7 add}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip_source_check_accept_command, static) = {
  .path = "ip urpf-accept",
  .function = ip_source_check_accept,
  .short_help = "ip urpf-accept [table <table-id>] [add|del]",
};
/* *INDENT-ON* */


/* Dummy init function to get us linked in. */
clib_error_t *
ip4_source_check_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (ip4_source_check_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
