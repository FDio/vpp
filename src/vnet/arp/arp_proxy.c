/*
 * ethernet/arp.c: IP v4 ARP node
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

#include <vnet/arp/arp.h>
#include <vnet/arp/arp_packet.h>

#include <vnet/fib/ip4_fib.h>

typedef struct
{
  ip4_address_t lo_addr;
  ip4_address_t hi_addr;
  u32 fib_index;
} ethernet_proxy_arp_t;

typedef struct arp_proxy_main_t_
{
  /** Per interface state */
  bool *enabled_by_sw_if_index;

  /* Proxy arp vector */
  ethernet_proxy_arp_t *proxy_arps;
} arp_proxy_main_t;

arp_proxy_main_t arp_proxy_main;

void
proxy_arp_walk (proxy_arp_walk_t cb, void *data)
{
  arp_proxy_main_t *am = &arp_proxy_main;
  ethernet_proxy_arp_t *pa;

  vec_foreach (pa, am->proxy_arps)
  {
    if (!cb (&pa->lo_addr, &pa->hi_addr, pa->fib_index, data))
      break;
  }
}

int
arp_proxy_disable (u32 sw_if_index)
{
  arp_proxy_main_t *am = &arp_proxy_main;

  vec_validate (am->enabled_by_sw_if_index, sw_if_index);

  if (am->enabled_by_sw_if_index[sw_if_index])
    {
      vnet_feature_enable_disable ("arp", "arp-proxy",
				   sw_if_index, 0, NULL, 0);
    }
  am->enabled_by_sw_if_index[sw_if_index] = false;

  return (0);
}

int
arp_proxy_enable (u32 sw_if_index)
{
  arp_proxy_main_t *am = &arp_proxy_main;

  vec_validate (am->enabled_by_sw_if_index, sw_if_index);

  if (!am->enabled_by_sw_if_index[sw_if_index])
    {
      vnet_feature_enable_disable ("arp", "arp-proxy",
				   sw_if_index, 1, NULL, 0);
    }
  am->enabled_by_sw_if_index[sw_if_index] = true;

  return (0);
}

static int
vnet_proxy_arp_add_del (const ip4_address_t * lo_addr,
			const ip4_address_t * hi_addr,
			u32 fib_index, int is_del)
{
  arp_proxy_main_t *am = &arp_proxy_main;
  ethernet_proxy_arp_t *pa;
  u32 found_at_index = ~0;

  vec_foreach (pa, am->proxy_arps)
  {
    if (pa->lo_addr.as_u32 == lo_addr->as_u32 &&
	pa->hi_addr.as_u32 == hi_addr->as_u32 && pa->fib_index == fib_index)
      {
	found_at_index = pa - am->proxy_arps;
	break;
      }
  }

  if (found_at_index != ~0)
    {
      /* Delete, otherwise it's already in the table */
      if (is_del)
	vec_delete (am->proxy_arps, 1, found_at_index);
      return 0;
    }
  /* delete, no such entry */
  if (is_del)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  /* add, not in table */
  vec_add2 (am->proxy_arps, pa, 1);
  pa->lo_addr.as_u32 = lo_addr->as_u32;
  pa->hi_addr.as_u32 = hi_addr->as_u32;
  pa->fib_index = fib_index;
  return 0;
}

int
arp_proxy_add (u32 fib_index,
	       const ip4_address_t * lo, const ip4_address_t * hi)
{
  return (vnet_proxy_arp_add_del (lo, hi, fib_index, 0));
}

int
arp_proxy_del (u32 fib_index,
	       const ip4_address_t * lo, const ip4_address_t * hi)
{
  return (vnet_proxy_arp_add_del (lo, hi, fib_index, 1));
}

void
proxy_arp_intfc_walk (proxy_arp_intf_walk_t cb, void *data)
{
  arp_proxy_main_t *am = &arp_proxy_main;
  bool *enabled;

  vec_foreach (enabled, am->enabled_by_sw_if_index)
  {
    if (*enabled)
      cb (enabled - am->enabled_by_sw_if_index, data);
  }
}

static clib_error_t *
set_int_proxy_arp_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index;
  int enable = 0;

  sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	;
      else if (unformat (input, "enable") || unformat (input, "on"))
	enable = 1;
      else if (unformat (input, "disable") || unformat (input, "off"))
	enable = 0;
      else
	break;
    }

  if (~0 == sw_if_index)
    return clib_error_return (0, "unknown input '%U'",
			      format_unformat_error, input);

  if (enable)
    arp_proxy_enable (sw_if_index);
  else
    arp_proxy_disable (sw_if_index);

  return 0;
}

static clib_error_t *
set_arp_proxy (vlib_main_t * vm,
	       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  ip4_address_t start = {.as_u32 = ~0 }, end =
  {
  .as_u32 = ~0};
  u32 fib_index, table_id = 0;
  int add = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "table-id %u", &table_id))
	;
      else if (unformat (input, "start %U", unformat_ip4_address, &start))
	;
      else if (unformat (input, "end %U", unformat_ip4_address, &end))
	;
      else if (unformat (input, "del") || unformat (input, "delete"))
	add = 0;
      else
	break;
    }

  fib_index = fib_table_find (FIB_PROTOCOL_IP4, table_id);

  if (~0 == fib_index)
    return (clib_error_return (0, "no such table: %d", table_id));

  if (add)
    arp_proxy_add (fib_index, &start, &end);
  else
    arp_proxy_del (fib_index, &start, &end);

  return (NULL);
}

/* *INDENT-OFF* */
/*?
 * Enable proxy-arp on an interface. The vpp stack will answer ARP
 * requests for the indicated address range. Multiple proxy-arp
 * ranges may be provisioned.
 *
 * @note Proxy ARP as a technology is infamous for blackholing traffic.
 * Also, the underlying implementation has not been performance-tuned.
 * Avoid creating an unnecessarily large set of ranges.
 *
 * @cliexpar
 * To enable proxy arp on a range of addresses, use:
 * @cliexcmd{set ip arp proxy 6.0.0.1 - 6.0.0.11}
 * Append 'del' to delete a range of proxy ARP addresses:
 * @cliexcmd{set ip arp proxy 6.0.0.1 - 6.0.0.11 del}
 * You must then specifically enable proxy arp on individual interfaces:
 * @cliexcmd{set interface proxy-arp GigabitEthernet0/8/0 enable}
 * To disable proxy arp on an individual interface:
 * @cliexcmd{set interface proxy-arp GigabitEthernet0/8/0 disable}
 ?*/
VLIB_CLI_COMMAND (set_int_proxy_enable_command, static) = {
  .path = "set interface proxy-arp",
  .short_help =
  "set interface proxy-arp <intfc> [enable|disable]",
  .function = set_int_proxy_arp_command_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_arp_proxy_command, static) = {
  .path = "set arp proxy",
  .short_help = "set arp proxy [del] table-ID <table-ID> start <start-address> end <end-addres>",
  .function = set_arp_proxy,
};
/* *INDENT-ON* */

typedef struct
{
  u8 packet_data[64];
} ethernet_arp_input_trace_t;

static u8 *
format_ethernet_arp_input_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  ethernet_arp_input_trace_t *t = va_arg (*va, ethernet_arp_input_trace_t *);

  s = format (s, "%U",
	      format_ethernet_arp_header,
	      t->packet_data, sizeof (t->packet_data));

  return s;
}

static uword
arp_proxy (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  arp_proxy_main_t *am = &arp_proxy_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 n_left_from, next_index, *from, *to_next;
  u32 n_arp_replies_sent = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (ethernet_arp_input_trace_t));

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ethernet_arp_header_t *arp0;
	  ethernet_header_t *eth_rx;
	  ip4_address_t proxy_src;
	  u32 pi0, error0, next0, sw_if_index0, fib_index0;
	  u8 is_request0;
	  ethernet_proxy_arp_t *pa;

	  pi0 = from[0];
	  to_next[0] = pi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  arp0 = vlib_buffer_get_current (p0);
	  /* Fill in ethernet header. */
	  eth_rx = ethernet_buffer_get_header (p0);

	  is_request0 = arp0->opcode
	    == clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_request);

	  error0 = ARP_ERROR_REPLIES_SENT;
	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];
	  next0 = ARP_REPLY_NEXT_DROP;

	  fib_index0 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);
	  if (~0 == fib_index0)
	    {
	      error0 = ARP_ERROR_INTERFACE_NO_TABLE;
	    }

	  if (0 == error0 && is_request0)
	    {
	      u32 this_addr = clib_net_to_host_u32
		(arp0->ip4_over_ethernet[1].ip4.as_u32);

	      vec_foreach (pa, am->proxy_arps)
	      {
		u32 lo_addr = clib_net_to_host_u32 (pa->lo_addr.as_u32);
		u32 hi_addr = clib_net_to_host_u32 (pa->hi_addr.as_u32);

		/* an ARP request hit in the proxy-arp table? */
		if ((this_addr >= lo_addr && this_addr <= hi_addr) &&
		    (fib_index0 == pa->fib_index))
		  {
		    proxy_src.as_u32 =
		      arp0->ip4_over_ethernet[1].ip4.data_u32;

		    /*
		     * change the interface address to the proxied
		     */
		    n_arp_replies_sent++;

		    next0 =
		      arp_mk_reply (vnm, p0, sw_if_index0, &proxy_src, arp0,
				    eth_rx);
		  }
	      }
	    }
	  else
	    {
	      p0->error = node->errors[error0];
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_error_count (vm, node->node_index, ARP_ERROR_REPLIES_SENT,
		    n_arp_replies_sent);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (arp_proxy_node, static) =
{
  .function = arp_proxy,
  .name = "arp-proxy",
  .vector_size = sizeof (u32),
  .n_errors = ARP_N_ERROR,
  .error_counters = arp_error_counters,
  .n_next_nodes = ARP_REPLY_N_NEXT,
  .next_nodes =
  {
    [ARP_REPLY_NEXT_DROP] = "error-drop",
    [ARP_REPLY_NEXT_REPLY_TX] = "interface-output",
  },
  .format_buffer = format_ethernet_arp_header,
  .format_trace = format_ethernet_arp_input_trace,
};

static clib_error_t *
show_ip4_arp (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  arp_proxy_main_t *am = &arp_proxy_main;
  ethernet_proxy_arp_t *pa;

  if (vec_len (am->proxy_arps))
    {
      vlib_cli_output (vm, "Proxy arps enabled for:");
      vec_foreach (pa, am->proxy_arps)
      {
	vlib_cli_output (vm, "Fib_index %d   %U - %U ",
			 pa->fib_index,
			 format_ip4_address, &pa->lo_addr,
			 format_ip4_address, &pa->hi_addr);
      }
    }

  return (NULL);
}

/*?
 * Display all the IPv4 ARP proxy entries.
 *
 * @cliexpar
 * Example of how to display the IPv4 ARP table:
 * @cliexstart{show ip arp}
 *    Time      FIB        IP4       Flags      Ethernet              Interface
 *    346.3028   0       6.1.1.3            de:ad:be:ef:ba:be   GigabitEthernet2/0/0
 *   3077.4271   0       6.1.1.4       S    de:ad:be:ef:ff:ff   GigabitEthernet2/0/0
 *   2998.6409   1       6.2.2.3            de:ad:be:ef:00:01   GigabitEthernet2/0/0
 * Proxy arps enabled for:
 * Fib_index 0   6.0.0.1 - 6.0.0.11
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip4_arp_command, static) = {
  .path = "show arp proxy",
  .function = show_ip4_arp,
  .short_help = "show ip arp",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
