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
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#if DPDK == 0
#include <vnet/devices/pci/ixge.h>
#else
#include <vnet/devices/dpdk/dpdk.h>
#endif

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <app/l2t.h>

l2t_main_t l2t_main;

/* $$$$ unused?
 * get_interface_ethernet_address
 * paints the ethernet address for a given interface
 * into the supplied destination
 */
void
get_interface_ethernet_address (l2t_main_t * lm, u8 * dst, u32 sw_if_index)
{
  ethernet_main_t *em = ethernet_get_main (lm->vlib_main);
  ethernet_interface_t *ei;
  vnet_hw_interface_t *hi;

  hi = vnet_get_sup_hw_interface (lm->vnet_main, sw_if_index);
  ei = pool_elt_at_index (em->interfaces, hi->hw_instance);
  clib_memcpy (dst, ei->address, sizeof (ei->address));
}

/* packet trace format function */
u8 *
format_l2t_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2t_trace_t *t = va_arg (*args, l2t_trace_t *);

  if (t->is_user_to_network)
    s = format (s, "L2T: %U (client) -> %U (our) session %d",
		format_ip6_address, &t->client_address,
		format_ip6_address, &t->our_address, t->session_index);
  else
    s = format (s, "L2T: %U (our) -> %U (client) session %d)",
		format_ip6_address, &t->our_address,
		format_ip6_address, &t->client_address, t->session_index);
  return s;
}

u8 *
format_l2t_session (u8 * s, va_list * args)
{
  l2t_session_t *session = va_arg (*args, l2t_session_t *);
  l2t_main_t *lm = &l2t_main;
  u32 counter_index;
  vlib_counter_t v;

  s = format (s, "[%d] %U (our) %U (client) vlan-id %d rx_sw_if_index %d\n",
	      session - lm->sessions,
	      format_ip6_address, &session->our_address,
	      format_ip6_address, &session->client_address,
	      clib_net_to_host_u16 (session->vlan_id), session->sw_if_index);

  s = format (s, "   local cookie %llx remote cookie %llx\n",
	      clib_net_to_host_u64 (session->local_cookie),
	      clib_net_to_host_u64 (session->remote_cookie));

  if (session->cookie_flags & L2TP_COOKIE_ROLLOVER_LOCAL)
    {
      s = format (s, "   local rollover cookie %llx\n",
		  clib_net_to_host_u64 (session->lcl_ro_cookie));
    }

  s = format (s, "   local session-id %d remote session-id %d\n",
	      clib_net_to_host_u32 (session->local_session_id),
	      clib_net_to_host_u32 (session->remote_session_id));

  s = format (s, "   l2 specific sublayer %s\n",
	      session->l2_sublayer_present ? "preset" : "absent");

  counter_index =
    session_index_to_counter_index (session - lm->sessions,
				    SESSION_COUNTER_USER_TO_NETWORK);

  vlib_get_combined_counter (&lm->counter_main, counter_index, &v);
  if (v.packets != 0)
    s = format (s, "   user-to-net: %llu pkts %llu bytes\n",
		v.packets, v.bytes);

  vlib_get_combined_counter (&lm->counter_main, counter_index + 1, &v);

  if (v.packets != 0)
    s = format (s, "   net-to-user: %llu pkts %llu bytes\n",
		v.packets, v.bytes);
  return s;
}

static clib_error_t *
show_session_summary_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  l2t_main_t *lm = &l2t_main;

  vlib_cli_output (vm, "%d active sessions\n", pool_elts (lm->sessions));

  return 0;
}

/* *INDENT-OFF* */
static VLIB_CLI_COMMAND (show_session_summary_command) = {
  .path = "show session",
  .short_help = "show session summary",
  .function = show_session_summary_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_session_detail_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  l2t_session_t *session;
  l2t_main_t *lm = &l2t_main;

  /* *INDENT-OFF* */
  pool_foreach (session, lm->sessions,
  ({
    vlib_cli_output (vm, "%U", format_l2t_session, session);
  }));
  /* *INDENT-ON* */

  return 0;
}

/* *INDENT-OFF* */
static VLIB_CLI_COMMAND (show_session_detail_command) = {
  .path = "show session detail",
  .short_help = "show session table detail",
  .function = show_session_detail_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
test_counters_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  l2t_session_t *session;
  l2t_main_t *lm = &l2t_main;
  u32 session_index;
  u32 counter_index;
  u32 nincr = 0;

  /* *INDENT-OFF* */
  pool_foreach (session, lm->sessions,
  ({
    session_index = session - lm->sessions;
    counter_index =
      session_index_to_counter_index (session_index,
                                      SESSION_COUNTER_USER_TO_NETWORK);
    vlib_increment_combined_counter (&lm->counter_main,
                                     counter_index,
                                     1/*pkt*/, 1111 /*bytes*/);
    vlib_increment_combined_counter (&lm->counter_main,
                                     counter_index+1,
                                     1/*pkt*/, 2222 /*bytes*/);
    nincr++;
  }));
  /* *INDENT-ON* */
  vlib_cli_output (vm, "Incremented %d active counters\n", nincr);

  return 0;
}

/* *INDENT-OFF* */
static VLIB_CLI_COMMAND (test_counters_command) = {
  .path = "test counters",
  .short_help = "increment all active counters",
  .function = test_counters_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
clear_counters_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  l2t_session_t *session;
  l2t_main_t *lm = &l2t_main;
  u32 session_index;
  u32 counter_index;
  u32 nincr = 0;

  /* *INDENT-OFF* */
  pool_foreach (session, lm->sessions,
  ({
    session_index = session - lm->sessions;
    counter_index =
      session_index_to_counter_index (session_index,
                                      SESSION_COUNTER_USER_TO_NETWORK);
    vlib_zero_combined_counter (&lm->counter_main, counter_index);
    vlib_zero_combined_counter (&lm->counter_main, counter_index+1);
    nincr++;
  }));
  /* *INDENT-ON* */
  vlib_cli_output (vm, "Cleared %d active counters\n", nincr);

  return 0;
}

/* *INDENT-OFF* */
static VLIB_CLI_COMMAND (clear_counters_command) = {
  .path = "clear counters",
  .short_help = "clear all active counters",
  .function = clear_counters_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
l2tp_session_add_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  ip6_address_t client_address, our_address;
  ip6_address_t *dst_address_copy, *src_address_copy;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 vlan_id;
  u32 sw_if_index = (u32) ~ 0;
  l2t_main_t *lm = &l2t_main;
  l2t_session_t *s;
  uword *p;
  vnet_hw_interface_t *hi;
  vnet_sw_interface_t *si;
  u32 next_index;
  uword vlan_and_sw_if_index_key;
  u32 counter_index;
  u64 local_cookie = (u64) ~ 0, remote_cookie = (u64) ~ 0;
  u32 local_session_id = 1, remote_session_id = 1;
  int our_address_set = 0, client_address_set = 0;
  int l2_sublayer_present = 0;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "client %U",
		    unformat_ip6_address, &client_address))
	client_address_set = 1;
      else if (unformat (line_input, "our %U",
			 unformat_ip6_address, &our_address))
	our_address_set = 1;
      else if (unformat (line_input, "vlan %d", &vlan_id))
	;
      else if (unformat (line_input, "l2-interface %U",
			 unformat_vnet_sw_interface,
			 vnet_get_main (), &sw_if_index))
	;
      else if (unformat (line_input, "interface %U",
			 unformat_vnet_sw_interface,
			 vnet_get_main (), &sw_if_index))
	;
      else if (unformat (line_input, "local-cookie %llx", &local_cookie))
	;
      else if (unformat (line_input, "remote-cookie %llx", &remote_cookie))
	;
      else if (unformat (line_input, "local-session-id %d",
			 &local_session_id))
	;
      else if (unformat (line_input, "remote-session-id %d",
			 &remote_session_id))
	;
      else if (unformat (line_input, "l2-sublayer-present"))
	l2_sublayer_present = 1;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  unformat_free (line_input);
	  return error;
	}
    }

  unformat_free (line_input);

  if (sw_if_index == (u32) ~ 0)
    return clib_error_return (0, "l2-interface not specified");
  if (our_address_set == 0)
    return clib_error_return (0, "our address not specified");
  if (client_address_set == 0)
    return clib_error_return (0, "client address not specified");

  remote_session_id = clib_host_to_net_u32 (remote_session_id);
  local_session_id = clib_host_to_net_u32 (local_session_id);

  switch (lm->lookup_type)
    {
    case L2T_LOOKUP_SRC_ADDRESS:
      p = hash_get_mem (lm->session_by_src_address, &client_address);
      if (p)
	return clib_error_return
	  (0, "Session w/ client address %U already exists",
	   format_ip6_address, &client_address);
      break;

    case L2T_LOOKUP_DST_ADDRESS:
      p = hash_get_mem (lm->session_by_dst_address, &our_address);
      if (p)
	return clib_error_return
	  (0, "Session w/ our address %U already exists",
	   format_ip6_address, &our_address);
      break;

    case L2T_LOOKUP_SESSION_ID:
      p = hash_get (lm->session_by_session_id, local_session_id);
      if (p)
	return clib_error_return
	  (0,
	   "Session w/ local session id %d already exists",
	   clib_net_to_host_u32 (local_session_id));
      break;

    default:
      ASSERT (0);
    }

  pool_get (lm->sessions, s);
  memset (s, 0, sizeof (*s));
  clib_memcpy (&s->our_address, &our_address, sizeof (s->our_address));
  clib_memcpy (&s->client_address, &client_address,
	       sizeof (s->client_address));
  s->sw_if_index = sw_if_index;
  s->vlan_id = clib_host_to_net_u16 (vlan_id);
  s->local_cookie = clib_host_to_net_u64 (local_cookie);
  l2tp_session_set_remote_cookie (s, remote_cookie);
  s->local_session_id = local_session_id;
  s->remote_session_id = remote_session_id;
  s->l2_sublayer_present = l2_sublayer_present;

  hi = vnet_get_sup_hw_interface (lm->vnet_main, sw_if_index);
  si = vnet_get_sup_sw_interface (lm->vnet_main, sw_if_index);

  next_index = vlib_node_add_next (vm, l2t_ip6_node.index,
				   hi->output_node_index);
  s->l2_output_next_index = next_index;
  s->l2_output_sw_if_index = si->sw_if_index;

  /* Setup hash table entries */
  switch (lm->lookup_type)
    {
    case L2T_LOOKUP_SRC_ADDRESS:
      src_address_copy = clib_mem_alloc (sizeof (*src_address_copy));
      clib_memcpy (src_address_copy, &client_address,
		   sizeof (*src_address_copy));
      hash_set_mem (lm->session_by_src_address, src_address_copy,
		    s - lm->sessions);
      break;
    case L2T_LOOKUP_DST_ADDRESS:
      dst_address_copy = clib_mem_alloc (sizeof (*dst_address_copy));
      clib_memcpy (dst_address_copy, &our_address,
		   sizeof (*dst_address_copy));
      hash_set_mem (lm->session_by_dst_address, dst_address_copy,
		    s - lm->sessions);
      break;
    case L2T_LOOKUP_SESSION_ID:
      hash_set (lm->session_by_session_id, local_session_id,
		s - lm->sessions);
      break;

    default:
      ASSERT (0);
    }

  vlan_and_sw_if_index_key = ((uword) (s->vlan_id) << 32) | sw_if_index;
  hash_set (lm->session_by_vlan_and_rx_sw_if_index,
	    vlan_and_sw_if_index_key, s - lm->sessions);

  /* validate counters */
  counter_index =
    session_index_to_counter_index (s - lm->sessions,
				    SESSION_COUNTER_USER_TO_NETWORK);
  vlib_validate_counter (&lm->counter_main, counter_index);
  vlib_validate_counter (&lm->counter_main, counter_index + 1);

  /* Set promiscuous mode on the l2 interface */
  ethernet_set_flags (lm->vnet_main, hi->hw_if_index,
		      ETHERNET_INTERFACE_FLAG_ACCEPT_ALL);
  vnet_hw_interface_rx_redirect_to_node (lm->vnet_main, hi->hw_if_index,
					 l2t_l2_node.index);
  return 0;
}

/* *INDENT-OFF* */
static VLIB_CLI_COMMAND (l2tp_session_add_command) = {
  .path = "l2tp session add",
  .short_help =
  "l2tp session add client <ip6> our <ip6> vlan <id> local-cookie <hex> remote-cookie <hex> local-session <dec> remote-session <dec> l2-interface <int>",
  .function = l2tp_session_add_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
l2tp_session_del_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  l2t_main_t *lm = &l2t_main;
  u32 session_index;
  l2t_session_t *s;
  hash_pair_t *hp;
  void *key;
  uword vlan_and_sw_if_index_key;

  if (!unformat (input, "%d", &session_index))
    return clib_error_return (0, "missing session index: '%U'",
			      format_unformat_error, input);

  if (pool_is_free_index (lm->sessions, session_index))
    return clib_error_return (0, "session %d not in use", session_index);

  s = pool_elt_at_index (lm->sessions, session_index);

  switch (lm->lookup_type)
    {
    case L2T_LOOKUP_SRC_ADDRESS:
      hp = hash_get_pair_mem (lm->session_by_src_address, &s->client_address);
      if (hp)
	{
	  key = (void *) (hp->key);
	  hash_unset_mem (lm->session_by_src_address, &s->client_address);
	  clib_mem_free (key);
	}
      else
	clib_warning ("session %d src address key %U AWOL",
		      s - lm->sessions,
		      format_ip6_address, &s->client_address);
      break;

    case L2T_LOOKUP_DST_ADDRESS:
      hp = hash_get_pair_mem (lm->session_by_dst_address, &s->our_address);
      if (hp)
	{
	  key = (void *) (hp->key);
	  hash_unset_mem (lm->session_by_dst_address, &s->our_address);
	  clib_mem_free (key);
	}
      else
	clib_warning ("session %d dst address key %U AWOL",
		      s - lm->sessions, format_ip6_address, &s->our_address);
      break;

    case L2T_LOOKUP_SESSION_ID:
      hash_unset (lm->session_by_session_id, s->local_session_id);
      break;

    default:
      ASSERT (0);
    }

  vlan_and_sw_if_index_key = ((uword) (s->vlan_id) << 32) | s->sw_if_index;

  hash_unset (lm->session_by_vlan_and_rx_sw_if_index,
	      vlan_and_sw_if_index_key);

  pool_put (lm->sessions, s);
  return 0;
}

/* *INDENT-OFF* */
static VLIB_CLI_COMMAND (l2tp_session_del_command) = {
  .path = "l2tp session delete",
  .short_help =
  "l2tp session delete <session-id>",
  .function = l2tp_session_del_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
l2tp_session_cookie_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  l2t_main_t *lm = &l2t_main;
  u32 session_index;
  l2t_session_t *s;
  u64 lcl_ro_cookie = (u64) ~ 0, rem_ro_cookie = (u64) ~ 0;
  u8 cookie_flags = 0;

  if (!unformat (input, "%d", &session_index))
    return clib_error_return (0, "missing session index: '%U'",
			      format_unformat_error, input);

  if (pool_is_free_index (lm->sessions, session_index))
    return clib_error_return (0, "session %d not in use", session_index);

  s = pool_elt_at_index (lm->sessions, session_index);

  if (unformat (input, "commit"))
    {
      if (!s->cookie_flags)
	{
	  return clib_error_return (0, "no rollover cookie ready to commit");
	}
      else
	{
	  l2tp_session_cookie_commit (s);
	  return 0;
	}
    }
  if (!unformat (input, "rollover"))
    return clib_error_return (0, "missing 'commit|rollover': '%U'",
			      format_unformat_error, input);
  if (unformat (input, "local %llx", &lcl_ro_cookie))
    {
      cookie_flags |= L2TP_COOKIE_ROLLOVER_LOCAL;
      l2tp_session_set_local_rollover_cookie (s, lcl_ro_cookie);
    }
  if (unformat (input, "remote %llx", &rem_ro_cookie))
    {
      cookie_flags |= L2TP_COOKIE_ROLLOVER_REMOTE;
      l2tp_session_set_remote_cookie (s, rem_ro_cookie);
    }
  if (!cookie_flags)
    return clib_error_return (0, "no rollover cookie specified");

  return 0;
}

/* *INDENT-OFF* */
static VLIB_CLI_COMMAND (l2tp_session_cookie_command) = {
  .path = "l2tp session cookie",
  .short_help =
  "l2tp session cookie <session id> commit|rollover [local <hex>] [remote <hex>]",
  .function = l2tp_session_cookie_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
