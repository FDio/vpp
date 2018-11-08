/*
 * l2tp.c : L2TPv3 tunnel support
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/l2tp/l2tp.h>

l2t_main_t l2t_main;

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

  s = format (s, "[%d] %U (our) %U (client) %U (sw_if_index %d)\n",
	      session - lm->sessions,
	      format_ip6_address, &session->our_address,
	      format_ip6_address, &session->client_address,
	      format_vnet_sw_interface_name, lm->vnet_main,
	      vnet_get_sw_interface (lm->vnet_main, session->sw_if_index),
	      session->sw_if_index);

  s = format (s, "   local cookies %016llx %016llx remote cookie %016llx\n",
	      clib_net_to_host_u64 (session->local_cookie[0]),
	      clib_net_to_host_u64 (session->local_cookie[1]),
	      clib_net_to_host_u64 (session->remote_cookie));

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
show_l2tp_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  l2t_session_t *session;
  l2t_main_t *lm = &l2t_main;
  char *keystr = 0;
  int verbose = 0;

  if (unformat (input, "verbose") || unformat (input, "v"))
    verbose = 1;

  if (pool_elts (lm->sessions) == 0)
    vlib_cli_output (vm, "No l2tp sessions...");
  else
    vlib_cli_output (vm, "%u l2tp sessions...", pool_elts (lm->sessions));

  if (verbose)
    {
      switch (lm->lookup_type)
	{
	case L2T_LOOKUP_SRC_ADDRESS:
	  keystr = "src address";
	  break;

	case L2T_LOOKUP_DST_ADDRESS:
	  keystr = "dst address";
	  break;

	case L2T_LOOKUP_SESSION_ID:
	  keystr = "session id";
	  break;

	default:
	  keystr = "BOGUS!";
	  break;
	}

      vlib_cli_output (vm, "L2tp session lookup on %s", keystr);

      /* *INDENT-OFF* */
      pool_foreach (session, lm->sessions,
      ({
        vlib_cli_output (vm, "%U", format_l2t_session, session);
      }));
      /* *INDENT-ON* */
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_session_detail_command, static) = {
  .path = "show l2tpv3",
  .short_help = "show l2tpv3 [verbose]",
  .function = show_l2tp_command_fn,
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
  u32 thread_index = vm->thread_index;

  /* *INDENT-OFF* */
  pool_foreach (session, lm->sessions,
  ({
    session_index = session - lm->sessions;
    counter_index =
      session_index_to_counter_index (session_index,
                                      SESSION_COUNTER_USER_TO_NETWORK);
    vlib_increment_combined_counter (&lm->counter_main,
                                     thread_index,
                                     counter_index,
                                     1/*pkt*/, 1111 /*bytes*/);
    vlib_increment_combined_counter (&lm->counter_main,
                                     thread_index,
                                     counter_index+1,
                                     1/*pkt*/, 2222 /*bytes*/);
    nincr++;

  }));
  /* *INDENT-ON* */
  vlib_cli_output (vm, "Incremented %d active counters\n", nincr);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_counters_command, static) = {
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
VLIB_CLI_COMMAND (clear_counters_command, static) = {
  .path = "clear counters",
  .short_help = "clear all active counters",
  .function = clear_counters_command_fn,
};
/* *INDENT-ON* */

static u8 *
format_l2tpv3_name (u8 * s, va_list * args)
{
  l2t_main_t *lm = &l2t_main;
  u32 i = va_arg (*args, u32);
  u32 show_dev_instance = ~0;

  if (i < vec_len (lm->dev_inst_by_real))
    show_dev_instance = lm->dev_inst_by_real[i];

  if (show_dev_instance != ~0)
    i = show_dev_instance;

  return format (s, "l2tpv3_tunnel%d", i);
}

static int
l2tpv3_name_renumber (vnet_hw_interface_t * hi, u32 new_dev_instance)
{
  l2t_main_t *lm = &l2t_main;

  vec_validate_init_empty (lm->dev_inst_by_real, hi->dev_instance, ~0);

  lm->dev_inst_by_real[hi->dev_instance] = new_dev_instance;

  return 0;
}

static uword
dummy_interface_tx (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  clib_warning ("you shouldn't be here, leaking buffers...");
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (l2tpv3_device_class,static) = {
  .name = "L2TPv3",
  .format_device_name = format_l2tpv3_name,
  .name_renumber = l2tpv3_name_renumber,
  .tx_function = dummy_interface_tx,
};
/* *INDENT-ON* */

static u8 *
format_l2tp_header_with_length (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  s = format (s, "unimplemented dev %u", dev_instance);
  return s;
}

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (l2tpv3_hw_class) = {
  .name = "L2TPV3",
  .format_header = format_l2tp_header_with_length,
  .build_rewrite = default_build_rewrite,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};
/* *INDENT-ON* */

int
create_l2tpv3_ipv6_tunnel (l2t_main_t * lm,
			   ip6_address_t * client_address,
			   ip6_address_t * our_address,
			   u32 local_session_id,
			   u32 remote_session_id,
			   u64 local_cookie,
			   u64 remote_cookie,
			   int l2_sublayer_present,
			   u32 encap_fib_index, u32 * sw_if_index)
{
  l2t_session_t *s = 0;
  vnet_main_t *vnm = lm->vnet_main;
  vnet_hw_interface_t *hi;
  uword *p = (uword *) ~ 0;
  u32 hw_if_index;
  l2tpv3_header_t l2tp_hdr;
  ip6_address_t *dst_address_copy, *src_address_copy;
  u32 counter_index;

  remote_session_id = clib_host_to_net_u32 (remote_session_id);
  local_session_id = clib_host_to_net_u32 (local_session_id);

  switch (lm->lookup_type)
    {
    case L2T_LOOKUP_SRC_ADDRESS:
      p = hash_get_mem (lm->session_by_src_address, client_address);
      break;

    case L2T_LOOKUP_DST_ADDRESS:
      p = hash_get_mem (lm->session_by_dst_address, our_address);
      break;

    case L2T_LOOKUP_SESSION_ID:
      p = hash_get (lm->session_by_session_id, local_session_id);
      break;

    default:
      ASSERT (0);
    }

  /* adding a session: session must not already exist */
  if (p)
    return VNET_API_ERROR_INVALID_VALUE;

  pool_get (lm->sessions, s);
  clib_memset (s, 0, sizeof (*s));
  clib_memcpy (&s->our_address, our_address, sizeof (s->our_address));
  clib_memcpy (&s->client_address, client_address,
	       sizeof (s->client_address));
  s->local_cookie[0] = clib_host_to_net_u64 (local_cookie);
  s->remote_cookie = clib_host_to_net_u64 (remote_cookie);
  s->local_session_id = local_session_id;
  s->remote_session_id = remote_session_id;
  s->l2_sublayer_present = l2_sublayer_present;
  /* precompute l2tp header size */
  s->l2tp_hdr_size = l2_sublayer_present ?
    sizeof (l2tpv3_header_t) :
    sizeof (l2tpv3_header_t) - sizeof (l2tp_hdr.l2_specific_sublayer);
  s->admin_up = 0;
  s->encap_fib_index = encap_fib_index;

  /* Setup hash table entries */
  switch (lm->lookup_type)
    {
    case L2T_LOOKUP_SRC_ADDRESS:
      src_address_copy = clib_mem_alloc (sizeof (*src_address_copy));
      clib_memcpy (src_address_copy, client_address,
		   sizeof (*src_address_copy));
      hash_set_mem (lm->session_by_src_address, src_address_copy,
		    s - lm->sessions);
      break;
    case L2T_LOOKUP_DST_ADDRESS:
      dst_address_copy = clib_mem_alloc (sizeof (*dst_address_copy));
      clib_memcpy (dst_address_copy, our_address, sizeof (*dst_address_copy));
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

  /* validate counters */
  counter_index =
    session_index_to_counter_index (s - lm->sessions,
				    SESSION_COUNTER_USER_TO_NETWORK);
  vlib_validate_combined_counter (&lm->counter_main, counter_index);
  vlib_validate_combined_counter (&lm->counter_main, counter_index + 1);

  if (vec_len (lm->free_l2tpv3_tunnel_hw_if_indices) > 0)
    {
      hw_if_index = lm->free_l2tpv3_tunnel_hw_if_indices
	[vec_len (lm->free_l2tpv3_tunnel_hw_if_indices) - 1];
      _vec_len (lm->free_l2tpv3_tunnel_hw_if_indices) -= 1;

      hi = vnet_get_hw_interface (vnm, hw_if_index);
      hi->dev_instance = s - lm->sessions;
      hi->hw_instance = hi->dev_instance;
    }
  else
    {
      hw_if_index = vnet_register_interface
	(vnm, l2tpv3_device_class.index, s - lm->sessions,
	 l2tpv3_hw_class.index, s - lm->sessions);
      hi = vnet_get_hw_interface (vnm, hw_if_index);
      hi->output_node_index = l2t_encap_node.index;
      /* $$$$ initialize custom dispositions, if needed */
    }

  s->hw_if_index = hw_if_index;
  s->sw_if_index = hi->sw_if_index;

  if (sw_if_index)
    *sw_if_index = hi->sw_if_index;

  return 0;
}

static clib_error_t *
create_l2tpv3_tunnel_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  ip6_address_t client_address, our_address;
  unformat_input_t _line_input, *line_input = &_line_input;
  l2t_main_t *lm = &l2t_main;
  u64 local_cookie = (u64) ~ 0, remote_cookie = (u64) ~ 0;
  u32 local_session_id = 1, remote_session_id = 1;
  int our_address_set = 0, client_address_set = 0;
  int l2_sublayer_present = 0;
  int rv;
  u32 sw_if_index;
  u32 encap_fib_id = ~0;
  u32 encap_fib_index = ~0;
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
      else if (unformat (line_input, "fib-id %d", &encap_fib_id))
	;
      else if (unformat (line_input, "l2-sublayer-present"))
	l2_sublayer_present = 1;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (encap_fib_id != ~0)
    {
      uword *p;
      ip6_main_t *im = &ip6_main;
      if (!(p = hash_get (im->fib_index_by_table_id, encap_fib_id)))
	{
	  error = clib_error_return (0, "No fib with id %d", encap_fib_id);
	  goto done;
	}
      encap_fib_index = p[0];
    }
  else
    {
      encap_fib_index = ~0;
    }

  if (our_address_set == 0)
    {
      error = clib_error_return (0, "our address not specified");
      goto done;
    }
  if (client_address_set == 0)
    {
      error = clib_error_return (0, "client address not specified");
      goto done;
    }

  rv = create_l2tpv3_ipv6_tunnel (lm, &client_address, &our_address,
				  local_session_id, remote_session_id,
				  local_cookie, remote_cookie,
				  l2_sublayer_present,
				  encap_fib_index, &sw_if_index);
  switch (rv)
    {
    case 0:
      vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name,
		       vnet_get_main (), sw_if_index);
      break;
    case VNET_API_ERROR_INVALID_VALUE:
      error = clib_error_return (0, "session already exists...");
      goto done;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "session does not exist...");
      goto done;

    default:
      error = clib_error_return (0, "l2tp_session_add_del returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (create_l2tpv3_tunnel_command, static) =
{
  .path = "create l2tpv3 tunnel",
  .short_help =
  "create l2tpv3 tunnel client <ip6> our <ip6> local-cookie <hex> remote-cookie <hex> local-session <dec> remote-session <dec>",
  .function = create_l2tpv3_tunnel_command_fn,
};
/* *INDENT-ON* */

int
l2tpv3_set_tunnel_cookies (l2t_main_t * lm,
			   u32 sw_if_index,
			   u64 new_local_cookie, u64 new_remote_cookie)
{
  l2t_session_t *s;
  vnet_hw_interface_t *hi;
  vnet_main_t *vnm = vnet_get_main ();
  hi = vnet_get_sup_hw_interface (vnm, sw_if_index);

  if (pool_is_free_index (lm->sessions, hi->dev_instance))
    return VNET_API_ERROR_INVALID_VALUE;

  s = pool_elt_at_index (lm->sessions, hi->dev_instance);

  s->local_cookie[1] = s->local_cookie[0];
  s->local_cookie[0] = clib_host_to_net_u64 (new_local_cookie);
  s->remote_cookie = clib_host_to_net_u64 (new_remote_cookie);

  return 0;
}


static clib_error_t *
set_l2tp_tunnel_cookie_command_fn (vlib_main_t * vm,
				   unformat_input_t * input,
				   vlib_cli_command_t * cmd)
{
  l2t_main_t *lm = &l2t_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  u64 local_cookie = (u64) ~ 0, remote_cookie = (u64) ~ 0;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
		    &sw_if_index))
	;
      else if (unformat (input, "local %llx", &local_cookie))
	;
      else if (unformat (input, "remote %llx", &remote_cookie))
	;
      else
	break;
    }
  if (sw_if_index == ~0)
    return clib_error_return (0, "unknown interface");
  if (local_cookie == ~0)
    return clib_error_return (0, "local cookie required");
  if (remote_cookie == ~0)
    return clib_error_return (0, "remote cookie required");

  rv = l2tpv3_set_tunnel_cookies (lm, sw_if_index,
				  local_cookie, remote_cookie);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return (0, "invalid interface");

    default:
      return clib_error_return (0, "l2tp_session_set_cookies returned %d",
				rv);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_l2tp_tunnel_cookie_command, static) =
{
  .path = "set l2tpv3 tunnel cookie",
  .short_help =
  "set l2tpv3 tunnel cookie <intfc> local <hex> remote <hex>",
  .function = set_l2tp_tunnel_cookie_command_fn,
};
/* *INDENT-ON* */

int
l2tpv3_interface_enable_disable (vnet_main_t * vnm,
				 u32 sw_if_index, int enable_disable)
{

  if (pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_feature_enable_disable ("ip6-unicast", "l2tp-decap", sw_if_index,
			       enable_disable, 0, 0);
  return 0;
}

/* Enable/disable L2TPv3 intercept on IP6 forwarding path */
static clib_error_t *
set_ip6_l2tpv3 (vlib_main_t * vm,
		unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 sw_if_index = ~0;
  int is_add = 1;
  int rv;
  vnet_main_t *vnm = vnet_get_main ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
		    &sw_if_index))
	;
      else if (unformat (input, "del"))
	is_add = 0;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "interface required");

  rv = l2tpv3_interface_enable_disable (vnm, sw_if_index, is_add);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return (0, "invalid interface");

    default:
      return clib_error_return (0,
				"l2tp_interface_enable_disable returned %d",
				rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_ip6_l2tpv3, static) =
{
  .path = "set interface ip6 l2tpv3",
  .function = set_ip6_l2tpv3,
  .short_help = "set interface ip6 l2tpv3 <intfc> [del]",
};
/* *INDENT-ON* */

static clib_error_t *
l2tp_config (vlib_main_t * vm, unformat_input_t * input)
{
  l2t_main_t *lm = &l2t_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "lookup-v6-src"))
	lm->lookup_type = L2T_LOOKUP_SRC_ADDRESS;
      else if (unformat (input, "lookup-v6-dst"))
	lm->lookup_type = L2T_LOOKUP_DST_ADDRESS;
      else if (unformat (input, "lookup-session-id"))
	lm->lookup_type = L2T_LOOKUP_SESSION_ID;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (l2tp_config, "l2tp");


clib_error_t *
l2tp_sw_interface_up_down (vnet_main_t * vnm, u32 sw_if_index, u32 flags)
{
  l2t_main_t *lm = &l2t_main;
  vnet_hw_interface_t *hi = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (hi->hw_class_index != l2tpv3_hw_class.index)
    return 0;

  u32 session_index = hi->dev_instance;
  l2t_session_t *s = pool_elt_at_index (lm->sessions, session_index);
  s->admin_up = ! !(flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP);
  return 0;
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (l2tp_sw_interface_up_down);

clib_error_t *
l2tp_init (vlib_main_t * vm)
{
  l2t_main_t *lm = &l2t_main;
  ip_main_t *im = &ip_main;
  ip_protocol_info_t *pi;

  lm->vnet_main = vnet_get_main ();
  lm->vlib_main = vm;
  lm->lookup_type = L2T_LOOKUP_DST_ADDRESS;

  lm->session_by_src_address = hash_create_mem
    (0, sizeof (ip6_address_t) /* key bytes */ ,
     sizeof (u32) /* value bytes */ );
  lm->session_by_dst_address = hash_create_mem
    (0, sizeof (ip6_address_t) /* key bytes */ ,
     sizeof (u32) /* value bytes */ );
  lm->session_by_session_id = hash_create (0, sizeof (uword));

  pi = ip_get_protocol_info (im, IP_PROTOCOL_L2TP);
  pi->unformat_pg_edit = unformat_pg_l2tp_header;

  /* insure these nodes are included in build */
  l2tp_encap_init (vm);
  l2tp_decap_init ();

  return 0;
}

VLIB_INIT_FUNCTION (l2tp_init);

clib_error_t *
l2tp_worker_init (vlib_main_t * vm)
{
  l2tp_encap_init (vm);

  return 0;
}

VLIB_WORKER_INIT_FUNCTION (l2tp_worker_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
