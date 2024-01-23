/*
 * pvti.c - skeleton vpp engine plug-in
 *
 * Copyright (c) <current-year> <your-organization>
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
#include <vnet/plugin/plugin.h>
#include <vnet/fib/fib_table.h>
#include <pvti/pvti.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include <pvti/pvti.api_enum.h>
#include <pvti/pvti.api_types.h>

#include <pvti/pvti_if.h>

#define REPLY_MSG_ID_BASE pmp->msg_id_base
#include <vlibapi/api_helper_macros.h>
#include <vnet/ip/ip_format_fns.h>

pvti_main_t pvti_main;

u8 *
format_pvti_tx_peer_ptr (u8 *s, va_list *args)
{
  pvti_tx_peer_t *peer = va_arg (*args, pvti_tx_peer_t *);

  s = format (
    s,
    "[%p]%s local:%U:%d remote:%U:%d underlay_mtu:%d underlay_fib_idx:%d "
    "pvti_idx:%d b0_max_clen:%d cseq:%d chunk_count:%d reass_chunk_count:%d",
    peer, peer->deleted ? " DELETED" : "", format_ip46_address,
    &peer->local_ip, IP46_TYPE_ANY, peer->local_port, format_ip46_address,
    &peer->remote_ip, IP46_TYPE_ANY, peer->remote_port, peer->underlay_mtu,
    peer->underlay_fib_index, peer->pvti_if_index,
    peer->bo0_max_current_length, peer->current_tx_seq, peer->chunk_count,
    peer->reass_chunk_count);

  return (s);
}

u8 *
format_pvti_rx_peer_ptr (u8 *s, va_list *args)
{
  pvti_rx_peer_t *peer = va_arg (*args, pvti_rx_peer_t *);

  s = format (s, "[%p]%s local:%U:%d remote:%U:%d pvti_idx:%d", peer,
	      peer->deleted ? " DELETED" : "", format_ip46_address,
	      &peer->local_ip, IP46_TYPE_ANY, peer->local_port,
	      format_ip46_address, &peer->remote_ip, IP46_TYPE_ANY,
	      peer->remote_port, peer->pvti_if_index);

  return (s);
}

/* Action function shared between message handler and debug CLI */

int
pvti_enable_disable (pvti_main_t *pmp, u32 sw_if_index, int enable_disable)
{
  vnet_sw_interface_t *sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (pmp->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (pmp->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  pvti_create_periodic_process (pmp);

  vnet_feature_enable_disable ("device-input", "pvti", sw_if_index,
			       enable_disable, 0, 0);

  /* Send an event to enable/disable the periodic scanner process */
  vlib_process_signal_event (pmp->vlib_main, pmp->periodic_node_index,
			     PVTI_EVENT_PERIODIC_ENABLE_DISABLE,
			     (uword) enable_disable);
  return rv;
}

void
pvti_verify_initialized (pvti_main_t *pvm)
{
  if (!pvm->is_initialized)
    {
      const int n_threads = vlib_get_n_threads ();
      vec_validate (pvm->per_thread_data[0], n_threads - 1);
      vec_validate (pvm->per_thread_data[1], n_threads - 1);
      pvm->is_initialized = 1;
    }
}

void
vnet_int_pvti_bypass_mode (u32 sw_if_index, u8 is_ip6, u8 is_enable)
{
  pvti_main_t *pvm = &pvti_main;

  if (pool_is_free_index (pvm->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return;

  pvti_verify_initialized (pvm);

  is_enable = !!is_enable;

  if (is_ip6)
    {
      if (clib_bitmap_get (pvm->bm_ip6_bypass_enabled_by_sw_if, sw_if_index) !=
	  is_enable)
	{
	  vnet_feature_enable_disable ("ip6-unicast", "ip6-pvti-bypass",
				       sw_if_index, is_enable, 0, 0);
	  pvm->bm_ip6_bypass_enabled_by_sw_if = clib_bitmap_set (
	    pvm->bm_ip6_bypass_enabled_by_sw_if, sw_if_index, is_enable);
	}
    }
  else
    {
      if (clib_bitmap_get (pvm->bm_ip4_bypass_enabled_by_sw_if, sw_if_index) !=
	  is_enable)
	{
	  vnet_feature_enable_disable ("ip4-unicast", "ip4-pvti-bypass",
				       sw_if_index, is_enable, 0, 0);
	  pvm->bm_ip4_bypass_enabled_by_sw_if = clib_bitmap_set (
	    pvm->bm_ip4_bypass_enabled_by_sw_if, sw_if_index, is_enable);
	}
    }
}

static clib_error_t *
set_ip_pvti_bypass (u32 is_ip6, unformat_input_t *input,
		    vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index, is_enable;

  sw_if_index = ~0;
  is_enable = 1;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat_user (line_input, unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	;
      else if (unformat (line_input, "del"))
	is_enable = 0;
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

  vnet_int_pvti_bypass_mode (sw_if_index, is_ip6, is_enable);

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
set_ip4_pvti_bypass (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  return set_ip_pvti_bypass (0, input, cmd);
}

VLIB_CLI_COMMAND (set_interface_ip_pvti_bypass_command, static) = {
  .path = "set interface ip pvti-bypass",
  .function = set_ip4_pvti_bypass,
  .short_help = "set interface ip pvti-bypass <interface> [del]",
};

static clib_error_t *
set_ip6_pvti_bypass (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  return set_ip_pvti_bypass (1, input, cmd);
}

VLIB_CLI_COMMAND (set_interface_ip6_pvti_bypass_command, static) = {
  .path = "set interface ip6 pvti-bypass",
  .function = set_ip6_pvti_bypass,
  .short_help = "set interface ip6 pvti-bypass <interface> [del]",
};

static clib_error_t *
pvti_interface_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
				  vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;

  // pvti_main_t * pmp = &pvti_main;
  u32 sw_if_index = ~0;
  // int enable_disable = 1;
  int rv = 0;
  ip_address_t peer_ip = { 0 };
  ip_address_t local_ip = { 0 };
  u32 peer_port = 0;
  u32 local_port = 12345;
  u32 underlay_mtu = 1500;
  u32 underlay_fib_index = ~0;
  u32 underlay_table_id = ~0;
  pvti_peer_address_method_t peer_address_method = PVTI_PEER_ADDRESS_FIXED;
  bool peer_set = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "peer %U %d %d", unformat_ip_address, &peer_ip,
		    &peer_port, &local_port))
	{
	  peer_set = 1;
	}
      else if (unformat (line_input, "underlay-mtu %d", &underlay_mtu))
	{
	  // MTU set
	}
      else if (unformat (line_input, "local-ip %U", unformat_ip_address,
			 &local_ip))
	{
	  // local IP set
	}
      else if (unformat (line_input, "underlay-fib %d", &underlay_fib_index))
	{
	  // underlay fib set
	}
      else if (unformat (line_input, "peer-address-from-payload"))
	{
	  peer_address_method = PVTI_PEER_ADDRESS_FROM_PAYLOAD;
	}
      else if (unformat (line_input, "underlay-table %d", &underlay_table_id))
	{
	  fib_protocol_t fib_proto = FIB_PROTOCOL_IP4;
	  if (peer_ip.version == AF_IP6)
	    {
	      fib_proto = FIB_PROTOCOL_IP6;
	    }
	  u32 fib_index = fib_table_find (fib_proto, underlay_table_id);

	  if (~0 == fib_index)
	    {
	      error = clib_error_return (0, "Nonexistent table id %d",
					 underlay_table_id);
	      goto done;
	    }
	  underlay_fib_index = fib_index;
	}
      else
	break;
    }
  if (!peer_set)
    {
      error = clib_error_return (0, "Please specify a peer...");
      goto done;
    }

  rv = pvti_if_create (&local_ip, local_port, &peer_ip, peer_port,
		       peer_address_method, underlay_mtu, underlay_fib_index,
		       &sw_if_index);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      error = clib_error_return (
	0, "Invalid interface, only works on physical ports");
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      error =
	clib_error_return (0, "Device driver doesn't support redirection");
      break;

    default:
      error = clib_error_return (0, "pvti_enable_disable returned %d", rv);
    }
done:
  unformat_free (line_input);
  return error;
}

static clib_error_t *
pvti_interface_delete_command_fn (vlib_main_t *vm, unformat_input_t *input,
				  vlib_cli_command_t *cmd)
{
  // pvti_main_t * pmp = &pvti_main;
  u32 sw_if_index = ~0;
  // int enable_disable = 1;
  int rv = 0;
  bool peer_set = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "if-index %d", &sw_if_index))
	{
	  peer_set = 1;
	}
      else
	break;
    }
  if (!peer_set)
    return clib_error_return (0, "Please specify a peer...");

  rv = pvti_if_delete (sw_if_index);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return (
	0, "Invalid interface, only works on physical ports");
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return (0,
				"Device driver doesn't support redirection");
      break;

    default:
      return clib_error_return (0, "pvti_enable_disable returned %d", rv);
    }
  return 0;
}

VLIB_CLI_COMMAND (pvti_interface_create_command, static) = {
  .path = "pvti interface create",
  .short_help =
    "pvti interface create peer <remote-ip> <remote-port> <local-port> [ "
    "local-ip <ip-addr> ][ underlay-mtu <MTU>][underlay-table "
    "<table-index>][inderlay-fib <fib-index>]",
  .function = pvti_interface_create_command_fn,
};

VLIB_CLI_COMMAND (pvti_interface_delete_command, static) = {
  .path = "pvti interface delete",
  .short_help = "pvti interface delete if-index <sw-ifindex>",
  .function = pvti_interface_delete_command_fn,
};

static clib_error_t *
pvti_show_interface_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  pvti_if_t *pvti_if;
  vec_foreach (pvti_if, pvti_main.if_pool)
    {
      int index = pvti_if - pvti_main.if_pool;
      vlib_cli_output (vm, "%U", format_pvti_if, index);
    };
  return 0;
}

static clib_error_t *
pvti_show_tx_peers_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  pvti_per_thread_data_t *ptd;
  int is_ip6;
  for (is_ip6 = 0; is_ip6 <= 1; is_ip6++)
    {
      vec_foreach (ptd, pvti_main.per_thread_data[is_ip6])
	{
	  vlib_cli_output (vm, "thread %d (%s)",
			   ptd - pvti_main.per_thread_data[is_ip6],
			   is_ip6 ? "IPv6" : "IPv4");
	  pvti_tx_peer_t *peer;
	  vec_foreach (peer, ptd->tx_peers)
	    {
	      vlib_cli_output (vm, "      %U", format_pvti_tx_peer_ptr, peer);
	    }
	}
    }
  return 0;
}

static clib_error_t *
pvti_show_rx_peers_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  pvti_per_thread_data_t *ptd;
  int is_ip6;
  for (is_ip6 = 0; is_ip6 <= 1; is_ip6++)
    {
      vec_foreach (ptd, pvti_main.per_thread_data[is_ip6])
	{
	  vlib_cli_output (vm, "thread %d (%s)",
			   ptd - pvti_main.per_thread_data[is_ip6],
			   is_ip6 ? "IPv6" : "IPv4");
	  pvti_rx_peer_t *peer;
	  vec_foreach (peer, ptd->rx_peers)
	    {
	      vlib_cli_output (vm, "      %U", format_pvti_rx_peer_ptr, peer);
	    }
	}
    }
  return 0;
}

VLIB_CLI_COMMAND (pvti_show_interface_command, static) = {
  .path = "show pvti interface",
  .short_help = "show pvti interface",
  .function = pvti_show_interface_command_fn,
};

VLIB_CLI_COMMAND (pvti_show_tx_peers_command, static) = {
  .path = "show pvti tx peers",
  .short_help = "show pvti tx peers",
  .function = pvti_show_tx_peers_command_fn,
};

VLIB_CLI_COMMAND (pvti_show_rx_peers_command, static) = {
  .path = "show pvti rx peers",
  .short_help = "show pvti rx peers",
  .function = pvti_show_rx_peers_command_fn,
};

/* API definitions */
//#include <pvti/pvti.api.c>
//
//
void pvti_api_init ();

VNET_FEATURE_INIT (pvti4_bypass, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "ip4-pvti-bypass",
  .runs_before = 0,
};

VNET_FEATURE_INIT (pvti6_bypass, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "ip6-pvti-bypass",
  .runs_before = 0,
};

static clib_error_t *
pvti_early_config (vlib_main_t *vm, unformat_input_t *input)
{
  clib_warning ("early config pvti");
  u8 *runs_before = 0;
  int rbi = 0;
  if (vec_len (vnet_feat_pvti4_bypass.runs_before) == 0)
    {
      rbi = 0;
    }
  else
    {
      rbi = vec_len (vnet_feat_pvti4_bypass.runs_before) - 1;
    }
  vec_validate (vnet_feat_pvti4_bypass.runs_before, rbi);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "runs-before %v", &runs_before))
	{
	  vec_add1 (runs_before, 0);
	  vnet_feat_pvti4_bypass.runs_before[rbi] = (char *) runs_before;
	  vec_add1 (vnet_feat_pvti4_bypass.runs_before, 0);
	}
      else
	return clib_error_return (0, "unknown input");
    }

  return NULL;
}

VLIB_EARLY_CONFIG_FUNCTION (pvti_early_config, "pvti");

static clib_error_t *
pvti_init (vlib_main_t *vm)
{
  pvti_main_t *pmp = &pvti_main;
  clib_error_t *error = 0;
  clib_warning ("pvti init");

  pmp->vlib_main = vm;
  pmp->vnet_main = vnet_get_main ();
  pmp->is_initialized = 0;

  pvti_api_init ();
  return error;
}

VLIB_INIT_FUNCTION (pvti_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Packet Vector Tunnel Interface plugin",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
