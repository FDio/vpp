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
 * ip/ip_lookup.c: ip4/6 adjacency and lookup table management
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

#include <vnet/ip/ip_container_proxy.h>
#include <vnet/ip/format.h>
#include <vnet/fib/fib_table.h>
#include <vnet/dpo/l3_proxy_dpo.h>
#include <vnet/dpo/load_balance.h>

clib_error_t *
vnet_ip_container_proxy_add_del (vnet_ip_container_proxy_args_t * args)
{
  u32 fib_index;

  if (!vnet_sw_interface_is_api_valid (vnet_get_main (), args->sw_if_index))
    return clib_error_return_code (0, VNET_API_ERROR_INVALID_INTERFACE, 0,
				   "invalid sw_if_index");

  fib_index = fib_table_get_table_id_for_sw_if_index (args->prefix.fp_proto,
						      args->sw_if_index);
  if (args->is_add)
    {
      dpo_id_t proxy_dpo = DPO_INVALID;
      l3_proxy_dpo_add_or_lock (fib_proto_to_dpo (args->prefix.fp_proto),
				args->sw_if_index, &proxy_dpo);
      fib_table_entry_special_dpo_add (fib_index,
				       &args->prefix,
				       FIB_SOURCE_PROXY,
				       FIB_ENTRY_FLAG_EXCLUSIVE, &proxy_dpo);
      dpo_reset (&proxy_dpo);
    }
  else
    {
      fib_table_entry_special_remove (fib_index, &args->prefix,
				      FIB_SOURCE_PROXY);
    }
  return 0;
}

u8
ip_container_proxy_is_set (fib_prefix_t * pfx, u32 sw_if_index)
{
  u32 fib_index;
  fib_node_index_t fei;
  const dpo_id_t *dpo;
  l3_proxy_dpo_t *l3p;
  load_balance_t *lb0;

  fib_index = fib_table_get_table_id_for_sw_if_index (pfx->fp_proto,
						      sw_if_index);
  if (fib_index == ~0)
    return 0;

  fei = fib_table_lookup_exact_match (fib_index, pfx);
  if (fei == FIB_NODE_INDEX_INVALID)
    return 0;

  dpo = fib_entry_contribute_ip_forwarding (fei);
  lb0 = load_balance_get (dpo->dpoi_index);
  dpo = load_balance_get_bucket_i (lb0, 0);
  if (dpo->dpoi_type != DPO_L3_PROXY)
    return 0;

  l3p = l3_proxy_dpo_get (dpo->dpoi_index);
  return (l3p->l3p_sw_if_index == sw_if_index);
}

typedef struct ip_container_proxy_walk_ctx_t_
{
  ip_container_proxy_cb_t cb;
  void *ctx;
} ip_container_proxy_walk_ctx_t;

static fib_table_walk_rc_t
ip_container_proxy_fib_table_walk (fib_node_index_t fei, void *arg)
{
  ip_container_proxy_walk_ctx_t *ctx = arg;
  const fib_prefix_t *pfx;
  const dpo_id_t *dpo;
  load_balance_t *lb;
  l3_proxy_dpo_t *l3p;

  pfx = fib_entry_get_prefix (fei);
  if (fib_entry_is_sourced (fei, FIB_SOURCE_PROXY))
    {
      dpo = fib_entry_contribute_ip_forwarding (fei);
      lb = load_balance_get (dpo->dpoi_index);
      dpo = load_balance_get_bucket_i (lb, 0);
      l3p = l3_proxy_dpo_get (dpo->dpoi_index);
      ctx->cb (pfx, l3p->l3p_sw_if_index, ctx->ctx);
    }

  return FIB_TABLE_WALK_CONTINUE;
}

void
ip_container_proxy_walk (ip_container_proxy_cb_t cb, void *ctx)
{
  fib_table_t *fib_table;
  ip_container_proxy_walk_ctx_t wctx = {
    .cb = cb,
    .ctx = ctx,
  };

  /* *INDENT-OFF* */
  pool_foreach (fib_table, ip4_main.fibs)
   {
    fib_table_walk(fib_table->ft_index,
                   FIB_PROTOCOL_IP4,
                   ip_container_proxy_fib_table_walk,
                   &wctx);
  }
  pool_foreach (fib_table, ip6_main.fibs)
   {
    fib_table_walk(fib_table->ft_index,
                   FIB_PROTOCOL_IP6,
                   ip_container_proxy_fib_table_walk,
                   &wctx);
  }
  /* *INDENT-ON* */
}

clib_error_t *
ip_container_cmd (vlib_main_t * vm,
		  unformat_input_t * main_input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  fib_prefix_t pfx;
  u32 is_del, addr_set = 0;
  vnet_main_t *vnm;
  u32 sw_if_index;

  vnm = vnet_get_main ();
  is_del = 0;
  sw_if_index = ~0;
  clib_memset (&pfx, 0, sizeof (pfx));

  /* Get a line of input. */
  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_ip4_address, &pfx.fp_addr.ip4))
	{
	  pfx.fp_proto = FIB_PROTOCOL_IP4;
	  pfx.fp_len = 32;
	  addr_set = 1;
	}
      else if (unformat (line_input, "%U",
			 unformat_ip6_address, &pfx.fp_addr.ip6))
	{
	  pfx.fp_proto = FIB_PROTOCOL_IP6;
	  pfx.fp_len = 128;
	  addr_set = 1;
	}
      else if (unformat (line_input, "%U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (line_input, "del"))
	is_del = 1;
      else
	{
	  unformat_free (line_input);
	  return (clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input));
	}
    }

  if (~0 == sw_if_index || !addr_set)
    {
      unformat_free (line_input);
      vlib_cli_output (vm, "interface and address must be set");
      return 0;
    }

  vnet_ip_container_proxy_args_t args = {
    .prefix = pfx,
    .sw_if_index = sw_if_index,
    .is_add = !is_del,
  };
  vnet_ip_container_proxy_add_del (&args);
  unformat_free (line_input);
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip_container_command_node, static) = {
  .path = "ip container",
  .function = ip_container_cmd,
  .short_help = "ip container <address> <interface>",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

clib_error_t *
show_ip_container_cmd_fn (vlib_main_t * vm, unformat_input_t * main_input,
			  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  fib_prefix_t pfx;
  u32 sw_if_index = ~0;
  u8 has_proxy;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_ip4_address, &pfx.fp_addr.ip4))
	{
	  pfx.fp_proto = FIB_PROTOCOL_IP4;
	  pfx.fp_len = 32;
	}
      else if (unformat (line_input, "%U",
			 unformat_ip6_address, &pfx.fp_addr.ip6))
	{
	  pfx.fp_proto = FIB_PROTOCOL_IP6;
	  pfx.fp_len = 128;
	}
      else if (unformat (line_input, "%U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	{
	  unformat_free (line_input);
	  return (clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input));
	}
    }

  if (~0 == sw_if_index)
    {
      unformat_free (line_input);
      vlib_cli_output (vm, "no interface");
      return (clib_error_return (0, "no interface"));
    }

  has_proxy = ip_container_proxy_is_set (&pfx, sw_if_index);
  vlib_cli_output (vm, "ip container proxy is: %s", has_proxy ? "on" : "off");

  unformat_free (line_input);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ip_container_command, static) = {
  .path = "show ip container",
  .function = show_ip_container_cmd_fn,
  .short_help = "show ip container <address> <interface>",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
