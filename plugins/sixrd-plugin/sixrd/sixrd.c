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

#include "sixrd.h"
#include <vnet/plugin/plugin.h>

#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/adj/adj.h>

/*
 * This code supports the following sixrd modes:
 * 
 * 32 EA bits (Complete IPv4 address is embedded):
 *   ea_bits_len = 32
 * IPv4 suffix is embedded:
 *   ea_bits_len = < 32
 * No embedded address bits (1:1 mode):
 *   ea_bits_len = 0
 */

int
sixrd_create_domain (ip6_address_t *ip6_prefix,
		     u8 ip6_prefix_len,
		     ip4_address_t *ip4_prefix,
		     u8 ip4_prefix_len,
		     ip4_address_t *ip4_src,
		     u32 *sixrd_domain_index,
		     u16 mtu)
{
  sixrd_main_t *mm = &sixrd_main;
  fib_node_index_t fei;
  adj_index_t ai6, ai4;
  sixrd_domain_t *d;

  /* Get domain index */
  pool_get_aligned(mm->domains, d, CLIB_CACHE_LINE_BYTES);
  memset(d, 0, sizeof (*d));
  *sixrd_domain_index = d - mm->domains;

  /* Init domain struct */
  d->ip4_prefix.as_u32 = ip4_prefix->as_u32;
  d->ip4_prefix_len = ip4_prefix_len;
  d->ip6_prefix = *ip6_prefix;
  d->ip6_prefix_len = ip6_prefix_len;
  d->ip4_src = *ip4_src;
  d->mtu = mtu;

  if (ip4_prefix_len < 32)
    d->shift = 64 - ip6_prefix_len + (32 - ip4_prefix_len);
    
  /* Create IPv6 route/adjacency */
  fib_prefix_t pfx6 = {
      .fp_proto = FIB_PROTOCOL_IP6,
      .fp_len = d->ip6_prefix_len,
      .fp_addr = {
	  .ip6 = d->ip6_prefix,
      },
  };
  ai6 = adj_map_add_or_lock(FIB_PROTOCOL_IP6,
			    mm->ip6_lookup_next_index,
			    *sixrd_domain_index);
  fib_table_entry_special_add(0, &pfx6,
			      FIB_SOURCE_SIXRD,
			      FIB_ENTRY_FLAG_EXCLUSIVE,
			      ai6);

  /*
   * Multiple SIXRD domains may share same source IPv4 TEP
   * In this case the route will exist and be SixRD sourced.
   * Find the adj (if any) already contributed and modify it
   */
  fib_prefix_t pfx4 = {
      .fp_proto = FIB_PROTOCOL_IP6,
      .fp_len = d->ip4_prefix_len,
      .fp_addr = {
	  .ip4 = d->ip4_prefix,
      },
  };
  fei = fib_table_lookup_exact_match(0, &pfx4);

  if (FIB_NODE_INDEX_INVALID == fei)
  {
      ai4 = fib_entry_get_adj_for_source(fei, FIB_SOURCE_SIXRD);

      if (ADJ_INDEX_INVALID != ai6)
      {
	  /*
	   * modify the existing adj to indicate it's shared
	   * skip to route add.
	   * It is locked to pair with the unlock below.
	   */
	  adj_map_update(ai4, ~0);
	  adj_lock(ai4);

	  goto route_add;
      }
  }
  /* first time addition of the route */
  ai4 = adj_map_add_or_lock(FIB_PROTOCOL_IP4,
			    mm->ip6_lookup_next_index,
			    *sixrd_domain_index);

route_add:
  /*
   * Create ip4 route. This is a reference counted add. If the prefix
   * already exists and is SixRD sourced, it is now SixRD source n+1 times
   * and will need to be removed n+1 times.
   */
  fib_table_entry_special_add(0, &pfx4,
			      FIB_SOURCE_SIXRD,
			      FIB_ENTRY_FLAG_EXCLUSIVE,
			      ai4);
  adj_unlock(ai4);

  return 0;
}

/*
 * sixrd_delete_domain
 */
int
sixrd_delete_domain (u32 sixrd_domain_index)
{
  sixrd_main_t *mm = &sixrd_main;
  sixrd_domain_t *d;

  if (pool_is_free_index(mm->domains, sixrd_domain_index)) {
    clib_warning("SIXRD domain delete: domain does not exist: %d",
		 sixrd_domain_index);
    return -1;
  }

  d = pool_elt_at_index(mm->domains, sixrd_domain_index);

  fib_prefix_t pfx = {
      .fp_proto = FIB_PROTOCOL_IP4,
      .fp_len = d->ip4_prefix_len,
      .fp_addr = {
	  .ip4 = d->ip4_prefix,
      },
  };
  fib_table_entry_special_remove(0, &pfx, FIB_SOURCE_SIXRD);

  fib_prefix_t pfx6 = {
      .fp_proto = FIB_PROTOCOL_IP6,
      .fp_len = d->ip6_prefix_len,
      .fp_addr = {
	  .ip6 = d->ip6_prefix,
      },
  };
  fib_table_entry_special_remove(0, &pfx6, FIB_SOURCE_SIXRD);

  pool_put(mm->domains, d);

  return 0;
}

static clib_error_t *
sixrd_add_domain_command_fn (vlib_main_t *vm,
                           unformat_input_t *input,
                           vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t ip4_prefix;
  ip6_address_t ip6_prefix;
  ip4_address_t ip4_src;
  u32 ip6_prefix_len=0, ip4_prefix_len=0, sixrd_domain_index;
  u32 num_m_args = 0;
  /* Optional arguments */
  u32 mtu = 0;

  /* Get a line of input. */
  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "ip6-pfx %U/%d", unformat_ip6_address, &ip6_prefix, &ip6_prefix_len))
      num_m_args++;
    else if (unformat(line_input, "ip4-pfx %U/%d", unformat_ip4_address, &ip4_prefix, &ip4_prefix_len))
      num_m_args++;
    else if (unformat(line_input, "ip4-src %U", unformat_ip4_address, &ip4_src))
      num_m_args++;
    else if (unformat(line_input, "mtu %d", &mtu))
      num_m_args++;
    else
      return clib_error_return(0, "unknown input `%U'",
                               format_unformat_error, input);
  }
  unformat_free(line_input);

  if (num_m_args < 3)
    return clib_error_return(0, "mandatory argument(s) missing");

  sixrd_create_domain(&ip6_prefix, ip6_prefix_len, &ip4_prefix, ip4_prefix_len,
		      &ip4_src, &sixrd_domain_index, mtu);

  return 0;
}

static clib_error_t *
sixrd_del_domain_command_fn (vlib_main_t *vm,
			   unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 num_m_args = 0;
  u32 sixrd_domain_index;

  /* Get a line of input. */
  if (! unformat_user(input, unformat_line_input, line_input))
    return 0;
 
  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "index %d", &sixrd_domain_index))
      num_m_args++;
    else
      return clib_error_return(0, "unknown input `%U'",
				format_unformat_error, input);
  }
  unformat_free(line_input);

  if (num_m_args != 1)
    return clib_error_return(0, "mandatory argument(s) missing");

  sixrd_delete_domain(sixrd_domain_index);

  return 0;
}

static u8 *
format_sixrd_domain (u8 *s, va_list *args)
{
  sixrd_domain_t *d = va_arg(*args, sixrd_domain_t *);
  sixrd_main_t *mm = &sixrd_main;

  s = format(s,
	     "[%d] ip6-pfx %U/%d ip4-pfx %U/%d ip4-src %U mtu %d",
	     d - mm->domains,
	     format_ip6_address, &d->ip6_prefix, d->ip6_prefix_len,
	     format_ip4_address, &d->ip4_prefix, d->ip4_prefix_len,
	     format_ip4_address, &d->ip4_src, d->mtu);

  return s;
}

static clib_error_t *
show_sixrd_domain_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  sixrd_main_t *mm = &sixrd_main;
  sixrd_domain_t *d;

  if (pool_elts(mm->domains) == 0)
    vlib_cli_output(vm, "No SIXRD domains are configured...");

  pool_foreach(d, mm->domains, ({vlib_cli_output(vm, "%U", format_sixrd_domain, d);}));

  return 0;

}

static clib_error_t *
show_sixrd_stats_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  sixrd_main_t *mm = &sixrd_main;
  sixrd_domain_t *d;
  int domains = 0, domaincount = 0;
  if (pool_elts (mm->domains) == 0)
    vlib_cli_output (vm, "No SIXRD domains are configured...");

  pool_foreach(d, mm->domains, ({
    domains += sizeof(*d);
    domaincount++;
  }));

  vlib_cli_output(vm, "SIXRD domains structure: %d\n", sizeof (sixrd_domain_t));
  vlib_cli_output(vm, "SIXRD domains: %d (%d bytes)\n", domaincount, domains);

  return 0;
}

/*
 * packet trace format function
 */
u8 *
format_sixrd_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED(vlib_main_t *vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t *node) = va_arg (*args, vlib_node_t *);
  sixrd_trace_t *t = va_arg (*args, sixrd_trace_t *);
  u32 sixrd_domain_index = t->sixrd_domain_index;

  s = format(s, "SIXRD domain index: %d", sixrd_domain_index);

  return s;
}

VLIB_CLI_COMMAND(sixrd_add_domain_command, static) = {
  .path = "sixrd add domain",
  .short_help = 
  "sixrd add domain ip6-pfx <ip6-pfx> ip4-pfx <ip4-pfx> ip4-src <ip4-addr>",
  .function = sixrd_add_domain_command_fn,
};

VLIB_CLI_COMMAND(sixrd_del_command, static) = {
  .path = "sixrd del domain",
  .short_help = 
  "sixrd del domain index <domain>",
  .function = sixrd_del_domain_command_fn,
};

VLIB_CLI_COMMAND(show_sixrd_domain_command, static) = {
  .path = "show sixrd domain",
  .function = show_sixrd_domain_command_fn,
};

VLIB_CLI_COMMAND(show_sixrd_stats_command, static) = {
  .path = "show sixrd stats",
  .function = show_sixrd_stats_command_fn,
};

/* 
 * This routine exists to convince the vlib plugin framework that
 * we haven't accidentally copied a random .dll into the plugin directory.
 *
 * Also collects global variable pointers passed from the vpp engine
 */
clib_error_t * 
vlib_plugin_register (vlib_main_t * vm, vnet_plugin_handoff_t * h,
                      int from_early_init)
{
  clib_error_t * error = 0;
  sixrd_main_t *mm = &sixrd_main;

  mm->vnet_main = vnet_get_main();
  mm->vlib_main = vm;

  return error;
}

static clib_error_t * sixrd_init (vlib_main_t * vm)
{
  clib_error_t * error = 0;
//  sixrd_main_t *mm = &sixrd_main;

  /* vlib_node_t * ip6_lookup_node = vlib_get_node_by_name(vm, (u8 *)"ip6-lookup"); */
  /* vlib_node_t * ip4_lookup_node = vlib_get_node_by_name(vm, (u8 *)"ip4-lookup"); */
  /* vlib_node_t * ip6_sixrd_node = vlib_get_node_by_name(vm, (u8 *)"ip6-sixrd"); */
  /* vlib_node_t * ip4_sixrd_node = vlib_get_node_by_name(vm, (u8 *)"ip4-sixrd"); */
  /* ASSERT(ip6_lookup_node && ip4_lookup_node && ip6_sixrd_node && ip4_sixrd_node); */

  // FIXME Make DPO
  /* mm->ip6_lookup_next_index = vlib_node_add_next(vm, ip6_lookup_node->index, ip6_sixrd_node->index); */
  /* mm->ip4_lookup_next_index = vlib_node_add_next(vm, ip4_lookup_node->index, ip4_sixrd_node->index); */

  return error;
}

VLIB_INIT_FUNCTION (sixrd_init);
