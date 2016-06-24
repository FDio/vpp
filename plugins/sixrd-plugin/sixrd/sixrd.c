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
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  sixrd_domain_t *d;
  ip_adjacency_t adj;
  ip4_add_del_route_args_t args4;
  ip6_add_del_route_args_t args6;
  u32 *p;

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
    
  /* Init IP adjacency */
  memset(&adj, 0, sizeof(adj));
  adj.explicit_fib_index = ~0;
  p = (u32 *)&adj.rewrite_data[0];
  *p = (u32) (*sixrd_domain_index);

  /* Create ip6 adjacency */
  memset(&args6, 0, sizeof(args6));
  args6.table_index_or_table_id = 0;
  args6.flags = IP6_ROUTE_FLAG_ADD;
  args6.dst_address.as_u64[0] = ip6_prefix->as_u64[0];
  args6.dst_address.as_u64[1] = ip6_prefix->as_u64[1];
  args6.dst_address_length = ip6_prefix_len;
  args6.adj_index = ~0;
  args6.add_adj = &adj;
  args6.n_add_adj = 1;
  adj.lookup_next_index = mm->ip6_lookup_next_index;
  ip6_add_del_route(im6, &args6);

  /* Multiple SIXRD domains may share same source IPv4 TEP */
  uword *q = ip4_get_route(im4, 0, 0, (u8 *)ip4_src, 32);
  if (q) {
    u32 ai = q[0];
    ip_lookup_main_t *lm4 = &ip4_main.lookup_main;
    ip_adjacency_t *adj4 = ip_get_adjacency(lm4, ai);
    if (adj4->lookup_next_index != mm->ip4_lookup_next_index) {
      clib_warning("BR source address already assigned: %U", format_ip4_address, ip4_src);
      pool_put(mm->domains, d);
      return -1;
    }
    /* Shared source */
    p = (u32 *)&adj4->rewrite_data[0];
    p[0] = ~0;

    /* Add refcount, so we don't accidentially delete the route underneath someone */
    p[1]++;
  } else {
    /* Create ip4 adjacency. */
    memset(&args4, 0, sizeof(args4));
    args4.table_index_or_table_id = 0;
    args4.flags = IP4_ROUTE_FLAG_ADD;
    args4.dst_address.as_u32 = ip4_src->as_u32;
    args4.dst_address_length = 32;
    args4.adj_index = ~0;
    args4.add_adj = &adj;
    args4.n_add_adj = 1;
    adj.lookup_next_index = mm->ip4_lookup_next_index;
    ip4_add_del_route(im4, &args4);
  }

  return 0;
}

/*
 * sixrd_delete_domain
 */
int
sixrd_delete_domain (u32 sixrd_domain_index)
{
  sixrd_main_t *mm = &sixrd_main;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  sixrd_domain_t *d;
  ip_adjacency_t adj;
  ip4_add_del_route_args_t args4;
  ip6_add_del_route_args_t args6;

  if (pool_is_free_index(mm->domains, sixrd_domain_index)) {
    clib_warning("SIXRD domain delete: domain does not exist: %d", sixrd_domain_index);
    return -1;
  }

  d = pool_elt_at_index(mm->domains, sixrd_domain_index);

  memset(&adj, 0, sizeof(adj));
  adj.explicit_fib_index = ~0;

  /* Delete ip6 adjacency */
  memset(&args6, 0, sizeof (args6));
  args6.table_index_or_table_id = 0;
  args6.flags = IP6_ROUTE_FLAG_DEL;
  args6.dst_address.as_u64[0] = d->ip6_prefix.as_u64[0];
  args6.dst_address.as_u64[1] = d->ip6_prefix.as_u64[1];
  args6.dst_address_length = d->ip6_prefix_len;
  args6.adj_index = 0;
  args6.add_adj = &adj;
  args6.n_add_adj = 0;
  ip6_add_del_route(im6, &args6);

  /* Delete ip4 adjacency */
  uword *q = ip4_get_route(im4, 0, 0, (u8 *)&d->ip4_src, 32);
  if (q) {
    u32 ai = q[0];
    ip_lookup_main_t *lm4 = &ip4_main.lookup_main;
    ip_adjacency_t *adj4 = ip_get_adjacency(lm4, ai);

    u32 *p = (u32 *)&adj4->rewrite_data[0];
    /* Delete route when no other domains use this source */
    if (p[1] == 0) {
      memset(&args4, 0, sizeof(args4));
      args4.table_index_or_table_id = 0;
      args4.flags = IP4_ROUTE_FLAG_DEL;
      args4.dst_address.as_u32 = d->ip4_prefix.as_u32;
      args4.dst_address_length = d->ip4_prefix_len;
      args4.adj_index = 0;
      args4.add_adj = &adj;
      args4.n_add_adj = 0;
      ip4_add_del_route(im4, &args4);
    }
    p[1]--;
  }

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
  u32 ip6_prefix_len, ip4_prefix_len, sixrd_domain_index;
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
  sixrd_main_t *mm = &sixrd_main;

  vlib_node_t * ip6_lookup_node = vlib_get_node_by_name(vm, (u8 *)"ip6-lookup");
  vlib_node_t * ip4_lookup_node = vlib_get_node_by_name(vm, (u8 *)"ip4-lookup");
  vlib_node_t * ip6_sixrd_node = vlib_get_node_by_name(vm, (u8 *)"ip6-sixrd");
  vlib_node_t * ip4_sixrd_node = vlib_get_node_by_name(vm, (u8 *)"ip4-sixrd");
  ASSERT(ip6_lookup_node && ip4_lookup_node && ip6_sixrd_node && ip4_sixrd_node);

  mm->ip6_lookup_next_index = vlib_node_add_next(vm, ip6_lookup_node->index, ip6_sixrd_node->index);
  mm->ip4_lookup_next_index = vlib_node_add_next(vm, ip4_lookup_node->index, ip4_sixrd_node->index);

  return error;
}

VLIB_INIT_FUNCTION (sixrd_init);
