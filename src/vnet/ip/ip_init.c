/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* ip/ip_init.c: ip generic initialization */

#include <vnet/ip/ip.h>
#include <vnet/ip/ip4_mtrie.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/dpo/load_balance.h>

ip_main_t ip_main;

clib_error_t *
ip_main_init (vlib_main_t * vm)
{
  ip_main_t *im = &ip_main;
  clib_error_t *error = 0;

  clib_memset (im, 0, sizeof (im[0]));

  {
    ip_protocol_info_t *pi;
    u32 i;

#define ip_protocol(n,s)			\
do {						\
  vec_add2 (im->protocol_infos, pi, 1);		\
  pi->protocol = n;				\
  pi->name = (u8 *) #s;				\
} while (0);

#include "protocols.def"

#undef ip_protocol

    im->protocol_info_by_name = hash_create_string (0, sizeof (uword));
    for (i = 0; i < vec_len (im->protocol_infos); i++)
      {
	pi = im->protocol_infos + i;

	hash_set_mem (im->protocol_info_by_name, pi->name, i);
	hash_set (im->protocol_info_by_protocol, pi->protocol, i);
      }
  }

  {
    tcp_udp_port_info_t *pi;
    u32 i;
    static char *port_names[] = {
#define ip_port(s,n) #s,
#include "ports.def"
#undef ip_port
    };
    static u16 ports[] = {
#define ip_port(s,n) n,
#include "ports.def"
#undef ip_port
    };

    vec_resize (im->port_infos, ARRAY_LEN (port_names));
    im->port_info_by_name = hash_create_string (0, sizeof (uword));

    for (i = 0; i < vec_len (im->port_infos); i++)
      {
	pi = im->port_infos + i;
	pi->port = clib_host_to_net_u16 (ports[i]);
	pi->name = (u8 *) port_names[i];
	hash_set_mem (im->port_info_by_name, pi->name, i);
	hash_set (im->port_info_by_port, pi->port, i);
      }
  }

  return error;
}

VLIB_INIT_FUNCTION (ip_main_init) = {
  .init_order = VLIB_INITS ("vnet_main_init", "ip4_init", "ip6_init", "icmp4_init", "icmp6_init",
			    "ip6_hop_by_hop_init", "udp_local_init", "udp_init", "ip_classify_init",
			    "in_out_acl_init", "flow_classify_init"),
};

static clib_error_t *
ip_config_init (vlib_main_t *vm, unformat_input_t *input)
{
  uword lbsz = 0, fibentrysz = 0, mtriesz = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "load-balance-pool-size %U", unformat_memory_size,
		    &lbsz))
	;
      else if (unformat (input, "fib-entry-pool-size %U", unformat_memory_size,
			 &fibentrysz))
	;
      else if (unformat (input, "ip4-mtrie-pool-size %U", unformat_memory_size,
			 &mtriesz))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (lbsz)
    load_balance_pool_alloc (lbsz);
  if (fibentrysz)
    fib_entry_pool_alloc (fibentrysz);
  if (mtriesz)
    ip4_mtrie_pool_alloc (mtriesz);

  return 0;
}

VLIB_CONFIG_FUNCTION (ip_config_init, "l3fib");
