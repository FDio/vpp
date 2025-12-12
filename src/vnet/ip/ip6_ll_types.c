/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include <vnet/ip/ip6_ll_types.h>

#include <vnet/ip/ip.h>

u8 *
format_ip6_ll_prefix (u8 * s, va_list * args)
{
  ip6_ll_prefix_t *ilp = va_arg (*args, ip6_ll_prefix_t *);
  vnet_main_t *vnm = vnet_get_main ();

  s = format (s, "(%U, %U)", format_ip6_address, &ilp->ilp_addr,
	      format_vnet_sw_if_index_name, vnm, ilp->ilp_sw_if_index);

  return (s);
}
