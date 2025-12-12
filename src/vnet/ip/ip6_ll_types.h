/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#ifndef __IP6_LL_TYPES_H__
#define __IP6_LL_TYPES_H__

#include <vnet/ip/ip6_packet.h>

/**
 * Aggregate type for a prefix in the IPv6 Link-local table
 */
typedef struct ip6_ll_prefix_t_
{
  /**
   * The interface
   */
  u32 ilp_sw_if_index;

  /**
   * the IP6 address
   */
  ip6_address_t ilp_addr;
} ip6_ll_prefix_t;

extern u8 *format_ip6_ll_prefix (u8 *s, va_list *args);
#endif
