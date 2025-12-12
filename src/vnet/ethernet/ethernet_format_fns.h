/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

#ifndef included_ethernet_format_fns_h
#define included_ethernet_format_fns_h

static inline u8 *
format_vl_api_mac_address_t (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%02x%02x.%02x%02x.%02x%02x",
		 a[0], a[1], a[2], a[3], a[4], a[5]);
}

#endif
