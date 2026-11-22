/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#ifndef included_json_convert_h
#define included_json_convert_h

#include <stdbool.h>
/* vppapigen generated types */
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/ethernet/ethernet_types.api_types.h>

/* Formatting and parsing of the API types which are written as text */
uword unformat_ip4_address (unformat_input_t *input, va_list *args);
uword unformat_ip6_address (unformat_input_t *input, va_list *args);
u8 *format_ip6_address (u8 *s, va_list *args);
uword unformat_mac_address (unformat_input_t *input, va_list *args);
u8 *format_ip4_address (u8 *s, va_list *args);
uword unformat_vl_api_timedelta_t (unformat_input_t *input, va_list *args);
uword unformat_vl_api_timestamp_t (unformat_input_t *input, va_list *args);
uword unformat_vl_api_gbp_scope_t (unformat_input_t *input, va_list *args);

/* The text of a MAC address, aa:bb:cc:dd:ee:ff */
format_function_t format_vl_api_mac_address_t;

#endif
