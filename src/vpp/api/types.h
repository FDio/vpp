/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#ifndef __API_TYPES_H__
#define __API_TYPES_H__

#include <vlibapi/api_common.h>
#include <vlibapi/api_types.h>

#include <vnet/ip/ip_types.api_types.h>
#include <vnet/ethernet/ethernet_types.api_types.h>

#include <vpp/api/vpe_types.api_types.h>

extern const vl_api_mac_address_t VL_API_ZERO_MAC_ADDRESS;
extern const vl_api_address_t VL_API_ZERO_ADDRESS;

extern uword unformat_vl_api_mac_address (unformat_input_t * input, va_list * args);
extern uword unformat_vl_api_address_family (unformat_input_t * input, va_list * args);
extern uword unformat_vl_api_address (unformat_input_t * input, va_list * args);
extern uword unformat_vl_api_ip4_address (unformat_input_t * input, va_list * args);
extern uword unformat_vl_api_ip6_address (unformat_input_t * input, va_list * args);
extern uword unformat_vl_api_prefix (unformat_input_t * input, va_list * args);
extern uword unformat_vl_api_mprefix (unformat_input_t * input, va_list * args);
extern uword unformat_vl_api_version (unformat_input_t * input, va_list * args);

extern u8 *format_vl_api_address (u8 * s, va_list * args);
extern u8 *format_vl_api_address_family (u8 * s, va_list * args);
extern u8 *format_vl_api_ip4_address (u8 * s, va_list * args);
extern u8 *format_vl_api_ip6_address (u8 * s, va_list * args);
extern u8 *format_vl_api_prefix (u8 * s, va_list * args);
extern u8 *format_vl_api_mprefix (u8 * s, va_list * args);
extern u8 *format_vl_api_mac_address (u8 * s, va_list * args);
extern u8 *format_vl_api_version (u8 * s, va_list * args);

#endif
