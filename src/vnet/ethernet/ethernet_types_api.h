/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#ifndef __ETHERNET_TYPES_API_H__
#define __ETHERNET_TYPES_API_H__

/**
 * Conversion functions to/from (decode/encode) API types to VPP internal types
 */

#include <vnet/ethernet/mac_address.h>
#include <vlibapi/api_types.h>

extern void mac_address_decode (const u8 * in, mac_address_t * out);
extern void mac_address_encode (const mac_address_t * in, u8 * out);

#endif
