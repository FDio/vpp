/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include <vlibapi/api_types.h>
#include <vnet/ethernet/ethernet_types_api.h>

void
mac_address_decode (const u8 * in, mac_address_t * out)
{
  mac_address_from_bytes (out, in);
}

void
mac_address_encode (const mac_address_t * in, u8 * out)
{
  clib_memcpy_fast (out, in->bytes, 6);
}
