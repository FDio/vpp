/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Intel and/or its affiliates.
 */

/* esp_format.c : ESP format */

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ipsec/esp.h>

u8 *
format_esp_header (u8 * s, va_list * args)
{
  esp_header_t *esp = va_arg (*args, esp_header_t *);
  u32 spi = clib_net_to_host_u32 (esp->spi);

  s = format (s, "ESP: spi %u (0x%08x), seq %u",
	      spi, spi, clib_net_to_host_u32 (esp->seq));
  return s;
}
