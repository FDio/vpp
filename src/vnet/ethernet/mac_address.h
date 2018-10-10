/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef __MAC_ADDRESS_H__
#define __MAC_ADDRESS_H__

#include <vnet/ethernet/ethernet.h>

typedef struct mac_address_t_
{
  union
  {
    u8 bytes[6];
    u64 as_u64;
  };
} mac_address_t;

extern const mac_address_t ZERO_MAC_ADDRESS;

static_always_inline void
mac_address_from_bytes (mac_address_t * mac, const u8 * bytes)
{
  /* zero out the last 2 bytes, then copy over only 6 */
  mac->as_u64 = 0;
  clib_memcpy (mac->bytes, bytes, 6);
}

static_always_inline void
mac_address_to_bytes (const mac_address_t * mac, u8 * bytes)
{
  /* zero out the last 2 bytes, then copy over only 6 */
  clib_memcpy (bytes, mac->bytes, 6);
}

static_always_inline int
mac_address_is_zero (const mac_address_t * mac)
{
  return (0 == mac->as_u64);
}

static_always_inline u64
mac_address_as_u64 (const mac_address_t * mac)
{
  return (mac->as_u64);
}

static_always_inline void
mac_address_from_u64 (u64 u, mac_address_t * mac)
{
  mac->as_u64 = u;
  mac->bytes[4] = 0;
  mac->bytes[5] = 0;
}

static_always_inline void
mac_address_copy (mac_address_t * dst, const mac_address_t * src)
{
  mac_address_from_bytes (dst, src->bytes);
}

extern uword unformat_mac_address_t (unformat_input_t * input,
				     va_list * args);
extern u8 *format_mac_address_t (u8 * s, va_list * args);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
