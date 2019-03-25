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

#include <vlib/vlib.h>

typedef struct mac_address_t_
{
  union
  {
    u8 bytes[6];
    struct
    {
      u32 first_4;
      u16 last_2;
    } __clib_packed u;
  };
} mac_address_t;

STATIC_ASSERT ((sizeof (mac_address_t) == 6),
	       "MAC address must represent the on wire format");

extern const mac_address_t ZERO_MAC_ADDRESS;

always_inline u64
ethernet_mac_address_u64 (const u8 * a)
{
  return (((u64) a[0] << (u64) (5 * 8))
	  | ((u64) a[1] << (u64) (4 * 8))
	  | ((u64) a[2] << (u64) (3 * 8))
	  | ((u64) a[3] << (u64) (2 * 8))
	  | ((u64) a[4] << (u64) (1 * 8)) | ((u64) a[5] << (u64) (0 * 8)));
}

always_inline void
ethernet_mac_address_from_u64 (u64 u, u8 * a)
{
  i8 ii;

  for (ii = 5; ii >= 0; ii--)
    {
      a[ii] = u & 0xFF;
      u = u >> 8;
    }
}

static inline int
ethernet_mac_address_is_multicast_u64 (u64 a)
{
  return (a & (1ULL << (5 * 8))) != 0;
}

static inline int
ethernet_mac_address_is_zero (const u8 * mac)
{
  return ((*((u32 *) mac) == 0) && (*((u16 *) (mac + 4)) == 0));
}

static inline void
ethernet_mac_address_generate (u8 * mac)
{
  u32 rnd = clib_cpu_time_now ();
  rnd = random_u32 (&rnd);

  memcpy (mac + 2, &rnd, sizeof (rnd));
  mac[0] = 2;
  mac[1] = 0xfe;
}

static inline int
ethernet_mac_address_equal (const u8 * a, const u8 * b)
{
  return ((*((u32 *) a) == (*((u32 *) b))) &&
	  (*((u16 *) (a + 4)) == (*((u16 *) (b + 4)))));
}

static_always_inline void
mac_address_from_bytes (mac_address_t * mac, const u8 * bytes)
{
  /* zero out the last 2 bytes, then copy over only 6 */
  clib_memcpy_fast (mac->bytes, bytes, 6);
}

static_always_inline void
mac_address_to_bytes (const mac_address_t * mac, u8 * bytes)
{
  /* zero out the last 2 bytes, then copy over only 6 */
  clib_memcpy_fast (bytes, mac->bytes, 6);
}

static_always_inline int
mac_address_is_zero (const mac_address_t * mac)
{
  return (0 == mac->u.first_4 && 0 == mac->u.last_2);
}

static_always_inline u64
mac_address_as_u64 (const mac_address_t * mac)
{
  u64 *as_u64;

  as_u64 = (u64 *) mac->bytes;

  return (*as_u64);
}

static_always_inline void
mac_address_from_u64 (mac_address_t * mac, u64 u)
{
  clib_memcpy (mac->bytes, &u, 6);
}

static_always_inline void
mac_address_copy (mac_address_t * dst, const mac_address_t * src)
{
  mac_address_from_bytes (dst, src->bytes);
}

static_always_inline int
mac_address_cmp (const mac_address_t * a, const mac_address_t * b)
{
  return (memcmp (a->bytes, b->bytes, 6));
}

static_always_inline int
mac_address_equal (const mac_address_t * a, const mac_address_t * b)
{
  return (a->u.last_2 == b->u.last_2 && a->u.first_4 == b->u.first_4);
}

static_always_inline void
mac_address_set_zero (mac_address_t * mac)
{
  mac->u.first_4 = 0;
  mac->u.last_2 = 0;
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
