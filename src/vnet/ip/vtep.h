/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef included_ip_vtep_h
#define included_ip_vtep_h

#include <vppinfra/hash.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip46_address.h>

/**
 * @brief Tunnel endpoint key (IPv4)
 *
 * Tunnel modules maintain a set of vtep4_key_t-s to track local IP
 * addresses that have tunnels established.  Bypass node consults the
 * corresponding set to decide whether a packet should bypass normal
 * processing and go directly to the tunnel protocol handler node.
 */

/* *INDENT-OFF* */
typedef CLIB_PACKED
(struct {
  union {
    struct {
      ip4_address_t addr;
      u32 fib_index;
    };
    u64 as_u64;
  };
}) vtep4_key_t;
/* *INDENT-ON* */

/**
 * @brief Tunnel endpoint key (IPv6)
 *
 * Tunnel modules maintain a set of vtep6_key_t-s to track local IP
 * addresses that have tunnels established.  Bypass node consults the
 * corresponding set to decide whether a packet should bypass normal
 * processing and go directly to the tunnel protocol handler node.
 */

/* *INDENT-OFF* */
typedef CLIB_PACKED
(struct {
  ip6_address_t addr;
  u32 fib_index;
}) vtep6_key_t;
/* *INDENT-ON* */

typedef struct
{
  uword *vtep4;			/* local ip4 VTEPs keyed on their ip4 addr + fib_index */
  uword *vtep6;			/* local ip6 VTEPs keyed on their ip6 addr + fib_index */
} vtep_table_t;

always_inline vtep_table_t
vtep_table_create ()
{
  vtep_table_t t = { };
  t.vtep6 = hash_create_mem (0, sizeof (vtep6_key_t), sizeof (uword));
  return t;
}

uword vtep_addr_ref (vtep_table_t * t, u32 fib_index, ip46_address_t * ip);
uword vtep_addr_unref (vtep_table_t * t, u32 fib_index, ip46_address_t * ip);

always_inline void
vtep4_key_init (vtep4_key_t * k4)
{
  k4->as_u64 = ~((u64) 0);
}

always_inline void
vtep6_key_init (vtep6_key_t * k6)
{
  ip6_address_set_zero (&k6->addr);
  k6->fib_index = (u32) ~ 0;
}

enum
{
  VTEP_CHECK_FAIL = 0,
  VTEP_CHECK_PASS = 1,
  VTEP_CHECK_PASS_UNCHANGED = 2
};

always_inline u8
vtep4_check (vtep_table_t * t, vlib_buffer_t * b0, ip4_header_t * ip40,
	     vtep4_key_t * last_k4)
{
  vtep4_key_t k4;
  k4.addr.as_u32 = ip40->dst_address.as_u32;
  k4.fib_index = vlib_buffer_get_ip4_fib_index (b0);
  if (PREDICT_TRUE (k4.as_u64 == last_k4->as_u64))
    return VTEP_CHECK_PASS_UNCHANGED;
  if (PREDICT_FALSE (!hash_get (t->vtep4, k4.as_u64)))
    return VTEP_CHECK_FAIL;
  last_k4->as_u64 = k4.as_u64;
  return VTEP_CHECK_PASS;
}

#ifdef CLIB_HAVE_VEC512
typedef struct
{
  vtep4_key_t vtep4_cache[8];
  int idx;
} vtep4_cache_t;

always_inline u8
vtep4_check_vector (vtep_table_t * t, vlib_buffer_t * b0, ip4_header_t * ip40,
		    vtep4_key_t * last_k4, vtep4_cache_t * vtep4_u512)
{
  vtep4_key_t k4;
  k4.addr.as_u32 = ip40->dst_address.as_u32;
  k4.fib_index = vlib_buffer_get_ip4_fib_index (b0);

  if (PREDICT_TRUE (k4.as_u64 == last_k4->as_u64))
    return VTEP_CHECK_PASS_UNCHANGED;

  u64x8 k4_u64x8 = u64x8_splat (k4.as_u64);
  u64x8 cache = u64x8_load_unaligned (vtep4_u512->vtep4_cache);
  u8 result = u64x8_mask_is_equal (cache, k4_u64x8);
  if (PREDICT_TRUE (result != 0))
    {
      last_k4->as_u64 =
	vtep4_u512->vtep4_cache[count_trailing_zeros (result)].as_u64;
      return VTEP_CHECK_PASS_UNCHANGED;
    }

  if (PREDICT_FALSE (!hash_get (t->vtep4, k4.as_u64)))
    return VTEP_CHECK_FAIL;

  vtep4_u512->vtep4_cache[vtep4_u512->idx].as_u64 = k4.as_u64;
  vtep4_u512->idx = (vtep4_u512->idx + 1) & 0x7;

  last_k4->as_u64 = k4.as_u64;

  return VTEP_CHECK_PASS;
}
#endif

always_inline u8
vtep6_check (vtep_table_t * t, vlib_buffer_t * b0, ip6_header_t * ip60,
	     vtep6_key_t * last_k6)
{
  vtep6_key_t k6;
  k6.fib_index = vlib_buffer_get_ip6_fib_index (b0);
  if (PREDICT_TRUE (k6.fib_index == last_k6->fib_index
		    && ip60->dst_address.as_u64[0] == last_k6->addr.as_u64[0]
		    && ip60->dst_address.as_u64[1] ==
		    last_k6->addr.as_u64[1]))
    {
      return VTEP_CHECK_PASS_UNCHANGED;
    }
  k6.addr = ip60->dst_address;
  if (PREDICT_FALSE (!hash_get_mem (t->vtep6, &k6)))
    return VTEP_CHECK_FAIL;
  *last_k6 = k6;
  return VTEP_CHECK_PASS;
}
#endif /* included_ip_vtep_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
