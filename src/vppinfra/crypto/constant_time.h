/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef included_clib_crypto_constant_time_h
#define included_clib_crypto_constant_time_h

#include <vppinfra/clib.h>

/* Compare authentication material without data-dependent memory accesses or
 * early termination. Volatile loads prevent folding this into memcmp().
 * The length is public and must be valid for both inputs. */
static_always_inline int
clib_mem_equal_constant_time (const void *a, const void *b, uword len)
{
  const volatile u8 *p = a, *q = b;
  u8 diff = 0;

  for (uword i = 0; i < len; i++)
    diff |= p[i] ^ q[i];

  return diff == 0;
}

#endif
