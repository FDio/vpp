/*
 *------------------------------------------------------------------
 * Copyright (c) 2020 Intel and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef _IAVF_OSDEP_H_
#define _IAVF_OSDEP_H_

#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>

#include <vppinfra/byte_order.h>
#include <vppinfra/string.h>
#include <vppinfra/mem.h>

#define INLINE inline
#define STATIC static

#ifndef __be16
#define __be16 u16
#endif
#ifndef __be32
#define __be32 u32
#endif
#ifndef __be64
#define __be64 u64
#endif

#define __avf_packed __attribute__ ((__packed__))
#define __avf_aligned(a) __attribute__ ((__aligned__ (a)))

#define CPU_TO_BE16(o) clib_host_to_net_u16 (o)
#define CPU_TO_BE32(s) clib_host_to_net_u32 (s)
#define CPU_TO_BE64(h) clib_host_to_net_u64 (h)
#define BE16_TO_CPU(a) clib_net_to_host_u16 (a)
#define BE32_TO_CPU(c) clib_net_to_host_u32 (c)
#define BE64_TO_CPU(k) clib_net_to_host_u64 (k)

#define iavf_memcmp(a, b, c) clib_memcmp ((a), (b), (c))
#define iavf_memset_genrl(a, b, c) clib_memset ((a), (b), (c))
#define iavf_memcpy_genrl(a, b, c) clib_memcpy ((a), (b), (c))
#define iavf_malloc(s) clib_mem_alloc ((s))
#define iavf_free(p) clib_mem_free ((p))

/*
 * Return the last (most-significant) bit set.
 */
static inline int
avf_fls_u32 (u32 x)
{
  return (x == 0) ? 0 : 32 - __builtin_clz (x);
}

/**
 * Returns true if n is a power of 2
 */
static inline int
avf_is_power_of_2 (u32 n)
{
  return n && !(n & (n - 1));
}

#endif /* _IAVF_OSDEP_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
