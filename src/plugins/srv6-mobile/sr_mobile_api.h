/*
 * Copyright (c) 2022 BBSakura Networks Inc and/or its affiliates.
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

/**
 * @file
 * @brief Segment Routing for mobile u-plane api
 *
 */

#ifndef included_sr_mobile_api_h
#define included_sr_mobile_api_h
#include <stdint.h>
#include <vnet/srv6/sr.h>
#include <vnet/ip/ip_types_api.h>

#define clib_strcmp_with_size(s1, s1len, s2)                                  \
  ({                                                                          \
    int __indicator = 0;                                                      \
    strcmp_s_inline (s1, s1len, s2, &__indicator);                            \
    __indicator;                                                              \
  })

void alloc_param_srv6_end_m_gtp4_e (void **plugin_mem_p,
				    const void *v4src_addr,
				    const u32 v4src_position,
				    const u32 fib_table);

void alloc_param_srv6_end_m_gtp6_e (void **plugin_mem_p, const u32 fib_table);

void alloc_param_srv6_end_m_gtp6_d (void **plugin_mem_p, const void *sr_prefix,
				    const u32 sr_prefixlen, const u8 nhtype,
				    const bool drop_in, const u32 fib_table);

void alloc_param_srv6_end_m_gtp6_di (void **plugin_mem_p,
				     const void *sr_prefix,
				     const u32 sr_prefixlen, const u8 nhtype);

void alloc_param_srv6_end_m_gtp6_dt (void **plugin_mem_p, const u32 fib_index,
				     const u32 local_fib_index,
				     const u32 type);

void alloc_param_srv6_t_m_gtp4_d (void **plugin_mem_p,
				  const void *v6src_prefix,
				  const u32 v6src_prefixlen,
				  const void *sr_prefix,
				  const u32 sr_prefixlen, const u32 fib_index,
				  const u8 nhtype, const bool drop_in);

void alloc_param_srv6_t_m_gtp4_dt (void **plugin_mem_p, const u32 fib_index,
				   const u32 local_fib_index, const u8 type);

#endif /* included_sr_mobile_api_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
