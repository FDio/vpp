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

/**
 * @brief FIB Source Address selection
 *
 * Use the FIB for source address selection on an interface
 */

#ifndef __FIB_SAS_H__
#define __FIB_SAS_H__

#include <vnet/fib/fib_types.h>
#include <vnet/ip/ip_types.h>

/**
 * @brief Get a Source address to use in a packet being sent out
 *        an interface
 *
 * @param sw_if_index The interface on which the packet is to be sent
 * @param af The address family of the packet
 * @param dst The destination of the packet (can be NULL in which case any
 *            of the available address will be returned)
 * @param src OUT the source address to use
 *
 * @return True if an address is available False (and src is unset) otherwise
 */
extern bool fib_sas_get (u32 sw_if_index,
                         ip_address_family_t af,
                         const ip46_address_t *dst,
                         ip46_address_t *src);

/**
 * @brief Get an IPv4 Source address to use in a packet being sent out
 *        an interface
 *
 * @param sw_if_index The interface on which the packet is to be sent
 * @param dst The destination of the packet (can be NULL in which case any
 *            of the available address will be returned)
 * @param src OUT the source address to use
 *
 * @return True if an address is available False (and src is unset) otherwise
 */
extern bool fib_sas4_get (u32 sw_if_index,
                          const ip4_address_t *dst,
                          ip4_address_t *src);

/**
 * @brief Get an IPv6 Source address to use in a packet being sent out
 *        an interface
 *
 * @param sw_if_index The interface on which the packet is to be sent
 * @param dst The destination of the packet (can be NULL in which case any
 *            of the available address will be returned)
 * @param src OUT the source address to use
 *
 * @return True if an address is available False (and src is unset) otherwise
 */
extern bool fib_sas6_get (u32 sw_if_index,
                          const ip6_address_t *dst,
                          ip6_address_t *src);

#endif
