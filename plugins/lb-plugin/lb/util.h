/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

/*
 * Non-LB specific stuff comes here
 */

#ifndef LB_PLUGIN_LB_UTIL_H_
#define LB_PLUGIN_LB_UTIL_H_

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

#define ip46_address_type(ip46) (ip46_address_is_ip4(ip46)?IP46_TYPE_IP4:IP46_TYPE_IP6)
#define ip46_prefix_is_ip4(ip46, len) ((len) >= 96 && ip46_address_is_ip4(ip46))
#define ip46_prefix_type(ip46, len) (ip46_prefix_is_ip4(ip46, len)?IP46_TYPE_IP4:IP46_TYPE_IP6)

void ip46_prefix_normalize(ip46_address_t *prefix, u8 plen);
uword unformat_ip46_prefix (unformat_input_t * input, va_list * args);
u8 *format_ip46_prefix (u8 * s, va_list * args);

/**
 * 32 bits integer comparison for running values.
 * 1 > 0 is true. But 1 > 0xffffffff also is.
 */
#define clib_u32_loop_gt(a, b) (((u32)(a)) - ((u32)(b)) < 0x7fffffff)

#endif /* LB_PLUGIN_LB_UTIL_H_ */
