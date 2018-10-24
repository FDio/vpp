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

#ifndef __API_TYPES_H__
#define __API_TYPES_H__

#define vl_typedefs		/* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

const vl_api_mac_address_t VL_API_ZERO_MAC_ADDRESS;
const vl_api_address_t VL_API_ZERO_ADDRESS;

extern uword unformat_vl_api_mac_address (unformat_input_t * input, va_list * args);
extern uword unformat_vl_api_address (unformat_input_t * input, va_list * args);

extern u8 *format_vl_api_address (u8 * s, va_list * args);
extern u8 *format_vl_api_address_union (u8 * s, va_list * args);
extern u8 *format_vl_api_prefix (u8 * s, va_list * args);
extern u8 *format_vl_api_mprefix (u8 * s, va_list * args);
extern u8 *format_vl_api_mac_address (u8 * s, va_list * args);

#endif
