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

#ifndef __IPIP_TYPES_API_H__
#define __IPIP_TYPES_API_H__

/**
 * Conversion functions to/from (decode/encode) API types to VPP internal types
 */

#include <vnet/ipip/ipip.h>
#include <vnet/ipip/ipip.api_types.h>

/**
 * These enum decode/encodes use 'int' as the type for the enum because
 * one cannot forward declare an enum
 */
extern int ipip_tunnel_flags_decode (u8 _f, ipip_tunnel_flags_t * out);
extern u8 ipip_tunnel_flags_encode (ipip_tunnel_flags_t f);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
