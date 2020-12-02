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

#ifndef __URPF_H__
#define __URPF_H__

#include <vnet/ip/ip_types.h>

#define foreach_urpf_mode \
  _(OFF, "off")           \
  _(LOOSE, "loose")       \
  _(STRICT, "strict")     \

typedef enum urpf_mode_t_
{
#define _(a,b) URPF_MODE_##a,
  foreach_urpf_mode
#undef _
} __clib_packed urpf_mode_t;

#define URPF_N_MODES (URPF_MODE_STRICT+1)

extern u8 *format_urpf_mode (u8 * s, va_list * a);

extern u8 *format_urpf_location (u8 * s, va_list * a);

extern void urpf_update (urpf_mode_t mode,
			 u32 sw_if_index,
			 ip_address_family_t af,
			 ip_feature_location_t location);


#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
