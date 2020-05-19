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

#ifndef __CALICO_TYPES_H__
#define __CALICO_TYPES_H__

#include <vnet/fib/fib_node.h>
#include <vnet/fib/fib_source.h>
#include <vnet/ip/ip_types.h>

/* only in the default table for v4 and v6 */
#define CALICO_FIB_TABLE 0

#define CALICO_SESSION_MAX_AGE 10

typedef struct calico_endpoint_t_
{
  ip_address_t ce_ip;
  u16 ce_port;
} calico_endpoint_t;

extern u8 * format_calico_endpoint (u8 * s, va_list * args);

extern fib_source_t calico_fib_source;

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
