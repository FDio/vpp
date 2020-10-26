/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#ifndef included_ip_container_proxy_h
#define included_ip_container_proxy_h

#include <vnet/fib/fib_types.h>

typedef struct _vnet_ip_container_proxy_args
{
  fib_prefix_t prefix;
  u32 sw_if_index;
  u8 is_add;
} vnet_ip_container_proxy_args_t;

clib_error_t *vnet_ip_container_proxy_add_del (vnet_ip_container_proxy_args_t
					       * args);

typedef int (*ip_container_proxy_cb_t) (const fib_prefix_t * pfx,
					u32 sw_if_index, void *ctx);
void ip_container_proxy_walk (ip_container_proxy_cb_t cb, void *ctx);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
