/*
 * ip_interface_watch.h: ip neighbor event handling
 *
 * Copyright (c) 2020, LabN Consulting, L.L.C.
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

#ifndef __IP_INTERFACE_ADDRESS_WATCH_H__
#define __IP_INTERFACE_ADDRESS_WATCH_H__

#include <vnet/ip/ip.h>

#define	SW_INTERFACE_IP_ADDR_EVENT	1

typedef struct
{
  /* opaque cookie to identify the client */
  u32 client_index;

  /* client pid registered to receive notification */
  u32 pid;
} ip_interface_address_watcher_t;

extern void ip46_interface_address_register_callbacks(void);
extern void ip_interface_address_watch (ip46_type_t type,
                                     u32 sw_if_index,
                                     const ip_interface_address_watcher_t * watch);
extern void ip_interface_address_unwatch (ip46_type_t type,
                                       u32 sw_if_index,
                                       const ip_interface_address_watcher_t * watch);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
