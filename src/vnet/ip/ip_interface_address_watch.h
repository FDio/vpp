/*
 * ip_interface_watch.h: ip neighbor event handling
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020, LabN Consulting, L.L.C.
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
