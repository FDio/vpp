/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef __included_ip_validate_h__
#define __included_ip_validate_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
} ip_validate_main_t;

extern ip_validate_main_t ip_validate_main;

extern vlib_node_registration_t ip4_validate_node;
extern vlib_node_registration_t ip6_validate_node;

#define IP_VALIDATE_PLUGIN_BUILD_VER "1.0"

#endif /* __included_ip_validate_h__ */
