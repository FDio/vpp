/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco and/or its affiliates.
 */

/**
 * @file
 * @brief IPv6 DAD Auto-Remove Plugin Header
 */

#ifndef __included_ip6_dad_autoremove_h__
#define __included_ip6_dad_autoremove_h__

#include <vlib/vlib.h>
#include <vnet/ip/ip6_packet.h>

typedef struct
{
  /* Plugin enabled/disabled */
  bool enabled;

  /* Logging class */
  vlib_log_class_t log_class;

  /* Callback handle for DAD registration */
  u32 callback_handle;

  /* Convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} ip6_dad_autoremove_main_t;

extern ip6_dad_autoremove_main_t ip6_dad_autoremove_main;

#endif /* __included_ip6_dad_autoremove_h__ */
