/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

/* Argument types for VLIB_CLI_COMMAND: Ethernet. */

#pragma once

#include <vppinfra/cli.h>

/* value->prefix.addr holds the 6 bytes, aa:bb:cc:dd:ee:ff or aabb.ccdd.eeff */
__clib_export extern cli_type_t cli_type_mac_address;

/* vlan id 0-4095, or "any" which is VLAN_ID_ANY, the value is in value->u64 */
#define VLAN_ID_ANY 0x10000
__clib_export extern cli_type_t cli_type_vlan_id;
