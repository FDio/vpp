/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

/* Argument types for VLIB_CLI_COMMAND: Ethernet. */

#pragma once

#include <vppinfra/cli.h>

/* value->prefix.addr holds the 6 bytes, aa:bb:cc:dd:ee:ff or aabb.ccdd.eeff */
__clib_export extern cli_type_t cli_type_mac_address;
