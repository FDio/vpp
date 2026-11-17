/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

/* Argument types for VLIB_CLI_COMMAND: interfaces. */

#pragma once

#include <vppinfra/cli.h>

/* value->index is the sw_if_index, accepts interface name or index */
__clib_export extern cli_type_t cli_type_sw_interface;
/* value->index is the hw_if_index */
__clib_export extern cli_type_t cli_type_hw_interface;
