/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

/* Argument types for VLIB_CLI_COMMAND: IP addresses and prefixes. */

#pragma once

#include <vppinfra/cli.h>

/* value->prefix, a.b.c.d/len or an IPv6 prefix */
__clib_export extern cli_type_t cli_type_ip_prefix;
/* value->prefix.addr / is_ip6, IPv4 or IPv6 address */
__clib_export extern cli_type_t cli_type_ip_address;
/* value->ip_range, <first>-<last>, both of the same family */
__clib_export extern cli_type_t cli_type_ip_range;
