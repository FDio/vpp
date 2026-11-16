/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

/* Argument types for VLIB_CLI_COMMAND provided by vnet. */

#pragma once

#include <vppinfra/cli_decl.h>

/* value->index is the sw_if_index, accepts interface name or index */
extern cli_type_t cli_type_sw_interface;
/* value->index is the hw_if_index */
extern cli_type_t cli_type_hw_interface;
/* value->prefix, a.b.c.d/len or an IPv6 prefix */
extern cli_type_t cli_type_ip_prefix;
/* value->prefix.addr / is_ip6, IPv4 or IPv6 address */
extern cli_type_t cli_type_ip_address;
/* value->ip_range, <first>-<last>, both of the same family */
extern cli_type_t cli_type_ip_range;
