/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef __included_sfdp_services_sample_parser_h__
#define __included_sfdp_services_sample_parser_h__

#include <vnet/vnet.h>

clib_error_t *sample_parser_interface_enable_disable (u32 sw_if_index, u32 tenant_id, u8 disable);

#endif /* __included_sfdp_services_sample_parser_h__ */
