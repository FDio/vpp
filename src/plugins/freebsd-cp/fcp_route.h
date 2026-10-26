/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Intel Corporation
 */

#ifndef __FCP_ROUTE_H__
#define __FCP_ROUTE_H__

#include <vlib/vlib.h>

int fcp_route_processing (void);
void fcp_route_dump (u32 host_if_index);
void fcp_route_cleanup (u32 host_if_index);

#endif /* __FCP_ROUTE_H__ */
