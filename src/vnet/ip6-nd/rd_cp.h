/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#ifndef __RD_CP_H__
#define __RD_CP_H__

#include <vnet/ip6-nd/ip6_nd.h>

extern int rd_cp_set_address_autoconfig (u32 sw_if_index,
					 u8 enable,
					 u8 install_default_routes);

#endif
