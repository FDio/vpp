/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#ifndef included_vat2_helpers_h
#define included_vat2_helpers_h

#include <vlibmemory/vlib.api_types.h>

static inline void
vat2_control_ping (u32 context)
{
    vl_api_control_ping_t mp = {0};
    mp._vl_msg_id = clib_host_to_net_u16 (vac_get_msg_index (VL_API_CONTROL_PING_CRC));
    mp.context = clib_host_to_net_u32 (context);
    vac_write((char *)&mp, sizeof(mp));
}

#endif
