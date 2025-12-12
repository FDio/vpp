/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#ifndef included_vat2_helpers_h
#define included_vat2_helpers_h

#include <vlibmemory/vlib.api_types.h>

/* For control ping */
#define vl_endianfun
#include <vlibmemory/memclnt.api.h>
#undef vl_endianfun

static inline void
vat2_control_ping (u32 context)
{
    vl_api_control_ping_t mp = {0};
    mp._vl_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_CRC);
    mp.context = context;
    vl_api_control_ping_t_endian (&mp, 1 /* to network */);
    vac_write((char *)&mp, sizeof(mp));
}

#endif
