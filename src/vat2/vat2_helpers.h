/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef included_vat2_helpers_h
#define included_vat2_helpers_h

/* For control ping */
#define vl_endianfun
#include <vpp/api/vpe.api.h>
#undef vl_endianfun

static inline void
vat2_control_ping (u32 context)
{
    vl_api_control_ping_t mp = {0};
    mp._vl_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_CRC);
    mp.context = context;
    vl_api_control_ping_t_endian(&mp);
    vac_write((char *)&mp, sizeof(mp));
}

#endif
