/* 
 *------------------------------------------------------------------
 * cgse_defs.h - CGSE specific definiitions
 *
 * Copyright (c) 2007-2013 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef __CGSE_DEFS_H__
#define __CGSE_DEFS_H__

#include "spp_platform_common.h"
#include <cnat_cli.h>


#define CGSE_SVI_TYPE_CNAT            1
#define CGSE_SVI_TYPE_XLAT            2
#define CGSE_SVI_TYPE_NAT64_STATEFUL  3
#define CGSE_SVI_TYPE_V6RD            4 
#define CGSE_SVI_TYPE_INFRA           5 
#define CGSE_SVI_TYPE_DS_LITE         7 
#define CGSE_SVI_TYPE_MAPE            9

#define CGSE_SET_TX_PKT_TYPE(type)  PLATFORM_SET_CTX_RU_TX_PKT_TYPE(ctx, type) 

#define CGSE_INVALID_UIDX 0xffff /*invalid svi app uidb index */
#define CGSE_INVALID_VRFID 0xffffffff /*invalid vrf id */

#define CGSE_VRF_MASK 0x3fff
#define CGSE_MAX_VRFMAP_ENTRIES  (CGSE_VRF_MASK + 1)

#define CGSE_VRFMAP_ENTRY_INVALID 0xffff


#define CGSE_INVALID_CGSE_ID  (0)

#define CGSE_TABLE_ENTRY_DELETED      0
#define CGSE_TABLE_ENTRY_ACTIVE       1
#define CGSE_TABLE_ENTRY_DORMANT      2
#define CGSE_TABLE_ENTRY_INVALID_UIDB 3


#define CGSE_CONFIG_HANDLER_DEBUG_PRINTF1(level, a)                         \
    if (cgse_config_debug_level > level) printf(a);

#define CGSE_CONFIG_HANDLER_DEBUG_PRINTF2(level, a, b)                      \
    if (cgse_config_debug_level > level) printf(a, b);

#define CGSE_CONFIG_HANDLER_DEBUG_PRINTF3(level, a, b, c)                   \
    if (cgse_config_debug_level > level) printf(a, b, c);

#define CGSE_CONFIG_HANDLER_DEBUG_PRINTF4(level, a, b, c, d)                \
    if (cgse_config_debug_level > level) printf(a, b, c, d);

#define CGSE_CONFIG_HANDLER_DEBUG_PRINTF5(level, a, b, c, d, e)             \
    if (cgse_config_debug_level > level) printf(a, b, c, d, e);

#define CGSE_CONFIG_HANDLER_DEBUG_PRINTF6(level, a, b, c, d, e, f)          \
    if (cgse_config_debug_level > level) printf(a, b, c, d, e, f);

#define CGSE_CONFIG_HANDLER_DEBUG_PRINTF7(level, a, b, c, d, e, f, g)       \
    if (cgse_config_debug_level > level) printf(a, b, c, d, e, f, g);

#define CGSE_CONFIG_HANDLER_DEBUG_PRINTF8(level, a, b, c, d, e, f, g, h)    \
    if (cgse_config_debug_level > level) printf(a, b, c, d, e, f, g, h);

#define CGSE_CONFIG_HANDLER_DEBUG_PRINTF9(level, a, b, c, d, e, f, g, h, i) \
    if (cgse_config_debug_level > level) printf(a, b, c, d, e, f, g, h, i);

extern u16 *cgse_uidb_index_cgse_id_mapping_ptr;

#define CGSE_ADD_UIDB_INDEX_CGSE_ID_MAPPING(uidb_index, cgse_id) \
    *(cgse_uidb_index_cgse_id_mapping_ptr + uidb_index) = cgse_id;

extern u8 my_instance_number;

#endif
