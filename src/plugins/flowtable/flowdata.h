/*---------------------------------------------------------------------------
 * Copyright (c) 2016 Qosmos and/or its affiliates.
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
 *---------------------------------------------------------------------------
 */

#ifndef __flowdata_h__
#define __flowdata_h__

#include <vnet/vnet.h>

/*
 * keep this under 6x4 Bytes so that it may fit into unused opaques' field.
 */
typedef union {
    struct {
        u64 offloaded : 1;
        u64 flow_id : 63;

        union {
            u32 ctx_id;
            u8 opaque[16];
        };
    } __attribute__ ((packed)) data;

    u32 flow_data[6];
} flow_data_t;

static_always_inline u8 *
vnet_plugin_buffer(vlib_buffer_t * b)
{
    return (u8 *) &(vnet_buffer(b)->unused);
}

#endif  /* __flowdata_h__ */