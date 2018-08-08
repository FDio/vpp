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

/* the following union will be copied to vlib->opaque
 * it MUST be less or equal CLIB_CACHE_LINE_BYTES */
typedef union {
    struct {
        u32 sw_if_index_current;
        u8 offloaded;

        u8 opaque[27];
    } data;

    u32 flow_data[8]; /* 32 Bytes == sizeof vlib_buffer_t's opaque field */
} flow_data_t;

#endif /* __flowdata_h__ */
