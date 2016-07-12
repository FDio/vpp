/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#ifndef __span_h__
#define __span_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/dpdk_replication.h>

typedef struct {
    /* destination interface index by source interface index */
    uword *dst_sw_if_index_by_src;

    /* convenience */
    vlib_main_t * vlib_main;
    vnet_main_t * vnet_main;
} span_main_t;

span_main_t span_main;

extern vlib_node_registration_t span_node;

#endif /* __span_h__ */
