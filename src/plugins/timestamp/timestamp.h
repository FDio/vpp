/*
 * Copyright (c) 2020 TNO.
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
#ifndef __included_timestamp_h__
#define __included_timestamp_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

typedef struct {
    /* API message ID base */
    u16 msg_id_base;
    
    /* convenience */
    vnet_main_t * vnet_main;
} timestamp_main_t;

#define TIMESTAMP_
typedef struct {
  u32 *ptr_to_ioam_transit_delay;
  u64 timestamp_ingress;
  u64 timestamp_egress;
} timestamp_meta_t;
extern timestamp_main_t timestamp_main;

extern vlib_node_registration_t timestamp_ingress_node;
extern vlib_node_registration_t timestamp_egress_node;

#define TIMESTAMP_PLUGIN_BUILD_VER "1.0"

#endif /* __included_timestamp_h__ */
