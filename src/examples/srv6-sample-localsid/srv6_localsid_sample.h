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
#ifndef __included_srv6_localsid_sample_h__
#define __included_srv6_localsid_sample_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/srv6/sr.h>
#include <vnet/srv6/sr_packet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

typedef struct {
    /* API message ID base */
    u16 msg_id_base;

    /* convenience */
    vlib_main_t * vlib_main;
    vnet_main_t * vnet_main;
    
    /* DPO type */
    dpo_type_t srv6_localsid_sample_dpo_type;

    /* SRv6 LocalSID behavior number */
    u32 srv6_localsid_behavior_id;

} srv6_localsid_sample_main_t;

/*
 * This is the memory that will be stored per each localsid
 * the user instantiates
 */
typedef struct {
	u32 fib_table;	/* Stupid index used as an example.. */
} srv6_localsid_sample_per_sid_memory_t ;

extern srv6_localsid_sample_main_t srv6_localsid_sample_main;

format_function_t format_srv6_localsid_sample;
unformat_function_t unformat_srv6_localsid_sample;

void srv6_localsid_sample_dpo_lock (dpo_id_t * dpo);
void srv6_localsid_sample_dpo_unlock (dpo_id_t * dpo);

extern vlib_node_registration_t srv6_localsid_sample_node;

#endif /* __included_sample_h__ */
