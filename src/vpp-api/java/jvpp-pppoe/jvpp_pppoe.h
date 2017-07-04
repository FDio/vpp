/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#ifndef __included_jvpp_pppoe_h__
#define __included_jvpp_pppoe_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/api_errno.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <jni.h>

/* Global state for JVPP-pppoe */
typedef struct {
    /* Pointer to shared memory queue */
    unix_shared_memory_queue_t * vl_input_queue;

    /* VPP api client index */
    u32 my_client_index;

    /* Callback object and class references enabling asynchronous Java calls */
    jobject callbackObject;
    jclass callbackClass;

} pppoe_main_t;

pppoe_main_t pppoe_main __attribute__((aligned (64)));


#endif /* __included_jvpp_pppoe_h__ */
