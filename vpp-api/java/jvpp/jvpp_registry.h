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
#ifndef __included_jvpp_registry_h__
#define __included_jvpp_registry_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/api_errno.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <jni.h>

typedef struct {
    /* Unique identifier used for matching replays with requests  */
    volatile u32 context_id;

    /* Spinlock */
    volatile u32 lock;
    u32 tag;

    /* Used for first control ping */
    // TODO better names?
    volatile u32 result_ready;
    volatile i32 retval;

    /* JNI Native Method Interface pointer for message handlers */
    JNIEnv *jenv;

    /* thread cleanup */
    pthread_key_t cleanup_rx_thread_key;

    /* JNI Invoke Interface pointer for attachment of rx thread to java thread */
    JavaVM *jvm;

    /* Connected indication */
    volatile u8 is_connected;

    /* Convenience */
    unix_shared_memory_queue_t * vl_input_queue;
    u32 my_client_index;

} jvpp_main_t;

jvpp_main_t jvpp_main __attribute__((aligned (64)));

// FIXME: value should be constructed in a way that prevents collisions
static inline u32 vppjni_get_context_id (jvpp_main_t * jm)
{
    return __sync_add_and_fetch (&jm->context_id, 1);
}

static inline void vppjni_lock (jvpp_main_t * jm, u32 tag)
{
    while (__sync_lock_test_and_set (&jm->lock, 1))
        ;
    jm->tag = tag;
}

static inline void vppjni_unlock (jvpp_main_t * jm)
{
    jm->tag = 0;
    CLIB_MEMORY_BARRIER();
    jm->lock = 0;
}

#endif /* __included_jvpp_registry_h__ */
