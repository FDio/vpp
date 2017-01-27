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
#ifndef __included_jvpp_common_h__
#define __included_jvpp_common_h__
//
#include <vppinfra/types.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <jni.h>

typedef struct {
    /* Unique identifier used for matching replays with requests  */
    volatile u32 context_id;

    /* Spinlock */
    volatile u32 lock;
    u32 tag;

    /* JNI Native Method Interface pointer for message handlers */
    JNIEnv *jenv;

    /* JNI Invoke Interface pointer for attachment of rx thread to java thread */
    JavaVM *jvm;

    /* Convenience */
    unix_shared_memory_queue_t * vl_input_queue;
    u32 my_client_index;
    uword *messages_hash;
} jvpp_main_t;

extern jvpp_main_t jvpp_main __attribute__((aligned (64)));

static_always_inline u32 vppjni_get_context_id(jvpp_main_t * jm) {
    return __sync_add_and_fetch(&jm->context_id, 1);
}

static_always_inline void vppjni_lock(jvpp_main_t * jm, u32 tag) {
    while (__sync_lock_test_and_set(&jm->lock, 1))
        ;
    jm->tag = tag;
}

static_always_inline void vppjni_unlock(jvpp_main_t * jm) {
    jm->tag = 0;
    CLIB_MEMORY_BARRIER();
    jm->lock = 0;
}

/**
 * Calls onError callback on callbackObject reference. Passes instance of callbackExceptionClass as parameter.
 */
void call_on_error(const char* callName, int contextId, int retval,
        jclass callbackClass, jobject callbackObject,
        jclass callbackExceptionClass);

/**
 * Retrieves message id based on message name and crc (key format: name_crc).
 * Throws java/lang/IllegalStateException on failure.
 */
u32 get_message_id(JNIEnv *env, const char* key);

#endif /* __included_jvpp_common_h__ */
