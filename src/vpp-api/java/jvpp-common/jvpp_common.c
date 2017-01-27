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
#define _GNU_SOURCE /* for strcasestr(3) */

#include "jvpp_common.h"

#ifndef JVPP_DEBUG
#define JVPP_DEBUG 0
#endif

#if JVPP_DEBUG == 1
#define DEBUG_LOG(...) clib_warning(__VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

/* shared jvpp main structure */
jvpp_main_t jvpp_main __attribute__((aligned (64)));

void call_on_error(const char* callName, int contextId, int retval,
        jclass callbackClass, jobject callbackObject,
        jclass callbackExceptionClass) {
    DEBUG_LOG("\nCallOnError : callback=%s, retval=%d, context=%d\n", callName,
            clib_net_to_host_u32(retval), clib_net_to_host_u32(context));
    JNIEnv *env = jvpp_main.jenv;
    if (!callbackClass) {
        DEBUG_LOG("CallOnError : jm->callbackClass is null!\n");
        return;
    }
    jmethodID excConstructor = (*env)->GetMethodID(env, callbackExceptionClass,
            "<init>", "(Ljava/lang/String;II)V");
    if (!excConstructor) {
        DEBUG_LOG("CallOnError : excConstructor is null!\n");
        return;
    }
    jmethodID callbackExcMethod = (*env)->GetMethodID(env, callbackClass,
            "onError", "(Lio/fd/vpp/jvpp/VppCallbackException;)V");
    if (!callbackExcMethod) {
        DEBUG_LOG("CallOnError : callbackExcMethod is null!\n");
        return;
    }

    jobject excObject = (*env)->NewObject(env, callbackExceptionClass,
            excConstructor, (*env)->NewStringUTF(env, callName),
            clib_net_to_host_u32(contextId), clib_net_to_host_u32(retval));
    if (!excObject) {
        DEBUG_LOG("CallOnError : excObject is null!\n");
        return;
    }

    (*env)->CallVoidMethod(env, callbackObject, callbackExcMethod, excObject);
    DEBUG_LOG("CallOnError : Response sent\n");
}

u32 get_message_id(JNIEnv *env, const char *key) {
    uword *p = hash_get(jvpp_main.messages_hash, key);
    if (!p) {
        jclass exClass = (*env)->FindClass(env, "java/lang/IllegalStateException");
        char *msgBuf  = clib_mem_alloc(strlen(key) + 40);
        strcpy(msgBuf, "API mismatch detected: ");
        strcat(msgBuf, key);
        strcat(msgBuf, " is missing");
        DEBUG_LOG("get_message_id : %s\n", msgBuf);
        (*env)->ThrowNew(env, exClass, msgBuf);
        clib_mem_free(msgBuf);
        return 0;
    }
    return (u32) p[0];
}
