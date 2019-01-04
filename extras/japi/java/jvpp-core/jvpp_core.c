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

#include <vnet/vnet.h>
#include <jvpp-common/jvpp_common.h>
#include <vpp/api/vpe_msg_enum.h>
#define vl_typedefs             /* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

#include <vnet/api_errno.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <jni.h>
#include <jvpp_core.h>


// TODO: generate jvpp_plugin_name.c files (or at least reuse plugin's main structure)
typedef struct {
    /* Pointer to shared memory queue */
    svm_queue_t * vl_input_queue;

    /* VPP api client index */
    u32 my_client_index;

    /* Callback object and class references enabling asynchronous Java calls */
    jobject callbackObject;
    jclass callbackClass;

} core_main_t;

core_main_t core_main __attribute__((aligned (64)));

#include "io_fd_vpp_jvpp_core_JVppCoreImpl.h"
#include "jvpp_core_gen.h"

JNIEXPORT void JNICALL Java_io_fd_vpp_jvpp_core_JVppCoreImpl_init0
(JNIEnv * env, jclass clazz, jobject callback, jlong queue_address, jint my_client_index) {
    core_main_t * plugin_main = &core_main;
    plugin_main->my_client_index = my_client_index;
    plugin_main->vl_input_queue = uword_to_pointer (queue_address, svm_queue_t *);

    plugin_main->callbackObject = (*env)->NewGlobalRef(env, callback);
    plugin_main->callbackClass = (jclass)(*env)->NewGlobalRef(env, (*env)->GetObjectClass(env, callback));

    // verify API has not changed since jar generation (exit on mismatch)
    #define _(N)             \
        if (get_message_id(env, #N) == 0) return;
        foreach_supported_api_message;
    #undef _

    #define _(N,n)                                  \
        vl_msg_api_set_handlers(get_message_id(env, #N), #n,     \
                vl_api_##n##_t_handler,             \
                vl_noop_handler,                    \
                vl_noop_handler,              \
                vl_noop_handler,               \
                sizeof(vl_api_##n##_t), 1);
        foreach_api_reply_handler;
    #undef _
}

JNIEXPORT void JNICALL Java_io_fd_vpp_jvpp_core_JVppCoreImpl_close0
(JNIEnv *env, jclass clazz) {
    core_main_t * plugin_main = &core_main;

    // cleanup:
    (*env)->DeleteGlobalRef(env, plugin_main->callbackClass);
    (*env)->DeleteGlobalRef(env, plugin_main->callbackObject);

    plugin_main->callbackClass = NULL;
    plugin_main->callbackObject = NULL;
}

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv* env;

    if ((*vm)->GetEnv(vm, (void**) &env, JNI_VERSION_1_8) != JNI_OK) {
        return JNI_EVERSION;
    }

    if (cache_class_references(env) != 0) {
        clib_warning ("Failed to cache class references\n");
        return JNI_ERR;
    }

    return JNI_VERSION_1_8;
}

void JNI_OnUnload(JavaVM *vm, void *reserved) {
    JNIEnv* env;
    if ((*vm)->GetEnv(vm, (void**) &env, JNI_VERSION_1_8) != JNI_OK) {
        return;
    }
    delete_class_references(env);
}


static void _host_to_net_string(JNIEnv * env, jstring javaString, vl_api_string_t * vl_api_string)
{
    const char *nativeString;
    // prevent null, which causes jni to crash
    if (NULL != javaString) {
        nativeString = (*env)->GetStringUTFChars(env, javaString, 0);
    } else{
        nativeString = "";
    }

    vl_api_to_api_string(jstr_length(env, javaString), nativeString, vl_api_string);

    (*env)->ReleaseStringUTFChars(env, javaString, nativeString);
}


static jstring _net_to_host_string(JNIEnv * env, const vl_api_string_t * _net)
{
    return (*env)->NewStringUTF(env, (char *)_net->buf);
}


static size_t jstr_length(JNIEnv *env, jstring string)
{
    return ((int) (*env)->GetStringUTFLength(env, string));
}
