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

#include <vpp-api/vpe_msg_enum.h>
#define vl_typedefs             /* define message structures */
#include <vpp-api/vpe_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun
#include <vpp-api/vpe_all_api_h.h>
#undef vl_endianfun

#define vl_print(handle, ...)
#define vl_printfun
#include <vpp-api/vpe_all_api_h.h>
#undef vl_printfun


#include <vnet/api_errno.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <jvpp-core/org_openvpp_jvpp_core_JVppCoreImpl.h>

#include <jvpp-registry/jvpp_registry.h>
#include <jvpp-registry/jvpp_core.h> // FIXME move to separate dir
#include "jvpp-core/jvpp_gen.h"

/* cleanup handler for RX thread */
static void cleanup_rx_thread(void *arg)
{
    jvpp_main_t * jm = &jvpp_main;

    vppjni_lock (jm, 99);

    int getEnvStat = (*jm->jvm)->GetEnv(jm->jvm, (void **)&(jm->jenv), JNI_VERSION_1_8);
    if (getEnvStat == JNI_EVERSION) {
        clib_warning ("Unsupported JNI version\n");
        jm->retval = VNET_API_ERROR_UNSUPPORTED_JNI_VERSION;
        goto out;
    } else if (getEnvStat != JNI_EDETACHED) {
        (*jm->jvm)->DetachCurrentThread(jm->jvm);
    }
out:
    vppjni_unlock (jm);
}

// control ping needs to be very first thing called
// to attach rx thread to java thread
static void vl_api_control_ping_reply_t_handler
(vl_api_control_ping_reply_t * mp)
{
    jvpp_main_t * jm = &jvpp_main;

    printf("vl_api_control_ping_reply_t_handler\n");

    char was_thread_connected = 0;

    // attach to java thread if not attached
    int getEnvStat = (*jm->jvm)->GetEnv(jm->jvm, (void **)&(jm->jenv), JNI_VERSION_1_8);
    if (getEnvStat == JNI_EDETACHED) {
        if ((*jm->jvm)->AttachCurrentThread(jm->jvm, (void **)&(jm->jenv), NULL) != 0) {
            clib_warning("Failed to attach thread\n");
            jm->retval = VNET_API_ERROR_FAILED_TO_ATTACH_TO_JAVA_THREAD;
            goto out;
        }

        // workaround as we can't use pthread_cleanup_push
        pthread_key_create(&jm->cleanup_rx_thread_key, cleanup_rx_thread);
        // destructor is only called if the value of key is non null
        pthread_setspecific(jm->cleanup_rx_thread_key, (void *)1);
        was_thread_connected = 1;
    } else if (getEnvStat == JNI_EVERSION) {
        clib_warning ("Unsupported JNI version\n");
        jm->retval = VNET_API_ERROR_UNSUPPORTED_JNI_VERSION;
        goto out;
    }

    if (was_thread_connected == 0) {
        // JNIEnv *env = jm->jenv;

        if (mp->retval<0){
            // FIXME
            clib_warning ("vl_api_control_ping_reply_t_handler retval < 0\n");
            //CallOnError("controlPing", mp->context, mp->retval);
        } else {
            // FIXME add ping handler to the registry?


//            jmethodID constructor = (*env)->GetMethodID(env, controlPingReplyClass, "<init>", "()V");
//            jmethodID callbackMethod = (*env)->GetMethodID(env, jm->callbackClass, "onControlPingReply", "(Lorg/openvpp/jvpp/dto/ControlPingReply;)V");
//
//            jobject dto = (*env)->NewObject(env, controlPingReplyClass, constructor);
//
//            jfieldID contextFieldId = (*env)->GetFieldID(env, controlPingReplyClass, "context", "I");
//            (*env)->SetIntField(env, dto, contextFieldId, clib_net_to_host_u32(mp->context));
//
//            jfieldID clientIndexFieldId = (*env)->GetFieldID(env, controlPingReplyClass, "clientIndex", "I");
//            (*env)->SetIntField(env, dto, clientIndexFieldId, clib_net_to_host_u32(mp->client_index));
//
//            jfieldID vpePidFieldId = (*env)->GetFieldID(env, controlPingReplyClass, "vpePid", "I");
//            (*env)->SetIntField(env, dto, vpePidFieldId, clib_net_to_host_u32(mp->vpe_pid));
//
//            (*env)->CallVoidMethod(env, jm->callback, callbackMethod, dto);
        }
    }

    out:
        jm->result_ready = 1;
}

JNIEXPORT void JNICALL Java_org_openvpp_jvpp_core_JVppCoreImpl_init0
(JNIEnv * env, jclass clazz, jobject callback, jlong queue_address, jint my_client_index) {
    core_main_t * plugin_main = &core_main;
    jvpp_main_t *jm = &jvpp_main;
    plugin_main->my_client_index = my_client_index;
    plugin_main->vl_input_queue = (unix_shared_memory_queue_t *)queue_address;

    plugin_main->callbackObject = (*env)->NewGlobalRef(env, callback);
    plugin_main->callbackClass = (jclass)(*env)->NewGlobalRef(env, (*env)->GetObjectClass(env, callback));

    #define _(N,n)                                  \
        vl_msg_api_set_handlers(VL_API_##N, #n,     \
                vl_api_##n##_t_handler,             \
                vl_noop_handler,                    \
                vl_api_##n##_t_endian,              \
                vl_api_##n##_t_print,               \
                sizeof(vl_api_##n##_t), 1);
        foreach_api_reply_handler;
    #undef _

    {
        f64 timeout;
        clib_time_t clib_time;
        clib_time_init (&clib_time);
        // call control ping first to attach rx thread to java thread

        vl_api_control_ping_t * mp;
        mp = vl_msg_api_alloc(sizeof(*mp));
        memset (mp, 0, sizeof (*mp));
        mp->_vl_msg_id = ntohs (VL_API_CONTROL_PING);
        mp->client_index = plugin_main->my_client_index;

        printf("sending VL_API_CONTROL_PING\n");

        // send message:
        vl_msg_api_send_shmem (plugin_main->vl_input_queue, (u8 *)&mp);
        printf("after sending VL_API_CONTROL_PING\n");

        // wait for results: Current time + 10 seconds is the timeout
        timeout = clib_time_now (&clib_time) + 10.0;
        int rv = VNET_API_ERROR_RESPONSE_NOT_READY;
        while (clib_time_now (&clib_time) < timeout) {
          if (jm->result_ready == 1) {
            rv = (jm->retval);
            break;
          }
        }

        if (rv != 0) {
            clib_warning ("first control ping failed: %d", rv);
        }
    }
}

JNIEXPORT void JNICALL Java_org_openvpp_jvpp_core_JVppCoreImpl_close0
(JNIEnv *env, jclass clazz) {
    core_main_t * plugin_main = &core_main;

    // cleanup:
    (*env)->DeleteGlobalRef(env, plugin_main->callbackClass);
    (*env)->DeleteGlobalRef(env, plugin_main->callbackObject);

    plugin_main->callbackClass = NULL;
    plugin_main->callbackObject = NULL;
}

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    jvpp_main_t * jm = &jvpp_main;
    JNIEnv* env;

    printf("JNI onload core");

    if ((*vm)->GetEnv(vm, (void**) &env, JNI_VERSION_1_8) != JNI_OK) {
        return JNI_EVERSION;
    }

    if (cache_class_references(env) != 0) {
        return JNI_ERR; // FIXME: that will result in java.lang.UnsatisfiedLinkError: unsupported JNI version 0xFFFFFFFF
        // which is misleading, can we do better?
    }

    jm->jvm = vm;
    return JNI_VERSION_1_8;
}

void JNI_OnUnload(JavaVM *vm, void *reserved) {
    jvpp_main_t * jm = &jvpp_main;
    JNIEnv* env;
    if ((*vm)->GetEnv(vm, (void**) &env, JNI_VERSION_1_8) != JNI_OK) {
        return;
    }

    jm->jenv = NULL;
    jm->jvm = NULL;
}



