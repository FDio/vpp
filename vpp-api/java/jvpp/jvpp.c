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
#include <vnet/vnet.h>

#define vl_api_version(n,v) static u32 vpe_api_version = (v);
#include <api/vpe.api.h>
#undef vl_api_version

#include <jni.h>
#include <jvpp/jvpp.h>
#include <jvpp/org_openvpp_jvpp_VppJNIConnection.h>
#include <jvpp/org_openvpp_jvpp_JVppImpl.h>

#include <api/vpe_msg_enum.h>
#define vl_typedefs             /* define message structures */
#include <api/vpe_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun
#include <api/vpe_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <api/vpe_all_api_h.h>
#undef vl_printfun

#define VPPJNI_DEBUG 0

#if VPPJNI_DEBUG == 1
  #define DEBUG_LOG(...) clib_warning(__VA_ARGS__)
#else
  #define DEBUG_LOG(...)
#endif

#include "gen/target/jvpp_gen.h"

static int connect_to_vpe(char *name);

/*
 * The Java runtime isn't compile w/ -fstack-protector,
 * so we have to supply missing external references for the
 * regular vpp libraries. Weak reference in case folks get religion
 * at a later date...
 */
void __stack_chk_guard (void) __attribute__((weak));
void __stack_chk_guard (void) {  }

void vl_client_add_api_signatures (vl_api_memclnt_create_t *mp)
{
    /*
     * Send the main API signature in slot 0. This bit of code must
     * match the checks in ../vpe/api/api.c: vl_msg_api_version_check().
     */
    mp->api_versions[0] = clib_host_to_net_u32 (vpe_api_version);
}

/* cleanup handler for RX thread */
static void cleanup_rx_thread(void *arg)
{
    vppjni_main_t * jm = &vppjni_main;

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

JNIEXPORT jint JNICALL Java_org_openvpp_jvpp_VppJNIConnection_clientConnect
  (JNIEnv *env, jclass obj, jstring clientName, jobject callback)
{
    int rv;
    const char *client_name;
    void vl_msg_reply_handler_hookup(void);
    vppjni_main_t * jm = &vppjni_main;

    /*
     * Bail out now if we're not running as root
     */
    if (geteuid() != 0)
        return VNET_API_ERROR_NOT_RUNNING_AS_ROOT;

    if (jm->is_connected)
        return VNET_API_ERROR_ALREADY_CONNECTED;

    client_name = (*env)->GetStringUTFChars(env, clientName, 0);
    if (!client_name)
        return VNET_API_ERROR_INVALID_VALUE;

    rv = connect_to_vpe ((char *) client_name);

    if (rv < 0)
        clib_warning ("connection failed, rv %d", rv);

    (*env)->ReleaseStringUTFChars (env, clientName, client_name);

    if (rv == 0) {
        f64 timeout;
        clib_time_t clib_time;
        clib_time_init (&clib_time);

        /* vl_msg_reply_handler_hookup (); */
        jm->is_connected = 1;

        jm->callback = (*env)->NewGlobalRef(env, callback);
        jm->callbackClass = (jclass)(*env)->NewGlobalRef(env, (*env)->GetObjectClass(env, callback));

        {
            // call control ping first to attach rx thread to java thread
            vl_api_control_ping_t * mp;
            M(CONTROL_PING, control_ping);
            S;

            // wait for results:
            timeout = clib_time_now (&clib_time) + 1.0;
            rv = VNET_API_ERROR_RESPONSE_NOT_READY;
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
    DEBUG_LOG ("clientConnect result: %d", rv);
    return rv;
}

JNIEXPORT void JNICALL Java_org_openvpp_jvpp_VppJNIConnection_clientDisconnect
  (JNIEnv *env, jclass clazz)
{
    vppjni_main_t * jm = &vppjni_main;
    jm->is_connected = 0; // TODO make thread safe
    vl_client_disconnect_from_vlib();
}

// control ping needs to be very first thing called
// to attach rx thread to java thread
static void vl_api_control_ping_reply_t_handler
(vl_api_control_ping_reply_t * mp)
{
    vppjni_main_t * jm = &vppjni_main;

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
        JNIEnv *env = jm->jenv;

        jmethodID constructor = (*env)->GetMethodID(env, controlPingReplyClass, "<init>", "()V");
        jmethodID callbackMethod = (*env)->GetMethodID(env, jm->callbackClass, "onControlPingReply", "(Lorg/openvpp/jvpp/dto/ControlPingReply;)V");

        jobject dto = (*env)->NewObject(env, controlPingReplyClass, constructor);

        jfieldID contextFieldId = (*env)->GetFieldID(env, controlPingReplyClass, "context", "I");
        (*env)->SetIntField(env, dto, contextFieldId, clib_net_to_host_u32(mp->context));

        jfieldID retvalFieldId = (*env)->GetFieldID(env, controlPingReplyClass, "retval", "I");
        (*env)->SetIntField(env, dto, retvalFieldId, clib_net_to_host_u32(mp->retval));

        jfieldID clientIndexFieldId = (*env)->GetFieldID(env, controlPingReplyClass, "clientIndex", "I");
        (*env)->SetIntField(env, dto, clientIndexFieldId, clib_net_to_host_u32(mp->client_index));

        jfieldID vpePidFieldId = (*env)->GetFieldID(env, controlPingReplyClass, "vpePid", "I");
        (*env)->SetIntField(env, dto, vpePidFieldId, clib_net_to_host_u32(mp->vpe_pid));

        (*env)->CallVoidMethod(env, jm->callback, callbackMethod, dto);
    }

    out:
        jm->result_ready = 1;
}

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    vppjni_main_t * jm = &vppjni_main;
    JNIEnv* env;
    if ((*vm)->GetEnv(vm, (void**) &env, JNI_VERSION_1_8) != JNI_OK) {
        return JNI_EVERSION;
    }

    if (cache_class_references(env) != 0) {
        return JNI_ERR;
    }

    jm->jvm = vm;
    return JNI_VERSION_1_8;
}

void JNI_OnUnload(JavaVM *vm, void *reserved) {
    vppjni_main_t * jm = &vppjni_main;
    JNIEnv* env;
    if ((*vm)->GetEnv(vm, (void**) &env, JNI_VERSION_1_8) != JNI_OK) {
        return;
    }

    // cleanup:
    (*env)->DeleteGlobalRef(env, jm->callbackClass);
    (*env)->DeleteGlobalRef(env, jm->callback);

    jm->callbackClass = NULL;
    jm->callback = NULL;
    jm->jenv = NULL;
    jm->jvm = NULL;
}

static int connect_to_vpe(char *name)
{
    vppjni_main_t * jm = &vppjni_main;
    api_main_t * am = &api_main;

    if (vl_client_connect_to_vlib("/vpe-api", name, 32) < 0)
        return -1;

    jm->my_client_index = am->my_client_index;
    jm->vl_input_queue = am->shmem_hdr->vl_input_queue;

#define _(N,n)                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,     \
            vl_api_##n##_t_handler,	            \
            vl_noop_handler,                    \
            vl_api_##n##_t_endian,              \
            vl_api_##n##_t_print,               \
            sizeof(vl_api_##n##_t), 1);
    foreach_vpe_api_msg;
#undef _

    return 0;
}
