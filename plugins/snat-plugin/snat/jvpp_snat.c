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

/* Declare message IDs */
#include <snat/snat_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <snat/snat_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun             /* define message structures */
#include <snat/snat_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <snat/snat_all_api_h.h>
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <snat/snat_all_api_h.h>
#undef vl_api_version

#include <vnet/api_errno.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#if VPPJNI_DEBUG == 1
  #define DEBUG_LOG(...) clib_warning(__VA_ARGS__)
#else
  #define DEBUG_LOG(...)
#endif

#include <jvpp-common/jvpp_common.h>


#include "jvpp-snat/org_openvpp_jvpp_snat_JVppSnatImpl.h"
#include "jvpp_snat.h"
#include "jvpp_ping.h"
#include "jvpp-snat/jvpp_gen.h"

/* cleanup handler for RX thread */
/*static void cleanup_rx_thread(void *arg)
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
}*/

/**
* Send error reply to the requestor
* const char* call  pointer to the request name
* int context       call context identifier
* int retval        result of the operation
*/
void CallOnError(const char* call, int context, int retval)
{
    DEBUG_LOG("\nCallOnError : callback=%s,retval=%d,context=%d\n", call, clib_net_to_host_u32(retval), clib_net_to_host_u32(context));
    snat_main_t *plugin_main = &snat_main;
    JNIEnv *env = jvpp_main.jenv;
    if (!plugin_main->callbackClass) {
        DEBUG_LOG("CallOnError : jm->callbackClass is null!\n");
        return;
    }
    jmethodID excConstructor = (*env)->GetMethodID(env, callbackExceptionClass, "<init>", "(Ljava/lang/String;II)V");
    if (!excConstructor) {
        DEBUG_LOG("CallOnError : excConstructor is null!\n");
        return;
    }
    jmethodID callbackExcMethod = (*env)->GetMethodID(env, plugin_main->callbackClass, "onError", "(Lorg/openvpp/jvpp/VppCallbackException;)V");
    if (!callbackExcMethod) {
        DEBUG_LOG("CallOnError : callbackExcMethod is null!\n");
        return;
    }

    jobject excObject = (*env)->NewObject(env, callbackExceptionClass, excConstructor,(*env)->NewStringUTF(env, call), clib_net_to_host_u32(context), clib_net_to_host_u32(retval));
    if (!excObject) {
        DEBUG_LOG("CallOnError : excObject is null!\n");
        return;
    }

    (*env)->CallVoidMethod(env, plugin_main->callbackObject, callbackExcMethod, excObject);
    DEBUG_LOG("CallOnError : Response sent\n");
}

// control ping needs to be very first thing called
// to attach rx thread to java thread
/*
static void vl_api_snat_control_ping_reply_t_handler
(vl_api_control_ping_reply_t * mp)
{
    jvpp_main_t * jm = &jvpp_main;

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
    	snat_main_t * plugin_main = &snat_main;
        JNIEnv *env = jm->jenv;

        if (mp->retval<0){
			CallOnError("controlPing", mp->context, mp->retval);
		} else {
		    printf("");
//			jmethodID constructor = (*env)->GetMethodID(env, snatControlPingReplyClass, "<init>", "()V");
//			jmethodID callbackMethod = (*env)->GetMethodID(env, plugin_main->callbackClass, "onsnatControlPingReplyClass", "(Lorg/openvpp/jvpp/snat/dto/snatControlPingReply;)V");
//
//			jobject dto = (*env)->NewObject(env, snatControlPingReplyClass, constructor);
//
//			jfieldID contextFieldId = (*env)->GetFieldID(env, snatControlPingReplyClass, "context", "I");
//			(*env)->SetIntField(env, dto, contextFieldId, clib_net_to_host_u32(mp->context));
//
//			jfieldID clientIndexFieldId = (*env)->GetFieldID(env, snatControlPingReplyClass, "clientIndex", "I");
//			(*env)->SetIntField(env, dto, clientIndexFieldId, clib_net_to_host_u32(mp->client_index));
//
//			(*env)->CallVoidMethod(env, plugin_main->callbackObject, callbackMethod, dto);
		}
    }

    out:
        jm->result_ready = 1;
}
*/
/*
 * Class:     org_openvpp_jvpp_snat_JVppsnatImpl
 * Method:    init0
 * Signature: (JI)V
 */
JNIEXPORT void JNICALL Java_org_openvpp_jvpp_snat_JVppsnatImpl_init0
  (JNIEnv *env, jclass clazz, jobject callback, jlong queue_address, jint my_client_index) {
	snat_main_t * plugin_main = &snat_main;
    //jvpp_main_t *jm = &jvpp_main;
	u8 * name;

	plugin_main->my_client_index = my_client_index;
	plugin_main->vl_input_queue = (unix_shared_memory_queue_t *)queue_address;

    name = format (0, "snat_%08x%c", api_version, 0);
    plugin_main->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

	plugin_main->callbackObject = (*env)->NewGlobalRef(env, callback);
	plugin_main->callbackClass = (jclass)(*env)->NewGlobalRef(env, (*env)->GetObjectClass(env, callback));

    #define _(N,n)                                  \
        vl_msg_api_set_handlers(VL_API_##N + plugin_main->msg_id_base, #n,     \
                vl_api_##n##_t_handler,             \
                vl_noop_handler,                    \
                vl_api_##n##_t_endian,              \
                vl_api_##n##_t_print,               \
                sizeof(vl_api_##n##_t), 1);
        foreach_api_reply_handler;
    #undef _

    {
        // f64 timeout;
        clib_time_t clib_time;
        clib_time_init (&clib_time);
        // call control ping first to attach rx thread to java thread

        int rv = send_ping();
//        vl_api_control_ping_t * mp;
//        mp = vl_msg_api_alloc(sizeof(*mp));
//        memset (mp, 0, sizeof (*mp));
//    	mp->_vl_msg_id = ntohs (VL_API_CONTROL_PING + plugin_main->msg_id_base);
//        mp->client_index = plugin_main->my_client_index;
//
//        // send message:
//        vl_msg_api_send_shmem (plugin_main->vl_input_queue, (u8 *)&mp);
//
//        // wait for results: Current time + 10 seconds is the timeout
//        timeout = clib_time_now (&clib_time) + 10.0;
//        int rv = VNET_API_ERROR_RESPONSE_NOT_READY;
//        while (clib_time_now (&clib_time) < timeout) {
//          if (jm->result_ready == 1) {
//            rv = (jm->retval);
//            break;
//          }
//        }

        if (rv != 0) {
            clib_warning ("first control ping failed: %d", rv);
        }
    }
}

JNIEXPORT void JNICALL Java_org_openvpp_jvpp_snat_JVppsnatImpl_close0
(JNIEnv *env, jclass clazz) {
	snat_main_t * plugin_main = &snat_main;

    // cleanup:
    (*env)->DeleteGlobalRef(env, plugin_main->callbackClass);
    (*env)->DeleteGlobalRef(env, plugin_main->callbackObject);

    plugin_main->callbackClass = NULL;
    plugin_main->callbackObject = NULL;
}

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
	jvpp_main_t *jm = &jvpp_main;
    JNIEnv* env;

    if ((*vm)->GetEnv(vm, (void**) &env, JNI_VERSION_1_8) != JNI_OK) {
        return JNI_EVERSION;
    }

    if (cache_class_references(env) != 0) {
        clib_warning ("Failed to cache class references\n");
        return JNI_ERR;
    }

    jm->jvm = vm;
    return JNI_VERSION_1_8;
}

void JNI_OnUnload(JavaVM *vm, void *reserved) {
	jvpp_main_t *jm = &jvpp_main;
    JNIEnv* env;
    if ((*vm)->GetEnv(vm, (void**) &env, JNI_VERSION_1_8) != JNI_OK) {
        return;
    }

    jm->jenv = NULL;
    jm->jvm = NULL;
}


