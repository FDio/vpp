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
//#include "jvpp-core/jvpp_gen.h"

#include <jvpp-registry/jvpp_registry.h>
#include <jvpp-registry/jvpp_core.h> // FIXME move to separate dir

/**
 * Handler for show_version_reply vpe.api message.
 * Generated based on defs_vpp_papi.py preparsed data:
 * {   'args': ['context', 'retval', 'program', 'version', 'build_date', 'build_directory'],
 *     'c_types': ['u32', 'i32', 'u8[]', 'u8[]', 'u8[]', 'u8[]'],
 *     'full_args': ['_vl_msg_id', 'context', 'retval', 'program', 'version', 'build_date', 'build_directory'],
 *     'java_name': 'showVersionReply',
 *     'lengths': [(0, False), (0, False), ('32', False), ('32', False), ('32', False), ('256', False)],
 *     'name': 'show_version_reply',
 *     'types': ['jint', 'jint', 'jbyteArray', 'jbyteArray', 'jbyteArray', 'jbyteArray']}
 */
static void vl_api_show_version_reply_t_handler (vl_api_show_version_reply_t * mp)
{
    //vppjni_main_t * jm = &vppjni_main;
    //JNIEnv *env = jm->jenv;

    printf("vl_api_show_version_reply_t_handler!!\n");

    // FIXME update the reply handler
/*
    // for negative result don't send callback message but send error callback
    if (mp->retval<0) {
        CallOnError("show_version_reply",mp->context,mp->retval);
        return;
    }
    if (mp->retval == VNET_API_ERROR_IN_PROGRESS) {
        clib_warning("Result in progress");
        return;
    }jvpp_core


    // TODO rename jm->callbackClass to jm->registryClass
    jmethodID getCallbackMethod = (*env)->GetMethodID(env, jm->callbackClass, "get", "(Ljava/lang/String;)Lorg/openvpp/jvpp/callback/JVppCallback;");

    // TODO rename jm->callback to jm->registry
    // TODO make vpp-core a parameter
    jstring pluginName = (*env)->NewStringUTF(env, "vpp-core");
    jobject callbackObject = (*env)->CallObjectMethod(env, jm->callback, getCallbackMethod, pluginName);
    jclass callbackClass = (*env)->GetObjectClass(env, callbackObject);
close0
    jmethodID constructor = (*env)->GetMethodID(env, showVersionReplyClass, "<init>", "()V");
    jmethodID callbackMethod = (*env)->GetMethodID(env, callbackClass, "onShowVersionReply", "(Lorg/openvpp/jvpp/dto/ShowVersionReply;)V");

    jobject dto = (*env)->NewObject(env, showVersionReplyClass, constructor);

    jfieldID contextFieldId = (*env)->GetFieldID(env, showVersionReplyClass, "context", "I");
    (*env)->SetIntField(env, dto, contextFieldId, clib_net_to_host_u32(mp->context));

    jfieldID programFieldId = (*env)->GetFieldID(env, showVersionReplyClass, "program", "[B");
    jbyteArray program = (*env)->NewByteArray(env, 32);
    (*env)->SetByteArrayRegion(env, program, 0, 32, (const jbyte*)mp->program);
    (*env)->SetObjectField(env, dto, programFieldId, program);

    jfieldID versionFieldId = (*env)->GetFieldID(env, showVersionReplyClass, "version", "[B");
    jbyteArray version = (*env)->NewByteArray(env, 32);
    (*env)->SetByteArrayRegion(env, version, 0, 32, (const jbyte*)mp->version);
    (*env)->SetObjectField(env, dto, versionFieldId, version);

    jfieldID buildDateFieldId = (*env)->GetFieldID(env, showVersionReplyClass, "buildDate", "[B");
    jbyteArray buildDate = (*env)->NewByteArray(env, 32);
    (*env)->SetByteArrayRegion(env, buildDate, 0, 32, (const jbyte*)mp->build_date);
    (*env)->SetObjectField(env, dto, buildDateFieldId, buildDate);

    jfieldID buildDirectoryFieldId = (*env)->GetFieldID(env, showVersionReplyClass, "buildDirectory", "[B");
    jbyteArray buildDirectory = (*env)->NewByteArray(env, 256);
    (*env)->SetByteArrayRegion(env, buildDirclose0ectory, 0, 256, (const jbyte*)mp->build_directory);
    (*env)->SetObjectField(env, dto, buildDirectoryFieldId, buildDirectory);

    (*env)->CallVoidMethod(env, callbackObject, callbackMethod, dto);*/
}

/**
 * JNI binding for sending show_version vpe.api message.
 * Generated based on defs_vpp_papi.py preparsed data:
 * {   'args': [],
 *     'c_types': [],
 *     'full_args': ['_vl_msg_id', 'client_index', 'context'],
 *     'java_name': 'showVersion',
 *     'lengths': [],
 *     'name': 'show_version',
 *     'types': []}
 */
JNIEXPORT jint JNICALL Java_org_openvpp_jvpp_core_JVppCoreImpl_showVersion0
(JNIEnv * env, jclass clazz) {
    vppjni_main_t *jm = &vppjni_main;
    vpp_core_main_t * core_main = &vpp_core_main;
    vl_api_show_version_t * mp;
    u32 my_context_id;

    int rv;
    rv = vppjni_sanity_check (jm);
    if (rv) return rv;
    my_context_id = vppjni_get_context_id (jm);

    printf("my_context_id=%d\n", my_context_id);

    mp = vl_msg_api_alloc(sizeof(*mp));
    memset (mp, 0, sizeof (*mp));
    printf("memset\n");
    mp->_vl_msg_id = ntohs (VL_API_SHOW_VERSION);
    printf("_vl_msg_id %d\n", mp->_vl_msg_id);
    mp->client_index = core_main->my_client_index;
    printf("client_index\n");
    mp->context = clib_host_to_net_u32 (my_context_id);
    printf("context\n");

    vl_msg_api_send_shmem (core_main->vl_input_queue, (u8 *)&mp);
    printf("vl_msg_api_send_shmem\n");

    if ((*env)->ExceptionCheck(env)) {
        printf("error\n");
        return JNI_ERR;
    }
    printf("return\n");
    return my_context_id;
}

JNIEXPORT void JNICALL Java_org_openvpp_jvpp_core_JVppCoreImpl_init0
(JNIEnv * env, jclass clazz, jobject callback, jlong queue_address, jint my_client_index) {
    vpp_core_main_t * core_main = &vpp_core_main;
    core_main->my_client_index = my_client_index;
    core_main->vl_input_queue = (unix_shared_memory_queue_t *)queue_address;




    core_main->callback = (*env)->NewGlobalRef(env, callback);
    core_main->callbackClass = (jclass)(*env)->NewGlobalRef(env, (*env)->GetObjectClass(env, callback));


    vl_msg_api_set_handlers(VL_API_SHOW_VERSION_REPLY, "show_version_reply",
                    vl_api_show_version_reply_t_handler,
                    vl_noop_handler,
                    vl_api_show_version_reply_t_endian,
                    vl_api_show_version_reply_t_print,
                    sizeof(vl_api_show_version_reply_t), 1);

    // TODO:
    // class caching
    // register all the reply handlers
}

JNIEXPORT void JNICALL Java_org_openvpp_jvpp_core_JVppCoreImpl_close0
(JNIEnv *env, jclass clazz) {
    vpp_core_main_t * core_main = &vpp_core_main;

    // cleanup:
    (*env)->DeleteGlobalRef(env, core_main->callbackClass);
    (*env)->DeleteGlobalRef(env, core_main->callback);

    core_main->callbackClass = NULL;
    core_main->callback = NULL;
}


