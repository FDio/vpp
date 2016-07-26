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


// FIXME cass caching
jclass showVersionReplyClass;
jclass swInterfaceDetailsClass;


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

// control ping needs to be very first thing called
// to attach rx thread to java thread
static void vl_api_control_ping_reply_t_handler
(vl_api_control_ping_reply_t * mp)
{
    vppjni_main_t * jm = &vppjni_main;

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
    vpp_core_main_t * core_main = &vpp_core_main;
    JNIEnv *env = vppjni_main.jenv;

    printf("vl_api_show_version_reply_t_handler!!\n");
    clib_warning("vl_api_show_version_reply_t_handler warn");

    // FIXME
    // for negative result don't send callback message but send error callback
//    if (mp->retval<0) {
//        CallOnError("show_version_reply",mp->context,mp->retval);
//        return;
//    }
//    if (mp->retval == VNET_API_ERROR_IN_PROGRESS) {
//        clib_warning("Result in progress");
//        return;
//    }
    //jclass showVersionReplyClass = (*env)->FindClass(env, "org/openvpp/jvpp/core/dto/ShowVersionReply");

    jmethodID constructor = (*env)->GetMethodID(env, showVersionReplyClass, "<init>", "()V");
    clib_warning("constructor %p", (void*)constructor);

    jmethodID callbackMethod = (*env)->GetMethodID(env, core_main->callbackClass, "onShowVersionReply", "(Lorg/openvpp/jvpp/core/dto/ShowVersionReply;)V");
    clib_warning("callbackMethod %p", (void*)callbackMethod);

    jobject dto = (*env)->NewObject(env, showVersionReplyClass, constructor);
    clib_warning("NewObject %p", (void*)dto);

    jfieldID contextFieldId = (*env)->GetFieldID(env, showVersionReplyClass, "context", "I");
    clib_warning("contextFieldId %p", (void*)contextFieldId);
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
    (*env)->SetByteArrayRegion(env, buildDirectory, 0, 256, (const jbyte*)mp->build_directory);
    (*env)->SetObjectField(env, dto, buildDirectoryFieldId, buildDirectory);

    clib_warning("before CallVoidMethod callbackObject=%p callbackMethod=%p", core_main->callback, callbackMethod);
    (*env)->CallVoidMethod(env, core_main->callback, callbackMethod, dto);
}

static void vl_api_sw_interface_details_t_handler (vl_api_sw_interface_details_t * mp)
{
    vpp_core_main_t * core_main = &vpp_core_main;
    JNIEnv *env = vppjni_main.jenv;

    printf("vl_api_sw_interface_details_t_handler!!\n");

    jmethodID constructor = (*env)->GetMethodID(env, swInterfaceDetailsClass, "<init>", "()V");
    clib_warning("constructor %p", (void*)constructor);

    jmethodID callbackMethod = (*env)->GetMethodID(env, core_main->callbackClass, "onSwInterfaceDetails", "(Lorg/openvpp/jvpp/core/dto/SwInterfaceDetails;)V");
    clib_warning("callbackMethod %p", (void*)callbackMethod);

    jobject dto = (*env)->NewObject(env, swInterfaceDetailsClass, constructor);

    jfieldID contextFieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "context", "I");
    (*env)->SetIntField(env, dto, contextFieldId, clib_net_to_host_u32(mp->context));

    jfieldID swIfIndexFieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "swIfIndex", "I");
    (*env)->SetIntField(env, dto, swIfIndexFieldId, clib_net_to_host_u32(mp->sw_if_index));

    jfieldID supSwIfIndexFieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "supSwIfIndex", "I");
    (*env)->SetIntField(env, dto, supSwIfIndexFieldId, clib_net_to_host_u32(mp->sup_sw_if_index));

    jfieldID l2AddressLengthFieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "l2AddressLength", "I");
    (*env)->SetIntField(env, dto, l2AddressLengthFieldId, clib_net_to_host_u32(mp->l2_address_length));

    jfieldID l2AddressFieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "l2Address", "[B");
    jbyteArray l2Address = (*env)->NewByteArray(env, 8);
    (*env)->SetByteArrayRegion(env, l2Address, 0, 8, (const jbyte*)mp->l2_address);
    (*env)->SetObjectField(env, dto, l2AddressFieldId, l2Address);

    jfieldID interfaceNameFieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "interfaceName", "[B");
    jbyteArray interfaceName = (*env)->NewByteArray(env, 64);
    (*env)->SetByteArrayRegion(env, interfaceName, 0, 64, (const jbyte*)mp->interface_name);
    (*env)->SetObjectField(env, dto, interfaceNameFieldId, interfaceName);

    jfieldID adminUpDownFieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "adminUpDown", "B");
    (*env)->SetByteField(env, dto, adminUpDownFieldId, mp->admin_up_down);

    jfieldID linkUpDownFieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "linkUpDown", "B");
    (*env)->SetByteField(env, dto, linkUpDownFieldId, mp->link_up_down);

    jfieldID linkDuplexFieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "linkDuplex", "B");
    (*env)->SetByteField(env, dto, linkDuplexFieldId, mp->link_duplex);

    jfieldID linkSpeedFieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "linkSpeed", "B");
    (*env)->SetByteField(env, dto, linkSpeedFieldId, mp->link_speed);

    jfieldID linkMtuFieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "linkMtu", "S");
    (*env)->SetShortField(env, dto, linkMtuFieldId, clib_net_to_host_u16(mp->link_mtu));

    jfieldID subIdFieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "subId", "I");
    (*env)->SetIntField(env, dto, subIdFieldId, clib_net_to_host_u32(mp->sub_id));

    jfieldID subDot1AdFieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "subDot1Ad", "B");
    (*env)->SetByteField(env, dto, subDot1AdFieldId, mp->sub_dot1ad);

    jfieldID subNumberOfTagsFieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "subNumberOfTags", "B");
    (*env)->SetByteField(env, dto, subNumberOfTagsFieldId, mp->sub_number_of_tags);

    jfieldID subOuterVlanIdFieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "subOuterVlanId", "S");
    (*env)->SetShortField(env, dto, subOuterVlanIdFieldId, clib_net_to_host_u16(mp->sub_outer_vlan_id));

    jfieldID subInnerVlanIdFieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "subInnerVlanId", "S");
    (*env)->SetShortField(env, dto, subInnerVlanIdFieldId, clib_net_to_host_u16(mp->sub_inner_vlan_id));

    jfieldID subExactMatchFieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "subExactMatch", "B");
    (*env)->SetByteField(env, dto, subExactMatchFieldId, mp->sub_exact_match);

    jfieldID subDefaultFieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "subDefault", "B");
    (*env)->SetByteField(env, dto, subDefaultFieldId, mp->sub_default);

    jfieldID subOuterVlanIdAnyFieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "subOuterVlanIdAny", "B");
    (*env)->SetByteField(env, dto, subOuterVlanIdAnyFieldId, mp->sub_outer_vlan_id_any);

    jfieldID subInnerVlanIdAnyFieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "subInnerVlanIdAny", "B");
    (*env)->SetByteField(env, dto, subInnerVlanIdAnyFieldId, mp->sub_inner_vlan_id_any);

    jfieldID vtrOpFieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "vtrOp", "I");
    (*env)->SetIntField(env, dto, vtrOpFieldId, clib_net_to_host_u32(mp->vtr_op));

    jfieldID vtrPushDot1QFieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "vtrPushDot1Q", "I");
    (*env)->SetIntField(env, dto, vtrPushDot1QFieldId, clib_net_to_host_u32(mp->vtr_push_dot1q));

    jfieldID vtrTag1FieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "vtrTag1", "I");
    (*env)->SetIntField(env, dto, vtrTag1FieldId, clib_net_to_host_u32(mp->vtr_tag1));

    jfieldID vtrTag2FieldId = (*env)->GetFieldID(env, swInterfaceDetailsClass, "vtrTag2", "I");
    (*env)->SetIntField(env, dto, vtrTag2FieldId, clib_net_to_host_u32(mp->vtr_tag2));

    printf("CallVoidMethod %p %p\n", core_main->callback, callbackMethod);

    (*env)->CallVoidMethod(env, core_main->callback, callbackMethod, dto);
}

#define foreach_api_reply_handler \
_(SW_INTERFACE_DETAILS, sw_interface_details) \
_(SHOW_VERSION_REPLY, show_version_reply) \
_(CONTROL_PING_REPLY, control_ping_reply) \


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
    //    int rv;
    //    rv = vppjni_sanity_check (jm);
    //    if (rv) return rv;
    my_context_id = vppjni_get_context_id (jm);

    // create message:
    mp = vl_msg_api_alloc(sizeof(*mp));
    memset (mp, 0, sizeof (*mp));
    mp->_vl_msg_id = ntohs (VL_API_SHOW_VERSION);
    mp->client_index = core_main->my_client_index;
    mp->context = clib_host_to_net_u32 (my_context_id);

    // send message:
    vl_msg_api_send_shmem (core_main->vl_input_queue, (u8 *)&mp);
    if ((*env)->ExceptionCheck(env)) {
        return JNI_ERR;
    }
    printf("return\n");
    return my_context_id;
}

/*
 * Class:     org_openvpp_jvpp_core_JVppCoreImpl
 * Method:    swInterfaceDump0
 * Signature: (Lorg/openvpp/jvpp/core/dto/SwInterfaceDump;)I
 */
JNIEXPORT jint JNICALL Java_org_openvpp_jvpp_core_JVppCoreImpl_swInterfaceDump0
(JNIEnv * env, jclass clazz, jobject request) {
    vppjni_main_t *jm = &vppjni_main;
    vpp_core_main_t * core_main = &vpp_core_main;
    vl_api_sw_interface_dump_t * mp;
    u32 my_context_id;
//    int rv;
//    rv = vppjni_sanity_check (jm);
//    if (rv) return rv;
    my_context_id = vppjni_get_context_id (jm);

    jclass requestClass = (*env)->FindClass(env, "org/openvpp/jvpp/core/dto/SwInterfaceDump");

    jfieldID nameFilterValidFieldId = (*env)->GetFieldID(env, requestClass, "nameFilterValid", "B");
    jbyte nameFilterValid = (*env)->GetByteField(env, request, nameFilterValidFieldId);

    jfieldID nameFilterFieldId = (*env)->GetFieldID(env, requestClass, "nameFilter", "[B");
    jbyteArray nameFilter = (*env)->GetObjectField(env, request, nameFilterFieldId);

    // create message:
    mp = vl_msg_api_alloc(sizeof(*mp));
    memset (mp, 0, sizeof (*mp));
    mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_DUMP);
    mp->client_index = core_main->my_client_index;
    mp->context = clib_host_to_net_u32 (my_context_id);

    mp->name_filter_valid = nameFilterValid;
    if (nameFilter) {
        jsize cnt = (*env)->GetArrayLength (env, nameFilter);
        size_t max_size = 49;
        if (max_size != 0 && cnt > max_size) cnt = max_size;
        (*env)->GetByteArrayRegion(env, nameFilter, 0, cnt, (jbyte *)mp->name_filter);
    }

    // send message:
    vl_msg_api_send_shmem (core_main->vl_input_queue, (u8 *)&mp);
    if ((*env)->ExceptionCheck(env)) {
        return JNI_ERR;
    }
    return my_context_id;
}

JNIEXPORT void JNICALL Java_org_openvpp_jvpp_core_JVppCoreImpl_init0
(JNIEnv * env, jclass clazz, jobject callback, jlong queue_address, jint my_client_index) {
    vpp_core_main_t * core_main = &vpp_core_main;
    vppjni_main_t *jm = &vppjni_main;
    core_main->my_client_index = my_client_index;
    core_main->vl_input_queue = (unix_shared_memory_queue_t *)queue_address;

    core_main->callback = (*env)->NewGlobalRef(env, callback);
    core_main->callbackClass = (jclass)(*env)->NewGlobalRef(env, (*env)->GetObjectClass(env, callback));


    printf("Java_org_openvpp_jvpp_core_JVppCoreImpl_init0\n");

    // TODO register all the reply handlers
    #define _(N,n)                                  \
        vl_msg_api_set_handlers(VL_API_##N, #n,     \
                vl_api_##n##_t_handler,             \
                vl_noop_handler,                    \
                vl_api_##n##_t_endian,              \
                vl_api_##n##_t_print,               \
                sizeof(vl_api_##n##_t), 1);
        foreach_api_reply_handler;
    #undef _




//    int getJavaVMRetval = (*env)->GetJavaVM(env, &(core_main->jvm));
//    printf("getJavaVMRetval = %d", getJavaVMRetval); // FIXME handle errors
//    int getEnvStat = (*core_main->jvm)->GetEnv(core_main->jvm, (void **)&(core_main->jenv), JNI_VERSION_1_8);
//    printf("getEnvStat = %d", getEnvStat); // FIXME handle errors
    // TODO what with thread attachement
    // TODO add ping to all plugins? + invoke in init fo thread attachement?

    {
        f64 timeout;
        clib_time_t clib_time;
        clib_time_init (&clib_time);
        // call control ping first to attach rx thread to java thread

        vl_api_control_ping_t * mp;
        mp = vl_msg_api_alloc(sizeof(*mp));
        memset (mp, 0, sizeof (*mp));
        mp->_vl_msg_id = ntohs (VL_API_CONTROL_PING);
        mp->client_index = core_main->my_client_index;

        printf("sending VL_API_CONTROL_PING\n");

        // send message:
        vl_msg_api_send_shmem (core_main->vl_input_queue, (u8 *)&mp);
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


    // TODO:
    // class caching
//    showVersionReplyClass = (jclass)(*env)->NewGlobalRef(env, (*env)->FindClass(env, "org/openvpp/jvpp/core/dto/ShowVersionReply"));
//    if ((*env)->ExceptionCheck(env)) {
//        (*env)->ExceptionDescribe(env);
//        // return JNI_ERR; // FIXME change return type?
//    }
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

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    vppjni_main_t * jm = &vppjni_main;
    JNIEnv* env;

    printf("JNI onload core");

    if ((*vm)->GetEnv(vm, (void**) &env, JNI_VERSION_1_8) != JNI_OK) {
        return JNI_EVERSION;
    }

    // TODO
//    if (cache_class_references(env) != 0) {
//        return JNI_ERR; // FIXME: that will result in java.lang.UnsatisfiedLinkError: unsupported JNI version 0xFFFFFFFF
//        // which is misleading, can we do better?
//    }

    showVersionReplyClass = (jclass)(*env)->NewGlobalRef(env, (*env)->FindClass(env, "org/openvpp/jvpp/core/dto/ShowVersionReply"));
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        return JNI_ERR;
    }

    swInterfaceDetailsClass = (jclass)(*env)->NewGlobalRef(env, (*env)->FindClass(env, "org/openvpp/jvpp/core/dto/SwInterfaceDetails"));
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
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

    jm->jenv = NULL;
    jm->jvm = NULL;
}



