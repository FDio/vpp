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
#include <vpp-api/vpe.api.h>
#undef vl_api_version

#include <jni.h>
#include <jvpp/jvpp_registry.h>
#include <jvpp-registry/org_openvpp_jvpp_VppJNIConnection.h>

#include <vpp-api/vpe_msg_enum.h>
#define vl_typedefs             /* define message structures */
#include <vpp-api/vpe_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun
#include <vpp-api/vpe_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <vpp-api/vpe_all_api_h.h>
#undef vl_printfun

/*
 * The Java runtime isn't compile w/ -fstack-protector,
 * so we have to supply missing external references for the
 * regular vpp libraries.
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

static void vl_api_control_ping_reply_t_handler
(vl_api_control_ping_reply_t * mp)
{
    clib_warning("vl_api_control_ping_reply received by the jvpp registry. Ignoring");
}

static int connect_to_vpe(char *name)
{
    jvpp_main_t * jm = &jvpp_main;
    api_main_t * am = &api_main;

    if (vl_client_connect_to_vlib("/vpe-api", name, 32) < 0)
        return -1;

    jm->my_client_index = am->my_client_index;

    jm->vl_input_queue = am->shmem_hdr->vl_input_queue;

    // TODO sending ping is not needed for registry,
    // but if handler is not registered,
    // vl_client_get_first_plugin_msg_id invocation in the NSH plugin gets timeout:
    // msg_handler_internal:408: no handler for msg id 9 (get_first_msg_id_reply)
    vl_msg_api_set_handlers(VL_API_CONTROL_PING_REPLY, "control_ping_reply",
                vl_api_control_ping_reply_t_handler,
                vl_noop_handler,
                vl_api_control_ping_reply_t_endian,
                vl_api_control_ping_reply_t_print,
                sizeof(vl_api_control_ping_reply_t), 1);
    return 0;
}

JNIEXPORT jobject JNICALL Java_org_openvpp_jvpp_VppJNIConnection_clientConnect
  (JNIEnv *env, jclass obj, jstring clientName)
{
    int rv;
    const char *client_name;
    void vl_msg_reply_handler_hookup(void);
    jvpp_main_t * jm = &jvpp_main;

    jclass connectionInfoClass  = (*env)->FindClass(env, "org/openvpp/jvpp/VppJNIConnection$ConnectionInfo");
    jmethodID connectionInfoConstructor = (*env)->GetMethodID(env, connectionInfoClass, "<init>", "(JII)V");

    /*
     * Bail out now if we're not running as root
     */
    if (geteuid() != 0) {
        return (*env)->NewObject(env, connectionInfoClass, connectionInfoConstructor, 0, 0, VNET_API_ERROR_NOT_RUNNING_AS_ROOT);
    }

    if (jm->is_connected) {
        return (*env)->NewObject(env, connectionInfoClass, connectionInfoConstructor, 0, 0, VNET_API_ERROR_ALREADY_CONNECTED);
    }

    client_name = (*env)->GetStringUTFChars(env, clientName, 0);
    if (!client_name) {
        return (*env)->NewObject(env, connectionInfoClass, connectionInfoConstructor, 0, 0, VNET_API_ERROR_INVALID_VALUE);
    }

    rv = connect_to_vpe ((char *) client_name);

    if (rv < 0)
        clib_warning ("connection failed, rv %d", rv);

    (*env)->ReleaseStringUTFChars (env, clientName, client_name);

    return (*env)->NewObject(env, connectionInfoClass, connectionInfoConstructor, (jlong)jm->vl_input_queue, (jint)jm->my_client_index, (jint)rv);
}

JNIEXPORT void JNICALL Java_org_openvpp_jvpp_VppJNIConnection_clientDisconnect
  (JNIEnv *env, jclass clazz)
{
    jvpp_main_t * jm = &jvpp_main;
    jm->is_connected = 0; // TODO make thread safe
    vl_client_disconnect_from_vlib();
}


