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
#include <vpp/api/vpe.api.h>
#undef vl_api_version


#include <jni.h>
#include <jvpp-common/jvpp_common.h>
#include "io_fd_vpp_jvpp_VppJNIConnection.h"
#include "io_fd_vpp_jvpp_JVppRegistryImpl.h"

#include <vpp/api/vpe_msg_enum.h>
#define vl_typedefs             /* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_printfun

vlib_main_t vlib_global_main;
vlib_main_t **vlib_mains;

/*
 * The Java runtime isn't compile w/ -fstack-protector,
 * so we have to supply missing external references for the
 * regular vpp libraries.
 */
void __stack_chk_guard(void) __attribute__((weak));
void __stack_chk_guard(void) {
}

#define CONTROL_PING_MESSAGE "control_ping"
#define CONTROL_PING_REPLY_MESSAGE "control_ping_reply"

typedef struct {
    /* UThread attachment */
    volatile u32 control_ping_result_ready;
    volatile i32 control_ping_retval;

    /* Control ping callback */
    jobject registryObject;
    jclass registryClass;
    jclass controlPingReplyClass;
    jclass callbackExceptionClass;
    int control_ping_msg_id;
    int control_ping_reply_msg_id;

    /* Thread cleanup */
    pthread_key_t cleanup_rx_thread_key;

    /* Connected indication */
    volatile u8 is_connected;
    u32 vpe_pid;
} jvpp_registry_main_t;

jvpp_registry_main_t jvpp_registry_main __attribute__((aligned (64)));

void vl_client_add_api_signatures(vl_api_memclnt_create_t *mp) {
    /*
     * Send the main API signature in slot 0. This bit of code must
     * match the checks in ../vpe/api/api.c: vl_msg_api_version_check().
     */
    mp->api_versions[0] = clib_host_to_net_u32(vpe_api_version);
}

/* cleanup handler for RX thread */
static_always_inline void cleanup_rx_thread(void *arg) {
    jvpp_main_t * jm = &jvpp_main;
    jvpp_registry_main_t * rm = &jvpp_registry_main;

    vppjni_lock(jm, 99);

    int getEnvStat = (*jm->jvm)->GetEnv(jm->jvm, (void **) &(jm->jenv),
    JNI_VERSION_1_8);
    if (getEnvStat == JNI_EVERSION) {
        clib_warning("Unsupported JNI version\n");
        rm->control_ping_retval = VNET_API_ERROR_UNSUPPORTED_JNI_VERSION;
        goto out;
    } else if (getEnvStat != JNI_EDETACHED) {
        (*jm->jvm)->DetachCurrentThread(jm->jvm);
    }
    out: vppjni_unlock(jm);
}

static void vl_api_control_ping_reply_t_handler(
        vl_api_control_ping_reply_t * mp) {
    jvpp_main_t * jm = &jvpp_main;
    jvpp_registry_main_t * rm = &jvpp_registry_main;
    char was_thread_connected = 0;

    // attach to java thread if not attached
    int getEnvStat = (*jm->jvm)->GetEnv(jm->jvm, (void **) &(jm->jenv),
            JNI_VERSION_1_8);
    if (getEnvStat == JNI_EDETACHED) {
        if ((*jm->jvm)->AttachCurrentThread(jm->jvm, (void **) &(jm->jenv),
                NULL) != 0) {
            clib_warning("Failed to attach thread\n");
            rm->control_ping_retval =
                    VNET_API_ERROR_FAILED_TO_ATTACH_TO_JAVA_THREAD;
            goto out;
        }

        // workaround as we can't use pthread_cleanup_push
        pthread_key_create(&rm->cleanup_rx_thread_key, cleanup_rx_thread);
        // destructor is only called if the value of key is non null
        pthread_setspecific(rm->cleanup_rx_thread_key, (void *) 1);
        was_thread_connected = 1;
    } else if (getEnvStat == JNI_EVERSION) {
        clib_warning("Unsupported JNI version\n");
        rm->control_ping_retval = VNET_API_ERROR_UNSUPPORTED_JNI_VERSION;
        goto out;
    }

    if (was_thread_connected == 0) {
        JNIEnv *env = jm->jenv;
        if (mp->retval < 0) {
            call_on_error("controlPing", mp->context, mp->retval,
                    rm->registryClass, rm->registryObject,
                    rm->callbackExceptionClass);
        } else {
            jmethodID constructor = (*env)->GetMethodID(env,
                    rm->controlPingReplyClass, "<init>", "()V");
            jmethodID callbackMethod = (*env)->GetMethodID(env,
                    rm->registryClass, "onControlPingReply",
                    "(Lio/fd/vpp/jvpp/dto/ControlPingReply;)V");

            jobject dto = (*env)->NewObject(env, rm->controlPingReplyClass,
                    constructor);

            jfieldID contextFieldId = (*env)->GetFieldID(env,
                    rm->controlPingReplyClass, "context", "I");
            (*env)->SetIntField(env, dto, contextFieldId,
                    clib_net_to_host_u32(mp->context));

            jfieldID clientIndexFieldId = (*env)->GetFieldID(env,
                    rm->controlPingReplyClass, "clientIndex", "I");
            (*env)->SetIntField(env, dto, clientIndexFieldId,
                    clib_net_to_host_u32(mp->client_index));

            jfieldID vpePidFieldId = (*env)->GetFieldID(env,
                    rm->controlPingReplyClass, "vpePid", "I");
            (*env)->SetIntField(env, dto, vpePidFieldId,
                    clib_net_to_host_u32(mp->vpe_pid));

            (*env)->CallVoidMethod(env, rm->registryObject, callbackMethod,
                    dto);
            (*env)->DeleteLocalRef(env, dto);
        }
    }

    out: rm->vpe_pid = clib_net_to_host_u32(mp->vpe_pid);
    rm->control_ping_result_ready = 1;
}

static int find_ping_id() {
    int rv = 0;
    jvpp_main_t * jm = &jvpp_main;
    jvpp_registry_main_t * rm = &jvpp_registry_main;
    api_main_t *am = &api_main;
    hash_pair_t *hp;
    jm->messages_hash = am->msg_index_by_name_and_crc;

    rm->control_ping_msg_id = -1;
    rm->control_ping_reply_msg_id = -1;

    hash_foreach_pair (hp, jm->messages_hash,
    ({
        char *key = (char *)hp->key; // key format: name_crc
        int msg_name_len = strlen(key) - 9; // ignore crc
        if (strlen(CONTROL_PING_MESSAGE) == msg_name_len &&
                strncmp(CONTROL_PING_MESSAGE, (char *)hp->key, msg_name_len) == 0) {
            rm->control_ping_msg_id = (u32)hp->value[0];
        }
        if (strlen(CONTROL_PING_REPLY_MESSAGE) == msg_name_len &&
                strncmp(CONTROL_PING_REPLY_MESSAGE, (char *)hp->key, msg_name_len) == 0) {
            rm->control_ping_reply_msg_id  = (u32)hp->value[0];
        }
    }));
    if (rm->control_ping_msg_id == -1) {
        clib_warning("failed to find id for %s", CONTROL_PING_MESSAGE);
        rv = -1;
    }
    if (rm->control_ping_reply_msg_id == -1) {
        clib_warning("failed to find id for %s", CONTROL_PING_REPLY_MESSAGE);
        rv = -1;
    }
    return rv;
}

static int send_initial_control_ping() {
    f64 timeout;
    clib_time_t clib_time;
    vl_api_control_ping_t * mp;
    jvpp_main_t * jm = &jvpp_main;
    jvpp_registry_main_t * rm = &jvpp_registry_main;

    clib_time_init(&clib_time);

    rm->control_ping_result_ready = 0;
    mp = vl_msg_api_alloc(sizeof(*mp));
    memset(mp, 0, sizeof(*mp));
    mp->_vl_msg_id = ntohs(rm->control_ping_msg_id);
    mp->client_index = jm->my_client_index;

    // send message:
    vl_msg_api_send_shmem(jm->vl_input_queue, (u8 *) &mp);

    // wait for results: Current time + 10 seconds is the timeout
    timeout = clib_time_now(&clib_time) + 10.0;
    int rv = VNET_API_ERROR_RESPONSE_NOT_READY;
    while (clib_time_now(&clib_time) < timeout) {
        if (rm->control_ping_result_ready == 1) {
            rv = rm->control_ping_retval;
            break;
        }
    }

    if (rv != 0) {
        clib_warning("first control ping failed: %d", rv);
    }
    return rv;
}

static int connect_to_vpe(char *shm_prefix, char *name) {
    jvpp_main_t * jm = &jvpp_main;
    api_main_t * am = &api_main;
    jvpp_registry_main_t * rm = &jvpp_registry_main;

    if (vl_client_connect_to_vlib(shm_prefix, name, 32) < 0)
        return -1;
    jm->my_client_index = am->my_client_index;

    jm->vl_input_queue = am->shmem_hdr->vl_input_queue;

    if (find_ping_id() < 0)
        return -1;

    vl_msg_api_set_handlers(rm->control_ping_reply_msg_id, CONTROL_PING_REPLY_MESSAGE,
            vl_api_control_ping_reply_t_handler, vl_noop_handler,
            vl_api_control_ping_reply_t_endian,
            vl_api_control_ping_reply_t_print,
            sizeof(vl_api_control_ping_reply_t), 1);

    return send_initial_control_ping();
}

JNIEXPORT jobject JNICALL Java_io_fd_vpp_jvpp_VppJNIConnection_clientConnect(
        JNIEnv *env, jclass obj, jstring shmPrefix, jstring clientName) {
    /*
     * TODO introducing memory prefix as variable can be used in hc2vpp
     * to be able to run without root privileges
     * https://jira.fd.io/browse/HC2VPP-176
     */
    int rv;
    const char *client_name;
    const char *shm_prefix;
    void vl_msg_reply_handler_hookup(void);
    jvpp_main_t * jm = &jvpp_main;
    jvpp_registry_main_t * rm = &jvpp_registry_main;

    jclass connectionInfoClass = (*env)->FindClass(env,
            "io/fd/vpp/jvpp/VppJNIConnection$ConnectionInfo");
    jmethodID connectionInfoConstructor = (*env)->GetMethodID(env,
            connectionInfoClass, "<init>", "(JIII)V");

    if (rm->is_connected) {
        return (*env)->NewObject(env, connectionInfoClass,
                connectionInfoConstructor, 0, 0,
                VNET_API_ERROR_ALREADY_CONNECTED, 0);
    }

    client_name = (*env)->GetStringUTFChars(env, clientName, 0);
    shm_prefix = (*env)->GetStringUTFChars(env, shmPrefix, 0);

    if (!client_name) {
        return (*env)->NewObject(env, connectionInfoClass,
                connectionInfoConstructor, 0, 0, VNET_API_ERROR_INVALID_VALUE, 0, shmPrefix);
    }

    if (!shm_prefix) {
        return (*env)->NewObject(env, connectionInfoClass,
                connectionInfoConstructor, 0, 0, VNET_API_ERROR_INVALID_VALUE, 0, shmPrefix);
    }

    rv = connect_to_vpe((char *) shm_prefix, (char *) client_name);

    if (rv < 0)
        clib_warning("connection failed, rv %d", rv);

    (*env)->ReleaseStringUTFChars(env, clientName, client_name);
    (*env)->ReleaseStringUTFChars(env, shmPrefix, shm_prefix);

    return (*env)->NewObject(env, connectionInfoClass,
            connectionInfoConstructor, (jlong) pointer_to_uword (jm->vl_input_queue),
            (jint) jm->my_client_index, (jint) rv, (jint) rm->vpe_pid);
}

JNIEXPORT jint JNICALL Java_io_fd_vpp_jvpp_JVppRegistryImpl_controlPing0(
        JNIEnv *env, jobject regstryObject) {
    jvpp_main_t * jm = &jvpp_main;
    vl_api_control_ping_t * mp;
    u32 my_context_id = vppjni_get_context_id(&jvpp_main);
    jvpp_registry_main_t * rm = &jvpp_registry_main;

    if (rm->registryObject == 0) {
        rm->registryObject = (*env)->NewGlobalRef(env, regstryObject);
    }
    if (rm->registryClass == 0) {
        rm->registryClass = (jclass) (*env)->NewGlobalRef(env,
                (*env)->GetObjectClass(env, regstryObject));
    }

    mp = vl_msg_api_alloc(sizeof(*mp));
    memset(mp, 0, sizeof(*mp));
    mp->_vl_msg_id = ntohs(rm->control_ping_msg_id);
    mp->client_index = jm->my_client_index;
    mp->context = clib_host_to_net_u32(my_context_id);

    // send message:
    vl_msg_api_send_shmem(jm->vl_input_queue, (u8 *) &mp);
    return my_context_id;
}

JNIEXPORT void JNICALL Java_io_fd_vpp_jvpp_VppJNIConnection_clientDisconnect(
        JNIEnv *env, jclass clazz) {
    jvpp_registry_main_t * rm = &jvpp_registry_main;
    rm->is_connected = 0; // TODO make thread safe
    vl_client_disconnect_from_vlib();

    // cleanup:
    if (rm->registryObject) {
        (*env)->DeleteGlobalRef(env, rm->registryObject);
        rm->registryObject = 0;
    }
    if (rm->registryClass) {
        (*env)->DeleteGlobalRef(env, rm->registryClass);
        rm->registryClass = 0;
    }
}

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    jvpp_main_t * jm = &jvpp_main;
    jvpp_registry_main_t * rm = &jvpp_registry_main;
    JNIEnv* env;

    if ((*vm)->GetEnv(vm, (void**) &env, JNI_VERSION_1_8) != JNI_OK) {
        return JNI_EVERSION;
    }

    rm->controlPingReplyClass = (jclass) (*env)->NewGlobalRef(env,
            (*env)->FindClass(env, "io/fd/vpp/jvpp/dto/ControlPingReply"));
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        clib_warning("Failed to cache class references\n");
        return JNI_ERR;
    }

    rm->callbackExceptionClass = (jclass) (*env)->NewGlobalRef(env,
            (*env)->FindClass(env, "io/fd/vpp/jvpp/VppCallbackException"));
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        return JNI_ERR;
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
