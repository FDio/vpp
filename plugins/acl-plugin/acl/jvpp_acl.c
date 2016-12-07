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

#include <acl/acl_msg_enum.h>
#define vl_typedefs             /* define message structures */
#include <acl/acl_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun
#include <acl/acl_all_api_h.h>
#undef vl_endianfun

#define vl_print(handle, ...)
#define vl_printfun
#include <acl/acl_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <acl/acl_all_api_h.h>
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

#include "acl/jvpp/io_fd_vpp_jvpp_acl_JVppAclImpl.h"
#include "jvpp_acl.h"
#include "acl/jvpp/jvpp_acl_gen.h"

/*
 * Class:     io_fd_vpp_jvpp_acl_JVppaclImpl
 * Method:    init0
 * Signature: (JI)V
 */
JNIEXPORT void JNICALL Java_io_fd_vpp_jvpp_acl_JVppAclImpl_init0
  (JNIEnv *env, jclass clazz, jobject callback, jlong queue_address, jint my_client_index) {
  acl_main_t * plugin_main = &acl_main;
  u8 * name;
  clib_warning ("Java_io_fd_vpp_jvpp_acl_JVppAclImpl_init0");

  plugin_main->my_client_index = my_client_index;
  plugin_main->vl_input_queue = (unix_shared_memory_queue_t *)queue_address;

  name = format (0, "acl_%08x%c", api_version, 0);
  plugin_main->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  if (plugin_main->msg_id_base == (u16) ~0) {
    jclass exClass = (*env)->FindClass(env, "java/lang/IllegalStateException");
    (*env)->ThrowNew(env, exClass, "acl plugin is not loaded in VPP");
  } else {
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
  }
}

JNIEXPORT void JNICALL Java_io_fd_vpp_jvpp_acl_JVppAclImpl_close0
(JNIEnv *env, jclass clazz) {
  acl_main_t * plugin_main = &acl_main;

    // cleanup:
    (*env)->DeleteGlobalRef(env, plugin_main->callbackClass);
    (*env)->DeleteGlobalRef(env, plugin_main->callbackObject);

    plugin_main->callbackClass = NULL;
    plugin_main->callbackObject = NULL;
}

/* Attach thread to JVM and cache class references when initiating JVPP ACL */
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

/* Clean up cached references when disposing JVPP ACL */
void JNI_OnUnload(JavaVM *vm, void *reserved) {
    JNIEnv* env;
    if ((*vm)->GetEnv(vm, (void**) &env, JNI_VERSION_1_8) != JNI_OK) {
        return;
    }
    delete_class_references(env);
}
