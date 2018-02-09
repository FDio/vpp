#!/usr/bin/env python
#
# Copyright (c) 2018 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from string import Template

from jvpp_json_parser import is_dump, is_request, is_control_ping, is_control_ping_reply, is_retval

_MSG_HANDLER_TEMPLATE = Template("""
/**
 * Handler for ${c_name} message.
 * Generated based on $json_filename:
$json_definition
 */
static void vl_api_${c_name}_t_handler (vl_api_${c_name}_t * mp)
{
    ${plugin_name}_main_t *plugin_main = &${plugin_name}_main;
    JNIEnv *env = jvpp_main.jenv;
    jthrowable exc;
    $err_handler

    if (CLIB_DEBUG > 1)
        clib_warning ("Received ${c_name} event message");

    jmethodID constructor = (*env)->GetMethodID(env, ${class_ref_name}Class, "<init>", "()V");

    // User does not have to provide callbacks for all VPP messages.
    // We are ignoring messages that are not supported by user.
    (*env)->ExceptionClear(env); // just in case exception occurred in different place and was not properly cleared
    jmethodID callbackMethod = (*env)->GetMethodID(env, plugin_main->callbackClass, "on${dto_name}", "(Lio/fd/vpp/jvpp/${plugin_name}/dto/${dto_name};)V");
    exc = (*env)->ExceptionOccurred(env);
    if (exc) {
        clib_warning("Unable to extract on${dto_name} method reference from ${plugin_name} plugin's callbackClass. Ignoring message.\\n");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        return;
    }

    jobject dto = (*env)->NewObject(env, ${class_ref_name}Class, constructor);
    $dto_setters

    (*env)->CallVoidMethod(env, plugin_main->callbackObject, callbackMethod, dto);
    // free DTO as per http://stackoverflow.com/questions/1340938/memory-leak-when-calling-java-code-from-c-using-jni
    (*env)->DeleteLocalRef(env, dto);
}""")


def generate_jni_handlers(model):
    jni_impl = []
    for msg in model.messages:
        name = msg.name
        if is_control_ping(msg) or is_control_ping_reply(msg):
            # Skip control ping managed by jvpp registry.
            continue
        if is_dump(msg) or is_request(msg):
            continue

        err_handler = ""  # optional
        for field in msg.fields:
            if is_retval(field):
                err_handler = _ERR_HANDLER_TEMPLATE.substitute(name=name)

        jni_impl.append(_MSG_HANDLER_TEMPLATE.substitute(
            c_name=name,
            json_filename=model.json_api_files,
            json_definition=msg.doc,
            plugin_name=model.plugin_name,
            err_handler=err_handler,
            class_ref_name=msg.java_name_lower,
            dto_name=msg.java_name_upper,
            dto_setters=_generate_setters(msg)
        ))
    return "".join(jni_impl)


# Code fragment for checking result of the operation before sending request reply.
# Error checking is optional (some messages, e.g. detail messages do not have retval field).
_ERR_HANDLER_TEMPLATE = Template("""
    // for negative result don't send callback message but send error callback
    if (mp->retval<0) {
        call_on_error("${name}", mp->context, mp->retval, plugin_main->callbackClass, plugin_main->callbackObject, callbackExceptionClass);
        return;
    }
    if (mp->retval == VNET_API_ERROR_IN_PROGRESS) {
        clib_warning("Result in progress");
        return;
    }
""")


def _generate_setters(msg):
    return "// fixme setters"
