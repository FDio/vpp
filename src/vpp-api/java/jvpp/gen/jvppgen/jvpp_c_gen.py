#!/usr/bin/env python
#
# Copyright (c) 2016 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
# l
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os, util
from string import Template

import jni_gen


def is_manually_generated(f_name, plugin_name):
    return f_name in {'control_ping_reply'}


class_reference_template = Template("""jclass ${ref_name}Class;
""")

find_class_invocation_template = Template("""
    ${ref_name}Class = (jclass)(*env)->NewGlobalRef(env, (*env)->FindClass(env, "io/fd/vpp/jvpp/${plugin_name}/dto/${class_name}"));
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        return JNI_ERR;
    }""")

find_class_template = Template("""
    ${ref_name}Class = (jclass)(*env)->NewGlobalRef(env, (*env)->FindClass(env, "${class_name}"));
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        return JNI_ERR;
    }""")

delete_class_invocation_template = Template("""
    if (${ref_name}Class) {
        (*env)->DeleteGlobalRef(env, ${ref_name}Class);
    }""")

class_cache_template = Template("""
$class_references
static int cache_class_references(JNIEnv* env) {
    $find_class_invocations
    return 0;
}

static void delete_class_references(JNIEnv* env) {
    $delete_class_invocations
}""")


def generate_class_cache(func_list, plugin_name):
    class_references = []
    find_class_invocations = []
    delete_class_invocations = []
    for f in func_list:
        c_name = f['name']
        class_name = util.underscore_to_camelcase_upper(c_name)
        ref_name = util.underscore_to_camelcase(c_name)

        if util.is_ignored(c_name) or util.is_control_ping(class_name):
            continue

        if util.is_reply(class_name):
            class_references.append(class_reference_template.substitute(
                ref_name=ref_name))
            find_class_invocations.append(find_class_invocation_template.substitute(
                plugin_name=plugin_name,
                ref_name=ref_name,
                class_name=class_name))
            delete_class_invocations.append(delete_class_invocation_template.substitute(ref_name=ref_name))
        elif util.is_notification(c_name):
            class_references.append(class_reference_template.substitute(
                ref_name=ref_name))
            find_class_invocations.append(find_class_invocation_template.substitute(
                plugin_name=plugin_name,
                ref_name=ref_name,
                class_name=class_name))
            delete_class_invocations.append(delete_class_invocation_template.substitute(
                ref_name=ref_name))

    # add exception class to class cache
    ref_name = 'callbackException'
    class_name = 'io/fd/vpp/jvpp/VppCallbackException'
    class_references.append(class_reference_template.substitute(
            ref_name=ref_name))
    find_class_invocations.append(find_class_template.substitute(
            ref_name=ref_name,
            class_name=class_name))
    delete_class_invocations.append(delete_class_invocation_template.substitute(ref_name=ref_name))

    return class_cache_template.substitute(
        class_references="".join(class_references), find_class_invocations="".join(find_class_invocations),
        delete_class_invocations="".join(delete_class_invocations))


# TODO: cache method and field identifiers to achieve better performance
# https://jira.fd.io/browse/HONEYCOMB-42
request_class_template = Template("""
    jclass requestClass = (*env)->FindClass(env, "io/fd/vpp/jvpp/${plugin_name}/dto/${java_name_upper}");""")

request_field_identifier_template = Template("""
    jfieldID ${field_reference_name}FieldId = (*env)->GetFieldID(env, ${object_name}Class, "${field_name}", "${jni_signature}");
    ${jni_type} ${field_reference_name} = (*env)->Get${jni_getter}(env, ${object_name}, ${field_reference_name}FieldId);
    """)

jni_msg_size_template = Template(""" + ${array_length}*sizeof(${element_type})""")

jni_impl_template = Template("""
/**
 * JNI binding for sending ${c_name} message.
 * Generated based on $inputfile preparsed data:
$api_data
 */
JNIEXPORT jint JNICALL Java_io_fd_vpp_jvpp_${plugin_name}_JVpp${java_plugin_name}Impl_${field_name}0
(JNIEnv * env, jclass clazz$args) {
    ${plugin_name}_main_t *plugin_main = &${plugin_name}_main;
    vl_api_${c_name}_t * mp;
    u32 my_context_id = vppjni_get_context_id (&jvpp_main);
    $request_class

    $jni_identifiers

    // create message:
    mp = vl_msg_api_alloc(${msg_size});
    memset (mp, 0, ${msg_size});
    mp->_vl_msg_id = ntohs (get_message_id(env, "${c_name}_${crc}"));
    mp->client_index = plugin_main->my_client_index;
    mp->context = clib_host_to_net_u32 (my_context_id);

    $msg_initialization

    // send message:
    vl_msg_api_send_shmem (plugin_main->vl_input_queue, (u8 *)&mp);
    if ((*env)->ExceptionCheck(env)) {
        return JNI_ERR;
    }
    return my_context_id;
}""")

def generate_jni_impl(func_list, plugin_name, inputfile):
    jni_impl = []
    for f in func_list:
        f_name = f['name']
        camel_case_function_name = util.underscore_to_camelcase(f_name)
        if is_manually_generated(f_name, plugin_name) or util.is_reply(camel_case_function_name) \
                or util.is_ignored(f_name) or util.is_just_notification(f_name):
            continue

        arguments = ''
        request_class = ''
        jni_identifiers = ''
        msg_initialization = ''
        f_name_uppercase = f_name.upper()
        msg_size = 'sizeof(*mp)'

        if f['args']:
            arguments = ', jobject request'
            camel_case_function_name_upper = util.underscore_to_camelcase_upper(f_name)

            request_class = request_class_template.substitute(
                    java_name_upper=camel_case_function_name_upper,
                    plugin_name=plugin_name)

            for t in zip(f['types'], f['args'], f['lengths'], f['arg_types']):
                field_name = util.underscore_to_camelcase(t[1])
                is_variable_len_array = t[2][1]
                if is_variable_len_array:
                    msg_size += jni_msg_size_template.substitute(array_length=util.underscore_to_camelcase(t[2][0]),
                                                                 element_type=t[3])
                jni_identifiers += jni_gen.jni_request_identifiers_for_type(field_type=t[0],
                                                                            field_reference_name=field_name,
                                                                            field_name=field_name)
                msg_initialization += jni_gen.jni_request_binding_for_type(field_type=t[0], c_name=t[1],
                                                                           field_reference_name=field_name,
                                                                           field_length=t[2][0],
                                                                           is_variable_len_array=is_variable_len_array)

        jni_impl.append(jni_impl_template.substitute(
                inputfile=inputfile,
                api_data=util.api_message_to_javadoc(f),
                field_reference_name=camel_case_function_name,
                field_name=camel_case_function_name,
                c_name_uppercase=f_name_uppercase,
                c_name=f_name,
                crc=f['crc'],
                plugin_name=plugin_name,
                java_plugin_name=plugin_name.title(),
                request_class=request_class,
                jni_identifiers=jni_identifiers,
                msg_size=msg_size,
                msg_initialization=msg_initialization,
                args=arguments))

    return "\n".join(jni_impl)

# code fragment for checking result of the operation before sending request reply
callback_err_handler_template = Template("""
    // for negative result don't send callback message but send error callback
    if (mp->retval<0) {
        call_on_error("${handler_name}", mp->context, mp->retval, plugin_main->callbackClass, plugin_main->callbackObject, callbackExceptionClass);
        return;
    }
    if (mp->retval == VNET_API_ERROR_IN_PROGRESS) {
        clib_warning("Result in progress");
        return;
    }
""")

msg_handler_template = Template("""
/**
 * Handler for ${handler_name} message.
 * Generated based on $inputfile preparsed data:
$api_data
 */
static void vl_api_${handler_name}_t_handler (vl_api_${handler_name}_t * mp)
{
    ${plugin_name}_main_t *plugin_main = &${plugin_name}_main;
    JNIEnv *env = jvpp_main.jenv;
    jthrowable exc;
    $err_handler

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


def generate_msg_handlers(func_list, plugin_name, inputfile):
    handlers = []
    for f in func_list:
        handler_name = f['name']
        dto_name = util.underscore_to_camelcase_upper(handler_name)
        ref_name = util.underscore_to_camelcase(handler_name)

        if is_manually_generated(handler_name, plugin_name) or util.is_ignored(handler_name):
            continue

        if not util.is_reply(dto_name) and not util.is_notification(handler_name):
            continue

        dto_setters = ''
        err_handler = ''
        # dto setters
        for t in zip(f['types'], f['args'], f['lengths']):
            c_name = t[1]
            java_name = util.underscore_to_camelcase(c_name)
            field_length = t[2][0]
            is_variable_len_array = t[2][1]
            length_field_type = None
            if is_variable_len_array:
                length_field_type = f['types'][f['args'].index(field_length)]
            dto_setters += jni_gen.jni_reply_handler_for_type(handler_name=handler_name, ref_name=ref_name,
                                                              field_type=t[0], c_name=t[1],
                                                              field_reference_name=java_name,
                                                              field_name=java_name, field_length=field_length,
                                                              is_variable_len_array=is_variable_len_array,
                                                              length_field_type=length_field_type)

            # for retval don't generate setters and generate retval check
            if util.is_retval_field(c_name):
                err_handler = callback_err_handler_template.substitute(
                    handler_name=handler_name
                )
                continue

        handlers.append(msg_handler_template.substitute(
            inputfile=inputfile,
            api_data=util.api_message_to_javadoc(f),
            handler_name=handler_name,
            plugin_name=plugin_name,
            dto_name=dto_name,
            class_ref_name=ref_name,
            dto_setters=dto_setters,
            err_handler=err_handler))

    return "\n".join(handlers)


handler_registration_template = Template("""_(${name}_${crc}, ${name}) \\
""")


def generate_handler_registration(func_list):
    handler_registration = ["#define foreach_api_reply_handler \\\n"]
    for f in func_list:
        name = f['name']
        camelcase_name = util.underscore_to_camelcase(f['name'])

        if (not util.is_reply(camelcase_name) and not util.is_notification(name)) or util.is_ignored(name) \
                or util.is_control_ping(camelcase_name):
            continue

        handler_registration.append(handler_registration_template.substitute(
            name=name,
            crc=f['crc']))

    return "".join(handler_registration)


api_verification_template = Template("""_(${name}_${crc}) \\
""")


def generate_api_verification(func_list):
    api_verification = ["#define foreach_supported_api_message \\\n"]
    for f in func_list:
        name = f['name']

        if util.is_ignored(name):
            continue

        api_verification.append(api_verification_template.substitute(
            name=name,
            crc=f['crc']))

    return "".join(api_verification)


jvpp_c_template = Template("""/**
 * This file contains JNI bindings for jvpp Java API.
 * It was generated by jvpp_c_gen.py based on $inputfile
 * (python representation of api file generated by vppapigen).
 */

// JAVA class reference cache
$class_cache

// List of supported API messages used for verification
$api_verification

// JNI bindings
$jni_implementations

// Message handlers
$msg_handlers

// Registration of message handlers in vlib
$handler_registration
""")

def generate_jvpp(func_list, plugin_name, inputfile, path):
    """ Generates jvpp C file """
    print "Generating jvpp C"

    class_cache = generate_class_cache(func_list, plugin_name)
    jni_impl = generate_jni_impl(func_list, plugin_name, inputfile)
    msg_handlers = generate_msg_handlers(func_list, plugin_name, inputfile)
    handler_registration = generate_handler_registration(func_list)
    api_verification = generate_api_verification(func_list)

    jvpp_c_file = open("%s/jvpp_%s_gen.h" % (path, plugin_name), 'w')
    jvpp_c_file.write(jvpp_c_template.substitute(
            inputfile=inputfile,
            class_cache=class_cache,
            api_verification=api_verification,
            jni_implementations=jni_impl,
            msg_handlers=msg_handlers,
            handler_registration=handler_registration))
    jvpp_c_file.flush()
    jvpp_c_file.close()

