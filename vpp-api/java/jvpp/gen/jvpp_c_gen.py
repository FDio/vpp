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

def is_manually_generated(f_name):
    return f_name in {'control_ping_reply'}


class_reference_template = Template("""jclass ${ref_name}Class;
""")

find_class_invocation_template = Template("""
    ${ref_name}Class = (jclass)(*env)->NewGlobalRef(env, (*env)->FindClass(env, "org/openvpp/jvpp/dto/${class_name}"));
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

class_cache_template = Template("""
$class_references
static int cache_class_references(JNIEnv* env) {
    $find_class_invocations
    return 0;
}""")

def generate_class_cache(func_list):
    class_references = []
    find_class_invocations = []
    for f in func_list:
        c_name = f['name']
        class_name = util.underscore_to_camelcase_upper(c_name)
        ref_name = util.underscore_to_camelcase(c_name)

        if util.is_ignored(c_name):
            continue

        if util.is_reply(class_name):
            class_references.append(class_reference_template.substitute(
                ref_name=ref_name))
            find_class_invocations.append(find_class_invocation_template.substitute(
                ref_name=ref_name,
                class_name=class_name))
        elif util.is_notification(c_name):
            class_references.append(class_reference_template.substitute(
                ref_name=util.add_notification_suffix(ref_name)))
            find_class_invocations.append(find_class_invocation_template.substitute(
                ref_name=util.add_notification_suffix(ref_name),
                class_name=util.add_notification_suffix(class_name)))

    # add exception class to class cache
    ref_name = 'callbackException'
    class_name = 'org/openvpp/jvpp/VppCallbackException'
    class_references.append(class_reference_template.substitute(
        ref_name=ref_name))
    find_class_invocations.append(find_class_template.substitute(
            ref_name=ref_name,
            class_name=class_name))
    return class_cache_template.substitute(
        class_references="".join(class_references), find_class_invocations="".join(find_class_invocations))


# TODO: cache method and field identifiers to achieve better performance
# https://jira.fd.io/browse/HONEYCOMB-42
request_class_template = Template("""
    jclass requestClass = (*env)->FindClass(env, "org/openvpp/jvpp/dto/${java_name_upper}");""")

request_field_identifier_template = Template("""
    jfieldID ${java_name}FieldId = (*env)->GetFieldID(env, requestClass, "${java_name}", "${jni_signature}");
    ${jni_type} ${java_name} = (*env)->Get${jni_getter}(env, request, ${java_name}FieldId);
    """)

u8_struct_setter_template = Template("""
    mp->${c_name} = ${java_name};""")

u16_struct_setter_template = Template("""
    mp->${c_name} = clib_host_to_net_u16(${java_name});""")

u32_struct_setter_template = Template("""
    mp->${c_name} = clib_host_to_net_u32(${java_name});""")

i32_struct_setter_template = Template("""
    mp->${c_name} = clib_host_to_net_i32(${java_name});!""")

u64_struct_setter_template = Template("""
    mp->${c_name} = clib_host_to_net_u64(${java_name});""")

u8_array_struct_setter_template = Template("""
    {
        jsize cnt = (*env)->GetArrayLength (env, ${java_name});
        size_t max_size = ${field_length};
        if (max_size != 0 && cnt > max_size) cnt = max_size;
        (*env)->GetByteArrayRegion(env, ${java_name}, 0, cnt, (jbyte *)mp->${c_name});
    }
""")

u32_array_struct_setter_template = Template("""
    jint * ${java_name}ArrayElements = (*env)->GetIntArrayElements(env, ${java_name}, NULL);
    {
        size_t _i;
        jsize cnt = (*env)->GetArrayLength (env, ${java_name});
        size_t max_size = ${field_length};
        if (max_size != 0 && cnt > max_size) cnt = max_size;
        for (_i = 0; _i < cnt; _i++) {
            mp->${c_name}[_i] = clib_host_to_net_u32(${java_name}ArrayElements[_i]);
        }
    }
    (*env)->ReleaseIntArrayElements (env, ${java_name}, ${java_name}ArrayElements, 0);
    """)

vl_api_ip4_fib_counter_t_array_struct_setter_template = Template("""
    // vl_api_ip4_fib_counter_t_array_field_setter_template FIXME""")

vl_api_ip6_fib_counter_t_array_struct_setter_template = Template("""
    // vl_api_ip6_fib_counter_t_array_field_setter_template FIXME""")

struct_setter_templates = {'u8': u8_struct_setter_template,
                          'u16': u16_struct_setter_template,
                          'u32': u32_struct_setter_template,
                          'i32': u32_struct_setter_template,
                          'u64': u64_struct_setter_template,
                          'u8[]': u8_array_struct_setter_template,
                          'u32[]': u32_array_struct_setter_template,
                          'vl_api_ip4_fib_counter_t[]': vl_api_ip4_fib_counter_t_array_struct_setter_template,
                          'vl_api_ip6_fib_counter_t[]': vl_api_ip6_fib_counter_t_array_struct_setter_template
                  }

jni_impl_template = Template("""
/**
 * JNI binding for sending ${c_name} vpe.api message.
 * Generated based on $inputfile preparsed data:
$api_data
 */
JNIEXPORT jint JNICALL Java_org_openvpp_jvpp_JVppImpl_${java_name}0
(JNIEnv * env, jclass clazz$args) {
    vppjni_main_t *jm = &vppjni_main;
    vl_api_${c_name}_t * mp;
    u32 my_context_id;
    int rv;
    rv = vppjni_sanity_check (jm);
    if (rv) return rv;
    my_context_id = vppjni_get_context_id (jm);
    $request_class
    $field_identifiers
    M(${c_name_uppercase}, ${c_name});
    mp->context = clib_host_to_net_u32 (my_context_id);
    $struct_setters
    S;
    if ((*env)->ExceptionCheck(env)) {
        return JNI_ERR;
    }
    return my_context_id;
}""")

def generate_jni_impl(func_list, inputfile):
    jni_impl = []
    for f in func_list:
        f_name = f['name']
        camel_case_function_name = util.underscore_to_camelcase(f_name)
        if is_manually_generated(f_name) or util.is_reply(camel_case_function_name) \
                or util.is_ignored(f_name) or util.is_just_notification(f_name):
            continue

        arguments = ''
        request_class = ''
        field_identifiers = ''
        struct_setters = ''
        f_name_uppercase = f_name.upper()

        if f['args']:
            arguments = ', jobject request'
            camel_case_function_name_upper = util.underscore_to_camelcase_upper(f_name)

            request_class = request_class_template.substitute(java_name_upper=camel_case_function_name_upper)

            # field identifiers
            for t in zip(f['types'], f['args']):
                jni_type = t[0]
                java_field_name = util.underscore_to_camelcase(t[1])
                jni_signature = util.jni_2_signature_mapping[jni_type]
                jni_getter = util.jni_field_accessors[jni_type]
                field_identifiers += request_field_identifier_template.substitute(
                        jni_type=jni_type,
                        java_name=java_field_name,
                        jni_signature=jni_signature,
                        jni_getter=jni_getter)

            # field setters
            for t in zip(f['c_types'], f['args'], f['lengths']):
                c_type = t[0]
                c_name = t[1]
                field_length = t[2]
                java_field_name = util.underscore_to_camelcase(c_name)

                struct_setter_template = struct_setter_templates[c_type]

                struct_setters += struct_setter_template.substitute(
                        c_name=c_name,
                        java_name=java_field_name,
                        field_length=field_length)

        jni_impl.append(jni_impl_template.substitute(
                inputfile=inputfile,
                api_data=util.api_message_to_javadoc(f),
                java_name=camel_case_function_name,
                c_name_uppercase=f_name_uppercase,
                c_name=f_name,
                request_class=request_class,
                field_identifiers=field_identifiers,
                struct_setters=struct_setters,
                args=arguments))

    return "\n".join(jni_impl)


dto_field_id_template = Template("""
    jfieldID ${java_name}FieldId = (*env)->GetFieldID(env, ${class_ref_name}Class, "${java_name}", "${jni_signature}");""")

default_dto_field_setter_template = Template("""
    (*env)->Set${jni_setter}(env, dto, ${java_name}FieldId, mp->${c_name});
""")

u16_dto_field_setter_template = Template("""
    (*env)->Set${jni_setter}(env, dto, ${java_name}FieldId, clib_net_to_host_u16(mp->${c_name}));
""")

u32_dto_field_setter_template = Template("""
    (*env)->Set${jni_setter}(env, dto, ${java_name}FieldId, clib_net_to_host_u32(mp->${c_name}));
""")

u64_dto_field_setter_template = Template("""
    (*env)->Set${jni_setter}(env, dto, ${java_name}FieldId, clib_net_to_host_u64(mp->${c_name}));
""")

u8_array_dto_field_setter_template = Template("""
    jbyteArray ${java_name} = (*env)->NewByteArray(env, ${field_length});
    (*env)->SetByteArrayRegion(env, ${java_name}, 0, ${field_length}, (const jbyte*)mp->${c_name});
    (*env)->SetObjectField(env, dto, ${java_name}FieldId, ${java_name});
""")

# For each u64 array we get its elements. Then we convert values to host byte order.
# All changes to  jint* buffer are written to jlongArray (isCopy is set to NULL)
u64_array_dto_field_setter_template = Template("""
    {
        jlongArray ${java_name} = (*env)->NewLongArray(env, ${field_length});
        jlong * ${java_name}ArrayElements = (*env)->GetLongArrayElements(env, ${java_name}, NULL);
        unsigned int _i;
        for (_i = 0; _i < ${field_length}; _i++) {
            ${java_name}ArrayElements[_i] = clib_net_to_host_u64(mp->${c_name}[_i]);
        }
        (*env)->SetObjectField(env, dto, ${java_name}FieldId, ${java_name});
    }
""")

dto_field_setter_templates = {'u8': default_dto_field_setter_template,
                      'u16': u16_dto_field_setter_template,
                      'u32': u32_dto_field_setter_template,
                      'i32': u32_dto_field_setter_template,
                      'u64': u64_dto_field_setter_template,
                      'f64': default_dto_field_setter_template, #fixme
                      'u64[]': u64_array_dto_field_setter_template,
                      'u8[]': u8_array_dto_field_setter_template
                      }

# code fragment for checking result of the operation before sending request reply
callback_err_handler_template = Template("""
    // for negative result don't send callback message but send error callback
    if (mp->retval<0) {
        CallOnError("${handler_name}",mp->context,mp->retval);
        return;
    }
    if (mp->retval == VNET_API_ERROR_IN_PROGRESS) {
        clib_warning("Result in progress");
        return;
    }
""")

msg_handler_template = Template("""
/**
 * Handler for ${handler_name} vpe.api message.
 * Generated based on $inputfile preparsed data:
$api_data
 */
static void vl_api_${handler_name}_t_handler (vl_api_${handler_name}_t * mp)
{
    vppjni_main_t * jm = &vppjni_main;
    JNIEnv *env = jm->jenv;
    $err_handler

    jmethodID constructor = (*env)->GetMethodID(env, ${class_ref_name}Class, "<init>", "()V");
    jmethodID callbackMethod = (*env)->GetMethodID(env, jm->callbackClass, "on${dto_name}", "(Lorg/openvpp/jvpp/dto/${dto_name};)V");

    jobject dto = (*env)->NewObject(env, ${class_ref_name}Class, constructor);
    $dto_setters
    (*env)->CallVoidMethod(env, jm->callback, callbackMethod, dto);
}""")

def generate_msg_handlers(func_list, inputfile):
    handlers = []
    for f in func_list:
        handler_name = f['name']
        dto_name = util.underscore_to_camelcase_upper(handler_name)
        ref_name = util.underscore_to_camelcase(handler_name)

        if is_manually_generated(handler_name) or util.is_ignored(handler_name):
            continue

        if not util.is_reply(dto_name) and not util.is_notification(handler_name):
            continue

        if util.is_notification(handler_name):
            dto_name = util.add_notification_suffix(dto_name)
            ref_name = util.add_notification_suffix(ref_name)

        dto_setters = ''
        err_handler = ''
        # dto setters
        for t in zip(f['c_types'], f['types'], f['args'], f['lengths']):
            c_type = t[0]
            jni_type = t[1]
            c_name = t[2]
            field_length = t[3]

            # for retval don't generate setters and generate retval check
            if util.is_retval_field(c_name):
                err_handler = callback_err_handler_template.substitute(
                    handler_name=handler_name
                )
                continue

            java_field_name = util.underscore_to_camelcase(c_name)
            jni_signature = util.jni_2_signature_mapping[jni_type]
            jni_setter = util.jni_field_accessors[jni_type]

            dto_setters += dto_field_id_template.substitute(
                    java_name=java_field_name,
                    class_ref_name=ref_name,
                    jni_signature=jni_signature)

            dto_setter_template = dto_field_setter_templates[c_type]

            dto_setters += dto_setter_template.substitute(
                    java_name=java_field_name,
                    jni_signature=jni_signature,
                    c_name=c_name,
                    jni_setter=jni_setter,
                    field_length=field_length)

        handlers.append(msg_handler_template.substitute(
            inputfile=inputfile,
            api_data=util.api_message_to_javadoc(f),
            handler_name=handler_name,
            dto_name=dto_name,
            class_ref_name=ref_name,
            dto_setters=dto_setters,
            err_handler=err_handler))

    return "\n".join(handlers)


handler_registration_template = Template("""_(${upercase_name}, ${name}) \\
""")


def generate_handler_registration(func_list):
    handler_registration = ["#define foreach_vpe_api_msg \\\n"]
    for f in func_list:
        name = f['name']
        camelcase_name = util.underscore_to_camelcase(f['name'])

        if (not util.is_reply(camelcase_name) and not util.is_notification(name)) or util.is_ignored(name):
            continue

        handler_registration.append(handler_registration_template.substitute(
            name=name,
            upercase_name=name.upper()))

    return "".join(handler_registration)


jvpp_c_template = Template("""/**
 * This file contains JNI bindings for jvpp Java API.
 * It was generated by jvpp_c_gen.py based on $inputfile
 * (python representation of vpe.api generated by vppapigen).
 */

void CallOnError(const char* call, int context, int retval);

// JAVA class reference cache
$class_cache

// JNI bindings
$jni_implementations

// Message handlers
$msg_handlers

// Registration of message handlers in vlib
$handler_registration
""")

def generate_jvpp(func_list, inputfile):
    """ Generates jvpp C file """
    print "Generating jvpp C"

    class_cache = generate_class_cache(func_list)
    jni_impl = generate_jni_impl(func_list, inputfile)
    msg_handlers = generate_msg_handlers(func_list, inputfile)
    handler_registration = generate_handler_registration(func_list)

    jvpp_c_file = open("jvpp_gen.h", 'w')
    jvpp_c_file.write(jvpp_c_template.substitute(
            inputfile=inputfile,
            class_cache=class_cache,
            jni_implementations=jni_impl,
            msg_handlers=msg_handlers,
            handler_registration=handler_registration))
    jvpp_c_file.flush()
    jvpp_c_file.close()

