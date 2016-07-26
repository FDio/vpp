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

def is_manually_generated(f_name, plugin_name):
    return f_name in {'control_ping_reply'}


class_reference_template = Template("""jclass ${ref_name}Class;
""")

find_class_invocation_template = Template("""
    ${ref_name}Class = (jclass)(*env)->NewGlobalRef(env, (*env)->FindClass(env, "org/openvpp/jvpp/${plugin_name}/dto/${class_name}"));
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
                ref_name=util.add_notification_suffix(ref_name)))
            find_class_invocations.append(find_class_invocation_template.substitute(
                plugin_name=plugin_name,
                ref_name=util.add_notification_suffix(ref_name),
                class_name=util.add_notification_suffix(class_name)))
            delete_class_invocations.append(delete_class_invocation_template.substitute(
                ref_name=util.add_notification_suffix(ref_name)))

    # add exception class to class cache
    ref_name = 'callbackException'
    class_name = 'org/openvpp/jvpp/VppCallbackException'
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
    jclass requestClass = (*env)->FindClass(env, "org/openvpp/jvpp/${plugin_name}/dto/${java_name_upper}");""")

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
    if (${java_name}) {
        jsize cnt = (*env)->GetArrayLength (env, ${java_name});
        size_t max_size = ${field_length};
        if (max_size != 0 && cnt > max_size) cnt = max_size;
        (*env)->GetByteArrayRegion(env, ${java_name}, 0, cnt, (jbyte *)mp->${c_name});
    }
""")

u16_array_struct_setter_template = Template("""
    jshort * ${java_name}ArrayElements = (*env)->GetShortArrayElements(env, ${java_name}, NULL);
    if (${java_name}) {
        size_t _i;
        jsize cnt = (*env)->GetArrayLength (env, ${java_name});
        size_t max_size = ${field_length};
        if (max_size != 0 && cnt > max_size) cnt = max_size;
        for (_i = 0; _i < cnt; _i++) {
            mp->${c_name}[_i] = clib_host_to_net_u16(${java_name}ArrayElements[_i]);
        }
    }
    (*env)->ReleaseShortArrayElements (env, ${java_name}, ${java_name}ArrayElements, 0);
    """)

u32_array_struct_setter_template = Template("""
    jint * ${java_name}ArrayElements = (*env)->GetIntArrayElements(env, ${java_name}, NULL);
    if (${java_name}) {
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

u64_array_struct_setter_template = Template("""
    jlong * ${java_name}ArrayElements = (*env)->GetLongArrayElements(env, ${java_name}, NULL);
    if (${java_name}) {
        size_t _i;
        jsize cnt = (*env)->GetArrayLength (env, ${java_name});
        size_t max_size = ${field_length};
        if (max_size != 0 && cnt > max_size) cnt = max_size;
        for (_i = 0; _i < cnt; _i++) {
            mp->${c_name}[_i] = clib_host_to_net_u64(${java_name}ArrayElements[_i]);
        }
    }
    (*env)->ReleaseLongArrayElements (env, ${java_name}, ${java_name}ArrayElements, 0);
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
                          'u16[]': u16_array_struct_setter_template,
                          'u32[]': u32_array_struct_setter_template,
                          'u64[]': u64_array_struct_setter_template,
                          'vl_api_ip4_fib_counter_t[]': vl_api_ip4_fib_counter_t_array_struct_setter_template,
                          'vl_api_ip6_fib_counter_t[]': vl_api_ip6_fib_counter_t_array_struct_setter_template
                  }

jni_impl_template = Template("""
/**
 * JNI binding for sending ${c_name} message.
 * Generated based on $inputfile preparsed data:
$api_data
 */
JNIEXPORT jint JNICALL Java_org_openvpp_jvpp_${plugin_name}_JVpp${java_plugin_name}Impl_${java_name}0
(JNIEnv * env, jclass clazz$args) {
    ${plugin_name}_main_t *plugin_main = &${plugin_name}_main;
    vl_api_${c_name}_t * mp;
    u32 my_context_id = vppjni_get_context_id (&jvpp_main);
    $request_class
    $field_identifiers

    // create message:
    mp = vl_msg_api_alloc(sizeof(*mp));
    memset (mp, 0, sizeof (*mp));
    mp->_vl_msg_id = ntohs (VL_API_${c_name_uppercase} + plugin_main->msg_id_base);
    mp->client_index = plugin_main->my_client_index;
    mp->context = clib_host_to_net_u32 (my_context_id);

    $struct_setters
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
        field_identifiers = ''
        struct_setters = ''
        f_name_uppercase = f_name.upper()

        if f['args']:
            arguments = ', jobject request'
            camel_case_function_name_upper = util.underscore_to_camelcase_upper(f_name)

            request_class = request_class_template.substitute(
                    java_name_upper=camel_case_function_name_upper,
                    plugin_name=plugin_name)

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
                field_length = t[2][0]

                # check if we are processing variable length array:
                if t[2][1]:
                    field_length = util.underscore_to_camelcase(t[2][0])

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
                plugin_name=plugin_name,
                java_plugin_name=plugin_name.title(),
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

variable_length_array_value_template = Template("""mp->${length_var_name}""")
variable_length_array_template = Template("""clib_net_to_host_${length_field_type}(${value})""")

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

u16_array_dto_field_setter_template = Template("""
    {
        jshortArray ${java_name} = (*env)->NewShortArray(env, ${field_length});
        jshort * ${java_name}ArrayElements = (*env)->GetShortArrayElements(env, ${java_name}, NULL);
        unsigned int _i;
        for (_i = 0; _i < ${field_length}; _i++) {
            ${java_name}ArrayElements[_i] = clib_net_to_host_u16(mp->${c_name}[_i]);
        }

        (*env)->ReleaseShortArrayElements(env,  ${java_name}, ${java_name}ArrayElements, 0);
        (*env)->SetObjectField(env, dto, ${java_name}FieldId, ${java_name});
    }
""")

u32_array_dto_field_setter_template = Template("""
    {
        jintArray ${java_name} = (*env)->NewIntArray(env, ${field_length});
        jint * ${java_name}ArrayElements = (*env)->GetIntArrayElements(env, ${java_name}, NULL);
        unsigned int _i;
        for (_i = 0; _i < ${field_length}; _i++) {
            ${java_name}ArrayElements[_i] = clib_net_to_host_u32(mp->${c_name}[_i]);
        }

        (*env)->ReleaseIntArrayElements(env,  ${java_name}, ${java_name}ArrayElements, 0);
        (*env)->SetObjectField(env, dto, ${java_name}FieldId, ${java_name});
    }
""")

# For each u64 array we get its elements. Then we convert values to host byte order.
# All changes to  jlong* buffer are written to jlongArray (isCopy is set to NULL)
u64_array_dto_field_setter_template = Template("""
    {
        jlongArray ${java_name} = (*env)->NewLongArray(env, ${field_length});
        jlong * ${java_name}ArrayElements = (*env)->GetLongArrayElements(env, ${java_name}, NULL);
        unsigned int _i;
        for (_i = 0; _i < ${field_length}; _i++) {
            ${java_name}ArrayElements[_i] = clib_net_to_host_u64(mp->${c_name}[_i]);
        }

        (*env)->ReleaseLongArrayElements(env,  ${java_name}, ${java_name}ArrayElements, 0);
        (*env)->SetObjectField(env, dto, ${java_name}FieldId, ${java_name});
    }
""")

dto_field_setter_templates = {'u8': default_dto_field_setter_template,
                      'u16': u16_dto_field_setter_template,
                      'u32': u32_dto_field_setter_template,
                      'i32': u32_dto_field_setter_template,
                      'u64': u64_dto_field_setter_template,
                      'f64': default_dto_field_setter_template, #fixme
                      'u8[]': u8_array_dto_field_setter_template,
                      'u16[]': u16_array_dto_field_setter_template,
                      'u32[]': u32_array_dto_field_setter_template,
                      'u64[]': u64_array_dto_field_setter_template
                      }

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

    $err_handler

    jmethodID constructor = (*env)->GetMethodID(env, ${class_ref_name}Class, "<init>", "()V");
    jmethodID callbackMethod = (*env)->GetMethodID(env, plugin_main->callbackClass, "on${dto_name}", "(Lorg/openvpp/jvpp/${plugin_name}/dto/${dto_name};)V");

    jobject dto = (*env)->NewObject(env, ${class_ref_name}Class, constructor);
    $dto_setters

    (*env)->CallVoidMethod(env, plugin_main->callbackObject, callbackMethod, dto);
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
            field_length = t[3][0]

            if jni_type.endswith('Array') and field_length == '0':
                raise Exception('Variable array \'%s\' defined in message \'%s\' '
                                'should have defined length (e.g. \'%s[%s_length]\''
                                % (c_name, handler_name, c_name, c_name))

            # check if we are processing variable length array
            if t[3][1]:
                length_var_name = t[3][0]
                length_field_type = f['c_types'][f['args'].index(length_var_name)]
                field_length = variable_length_array_value_template.substitute(length_var_name=length_var_name)
                if length_field_type != 'u8':  # we need net to host conversion:
                    field_length = variable_length_array_template.substitute(
                        length_field_type=length_field_type, value=field_length)

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
            plugin_name=plugin_name,
            dto_name=dto_name,
            class_ref_name=ref_name,
            dto_setters=dto_setters,
            err_handler=err_handler))

    return "\n".join(handlers)


handler_registration_template = Template("""_(${upercase_name}, ${name}) \\
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
            upercase_name=name.upper()))

    return "".join(handler_registration)


jvpp_c_template = Template("""/**
 * This file contains JNI bindings for jvpp Java API.
 * It was generated by jvpp_c_gen.py based on $inputfile
 * (python representation of api file generated by vppapigen).
 */

// JAVA class reference cache
$class_cache

// JNI bindings
$jni_implementations

// Message handlers
$msg_handlers

// Registration of message handlers in vlib
$handler_registration
""")

def generate_jvpp(func_list, plugin_name, inputfile):
    """ Generates jvpp C file """
    print "Generating jvpp C"

    class_cache = generate_class_cache(func_list, plugin_name)
    jni_impl = generate_jni_impl(func_list, plugin_name, inputfile)
    msg_handlers = generate_msg_handlers(func_list, plugin_name, inputfile)
    handler_registration = generate_handler_registration(func_list)

    jvpp_c_file = open("jvpp_%s_gen.h" % plugin_name, 'w')
    jvpp_c_file.write(jvpp_c_template.substitute(
            inputfile=inputfile,
            class_cache=class_cache,
            jni_implementations=jni_impl,
            msg_handlers=msg_handlers,
            handler_registration=handler_registration))
    jvpp_c_file.flush()
    jvpp_c_file.close()

