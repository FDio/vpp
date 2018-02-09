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

from jvpp_json_parser import is_dump, is_request, is_control_ping, is_control_ping_reply, is_array

_JNI_IMPL_TEMPLATE = Template("""
/**
 * JNI binding for sending ${c_name} message.
 * Generated based on $json_filename:
$json_definition
 */
JNIEXPORT jint JNICALL Java_io_fd_vpp_jvpp_${plugin_name}_JVpp${plugin_java_name}Impl_${java_method_name}0
(JNIEnv * env, jclass clazz${arguments}) {
    ${plugin_name}_main_t *plugin_main = &${plugin_name}_main;
    vl_api_${c_name}_t * mp;
    u32 my_context_id = vppjni_get_context_id (&jvpp_main);
$request_class
$jni_identifiers

    // create message:
    const size_t _size = ${msg_size};
    mp = vl_msg_api_alloc(_size);
    memset (mp, 0, _size);
    mp->_vl_msg_id = ntohs (get_message_id(env, "${c_name}_${crc}"));
    mp->client_index = plugin_main->my_client_index;
    mp->context = clib_host_to_net_u32 (my_context_id);

$msg_initialization

    // send message:
    if (CLIB_DEBUG > 1)
        clib_warning ("Sending ${c_name} message");
    vl_msg_api_send_shmem (plugin_main->vl_input_queue, (u8 *)&mp);
    if ((*env)->ExceptionCheck(env)) {
        return JNI_ERR;
    }
    return my_context_id;
}""")

# TODO: cache method and field identifiers to achieve better performance
# https://jira.fd.io/browse/HONEYCOMB-42
_REQUEST_CLASS_TEMPLATE = Template("""    jclass requestClass = (*env)->FindClass(env, "io/fd/vpp/jvpp/${plugin_name}/dto/${java_dto_name}");
""")


def generate_jni_impl(model):
    """
    Generates JNI bindings for sending dump and request messages.
    :param model: meta-model of VPP API used for jVPP generation.
    """
    jni_impl = []
    for msg in model.messages:
        if is_control_ping(msg) or is_control_ping_reply(msg):
            # Skip control ping managed by jvpp registry.
            continue
        if not (is_dump(msg) or is_request(msg)):
            continue
        arguments = ""
        request_class = ""
        jni_identifiers = ""
        msg_initialization = ""

        if msg.has_fields:
            arguments = ", jobject request"
            request_class = _REQUEST_CLASS_TEMPLATE.substitute(
                plugin_name=model.plugin_name,
                java_dto_name=msg.java_name_upper
            )
            jni_identifiers = _generate_jni_identifiers(msg)
            msg_initialization = _generate_msg_initialization(msg)

        jni_impl.append(_JNI_IMPL_TEMPLATE.substitute(
            c_name=msg.name,
            json_filename=model.json_api_files,
            json_definition=msg.doc,
            plugin_name=model.plugin_name,
            plugin_java_name=model.plugin_java_name,
            java_method_name=msg.java_name_lower,
            arguments=arguments,
            request_class=request_class,
            jni_identifiers=jni_identifiers,
            msg_size=_generate_msg_size(msg),
            crc=msg.crc,
            msg_initialization=msg_initialization
        ))
    return "".join(jni_impl)


def _generate_msg_size(msg):
    msg_size = "sizeof(*mp)"
    _size_components = []
    for field in msg.fields:
        # todo: ignore ZLAs for simplicity (to support them we need to call jni functions to check actual size,
        # which is not done in VPP APIGEN 1)
        if field.array_len_field:
            _size_components += " + %s*sizeof(%s)" % (field.array_len_field.java_name, field.type.base_type_name)
            #fixme: to support nested structures we need to call a function that oomputes size of type instead of sizeof

    # todo 1) add support for arrays (use message struct in size computation)
    # todo 2) add support for custom types (produce create funciton for each message)
    # todo 3) add support for type nesting (VPP-586)
    return msg_size + "".join(_size_components)


_REQUEST_FIELD_IDENTIFIER_TEMPLATE = Template("""
    jfieldID ${java_name}FieldId = (*env)->GetFieldID(env, requestClass, "${java_name}", "${jni_signature}");
    ${jni_type} ${java_name} = (*env)->Get${jni_accessor}(env, request, ${java_name}FieldId);
""")


def _generate_jni_identifiers(msg):
    identifiers = []
    for field in msg.fields:
        field_type = field.type
        identifiers.append(_REQUEST_FIELD_IDENTIFIER_TEMPLATE.substitute(
            java_name=field.java_name,
            jni_signature=field_type.jni_signature,
            jni_type=field_type.jni_type,
            jni_accessor=field_type.jni_accessor,
        ))
    return "".join(identifiers)

# todo(s)
# rename to vpp struct setter or something simmilar
# generate host_to_net_functions for simple types (optional)
# generate host_to_net_functions for array type
# same for custom types


_ARRAY_J2C_NO_SWAP_TEMPLATE = Template("""
    if (${field_reference_name}) {
        jsize cnt = (*env)->GetArrayLength (env, ${field_reference_name});
        ${field_length_check}
        (*env)->Get${base_type}ArrayRegion(env, ${field_reference_name}, 0, cnt, (${jni_base_type} *)mp->${c_name});
    }
""")

_ARRAY_J2C_SWAP_TEMPLATE = Template("""
    if (${field_reference_name}) {
        ${jni_base_type} * ${field_reference_name}ArrayElements = (*env)->Get${base_type}ArrayElements(env, ${field_reference_name}, NULL);
        size_t _i;
        jsize cnt = (*env)->GetArrayLength(env, ${field_reference_name});
        ${field_length_check}
        for (_i = 0; _i < cnt; _i++) {
            mp->${c_name}[_i] = ${host_to_net_function}(${field_reference_name}ArrayElements[_i]);
        }
        (*env)->Release${base_type}ArrayElements (env, ${field_reference_name}, ${field_reference_name}ArrayElements, 0);
    }
    """)


def _generate_msg_initialization(msg):
    initialization = []
    for field in msg.fields:
        field_type = field.type
        if is_array(field):
            template = _ARRAY_J2C_SWAP_TEMPLATE if field_type.is_swap_needed else _ARRAY_J2C_NO_SWAP_TEMPLATE
            initialization.append(template.substitute(
                field_reference_name=field.java_name,
                field_length_check=_generate_field_length_check(field),
                base_type=field_type.base_type_java_name,
                jni_base_type=field_type.jni_base_type,
                c_name=field.name,
                host_to_net_function=field_type.host_to_net_function
            ))
        else:
            # todo field should know how to proceed, here are far too many conditions
            if field_type.is_swap_needed:
                initialization.append("    mp->%s = %s(%s);" % (field.name, field_type.host_to_net_function, field.java_name))
            else:
                initialization.append("    mp->%s = %s;" % (field.name, field.java_name))
            # todo: consider generating functions (at least for structs)

    return "\n".join(initialization)


# Make sure we do not write more elements that are expected
_FIELD_LENGTH_CHECK = Template("""
        size_t max_size = ${field_length};
        if (cnt > max_size) cnt = max_size;""")


def _generate_field_length_check(field):
    # enforce max length if array has fixed length or uses variable length syntax
    field_length = field.array_len
    if field.array_len_field:
        field_length = field.array_len_field.java_name

    # todo: remove when ZLAs without lenght field are disabled
    if field_length != "0":
        return _FIELD_LENGTH_CHECK.substitute(field_length=field_length)
    else:
        return ""
