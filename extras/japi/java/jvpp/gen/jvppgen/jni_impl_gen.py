#!/usr/bin/env python2
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

from jni_common_gen import generate_j2c_identifiers, generate_j2c_swap
from jvpp_model import is_dump, is_request, is_control_ping, is_control_ping_reply


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
            jni_identifiers = generate_j2c_identifiers(msg, class_ref_name="requestClass", object_ref_name="request")
            msg_initialization = generate_j2c_swap(msg, struct_ref_name="mp", is_alias=False)

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


def _generate_msg_size(msg):
    msg_size = "sizeof(*mp)"
    _size_components = []
    for field in msg.fields:
        # Ignore ZLAs for simplicity (to support them we need to call JNI functions to check actual size)
        if field.array_len_field:
            _size_components += " + %s*sizeof(%s)" % (field.array_len_field.java_name, field.type.base_type.vpp_name)
            # FIXME(VPP-586): for proper nested structures support, we need generate functions computing type sizes
            # and use it instead of sizeof
        if field.type.name == "string":
            _size_components += " + jstr_length(env, %s) * sizeof(u8)" % field.name
    return msg_size + "".join(_size_components)
