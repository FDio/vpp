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

from jvpp_json_parser import is_dump, is_request, is_control_ping, is_control_ping_reply

_JNI_IMPL_TEMPLATE = Template("""
/**
 * JNI binding for sending ${c_name} message.
 * Generated based on $json_filename:
$json_definition
 */
JNIEXPORT jint JNICALL Java_io_fd_vpp_jvpp_${plugin_name}_JVpp${plugin_java_name}Impl_${java_name}0
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
    if (CLIB_DEBUG > 1)
        clib_warning ("Sending ${c_name} message");
    vl_msg_api_send_shmem (plugin_main->vl_input_queue, (u8 *)&mp);
    if ((*env)->ExceptionCheck(env)) {
        return JNI_ERR;
    }
    return my_context_id;
}""")


def generate_jni_impl(model):
    jni_impl = []
    for msg in model.messages:
        if is_control_ping(msg) or is_control_ping_reply(msg):
            # Skip control ping managed by jvpp registry.
            continue
        if not (is_dump(msg) or is_request(msg)):
            continue
        jni_impl.append(_JNI_IMPL_TEMPLATE.substitute(
            c_name=msg.name,
            json_filename=model.json_api_files,
            json_definition=msg.doc,
            plugin_name=model.plugin_name,
            plugin_java_name=model.plugin_java_name,
            java_name=msg.java_name_lower,
            args="args FIXME",
            request_class="request_class FIXME",
            jni_identifiers="jni_identifiers FIXME",
            msg_size="msg_size FIXME",
            crc="crc FIXME",
            msg_initialization="msg_initialization FIXME"
        ))
    return "".join(jni_impl)
