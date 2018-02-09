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

from jni_common_gen import generate_j2c_swap, generate_j2c_identifiers, generate_c2j_swap
from jvpp_model import Class


def generate_type_handlers(model):
    """
    Generates msg handlers for all messages except for dumps and requests (handled by vpp, not client).
    :param model: meta-model of VPP API used for jVPP generation.
    """
    type_handlers = []
    for t in model.types:
        if not isinstance(t, Class):
            continue
        ref_name = t.java_name_lower
        jni_identifiers = generate_j2c_identifiers(t, class_ref_name="%sClass" % ref_name, object_ref_name="_host")
        type_handlers.append(_TYPE_NET_TO_HOST_TEMPLATE.substitute(
            c_name=t.name,
            json_filename=model.json_api_files,
            json_definition=t.doc,
            type_reference_name=ref_name,
            class_FQN=t.jni_name,
            jni_identifiers=jni_identifiers,
            type_swap=generate_j2c_swap(t, struct_ref_name="_net")
        ))

        type_handlers.append(_TYPE_HOST_TO_NET_TEMPLATE.substitute(
            c_name=t.name,
            json_filename=model.json_api_files,
            json_definition=t.doc,
            type_reference_name=ref_name,
            class_FQN=t.jni_name,
            jni_identifiers=jni_identifiers,
            type_swap=generate_c2j_swap(t, object_ref_name="_host", struct_ref_name="_net")
        ))

    return "\n".join(type_handlers)

_TYPE_NET_TO_HOST_TEMPLATE = Template("""
/**
 * Host to network byte order conversion for ${c_name} type.
 * Generated based on $json_filename:
$json_definition
 */
static inline void _host_to_net_${c_name}(JNIEnv * env, jobject _host, vl_api_${c_name}_t * _net)
{
    jclass ${type_reference_name}Class = (*env)->FindClass(env, "${class_FQN}");
$jni_identifiers
$type_swap
}""")

_TYPE_HOST_TO_NET_TEMPLATE = Template("""
/**
 * Network to host byte order conversion for ${c_name} type.
 * Generated based on $json_filename:
$json_definition
 */
static inline void _net_to_host_${c_name}(JNIEnv * env, vl_api_${c_name}_t * _net, jobject _host)
{
    jclass ${type_reference_name}Class = (*env)->FindClass(env, "${class_FQN}");
$type_swap
}""")
