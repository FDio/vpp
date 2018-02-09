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

# fixme extract common code from message handling and type handling for JNI bindings, but as a second step
# e.g create message swap functions
from jvpp_jni_common_gen import generate_j2c_swap, generate_j2c_identifiers
from jvpp_json_parser import Class

# fixme generate functions for computing structure sizes
# or more generic, functions for initializing messages/types

_TYPE_HANDLER_TEMPLATE = Template("""
/**
 * Handler for ${c_name} type.
 * Generated based on $json_filename:
$json_definition
 */
static inline vl_api_${c_name}_t * _net_to_host_${c_name}(vl_api_${c_name}_t *a)
{
    jclass ${type_reference_name}Class = (*env)->FindClass(env, "${class_FQN}");
    memset (&(mp->${c_name}), 0, sizeof (mp->${c_name})); // will not work if type definition uses VLA syntax
    // (either directly or by nesting)
$jni_identifiers
$type_initialization
}

}""")


def generate_type_handlers(model):
    """
    Generates msg handlers for all messages except for dumps and requests (handled by vpp, not client).
    :param model: meta-model of VPP API used for jVPP generation.
    """
    type_handlers = []
    for t in model.types:
        if isinstance(t, Class):
            type_handlers.append(_TYPE_HANDLER_TEMPLATE.substitute(
                c_name=t.name,
                json_filename=model.json_api_files,
                json_definition=t.doc,
                type_reference_name=t.java_name_lower,
                class_FQN=t.jni_name,
                jni_identifiers=generate_j2c_identifiers(t),
                type_initialization=generate_j2c_swap(t)
            ))

    return "\n".join(type_handlers)
