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

_REQUEST_FIELD_IDENTIFIER_TEMPLATE = Template("""
    jfieldID ${java_name}FieldId = (*env)->GetFieldID(env, requestClass, "${java_name}", "${jni_signature}");
    ${jni_type} ${java_name} = (*env)->Get${jni_accessor}(env, request, ${java_name}FieldId);
""")


def generate_j2c_identifiers(element):
    identifiers = []
    for field in element.fields:
        field_type = field.type
        identifiers.append(_REQUEST_FIELD_IDENTIFIER_TEMPLATE.substitute(
            java_name=field.java_name,
            jni_signature=field_type.jni_signature,
            jni_type=field_type.jni_type,
            jni_accessor=field_type.jni_accessor,
        ))
    return "".join(identifiers)


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


def generate_j2c_swap(element):
    initialization = []
    for field in element.fields:
        field_type = field.type
        if is_array(field):
            # todo generating array swap functions would eliminate this special case (todo do not include after
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
    field_length = str(field.array_len)
    if field.array_len_field:
        field_length = field.array_len_field.java_name

    # todo: remove when ZLAs without length field are disabled
    if field_length != "0":
        return _FIELD_LENGTH_CHECK.substitute(field_length=field_length)
    else:
        return ""
