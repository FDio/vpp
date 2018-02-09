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

from jvpp_json_parser import is_array, Class

_REQUEST_FIELD_IDENTIFIER_TEMPLATE = Template("""
    jfieldID ${java_name}FieldId = (*env)->GetFieldID(env, ${class_ref_name}, "${java_name}", "${jni_signature}");
    ${jni_type} ${java_name} = (*env)->Get${jni_accessor}Field(env, ${object_ref_name}, ${java_name}FieldId);
""")


def generate_j2c_identifiers(element, class_ref_name, object_ref_name):
    identifiers = []
    for field in element.fields:
        field_type = field.type
        identifiers.append(_REQUEST_FIELD_IDENTIFIER_TEMPLATE.substitute(
            java_name=field.java_name,
            class_ref_name=class_ref_name,
            jni_signature=field_type.jni_signature,
            jni_type=field_type.jni_type,
            jni_accessor=field_type.jni_accessor,
            object_ref_name=object_ref_name
        ))
    return "".join(identifiers)


_ARRAY_J2C_NO_SWAP_TEMPLATE = Template("""
    if (${field_reference_name}) {
        jsize cnt = (*env)->GetArrayLength (env, ${field_reference_name});
        ${field_length_check}
        (*env)->Get${base_type}ArrayRegion(env, ${field_reference_name}, 0, cnt, (${jni_base_type} *)${struct_reference_name}->${c_name});
    }
""")

_ARRAY_J2C_SWAP_TEMPLATE = Template("""
    if (${field_reference_name}) {
        ${jni_base_type} * ${field_reference_name}ArrayElements = (*env)->Get${base_type}ArrayElements(env, ${field_reference_name}, NULL);
        size_t _i;
        jsize cnt = (*env)->GetArrayLength(env, ${field_reference_name});
        ${field_length_check}
        for (_i = 0; _i < cnt; _i++) {
            ${swap_elements};
        }
        (*env)->Release${base_type}ArrayElements (env, ${field_reference_name}, ${field_reference_name}ArrayElements, 0);
    }
    """)

_CLASS_ARRAY_J2C_TEMPLATE = Template("""
    {
        jclass ${field_reference_name}ArrayElementClass = (*env)->FindClass(env, "${jni_name}");
        if (${field_reference_name}) {
            size_t _i;
            jsize cnt = (*env)->GetArrayLength (env, ${field_reference_name});
            ${field_length_check}
            for (_i = 0; _i < cnt; _i++) {
                jobject ${field_reference_name}ArrayElement = (*env)->GetObjectArrayElement(env, ${field_reference_name}, _i);
                ${swap_elements}
            }
        }
    }
""")

# todo: perhaps we can remove that after testing and introduce host_to_net functions wrappers to have single definition
def generate_j2c_swap(element, struct_ref_name):
    initialization = []
    for field in element.fields:
        field_type = field.type
        if is_array(field):
            template = _ARRAY_J2C_NO_SWAP_TEMPLATE
            field_reference_name = field.java_name
            c_name = field.name
            swap_elements = None
            jni_name = None
            if field_type.is_swap_needed:
                template = _ARRAY_J2C_SWAP_TEMPLATE
                host = "%sArrayElements[_i]" % field_reference_name
                net = "%s->%s[_i]" % (struct_ref_name, c_name)
                swap_elements = field_type.get_host_to_net_function(host, net)
            if isinstance(field_type._base_type, Class): # fixme unify isinstance vs is_array, #fixme do we need arrays as special type, or just make it field?
                jni_name = field_type._base_type.jni_name
                host = "%sArrayElement" % field_reference_name
                net = "%s->%s[_i]" % (struct_ref_name, c_name)
                swap_elements = field_type.get_host_to_net_function(host, net)
                template = _CLASS_ARRAY_J2C_TEMPLATE

            initialization.append(template.substitute(
                field_reference_name=field_reference_name,
                field_length_check=_generate_field_length_check(field),
                base_type=field_type.jni_base_accessor,
                jni_base_type=field_type.jni_base_type,
                struct_reference_name=struct_ref_name,
                jni_name=jni_name,
                c_name=c_name,
                swap_elements=swap_elements
            ))
        else:
            # todo field should know how to proceed, here are far too many conditions
            if field_type.is_swap_needed:
                host = field.java_name
                net = "%s->%s" % (struct_ref_name, field.name)
                initialization.append("    %s;" % field_type.get_host_to_net_function(host, net))
            else:
                initialization.append("    %s->%s = %s;" % (struct_ref_name, field.name, field.java_name))
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
