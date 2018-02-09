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

from jvpp_json_parser import is_array, Class, is_retval

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
        if (${field_reference_name}) {
            size_t _i;
            jsize cnt = (*env)->GetArrayLength (env, ${field_reference_name});
            ${field_length_check}
            for (_i = 0; _i < cnt; _i++) {
                jobject ${field_reference_name}ArrayElement = (*env)->GetObjectArrayElement(env, ${field_reference_name}, _i);
                ${swap_elements};
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
            if isinstance(field_type._base_type,
                          Class):  # fixme unify isinstance vs is_array, #fixme do we need arrays as special type, or just make it field?
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


_SIMPLE_TYPE_FIELD_SETTER_TEMPLATE = Template("""
    jfieldID ${java_name}FieldId = (*env)->GetFieldID(env, ${class_ref_name}Class, "${java_name}", "${jni_signature}");
    (*env)->Set${jni_accessor}Field(env, ${object_ref_name}, ${java_name}FieldId, ${net_to_host_function}(${struct_ref_name}->${c_name}));
""")

_STRUCT_SETTER_TEMPLATE = Template("""
    jfieldID ${java_name}FieldId = (*env)->GetFieldID(env, ${class_ref_name}Class, "${java_name}", "${jni_signature}");
    jclass ${java_name}Class = (*env)->FindClass(env, "${jni_name}");
    jmethodID ${java_name}Constructor = (*env)->GetMethodID(env, ${java_name}Class, "<init>", "()V");
    jobject ${java_name} = (*env)->NewObject(env, ${java_name}Class,  ${java_name}Constructor);
    ${net_to_host_function}(env, &(${struct_ref_name}->${c_name}), ${java_name});
    (*env)->Set${jni_accessor}Field(env, ${object_ref_name}, ${java_name}FieldId, ${java_name});
    (*env)->DeleteLocalRef(env, ${java_name});
""")

_SIMPLE_TYPE_NO_SWAP_FIELD_SETTER_TEMPLATE = Template("""
    jfieldID ${java_name}FieldId = (*env)->GetFieldID(env, ${class_ref_name}Class, "${java_name}", "${jni_signature}");
    (*env)->Set${jni_accessor}Field(env, ${object_ref_name}, ${java_name}FieldId, ${struct_ref_name}->${c_name});
""")

_ARRAY_C2J_NO_SWAP_TEMPLATE = Template("""
    jfieldID ${field_reference_name}FieldId = (*env)->GetFieldID(env, ${class_ref_name}Class, "${field_reference_name}", "${jni_signature}");
    ${jni_type} ${field_reference_name} = (*env)->New${base_type}Array(env, ${field_length});
    (*env)->Set${base_type}ArrayRegion(env, ${field_reference_name}, 0, ${field_length}, (const ${jni_base_type}*)${struct_ref_name}->${c_name});
    (*env)->SetObjectField(env, ${object_ref_name}, ${field_reference_name}FieldId, ${field_reference_name});
    (*env)->DeleteLocalRef(env, ${field_reference_name});
""")

_ARRAY_C2J_SWAP_TEMPLATE = Template("""
    jfieldID ${field_reference_name}FieldId = (*env)->GetFieldID(env, ${class_ref_name}Class, "${field_reference_name}", "${jni_signature}");
    {
        ${jni_type} ${field_reference_name} = (*env)->New${base_type}Array(env, ${field_length});
        ${jni_base_type} * ${field_reference_name}ArrayElements = (*env)->Get${base_type}ArrayElements(env, ${field_reference_name}, NULL);
        unsigned int _i;
        for (_i = 0; _i < ${field_length}; _i++) {
            ${field_reference_name}ArrayElements[_i] = ${net_to_host_function}(${struct_ref_name}->${c_name}[_i]);
        }

        (*env)->Release${base_type}ArrayElements(env,  ${field_reference_name}, ${field_reference_name}ArrayElements, 0);
        (*env)->SetObjectField(env, ${object_ref_name}, ${field_reference_name}FieldId, ${field_reference_name});
        (*env)->DeleteLocalRef(env, ${field_reference_name});
    }
""")

_ARRAY_C2J_CLASS_SWAP_TEMPLATE = Template("""
    jfieldID ${field_reference_name}FieldId = (*env)->GetFieldID(env, ${class_ref_name}Class, "${field_reference_name}", "${jni_signature}");
    {
        jclass ${field_reference_name}Class = (*env)->FindClass(env, "${jni_name}");
        jobjectArray ${field_reference_name} = (*env)->NewObjectArray(env, ${field_length}, ${field_reference_name}Class, 0);
        jmethodID ${field_reference_name}Constructor = (*env)->GetMethodID(env, ${field_reference_name}Class, "<init>", "()V");
        unsigned int _i;
        for (_i = 0; _i < ${field_length}; _i++) {
            jobject ${field_reference_name}ArrayElement = (*env)->NewObject(env, ${field_reference_name}Class,  ${field_reference_name}Constructor);
            ${net_to_host_function}(env, &(${struct_ref_name}->${c_name}[_i]), ${field_reference_name}ArrayElement);
            (*env)->SetObjectArrayElement(env, ${field_reference_name}, _i, ${field_reference_name}ArrayElement);
            (*env)->DeleteLocalRef(env, ${field_reference_name}ArrayElement);
        }
        (*env)->SetObjectField(env, ${object_ref_name}, ${field_reference_name}FieldId, ${field_reference_name});
        (*env)->DeleteLocalRef(env, ${field_reference_name});
    }
""")


def generate_c2j_swap(element, object_ref_name, struct_ref_name):
    msg_java_name = element.java_name_lower
    setters = []
    for field in element.fields:
        field_type = field.type
        # todo: too many conditions

        if is_retval(field):
            # for retval don't generate setters and generate retval check
            continue
        elif is_array(field):
            # fixme clean a bit
            jni_name = ""
            template = _ARRAY_C2J_SWAP_TEMPLATE if field_type.is_swap_needed else _ARRAY_C2J_NO_SWAP_TEMPLATE
            if isinstance(field_type._base_type, Class):
                template = _ARRAY_C2J_CLASS_SWAP_TEMPLATE
                jni_name = field_type._base_type.jni_name
            setters.append(template.substitute(
                field_reference_name=field.java_name,
                class_ref_name=msg_java_name,
                jni_signature=field_type.jni_signature,
                jni_type=field_type.jni_type,
                jni_name=jni_name,
                base_type=field_type.jni_base_accessor,
                field_length=_generate_array_length(field, struct_ref_name),
                jni_base_type=field_type.jni_base_type,
                object_ref_name=object_ref_name,
                struct_ref_name=struct_ref_name,
                net_to_host_function=field_type.net_to_host_function,
                c_name=field.name
            ))
        else:
            if field_type.is_swap_needed:
                template = _SIMPLE_TYPE_FIELD_SETTER_TEMPLATE
                jni_name = ""
                if isinstance(field_type, Class):
                    template = _STRUCT_SETTER_TEMPLATE
                    jni_name = field_type.jni_name
                setters.append(template.substitute(
                    java_name=field.java_name,
                    class_ref_name=msg_java_name,
                    jni_signature=field_type.jni_signature,
                    jni_name=jni_name,
                    jni_accessor=field_type.jni_accessor,
                    object_ref_name=object_ref_name,
                    struct_ref_name=struct_ref_name,
                    net_to_host_function=field_type.net_to_host_function,
                    c_name=field.name
                ))
            else:
                setters.append(_SIMPLE_TYPE_NO_SWAP_FIELD_SETTER_TEMPLATE.substitute(
                    java_name=field.java_name,
                    class_ref_name=msg_java_name,
                    jni_signature=field_type.jni_signature,
                    jni_accessor=field_type.jni_accessor,
                    object_ref_name=object_ref_name,
                    struct_ref_name=struct_ref_name,
                    c_name=field.name
                ))
    return "".join(setters)


def _generate_array_length(field, struct_ref_name):
    if field.array_len_field:
        len_field = field.array_len_field
        if len_field.type.is_swap_needed:
            return "%s(%s->%s)" % (len_field.type.host_to_net_function, struct_ref_name, len_field.name)
        else:
            return "%s->%s" % (struct_ref_name, len_field.name)
    return field.array_len
