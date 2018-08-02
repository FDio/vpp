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

from jvpp_model import is_array, is_retval, Class, Enum, Union


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

_REQUEST_FIELD_IDENTIFIER_TEMPLATE = Template("""
    jfieldID ${java_name}FieldId = (*env)->GetFieldID(env, ${class_ref_name}, "${java_name}", "${jni_signature}");
    ${jni_type} ${java_name} = (*env)->Get${jni_accessor}Field(env, ${object_ref_name}, ${java_name}FieldId);
""")


# TODO(VPP-1187): do not inline JNI object creation inside message handlers to reduce number of special cases
def generate_j2c_swap(element, struct_ref_name):
    initialization = []
    for field in element.fields:
        initialization.append(generate_j2c_field_swap(field, struct_ref_name))
    return "\n".join(initialization)


def generate_j2c_field_swap(field, struct_ref_name):
    if is_array(field):
        return _generate_j2c_array_swap(field, struct_ref_name)
    else:
        return _generate_j2c_scalar_swap(field, struct_ref_name)


def _generate_j2c_array_swap(field, struct_ref_name):
    # TODO(VPP-1186): move the logic to JNI generators
    base_type = field.type.base_type
    if isinstance(base_type, (Class, Enum, Union)):
        return _generate_j2c_object_array_swap(field, struct_ref_name)
    elif base_type.is_swap_needed:
        return _generate_j2c_primitive_type_array_swap(field, struct_ref_name)
    else:
        return _generate_j2c_primitive_type_array_no_swap(field, struct_ref_name)


def _generate_j2c_object_array_swap(field, struct_ref_name):
    field_type = field.type
    field_reference_name = field.java_name
    c_name = field.name
    host = "%sArrayElement" % field_reference_name
    net = "%s->%s[_i]" % (struct_ref_name, c_name)
    swap_elements = field_type.get_host_to_net_function(host, net)
    return _J2C_OBJECT_ARRAY_SWAP_TEMPLATE.substitute(
        field_reference_name=field_reference_name,
        field_length_check=_generate_field_length_check(field),
        swap_elements=swap_elements)

_J2C_OBJECT_ARRAY_SWAP_TEMPLATE = Template("""
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


def _generate_j2c_primitive_type_array_swap(field, struct_ref_name):
    field_reference_name = field.java_name
    field_type = field.type
    host = "%sArrayElements[_i]" % field_reference_name
    net = "%s->%s[_i]" % (struct_ref_name,  field.name)
    swap_elements = field_type.get_host_to_net_function(host, net)
    return _J2C_PRIMITIVE_TYPE_ARRAY_SWAP_TEMPLATE.substitute(
        field_reference_name=field_reference_name,
        field_length_check=_generate_field_length_check(field),
        base_type=field_type.base_type.jni_accessor,
        jni_base_type=field_type.base_type.jni_type,
        swap_elements=swap_elements
    )

_J2C_PRIMITIVE_TYPE_ARRAY_SWAP_TEMPLATE = Template("""
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


def _generate_j2c_primitive_type_array_no_swap(field, struct_ref_name):
    field_type = field.type
    return _J2C_PRIMITIVE_TYPE_ARRAY_NO_SWAP_TEMPLATE.substitute(
        field_reference_name=field.java_name,
        field_length_check=_generate_field_length_check(field),
        base_type=field_type.base_type.jni_accessor,
        jni_base_type=field_type.base_type.jni_type,
        struct_reference_name=struct_ref_name,
        c_name=field.name
    )

_J2C_PRIMITIVE_TYPE_ARRAY_NO_SWAP_TEMPLATE = Template("""
    if (${field_reference_name}) {
        jsize cnt = (*env)->GetArrayLength (env, ${field_reference_name});
        ${field_length_check}
        (*env)->Get${base_type}ArrayRegion(env, ${field_reference_name}, 0, cnt, (${jni_base_type} *)${struct_reference_name}->${c_name});
    }
""")


def _generate_field_length_check(field):
    # Enforce max length if array has fixed length or uses variable length syntax
    field_length = str(field.array_len)
    if field.array_len_field:
        field_length = field.array_len_field.java_name

    # TODO: remove when ZLAs without length field are disabled
    if field_length != "0":
        return _FIELD_LENGTH_CHECK.substitute(field_length=field_length)
    else:
        return ""

# Make sure we do not write more elements that are expected
_FIELD_LENGTH_CHECK = Template("""
        size_t max_size = ${field_length};
        if (cnt > max_size) cnt = max_size;""")


def _generate_j2c_scalar_swap(field, struct_ref_name):
    field_type = field.type
    if field_type.is_swap_needed:
        host = field.java_name
        net = "%s->%s" % (struct_ref_name, field.name)
        return "    %s;" % field_type.get_host_to_net_function(host, net)
    else:
        return "    %s->%s = %s;" % (struct_ref_name, field.name, field.java_name)


def generate_c2j_swap(element, object_ref_name, struct_ref_name):
    msg_java_name = element.java_name_lower
    initialization = []
    for field in element.fields:
        if is_retval(field):
            # For retval don't generate setters and generate retval check
            continue
        elif is_array(field):
            initialization.append(_generate_c2j_array_swap(msg_java_name, field, object_ref_name, struct_ref_name))
        else:
            initialization.append(_generate_c2j_scalar_swap(msg_java_name, field, object_ref_name, struct_ref_name))
    return "".join(initialization)


def _generate_c2j_array_swap(msg_java_name, field, object_ref_name, struct_ref_name):
    # TODO(VPP-1186): move the logic to JNI generators
    base_type = field.type.base_type
    if isinstance(base_type, (Class, Union)):
        return _generate_c2j_object_array_swap(msg_java_name, field, object_ref_name, struct_ref_name)
    elif isinstance(base_type, Enum):
        return _generate_c2j_enum_array_swap(msg_java_name, field, object_ref_name, struct_ref_name)
    elif base_type.is_swap_needed:
        return _generate_c2j_primitive_type_array_swap(msg_java_name, field, object_ref_name, struct_ref_name)
    else:
        return _generate_c2j_primitive_type_array_no_swap(msg_java_name, field, object_ref_name, struct_ref_name)


def _generate_c2j_object_array_swap(msg_java_name, field, object_ref_name, struct_ref_name):
    field_type = field.type
    return _C2J_OBJECT_ARRAY_SWAP_TEMPLATE.substitute(
        field_reference_name=field.java_name,
        class_ref_name=msg_java_name,
        jni_signature=field_type.jni_signature,
        jni_name=field_type.base_type.jni_name,
        field_length=_generate_array_length(field, struct_ref_name),
        net_to_host_function=field_type.net_to_host_function,
        struct_ref_name=struct_ref_name,
        object_ref_name=object_ref_name,
        c_name=field.name
    )

_C2J_OBJECT_ARRAY_SWAP_TEMPLATE = Template("""
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


def _generate_c2j_enum_array_swap(msg_java_name, field, object_ref_name, struct_ref_name):
    field_type = field.type
    base_type = field_type.base_type
    return _C2J_ENUM_ARRAY_SWAP_TEMPLATE.substitute(
        field_reference_name=field.java_name,
        class_ref_name=msg_java_name,
        jni_signature=field_type.jni_signature,
        jni_name=base_type.jni_name,
        field_length=_generate_array_length(field, struct_ref_name),
        net_to_host_function=field_type.net_to_host_function,
        jni_signature_enum_value=base_type.value.type.jni_signature,
        struct_ref_name=struct_ref_name,
        object_ref_name=object_ref_name,
        c_name=field.name
    )

_C2J_ENUM_ARRAY_SWAP_TEMPLATE = Template("""
    jfieldID ${field_reference_name}FieldId = (*env)->GetFieldID(env, ${class_ref_name}Class, "${field_reference_name}", "${jni_signature}");
    {
        jclass ${field_reference_name}Class = (*env)->FindClass(env, "${jni_name}");
        jobjectArray ${field_reference_name} = (*env)->NewObjectArray(env, ${field_length}, ${field_reference_name}Class, 0);
        jmethodID ${field_reference_name}Constructor = (*env)->GetStaticMethodID(env, ${field_reference_name}Class, "forValue", "(${jni_signature_enum_value})${jni_signature}");
        unsigned int _i;
        for (_i = 0; _i < ${field_length}; _i++) {
            jobject ${field_reference_name}ArrayElement = (*env)->CallStaticObjectMethod(env, ${field_reference_name}Class, ${field_reference_name}Constructor, ${net_to_host_function}(${struct_ref_name}->${c_name}[_i]));
            (*env)->SetObjectArrayElement(env, ${field_reference_name}, _i, ${field_reference_name}ArrayElement);
            (*env)->DeleteLocalRef(env, ${field_reference_name}ArrayElement);
        }
        (*env)->SetObjectField(env, ${object_ref_name}, ${field_reference_name}FieldId, ${field_reference_name});
        (*env)->DeleteLocalRef(env, ${field_reference_name});
    }
""")


def _generate_c2j_primitive_type_array_swap(msg_java_name, field, object_ref_name, struct_ref_name):
    field_type = field.type
    return _C2J_PRIMITIVE_TYPE_ARRAY_SWAP_TEMPLATE.substitute(
        field_reference_name=field.java_name,
        class_ref_name=msg_java_name,
        jni_signature=field_type.jni_signature,
        jni_type=field_type.jni_type,
        base_type=field_type.base_type.jni_accessor,
        field_length=_generate_array_length(field, struct_ref_name),
        jni_base_type=field_type.base_type.jni_type,
        object_ref_name=object_ref_name,
        struct_ref_name=struct_ref_name,
        net_to_host_function=field_type.net_to_host_function,
        c_name=field.name
    )

_C2J_PRIMITIVE_TYPE_ARRAY_SWAP_TEMPLATE = Template("""
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


def _generate_c2j_primitive_type_array_no_swap(msg_java_name, field, object_ref_name, struct_ref_name):
    field_type = field.type
    return _C2J_PRIMITIVE_TYPE_ARRAY_NO_SWAP_TEMPLATE.substitute(
        field_reference_name=field.java_name,
        class_ref_name=msg_java_name,
        jni_signature=field_type.jni_signature,
        jni_type=field_type.jni_type,
        base_type=field_type.base_type.jni_accessor,
        field_length=_generate_array_length(field, struct_ref_name),
        jni_base_type=field_type.base_type.jni_type,
        object_ref_name=object_ref_name,
        struct_ref_name=struct_ref_name,
        c_name=field.name
    )

_C2J_PRIMITIVE_TYPE_ARRAY_NO_SWAP_TEMPLATE = Template("""
    jfieldID ${field_reference_name}FieldId = (*env)->GetFieldID(env, ${class_ref_name}Class, "${field_reference_name}", "${jni_signature}");
    ${jni_type} ${field_reference_name} = (*env)->New${base_type}Array(env, ${field_length});
    (*env)->Set${base_type}ArrayRegion(env, ${field_reference_name}, 0, ${field_length}, (const ${jni_base_type}*)${struct_ref_name}->${c_name});
    (*env)->SetObjectField(env, ${object_ref_name}, ${field_reference_name}FieldId, ${field_reference_name});
    (*env)->DeleteLocalRef(env, ${field_reference_name});
""")


def _generate_array_length(field, struct_ref_name):
    if field.array_len_field:
        len_field = field.array_len_field
        if len_field.type.is_swap_needed:
            return "%s(%s->%s)" % (len_field.type.host_to_net_function, struct_ref_name, len_field.name)
        else:
            return "%s->%s" % (struct_ref_name, len_field.name)
    return field.array_len


def _generate_c2j_scalar_swap(msg_java_name, field, object_ref_name, struct_ref_name):
    field_type = field.type
    if field_type.is_swap_needed:
        # TODO(VPP-1186): move the logic to JNI generators
        if isinstance(field_type, (Class, Union)):
            return _generate_c2j_object_swap(msg_java_name, field, object_ref_name, struct_ref_name)
        elif isinstance(field_type, Enum):
            return _generate_c2j_enum_swap(msg_java_name, field, object_ref_name, struct_ref_name)
        else:
            return _generate_c2j_primitive_type_swap(msg_java_name, field, object_ref_name, struct_ref_name)
    else:
        return _generate_c2j_primitive_type_no_swap(msg_java_name, field, object_ref_name, struct_ref_name)


def _generate_c2j_object_swap(msg_java_name, field, object_ref_name, struct_ref_name):
    field_type = field.type
    return _C2J_OBJECT_SWAP_TEMPLATE.substitute(
        java_name=field.java_name,
        class_ref_name=msg_java_name,
        jni_signature=field_type.jni_signature,
        jni_name=field_type.jni_name,
        jni_accessor=field_type.jni_accessor,
        object_ref_name=object_ref_name,
        struct_ref_name=struct_ref_name,
        net_to_host_function=field_type.net_to_host_function,
        c_name=field.name)

_C2J_OBJECT_SWAP_TEMPLATE = Template("""
    jfieldID ${java_name}FieldId = (*env)->GetFieldID(env, ${class_ref_name}Class, "${java_name}", "${jni_signature}");
    jclass ${java_name}Class = (*env)->FindClass(env, "${jni_name}");
    jmethodID ${java_name}Constructor = (*env)->GetMethodID(env, ${java_name}Class, "<init>", "()V");
    jobject ${java_name} = (*env)->NewObject(env, ${java_name}Class,  ${java_name}Constructor);
    ${net_to_host_function}(env, &(${struct_ref_name}->${c_name}), ${java_name});
    (*env)->Set${jni_accessor}Field(env, ${object_ref_name}, ${java_name}FieldId, ${java_name});
    (*env)->DeleteLocalRef(env, ${java_name});
""")


def _generate_c2j_enum_swap(msg_java_name, field, object_ref_name, struct_ref_name):
    field_type = field.type
    return _C2J_ENUM_SWAP_TEMPLATE.substitute(
        java_name=field.java_name,
        class_ref_name=msg_java_name,
        jni_signature=field_type.jni_signature,
        jni_signature_enum_value=field_type.value.type.jni_signature,
        jni_name=field_type.jni_name,
        jni_accessor=field_type.jni_accessor,
        object_ref_name=object_ref_name,
        struct_ref_name=struct_ref_name,
        net_to_host_function=field_type.net_to_host_function,
        c_name=field.name)

_C2J_ENUM_SWAP_TEMPLATE = Template("""
    jfieldID ${java_name}FieldId = (*env)->GetFieldID(env, ${class_ref_name}Class, "${java_name}", "${jni_signature}");
    jclass ${java_name}Class = (*env)->FindClass(env, "${jni_name}");
    jmethodID ${java_name}Constructor = (*env)->GetStaticMethodID(env, ${java_name}Class, "forValue", "(${jni_signature_enum_value})${jni_signature}");
    jobject ${java_name} = (*env)->CallStaticObjectMethod(env, ${java_name}Class, ${java_name}Constructor, ${net_to_host_function}(${struct_ref_name}->${c_name}));
    (*env)->SetObjectField(env, ${object_ref_name}, ${java_name}FieldId, ${java_name});
    (*env)->DeleteLocalRef(env, ${java_name});
""")


def _generate_c2j_primitive_type_swap(msg_java_name, field, object_ref_name, struct_ref_name):
    field_type = field.type
    return _C2J_PRIMITIVE_TYPE_SWAP_TEMPLATE.substitute(
        java_name=field.java_name,
        class_ref_name=msg_java_name,
        jni_signature=field_type.jni_signature,
        jni_accessor=field_type.jni_accessor,
        object_ref_name=object_ref_name,
        net_to_host_function=field_type.net_to_host_function,
        struct_ref_name=struct_ref_name,
        c_name=field.name
    )

_C2J_PRIMITIVE_TYPE_SWAP_TEMPLATE = Template("""
    jfieldID ${java_name}FieldId = (*env)->GetFieldID(env, ${class_ref_name}Class, "${java_name}", "${jni_signature}");
    (*env)->Set${jni_accessor}Field(env, ${object_ref_name}, ${java_name}FieldId, ${net_to_host_function}(${struct_ref_name}->${c_name}));
""")


def _generate_c2j_primitive_type_no_swap(msg_java_name, field, object_ref_name, struct_ref_name):
    field_type = field.type
    return _C2J_PRIMITIVE_TYPE_NO_SWAP_TEMPLATE.substitute(
        java_name=field.java_name,
        class_ref_name=msg_java_name,
        jni_signature=field_type.jni_signature,
        jni_accessor=field_type.jni_accessor,
        object_ref_name=object_ref_name,
        struct_ref_name=struct_ref_name,
        c_name=field.name
    )

_C2J_PRIMITIVE_TYPE_NO_SWAP_TEMPLATE = Template("""
    jfieldID ${java_name}FieldId = (*env)->GetFieldID(env, ${class_ref_name}Class, "${java_name}", "${jni_signature}");
    (*env)->Set${jni_accessor}Field(env, ${object_ref_name}, ${java_name}FieldId, ${struct_ref_name}->${c_name});
""")
