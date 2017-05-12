#!/usr/bin/env python
#
# Copyright (c) 2016 Cisco and/or its affiliates.
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

from string import Template

import util

variable_length_array_value_template = Template("""mp->${length_var_name}""")
variable_length_array_template = Template("""clib_net_to_host_${length_field_type}(${value})""")

dto_field_id_template = Template("""
    jfieldID ${field_reference_name}FieldId = (*env)->GetFieldID(env, ${class_ref_name}Class, "${field_name}", "${jni_signature}");""")

default_dto_field_setter_template = Template("""
    (*env)->Set${jni_setter}(env, ${object_name}, ${field_reference_name}FieldId, mp->${c_name});
""")

variable_length_array_value_template = Template("""mp->${length_var_name}""")
variable_length_array_template = Template("""clib_net_to_host_${length_field_type}(${value})""")

u16_dto_field_setter_template = Template("""
    (*env)->Set${jni_setter}(env, ${object_name}, ${field_reference_name}FieldId, clib_net_to_host_u16(mp->${c_name}));
""")

u32_dto_field_setter_template = Template("""
    (*env)->Set${jni_setter}(env, ${object_name}, ${field_reference_name}FieldId, clib_net_to_host_u32(mp->${c_name}));
""")

u64_dto_field_setter_template = Template("""
    (*env)->Set${jni_setter}(env, ${object_name}, ${field_reference_name}FieldId, clib_net_to_host_u64(mp->${c_name}));
""")

u8_array_dto_field_setter_template = Template("""
    jbyteArray ${field_reference_name} = (*env)->NewByteArray(env, ${field_length});
    (*env)->SetByteArrayRegion(env, ${field_reference_name}, 0, ${field_length}, (const jbyte*)mp->${c_name});
    (*env)->SetObjectField(env, ${object_name}, ${field_reference_name}FieldId, ${field_reference_name});
    (*env)->DeleteLocalRef(env, ${field_reference_name});
""")

u16_array_dto_field_setter_template = Template("""
    {
        jshortArray ${field_reference_name} = (*env)->NewShortArray(env, ${field_length});
        jshort * ${field_reference_name}ArrayElements = (*env)->GetShortArrayElements(env, ${field_reference_name}, NULL);
        unsigned int _i;
        for (_i = 0; _i < ${field_length}; _i++) {
            ${field_reference_name}ArrayElements[_i] = clib_net_to_host_u16(mp->${c_name}[_i]);
        }

        (*env)->ReleaseShortArrayElements(env,  ${field_reference_name}, ${field_reference_name}ArrayElements, 0);
        (*env)->SetObjectField(env, ${object_name}, ${field_reference_name}FieldId, ${field_reference_name});
        (*env)->DeleteLocalRef(env, ${field_reference_name});
    }
""")

u32_array_dto_field_setter_template = Template("""
    {
        jintArray ${field_reference_name} = (*env)->NewIntArray(env, ${field_length});
        jint * ${field_reference_name}ArrayElements = (*env)->GetIntArrayElements(env, ${field_reference_name}, NULL);
        unsigned int _i;
        for (_i = 0; _i < ${field_length}; _i++) {
            ${field_reference_name}ArrayElements[_i] = clib_net_to_host_u32(mp->${c_name}[_i]);
        }

        (*env)->ReleaseIntArrayElements(env,  ${field_reference_name}, ${field_reference_name}ArrayElements, 0);
        (*env)->SetObjectField(env, ${object_name}, ${field_reference_name}FieldId, ${field_reference_name});
        (*env)->DeleteLocalRef(env, ${field_reference_name});
    }
""")

# For each u64 array we get its elements. Then we convert values to host byte order.
# All changes to  jlong* buffer are written to jlongArray (isCopy is set to NULL)
u64_array_dto_field_setter_template = Template("""
    {
        jlongArray ${field_reference_name} = (*env)->NewLongArray(env, ${field_length});
        jlong * ${field_reference_name}ArrayElements = (*env)->GetLongArrayElements(env, ${field_reference_name}, NULL);
        unsigned int _i;
        for (_i = 0; _i < ${field_length}; _i++) {
            ${field_reference_name}ArrayElements[_i] = clib_net_to_host_u64(mp->${c_name}[_i]);
        }

        (*env)->ReleaseLongArrayElements(env,  ${field_reference_name}, ${field_reference_name}ArrayElements, 0);
        (*env)->SetObjectField(env, ${object_name}, ${field_reference_name}FieldId, ${field_reference_name});
        (*env)->DeleteLocalRef(env, ${field_reference_name});
    }
""")

dto_field_setter_templates = {'u8': default_dto_field_setter_template,
                              'u16': u16_dto_field_setter_template,
                              'u32': u32_dto_field_setter_template,
                              'i32': u32_dto_field_setter_template,
                              'u64': u64_dto_field_setter_template,
                              'f64': default_dto_field_setter_template,  # fixme
                              'u8[]': u8_array_dto_field_setter_template,
                              'u16[]': u16_array_dto_field_setter_template,
                              'u32[]': u32_array_dto_field_setter_template,
                              'u64[]': u64_array_dto_field_setter_template
                              }


def jni_reply_handler_for_type(handler_name, ref_name, field_type, c_name, field_reference_name,
                               field_name, field_length, is_variable_len_array, length_field_type,
                               object_name="dto"):
    """
    Generates jni code that initializes a field of java object (dto or custom type).
    To be used in reply message handlers.
    :param field_type: type of the field to be initialized (as defined in vpe.api)
    :param c_name: name of the message struct member that stores initialization value
    :param field_reference_name: name of the field reference in generated code
    :param field_name: name of the field (camelcase)
    :param field_length: integer or name of variable that stores field length
    :param object_name: name of the object to be initialized
    """

    # todo move validation to vppapigen
    if field_type.endswith('[]') and field_length == '0':
        raise Exception('Variable array \'%s\' defined in \'%s\' '
                        'should have defined length (e.g. \'%s[%s_length]\''
                        % (c_name, handler_name, c_name, c_name))

    if is_variable_len_array:
        length_var_name = field_length
        field_length = variable_length_array_value_template.substitute(length_var_name=length_var_name)
        if length_field_type != 'u8':  # we need net to host conversion:
            field_length = variable_length_array_template.substitute(
                    length_field_type=length_field_type, value=field_length)

    # for retval don't generate setters
    if util.is_retval_field(c_name):
        return ""

    jni_signature = util.jni_2_signature_mapping[field_type]
    jni_setter = util.jni_field_accessors[field_type]

    result = dto_field_id_template.substitute(
            field_reference_name=field_reference_name,
            field_name=field_name,
            class_ref_name=ref_name,
            jni_signature=jni_signature)

    dto_setter_template = dto_field_setter_templates[field_type]

    result += dto_setter_template.substitute(
            jni_signature=jni_signature,
            object_name=object_name,
            field_reference_name=field_reference_name,
            c_name=c_name,
            jni_setter=jni_setter,
            field_length=field_length)
    return result


request_field_identifier_template = Template("""
    jfieldID ${field_reference_name}FieldId = (*env)->GetFieldID(env, ${object_name}Class, "${field_name}", "${jni_signature}");
    ${jni_type} ${field_reference_name} = (*env)->Get${jni_getter}(env, ${object_name}, ${field_reference_name}FieldId);
    """)

array_length_enforcement_template = Template("""
        size_t max_size = ${field_length};
        if (cnt > max_size) cnt = max_size;""")

u8_struct_setter_template = Template("""
    mp->${c_name} = ${field_reference_name};""")

u16_struct_setter_template = Template("""
    mp->${c_name} = clib_host_to_net_u16(${field_reference_name});""")

u32_struct_setter_template = Template("""
    mp->${c_name} = clib_host_to_net_u32(${field_reference_name});""")

i32_struct_setter_template = Template("""
    mp->${c_name} = clib_host_to_net_i32(${field_reference_name});!""")

u64_struct_setter_template = Template("""
    mp->${c_name} = clib_host_to_net_u64(${field_reference_name});""")

array_length_enforcement_template = Template("""
        size_t max_size = ${field_length};
        if (cnt > max_size) cnt = max_size;""")

u8_array_struct_setter_template = Template("""
    if (${field_reference_name}) {
        jsize cnt = (*env)->GetArrayLength (env, ${field_reference_name});
        ${field_length_check}
        (*env)->GetByteArrayRegion(env, ${field_reference_name}, 0, cnt, (jbyte *)mp->${c_name});
    }
""")

u16_array_struct_setter_template = Template("""
    if (${field_reference_name}) {
        jshort * ${field_reference_name}ArrayElements = (*env)->GetShortArrayElements(env, ${field_reference_name}, NULL);
        size_t _i;
        jsize cnt = (*env)->GetArrayLength (env, ${field_reference_name});
        ${field_length_check}
        for (_i = 0; _i < cnt; _i++) {
            mp->${c_name}[_i] = clib_host_to_net_u16(${field_reference_name}ArrayElements[_i]);
        }
        (*env)->ReleaseShortArrayElements (env, ${field_reference_name}, ${field_reference_name}ArrayElements, 0);
    }
    """)

u32_array_struct_setter_template = Template("""
    if (${field_reference_name}) {
        jint * ${field_reference_name}ArrayElements = (*env)->GetIntArrayElements(env, ${field_reference_name}, NULL);
        size_t _i;
        jsize cnt = (*env)->GetArrayLength (env, ${field_reference_name});
        ${field_length_check}
        for (_i = 0; _i < cnt; _i++) {
            mp->${c_name}[_i] = clib_host_to_net_u32(${field_reference_name}ArrayElements[_i]);
        }
        (*env)->ReleaseIntArrayElements (env, ${field_reference_name}, ${field_reference_name}ArrayElements, 0);
    }
    """)

u64_array_struct_setter_template = Template("""
    if (${field_reference_name}) {
        jlong * ${field_reference_name}ArrayElements = (*env)->GetLongArrayElements(env, ${field_reference_name}, NULL);
        size_t _i;
        jsize cnt = (*env)->GetArrayLength (env, ${field_reference_name});
        ${field_length_check}
        for (_i = 0; _i < cnt; _i++) {
            mp->${c_name}[_i] = clib_host_to_net_u64(${field_reference_name}ArrayElements[_i]);
        }
        (*env)->ReleaseLongArrayElements (env, ${field_reference_name}, ${field_reference_name}ArrayElements, 0);
    }
    """)

struct_setter_templates = {'u8': u8_struct_setter_template,
                           'u16': u16_struct_setter_template,
                           'u32': u32_struct_setter_template,
                           'i32': u32_struct_setter_template,
                           'u64': u64_struct_setter_template,
                           'u8[]': u8_array_struct_setter_template,
                           'u16[]': u16_array_struct_setter_template,
                           'u32[]': u32_array_struct_setter_template,
                           'u64[]': u64_array_struct_setter_template
                           }


def jni_request_identifiers_for_type(field_type, field_reference_name, field_name, object_name="request"):
    """
    Generates jni code that defines C variable corresponding to field of java object
    (dto or custom type). To be used in request message handlers.
    :param field_type: type of the field to be initialized (as defined in vpe.api)
    :param field_reference_name: name of the field reference in generated code
    :param field_name: name of the field (camelcase)
    :param object_name: name of the object to be initialized
    """
    # field identifiers
    jni_type = util.vpp_2_jni_type_mapping[field_type]
    jni_signature = util.jni_2_signature_mapping[field_type]
    jni_getter = util.jni_field_accessors[field_type]

    # field identifier
    return request_field_identifier_template.substitute(
            jni_type=jni_type,
            field_reference_name=field_reference_name,
            field_name=field_name,
            jni_signature=jni_signature,
            jni_getter=jni_getter,
            object_name=object_name)


def jni_request_binding_for_type(field_type, c_name, field_reference_name, field_length, is_variable_len_array):
    """
    Generates jni code that initializes C structure that corresponds to a field of java object
    (dto or custom type). To be used in request message handlers.
    :param field_type: type of the field to be initialized (as defined in vpe.api)
    :param c_name: name of the message struct member to be initialized
    :param field_reference_name: name of the field reference in generated code
    :param field_length: integer or name of variable that stores field length
    """

    # field setter
    field_length_check = ""

    # check if we are processing variable length array:
    if is_variable_len_array:
        field_length = util.underscore_to_camelcase(field_length)

    # enforce max length if array has fixed length or uses variable length syntax
    if str(field_length) != "0":
        field_length_check = array_length_enforcement_template.substitute(field_length=field_length)

    struct_setter_template = struct_setter_templates[field_type]

    msg_initialization = struct_setter_template.substitute(
            c_name=c_name,
            field_reference_name=field_reference_name,
            field_length_check=field_length_check)

    return msg_initialization
