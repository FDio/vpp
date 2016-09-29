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

import util
from string import Template

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
    }
""")

dto_field_setter_templates = {'u8': default_dto_field_setter_template,
                              'u16': u16_dto_field_setter_template,
                              'u32': u32_dto_field_setter_template,
                              'i32': u32_dto_field_setter_template,
                              'u64': u64_dto_field_setter_template,
                              'f64': default_dto_field_setter_template, #fixme
                              'u8[]': u8_array_dto_field_setter_template,
                              'u16[]': u16_array_dto_field_setter_template,
                              'u32[]': u32_array_dto_field_setter_template,
                              'u64[]': u64_array_dto_field_setter_template
                              }

def jni_reply_handler(handler_name, ref_name, c_type, jni_type, c_name, java_field_reference_name, java_field_name,
                      field_length, is_variable_len_array, length_field_type, object_name = "dto"):
    """
    Generates code
    :param c_type:
    :param jni_type:
    :param c_name:
    :param field_length:
    :param is_variable_len_array:
    :param length_field_type:
    :return:
    """
    if jni_type.endswith('Array') and field_length == '0':
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

    jni_signature = util.jni_2_signature_mapping[jni_type]
    jni_setter = util.jni_field_accessors[jni_type]

    result = dto_field_id_template.substitute(
            field_reference_name=java_field_reference_name,
            field_name=java_field_name,
            class_ref_name=ref_name,
            jni_signature=jni_signature)

    dto_setter_template = dto_field_setter_templates[c_type]

    result += dto_setter_template.substitute(
            jni_signature=jni_signature,
            object_name=object_name,
            field_reference_name=java_field_reference_name,
            c_name=c_name,
            jni_setter=jni_setter,
            field_length=field_length)
    return result
