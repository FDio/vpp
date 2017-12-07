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

import os, pprint
from os import removedirs


def underscore_to_camelcase(name):
    name = name.title().replace("_", "")
    return name[0].lower() + name[1:]


def underscore_to_camelcase_upper(name):
    name = name.title().replace("_", "")
    return name[0].upper() + name[1:]


def remove_folder(folder):
    """ Remove folder with all its files """
    for root, dirs, files in os.walk(folder, topdown=False):
        for name in files:
            os.remove(os.path.join(root, name))
        removedirs(folder)


_REPLY_SUFFIX = "reply"
_DETAILS_SUFFIX = "details"
_REPLY_SUFFIXES = (_REPLY_SUFFIX, _DETAILS_SUFFIX)


def is_reply(name):
    return name.lower().endswith(_REPLY_SUFFIXES)


def is_request(msg_name_underscore, all_messages):
    """
    Checks if reply message is present in all_messages.

    :param msg_name_underscore name of vpp API message
    :param all_messages: sequence of vpp message names
    :returns: True if reply for the msg_name_underscore message is defined.
    """
    reply_msg = msg_name_underscore + "_" + _REPLY_SUFFIX
    return reply_msg in [m['name'] for m in all_messages]


def is_details(name):
    return name.lower().endswith(_DETAILS_SUFFIX)


dump_suffix = "dump"


def is_dump(name):
    return name.lower().endswith(dump_suffix)


def is_retval_field(name):
    return name == 'retval'


def get_reply_suffix(name):
    for reply_suffix in _REPLY_SUFFIXES:
        if name.lower().endswith(reply_suffix):
            return reply_suffix

# Mapping according to:
# http://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/types.html
#
# Unsigned types are converted to signed java types that have the same size.
# It is the API user responsibility to interpret them correctly.
jni_2_java_type_mapping = {'u8': 'byte',
                           'u8[]': 'byte[]',
                           'i8': 'byte',
                           'i8[]': 'byte[]',
                           'u16': 'short',
                           'u16[]': 'short[]',
                           'i16': 'short',
                           'i16[]': 'short[]',
                           'u32': 'int',
                           'u32[]': 'int[]',
                           'i32': 'int',
                           'i32[]': 'int[]',
                           'u64': 'long',
                           'u64[]': 'long[]',
                           'i64': 'long',
                           'i64[]': 'long[]',
                           'f64': 'double',
                           'f64[]': 'double[]'
                           }

vpp_2_jni_type_mapping = {'u8': 'jbyte',
                          'u8[]': 'jbyteArray',
                          'i8': 'jbyte',
                          'i8[]': 'jbyteArray',
                          'u16': 'jshort',
                          'u16[]': 'jshortArray',
                          'i16': 'jshort',
                          'i16[]': 'jshortArray',
                          'u32': 'jint',
                          'u32[]': 'jintArray',
                          'i32': 'jint',
                          'i32[]': 'jintArray',
                          'u64': 'jlong',
                          'u64[]': 'jlongArray',
                          'i64': 'jlong',
                          'i64[]': 'jlongArray',
                          'f64': 'jdouble',
                          'f64[]': 'jdoubleArray'
                          }

# https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/types.html#type_signatures
jni_2_signature_mapping = {'u8': 'B',
                           'u8[]': '[B',
                           'i8': 'B',
                           'i8[]': '[B',
                           'u16': 'S',
                           'u16[]': '[S',
                           'i16': 'S',
                           'i16[]': '[S',
                           'u32': 'I',
                           'u32[]': '[I',
                           'i32': 'I',
                           'i32[]': '[I',
                           'u64': 'J',
                           'u64[]': '[J',
                           'i64': 'J',
                           'i64[]': '[J',
                           'f64': 'D',
                           'f64[]': '[D'
                           }

# https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html#Get_type_Field_routines
jni_field_accessors =  {'u8': 'ByteField',
                        'u8[]': 'ObjectField',
                        'i8': 'ByteField',
                        'i8[]': 'ObjectField',
                        'u16': 'ShortField',
                        'u16[]': 'ObjectField',
                        'i16': 'ShortField',
                        'i16[]': 'ObjectField',
                        'u32': 'IntField',
                        'u32[]': 'ObjectField',
                        'i32': 'IntField',
                        'i32[]': 'ObjectField',
                        'u64': 'LongField',
                        'u64[]': 'ObjectField',
                        'i64': 'LongField',
                        'i64[]': 'ObjectField',
                        'f64': 'DoubleField',
                        'f64[]': 'ObjectField'
                        }


def remove_reply_suffix(camel_case_name_with_suffix):
    return remove_suffix(camel_case_name_with_suffix, get_reply_suffix(camel_case_name_with_suffix))


def remove_suffix(camel_case_name_with_suffix, suffix):
    if not suffix:
        return camel_case_name_with_suffix
    suffix_length = len(suffix)
    return camel_case_name_with_suffix[:-suffix_length] if suffix_length != 0 else camel_case_name_with_suffix


def is_control_ping(camel_case_name_with_suffix):
    return camel_case_name_with_suffix.lower().startswith("controlping")


def api_message_to_javadoc(api_message):
    """ Converts vpe.api message description to javadoc """
    str = pprint.pformat(api_message, indent=4, width=120, depth=None)
    return " * " + str.replace("\n", "\n * ")


def is_array(java_type_as_string):
    return java_type_as_string.endswith("[]")
