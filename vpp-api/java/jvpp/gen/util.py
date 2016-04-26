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


reply_suffixes = ("reply", "details", "l2fibtableentry")


def is_reply(name):
    return name.lower().endswith(reply_suffixes)


def is_details(name):
    return name.lower().endswith(reply_suffixes[1]) or name.lower().endswith(reply_suffixes[2])

dump_suffix = "dump"


def is_dump(name):
    return name.lower().endswith(dump_suffix)


def get_reply_suffix(name):
    for reply_suffix in reply_suffixes:
        if name.lower().endswith(reply_suffix):
            if reply_suffix == reply_suffixes[2]:
                # FIXME workaround for l2_fib_table_entry
                return 'entry'
            else:
                return reply_suffix

# http://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/types.html
jni_2_java_type_mapping = {'jbyte': 'byte',
                           'jbyteArray': 'byte[]',
                           'jchar': 'char',
                           'jcharArray': 'char[]',
                           'jshort': 'short',
                           'jshortArray': 'short[]',
                           'jint': 'int',
                           'jintArray': 'int[]',
                           'jlong': 'long',
                           'jlongArray': 'long[]',
                           'jdouble': 'double',
                           'jdoubleArray': 'double[]',
                           'jfloat': 'float',
                           'jfloatArray': 'float[]',
                           'void': 'void',
                           'jstring': 'java.lang.String',
                           'jobject': 'java.lang.Object',
                           'jobjectArray': 'java.lang.Object[]'
                           }

# https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/types.html#type_signatures
jni_2_signature_mapping = {'jbyte': 'B',
                           'jbyteArray': '[B',
                           'jchar': 'C',
                           'jcharArray': '[C',
                           'jshort': 'S',
                           'jshortArray': '[S',
                           'jint': 'I',
                           'jintArray': '[I',
                           'jlong': 'J',
                           'jlongArray': '[J',
                           'jdouble': 'D',
                           'jdoubleArray': '[D',
                           'jfloat': 'F',
                           'jfloatArray': '[F'
                           }

# https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html#Get_type_Field_routines
jni_field_accessors = {
    'jbyte': 'ByteField',
    'jbyteArray': 'ObjectField',
    'jchar': 'CharField',
    'jcharArray': 'ObjectField',
    'jshort': 'ShortField',
    'jshortArray': 'ObjectField',
    'jint': 'IntField',
    'jintArray': 'ObjectField',
    'jlong': 'LongField',
    'jlongArray': 'ObjectField',
    'jdouble': 'DoubleField',
    'jdoubleArray': 'ObjectField',
    'jfloat': 'FloatField',
    'jfloatArray': 'ObjectField'
}

# TODO watch out for unsigned types
# http://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/types.html
vpp_2_jni_type_mapping = {'u8': 'jbyte',  # fixme
                          'i8': 'jbyte',
                          'u16': 'jchar',
                          'i16': 'jshort',
                          'u32': 'jint',  # fixme
                          'i32': 'jint',
                          'u64': 'jlong',  # fixme
                          'i64': 'jlong',
                          'f64': 'jdouble'
                          }

# vpe.api calls that do not follow naming conventions and have to be handled exceptionally when finding reply -> request mapping
# FIXME in vpe.api
unconventional_naming_rep_req = {
                                 'cli_reply': 'cli_request',
                                 'vnet_summary_stats_reply': 'vnet_get_summary_stats',
                                 # This below is actually a sub-details callback. We cannot derive the mapping of dump request
                                 # belonging to this sub-details from naming conventions. We need special mapping
                                 'bridge_domain_sw_if_details': 'bridge_domain',
                                 # This is standard dump call + details reply. However it's not called details but entry
                                 'l2_fib_table_entry': 'l2_fib_table'
                                 }

#
# FIXME no convention in the naming of events (notifications) in vpe.api
notifications_message_suffixes = ("event", "counters")
notification_messages = ["from_netconf_client", "from_netconf_server", "to_netconf_client", "to_netconf_server"]

# messages that must be ignored. These messages are INSUFFICIENTLY marked as disabled in vpe.api
# FIXME
ignored_messages = ["is_address_reachable"]


def is_notification(param):
    return param.lower().endswith(notifications_message_suffixes) or param.lower() in notification_messages


def is_ignored(param):
    return param.lower() in ignored_messages


def remove_reply_suffix(camel_case_name_with_suffix):
    return remove_suffix(camel_case_name_with_suffix, get_reply_suffix(camel_case_name_with_suffix))


def remove_suffix(camel_case_name_with_suffix, suffix):
    suffix_length = len(suffix)
    return camel_case_name_with_suffix[:-suffix_length] if suffix_length != 0 else camel_case_name_with_suffix


def is_control_ping(camel_case_name_with_suffix):
    return "controlping" in camel_case_name_with_suffix.lower()

def api_message_to_javadoc(api_message):
    """ Converts vpe.api message description to javadoc """
    str = pprint.pformat(api_message, indent=4, width=120, depth=None)
    return " * " + str.replace("\n", "\n * ")