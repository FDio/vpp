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

import os
import util
import jni_gen


def generate_enums(enum_list, inputfile, logger):
    """
    Generates Java representation of enum types defined in the provided JSON file.
    """

    if not enum_list:
        logger.debug("Skipping enum generation (%s does not define enum types)." % inputfile)
        return

    logger.debug("Generating enums for %s" % inputfile)

    for enum in enum_list:
        enum_name = None
        enum_type = None
        for e in enum:
            if isinstance(e, basestring):
                enum_name = e
            elif type(e) is dict and 'enumtype' in e:
                enum_type = e['enumtype']

        if not enum_name:
            logger.warn("%s enum is missing name. Skipping" % enum)
            continue

        if not enum_type:
            logger.warn("%s enum is missing value type. Skipping" % enum)
            continue

        # TODO(VPP-1153): add real enum support.
        # But first refactor java api generation
        # (either VPP-1154 or VPP-1155, see also VPP-480).

        # As a workaround we just update all the mappings
        # used for VPP API definitions to JAVA and C/JNI translation.
        enum_array_type = enum_type + "[]"
        type_name = "vl_api_" + enum_name + "_t"
        array_type_name = type_name + "[]"
        util.vpp_2_jni_type_mapping[type_name] = util.vpp_2_jni_type_mapping[enum_type]
        util.vpp_2_jni_type_mapping[array_type_name] = util.vpp_2_jni_type_mapping[enum_array_type]
        util.jni_2_java_type_mapping[type_name] = util.jni_2_java_type_mapping[enum_type]
        util.jni_2_java_type_mapping[array_type_name] = util.jni_2_java_type_mapping[enum_array_type]
        util.jni_2_signature_mapping[type_name] = util.jni_2_signature_mapping[enum_type]
        util.jni_2_signature_mapping[array_type_name] = util.jni_2_signature_mapping[enum_array_type]
        util.jni_field_accessors[type_name] = util.jni_field_accessors[enum_type]
        util.jni_field_accessors[array_type_name] = util.jni_field_accessors[enum_array_type]
        jni_gen.struct_setter_templates[type_name] = jni_gen.struct_setter_templates[enum_type]
        jni_gen.struct_setter_templates[array_type_name] = jni_gen.struct_setter_templates[enum_array_type]
        jni_gen.dto_field_setter_templates[type_name] = jni_gen.dto_field_setter_templates[enum_type]
        jni_gen.dto_field_setter_templates[array_type_name] = jni_gen.dto_field_setter_templates[enum_array_type]
