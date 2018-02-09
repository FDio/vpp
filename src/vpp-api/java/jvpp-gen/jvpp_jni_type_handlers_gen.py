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


#fixme generate functions for computing structure sizes
# or more generic, functions for initializing messages/types

# {
# jclass brTblIdClass = (*env)->FindClass(env, "io/fd/vpp/jvpp/core/types/BierTableId");
# memset (&(mp->br_tbl_id), 0, sizeof (mp->br_tbl_id));
#
# jfieldID br_tbl_idBtSetFieldId = (*env)->GetFieldID(env, brTblIdClass, "btSet", "B");
# jbyte br_tbl_idBtSet = (*env)->GetByteField(env, brTblId, br_tbl_idBtSetFieldId);
#
# mp->br_tbl_id.bt_set = br_tbl_idBtSet;
# jfieldID br_tbl_idBtSubDomainFieldId = (*env)->GetFieldID(env, brTblIdClass, "btSubDomain", "B");
# jbyte br_tbl_idBtSubDomain = (*env)->GetByteField(env, brTblId, br_tbl_idBtSubDomainFieldId);
#
# mp->br_tbl_id.bt_sub_domain = br_tbl_idBtSubDomain;
# jfieldID br_tbl_idBtHdrLenIdFieldId = (*env)->GetFieldID(env, brTblIdClass, "btHdrLenId", "B");
# jbyte br_tbl_idBtHdrLenId = (*env)->GetByteField(env, brTblId, br_tbl_idBtHdrLenIdFieldId);
#
# mp->br_tbl_id.bt_hdr_len_id = br_tbl_idBtHdrLenId;
# }

#fixme extract common code from message handling and type handling for JNI bindings, but as a second step
from jvpp_json_parser import Class

_TYPE_HANDLER_TEMPLATE = Template("""
/**
 * Handler for ${c_name} type.
 * Generated based on $json_filename:
$json_definition
 */
static inline void _net_to_host_${c_name}(vl_api${c_name}_t *a)
{
    jclass ${type_reference_name}Class = (*env)->FindClass(env, "${class_FQN}");
    memset (&(mp->${c_name}), 0, sizeof (mp->${c_name})); // will not work if type definition uses VLA syntax
    // (either directly or by nesting)
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
                type_initialization="// FIXME"
            ))

    return "\n".join(type_handlers)
