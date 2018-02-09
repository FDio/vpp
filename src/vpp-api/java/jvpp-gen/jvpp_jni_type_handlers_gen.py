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

# fixme extract common code from message handling and type handling for JNI bindings, but as a second step
# e.g create message swap functions
from jvpp_jni_common_gen import generate_j2c_swap, generate_j2c_identifiers
from jvpp_json_parser import Class

# fixme generate functions for computing structure sizes
# or more generic, functions for initializing messages/types




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

_TYPE_NET_TO_HOST_TEMPLATE = Template("""
/**
 * Handler for ${c_name} type.
 * Generated based on $json_filename:
$json_definition
 */
static inline void _host_to_net_${c_name}(jobject _host, vl_api_${c_name}_t * _net)
{
    jclass ${type_reference_name}Class = (*env)->FindClass(env, "${class_FQN}");
$jni_identifiers
$type_initialization
}""")


def generate_type_handlers(model):
    """
    Generates msg handlers for all messages except for dumps and requests (handled by vpp, not client).
    :param model: meta-model of VPP API used for jVPP generation.
    """
    type_handlers = []
    for t in model.types:
        if isinstance(t, Class):
            ref_name = t.java_name_lower
            jni_identifiers = generate_j2c_identifiers(t, class_ref_name="%sClass" % ref_name, object_ref_name="_host")
            type_handlers.append(_TYPE_NET_TO_HOST_TEMPLATE.substitute(
                c_name=t.name,
                json_filename=model.json_api_files,
                json_definition=t.doc,
                type_reference_name=ref_name,
                class_FQN=t.jni_name,
                jni_identifiers=jni_identifiers,
                type_initialization=generate_j2c_swap(t, struct_ref_name="_net")
            ))

    return "\n".join(type_handlers)






#fixme remove
____object_dto_field_setter_template = Template("""
    {
        jclass ${field_reference_name}Class = (*env)->FindClass(env, "${class_FQN}");
        jmethodID ${field_reference_name}Constructor = (*env)->GetMethodID(env, ${field_reference_name}Class, "<init>", "()V");
        jobject ${field_reference_name} = (*env)->NewObject(env, ${field_reference_name}Class,  ${field_reference_name}Constructor);
        ${type_initialization}
        (*env)->SetObjectField(env, dto, ${field_reference_name}FieldId, ${field_reference_name});
        (*env)->DeleteLocalRef(env, ${field_reference_name});
    }
""")

# jfieldID lclLocFieldId = (*env)->GetFieldID(env, gpeFwdEntryPathDetailsClass, "lclLoc", "Lio/fd/vpp/jvpp/core/types/GpeLocator;");
# {
#   jclass lclLocClass = (*env)->FindClass(env, "io/fd/vpp/jvpp/core/types/GpeLocator");
#   jmethodID lclLocConstructor = (*env)->GetMethodID(env, lclLocClass, "<init>", "()V");
#   jobject lclLoc = (*env)->NewObject(env, lclLocClass,  lclLocConstructor);
#
#   jfieldID lcl_locIsIp4FieldId = (*env)->GetFieldID(env, lclLocClass, "isIp4", "B");
#   (*env)->SetByteField(env, lclLoc, lcl_locIsIp4FieldId, mp->lcl_loc.is_ip4);
#
#   jfieldID lcl_locWeightFieldId = (*env)->GetFieldID(env, lclLocClass, "weight", "B");
#   (*env)->SetByteField(env, lclLoc, lcl_locWeightFieldId, mp->lcl_loc.weight);
#
#   jfieldID lcl_locAddrFieldId = (*env)->GetFieldID(env, lclLocClass, "addr", "[B");
#   jbyteArray lcl_locAddr = (*env)->NewByteArray(env, 16);
#   (*env)->SetByteArrayRegion(env, lcl_locAddr, 0, 16, (const jbyte*)mp->lcl_loc.addr);
#   (*env)->SetObjectField(env, lclLoc, lcl_locAddrFieldId, lcl_locAddr);
#   (*env)->DeleteLocalRef(env, lcl_locAddr);
#
#   (*env)->SetObjectField(env, dto, lclLocFieldId, lclLoc);
#   (*env)->DeleteLocalRef(env, lclLoc);
# }

# _TYPE_HOST_TO_NET_TEMPLATE = Template("""
# /**
#  * Handler for ${c_name} type.
#  * Generated based on $json_filename:
# $json_definition
#  */
# static inline vl_api_${c_name}_t * _net_to_host_${c_name}(jobject _arg)
# {
#     jclass ${type_reference_name}Class = (*env)->FindClass(env, "${class_FQN}");
#     memset (&(mp->${c_name}), 0, sizeof (mp->${c_name})); // will not work if type definition uses VLA syntax
#     // (either directly or by nesting)
# $jni_identifiers
# $type_initialization
# }""")
