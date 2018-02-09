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


def generate_type_handlers(model, logger):
    """
    Generates msg handlers for all messages except for dumps and requests (handled by vpp, not client).
    :param model: meta-model of VPP API used for jVPP generation.
    """
    type_handlers = []
    # for type in model.types:
    #     # this could be defined in the type class
    #     if isinstance(type, SimpleType):
    #         _SIMPLE_TYPE_JAVA_TO_C_TEMPLATE.substitute(c_name=type.name)
    #     elif isinstance(type, Array):
    #         _ARRAY_JAVA_TO_C_TEMPLATE.substitute(c_name=type.name)
    #     else:
    #         logger.warning("Unsupported type %s: Skipping generating JNI handler.", type)

    return "\n".join(type_handlers)
