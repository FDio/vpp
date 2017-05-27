#!/usr/bin/env python3
#
# Copyright (c) 2017 Pantheon Technologies, s.r.o.
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

from model import PluginModel
from jni_template import generate_jni
from time import perf_counter

import logging

FORMAT = '%(asctime)-15s %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

plugin = "acl"
infile = "/home/nite/fd.io/vpp/build-root/build-vpp_debug-native/vpp/plugins/acl/acl.api.json"

started = perf_counter()
logger.info("Processing plugin %s...", plugin)
logger.debug("Inputs %s ", infile)

phase = perf_counter()
model = PluginModel.forJsonFile(plugin, infile)

logger.debug("Model compiled in %s seconds", perf_counter() - phase)

phase = perf_counter()
jni_impl = generate_jni(model)
logger.debug("JNI implementation generated in %s seconds", perf_counter() - phase)

# FIXME: more files

logger.info("Plugin %s completed in %s seconds", plugin, perf_counter() - started)

logger.debug("Generated class init: %s", jni_impl)
