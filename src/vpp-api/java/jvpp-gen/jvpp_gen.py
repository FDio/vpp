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

import argparse
import logging
import os
import sys

from jvpp_callback_gen import CallbackGenerator
from jvpp_dto_gen import DtoGenerator
from jvpp_java_ifc_gen import JavaIfcGenerator
from jvpp_java_impl_gen import JavaImplGenerator
from jvpp_jni_gen import  generate_jni
from jvpp_json_parser import JsonParser


class JvppGenerator(object):
    def __init__(self, model, logger):
        self.model = model
        self.logger = logger
        self.dto_generator = DtoGenerator(model, logger)
        self.java_ifc_generator = JavaIfcGenerator(model, logger)
        self.java_impl_generator = JavaImplGenerator(model, logger)
        self.callback_generator = CallbackGenerator(model, logger)

    def generate(self):
        # self.generate_enums()
        # self.generate_types()
        self.dto_generator.generate()
        self.java_ifc_generator.generate()
        self.java_impl_generator.generate()
        self.callback_generator.generate()
        generate_jni(self.model, self.logger)
        # self.generate_notifications()
        # self.generate_future_api()
        # self.generate_callfacade_api()


if __name__ == '__main__':
    # Initialize logger
    try:
        verbose = int(os.getenv("V", 0))
    except:
        verbose = 0

    log_level = logging.WARNING
    if verbose == 1:
        log_level = logging.INFO
    elif verbose >= 2:
        log_level = logging.DEBUG

    logging.basicConfig(stream=sys.stdout, level=log_level)
    logger = logging.getLogger("JVPP GEN")
    logger.setLevel(log_level)

    argparser = argparse.ArgumentParser(description="VPP Java API generator")
    argparser.add_argument('-i', nargs='+', metavar='api_file.json', help="json vpp api file(s)")
    argparser.add_argument('--plugin_name')
    args = argparser.parse_args()

    jsonparser = JsonParser(logger, args.i, args.plugin_name)
    generator = JvppGenerator(jsonparser, logger)
    generator.generate()

    # car = Car()
    # car.accept(CarElementPrintVisitor())
    # car.accept(CarElementDoVisitor())
    # jvpp.generate(DtoGenerator())




"""
1) generate code just for requests (done)
- structure (done)
- fields (done)
- hash_code (done)
- equals (done)
- to_string (done)
- send (done)

2) add generation for replies (done)

3) java api
- jvpp interface (done),
- jvpp interface impl (done)
- callbacks (done)

4) C impl
- class cache (done)
- api_verification (done)
- jni_implementations (in progress)
- msg_handlers
- handler_registration (done)
- test it works end to end

5) dumps and details

6) Arrays

* Revisit structure of generator

7) Struct types

8) Future facade

9) Events

10) Callback facade

11) Integrate wit build system

12) Improve generated formatting (optional)

13) Tests (optional)

** update model and unit tests for model creation 
** write tests for code generation


"""