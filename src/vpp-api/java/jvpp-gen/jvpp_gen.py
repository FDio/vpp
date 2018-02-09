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

from jvpp_callback_gen import generate_callbacks
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

    def generate(self):
        # self.generate_enums()
        # self.generate_types()
        self.dto_generator.generate()
        self.java_ifc_generator.generate()
        self.java_impl_generator.generate()
        generate_callbacks(self.model, self.logger)
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
1) (10) generate code just for requests (done)
- structure (done)
- fields (done)
- hash_code (done)
- equals (done)
- to_string (done)
- send (done)

2) (20) add generation for replies (done)

3) (30) java api
- jvpp interface (done),
- jvpp interface impl (done)
- callbacks (done)

4) (50) C impl (done)
- class cache (done)
- api_verificatisadfsdfon (done)
- jni_implementations (done)
- msg_handlers
- handler_registration (done)

5) (55) dumps and details
- implement (done)
- test (in progress)
* test it works end to end (try to use it for java api generation for some plugin
and run tests
* check if generator can skip items it does not understand
* improve validation code

In order  to add message type one needs:

- add case in _parse_message
- add case in DtoGen._generate
- update java ifc and impl and decide if to include them in generation process
  (_jvpp_ifc_filter, _jvpp_impl_filter)
- check if callback generation needs to be altered
- check jni generation (jni implementaitons, message handlers, registration)
- 

todo:
improvement would be to include all that in the interface
that is require message class to expose some property/function that handles
requirement specific to component that is being generated.

(it is in confilct with requirement to have single message class)



6) (60) Arrays

* Revisit structure of generator

7) (70) Struct types

8) (80) Future facade

9) (90) Events

10) (95) Callback facade

11) (100) Integrate wit build system

12) Improve generated formatting (optional)

13) Tests (optional)

** update model and unit tests for model creation 
** write tests for code generation


"""