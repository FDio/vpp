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
from jvpp_dto_gen import generate_dto
from jvpp_java_ifc_gen import generate_java_ifc
from jvpp_java_impl_gen import generate_java_impl
from jvpp_jni_gen import generate_jni
from jvpp_json_parser import JsonParser
from jvpp_types_gen import generate_types


def _work_dir(work_dir, sub_dir=None):
    if sub_dir:
        work_dir = "%s/%s" % (work_dir, sub_dir)
    try:
        os.makedirs(work_dir)
    except OSError:
        if not os.path.isdir(work_dir):
            raise
    return work_dir


def _generate(root_dir, model, logger):
    base_dir = "%s/target/%s" % (root_dir, model.plugin_package.replace(".", "/"))
    # generate_enums()
    generate_types(_work_dir(base_dir, "types"), model, logger)
    generate_dto(_work_dir(base_dir, "dto"), model, logger)
    generate_java_ifc(_work_dir(base_dir), model, logger)
    generate_java_impl(_work_dir(base_dir), model, logger)
    generate_callbacks(_work_dir(base_dir, "callback"), model, logger)
    generate_jni(root_dir, model, logger)
    # generate_notifications()
    # generate_future_api()
    # generate_callfacade_api()


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
    argparser.add_argument('--root_dir')
    args = argparser.parse_args()

    logger.info("Generating Java API for %s" % args.i)
    logger.debug("plugin_name: %s" % args.plugin_name)
    logger.debug("root_dir: %s" % args.root_dir)

    model = JsonParser(logger, args.i, args.plugin_name)
    _generate(args.root_dir, model, logger)

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

5) (60) dumps and details (done)

6) (65) Integrate wit build system (done)
- add support for root dir parameter

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

todo:
improvement would be to include all that in the interface
that is require message class to expose some property/function that handles
requirement specific to component that is being generated.

(it is in conflict with requirement to have single message class)

testing:
sudo java -cp jvpp-registry-18.04.jar:jvpp-core-18.04.jar io.fd.vpp.jvpp.core.examples.CallbackApiExample

7) (75) Arrays (done)
to add array type one needs to do the same as for message type:
-parsing
-dto (fields, hashcode, equals, ...)
- ifc/impl, callbacks
- jni

it would be great to have interface for each item
which would make code fail until programmer updates all places

e.g. we could have a map of generators for each item
or more functional style: case for each type

this way we would group code by feature

alternatively we may split it even more
to have separate file for each type and item,

e.g. array_equals_generator, custom_type_hashcode_generator, simple_type_jni_setter_generator,
but this might be too detailed 

- u8 in requests (done)
- u8 in replies (done)
- swap in requests (done)
- swap in replies (done)
- fixed size (done)
- variable with length member (done)
- variable of length 0
- run jvpp examples (done)

fixme: there is bug in message allocation in the old generator

8) (85) Struct types (in progress)
- java classes (in progress)
- usage in messages (java part)
- usage in messages (c part)
-- message size computation
- nested structures

* Revisit structure of generator

9) (90) Future facade

10) (95) Events

11) (100) Callback facade

12) make it commitable (python packaging,...)

12) Improve generated formatting (optional)

13) Tests (optional)

** update model and unit tests for model creation 
** write tests for code generation


"""
