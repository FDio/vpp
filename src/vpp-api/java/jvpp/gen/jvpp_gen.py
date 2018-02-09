#!/usr/bin/env python2
#
# Copyright (c) 2016,2018 Cisco and/or its affiliates.
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

from jvppgen.types_gen import generate_types
from jvppgen.dto_gen import generate_dtos
from jvppgen.jvpp_ifc_gen import generate_java_ifc
from jvppgen.jvpp_impl_gen import generate_java_impl
from jvppgen.callback_gen import generate_callbacks
from jvppgen.jni_gen import generate_jni
from jvppgen.notification_gen import generate_notifications
from jvppgen.jvpp_future_facade_gen import generate_future_facade
from jvppgen.jvpp_callback_facade_gen import generate_callback_facade
from jvppgen.jvpp_model import JVppModel


def generate_jvpp(root_dir, model, logger):
    base_dir = "%s/target/%s" % (root_dir, model.plugin_package.replace(".", "/"))
    generate_types(_work_dir(base_dir, "types"), model, logger)
    generate_dtos(_work_dir(base_dir, "dto"), model, logger)
    generate_java_ifc(_work_dir(base_dir), model, logger)
    generate_java_impl(_work_dir(base_dir), model, logger)
    generate_callbacks(_work_dir(base_dir, "callback"), model, logger)
    generate_jni(root_dir, model, logger)
    generate_notifications(_work_dir(base_dir, "notification"), model, logger)
    generate_future_facade(_work_dir(base_dir, "future"), model, logger)
    generate_callback_facade(_work_dir(base_dir, "callfacade"), model, logger)


def _work_dir(work_dir, sub_dir=None):
    if sub_dir:
        work_dir = "%s/%s" % (work_dir, sub_dir)
    try:
        os.makedirs(work_dir)
    except OSError:
        if not os.path.isdir(work_dir):
            raise
    return work_dir


def _init_logger():
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
    return logger


if __name__ == '__main__':
    logger = _init_logger()

    argparser = argparse.ArgumentParser(description="VPP Java API generator")
    argparser.add_argument('-i', nargs='+', metavar='api_file.json', help="json vpp api file(s)")
    argparser.add_argument('--plugin_name')
    argparser.add_argument('--root_dir')
    args = argparser.parse_args()

    logger.info("Generating Java API for %s" % args.i)
    logger.debug("plugin_name: %s" % args.plugin_name)
    logger.debug("root_dir: %s" % args.root_dir)

    model = JVppModel(logger, args.i, args.plugin_name)
    generate_jvpp(args.root_dir, model, logger)
