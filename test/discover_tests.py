#!/usr/bin/env python3

# Copyright (c) 2021 Cisco and/or its affiliates.
#
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

# This is a standalone library not depending on any GPL-licensed code.

import sys
import os
import unittest
import importlib
import argparse


def discover_tests(directory, callback, ignore_path):
    do_insert = True
    for _f in os.listdir(directory):
        f = "%s/%s" % (directory, _f)
        if os.path.isdir(f):
            if ignore_path is not None and f.startswith(ignore_path):
                continue
            discover_tests(f, callback, ignore_path)
            continue
        if not os.path.isfile(f):
            continue
        if do_insert:
            sys.path.insert(0, directory)
            do_insert = False
        if not _f.startswith("test_") or not _f.endswith(".py"):
            continue
        name = "".join(f.split("/")[-1].split(".")[:-1])
        module = importlib.import_module(name)
        for name, cls in module.__dict__.items():
            if not isinstance(cls, type):
                continue
            if not issubclass(cls, unittest.TestCase):
                continue
            if name == "VppTestCase" or name.startswith("Template"):
                continue
            for method in dir(cls):
                if not callable(getattr(cls, method)):
                    continue
                if method.startswith("test_"):
                    callback(_f, cls, method)


def print_callback(file_name, cls, method):
    print("%s.%s.%s" % (file_name, cls.__name__, method))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Discover VPP unit tests")
    parser.add_argument("-d", "--dir", action='append', type=str,
                        help="directory containing test files "
                             "(may be specified multiple times)")
    args = parser.parse_args()
    if args.dir is None:
        args.dir = "."

    ignore_path = os.getenv("VENV_PATH", "")
    suite = unittest.TestSuite()
    for d in args.dir:
        discover_tests(d, print_callback, ignore_path)
