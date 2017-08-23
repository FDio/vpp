#!/usr/bin/env python

import sys
import os
import unittest
import importlib
import argparse


def discover_tests(directory, callback):
    do_insert = True
    for _f in os.listdir(directory):
        f = "%s/%s" % (directory, _f)
        if os.path.isdir(f):
            discover_tests(f, callback)
            continue
        if not os.path.isfile(f):
            continue
        if do_insert:
            sys.path.insert(0, directory)
            do_insert = False
        if not _f.startswith("test_") or not _f.endswith(".py"):
            continue
        name = "".join(f.split("/")[-1].split(".")[:-1])
        if name in sys.modules:
            raise Exception("Duplicate test module `%s' found!" % name)
        module = importlib.import_module(name)
        for name, cls in module.__dict__.items():
            if not isinstance(cls, type):
                continue
            if not issubclass(cls, unittest.TestCase):
                continue
            if name == "VppTestCase":
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

    suite = unittest.TestSuite()
    for d in args.dir:
        discover_tests(d, print_callback)
