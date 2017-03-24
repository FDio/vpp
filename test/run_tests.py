#!/usr/bin/env python

import sys
import os
import unittest
import argparse
import importlib
from framework import VppTestRunner


def add_from_dir(suite, directory):
    do_insert = True
    for _f in os.listdir(directory):
        f = "%s/%s" % (directory, _f)
        if os.path.isdir(f):
            add_from_dir(suite, f)
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
                    suite.addTest(cls(method))

if __name__ == '__main__':
    try:
        verbose = int(os.getenv("V", 0))
    except:
        verbose = 0

    parser = argparse.ArgumentParser(description="VPP unit tests")
    parser.add_argument("-f", "--failfast", action='count',
                        help="fast failure flag")
    parser.add_argument("-d", "--dir", action='append', type=str,
                        help="directory containing test files "
                             "(may be specified multiple times)")
    args = parser.parse_args()
    failfast = True if args.failfast == 1 else False

    suite = unittest.TestSuite()
    for d in args.dir:
        print("Adding tests from directory tree %s" % d)
        add_from_dir(suite, d)
    sys.exit(not VppTestRunner(verbosity=verbose,
                               failfast=failfast).run(suite).wasSuccessful())
