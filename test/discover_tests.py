#!/usr/bin/env python3

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
