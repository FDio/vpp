#!/usr/bin/env python3

import sys
import os
import re
import unittest
import importlib

# Classes that _is_parameterized_base recognizes as
# parameterized.parameterized_class base classes. run_tests.py consults
# this set so that an exact filter naming the family keeps selecting the
# generated variants. Names that merely look like a family, such as an
# unrelated Foo and Foo_256 pair, keep their exact filter semantics.
parameterized_family_names = set()


def _is_parameterized_base(name, cls, test_classes):
    """Detect a base class left behind by parameterized.parameterized_class.

    parameterized_class generates subclasses named "<base>_<index>" and
    leaves the base class in place, stripped only of the test methods it
    owns directly. A base that inherits its tests from mixins keeps them
    all, so the runner would execute the base as a duplicate of the first
    variant. A base matches when a same-module "<name>_<digits>" class
    derives from it, the exact shape parameterized_class generates. The
    MRO check keeps independent classes collectable when they merely share
    a name prefix, such as Foo and Foo_256.
    """
    pattern = re.compile(r"%s_\d+" % re.escape(name))
    return any(
        sub_name != name and sub_cls is not cls and issubclass(sub_cls, cls)
        for sub_name, sub_cls in test_classes.items()
        if pattern.fullmatch(sub_name)
    )


def discover_tests(directory, callback):
    do_insert = True
    for _f in os.listdir(directory):
        f = "%s/%s" % (directory, _f)
        if os.path.isdir(f):
            if not _f.startswith("hs-test"):
                discover_tests(f, callback)
            continue
        if not os.path.isfile(f):
            continue
        if do_insert:
            sys.path.insert(0, directory)
            do_insert = False
        if not _f.startswith("test_") or not _f.endswith(".py"):
            continue
        module_name = "".join(f.split("/")[-1].split(".")[:-1])
        module = importlib.import_module(module_name)
        test_classes = {
            name: cls
            for name, cls in module.__dict__.items()
            if isinstance(cls, type) and issubclass(cls, unittest.TestCase)
        }
        skipped = {
            name
            for name, cls in test_classes.items()
            if _is_parameterized_base(name, cls, test_classes)
        }
        parameterized_family_names.update(skipped)
        for name, cls in test_classes.items():
            if (
                name == "VppTestCase"
                or name == "VppAsfTestCase"
                or name.startswith("Template")
            ):
                continue
            if name in skipped:
                continue
            for method in dir(cls):
                if not callable(getattr(cls, method)):
                    continue
                if method.startswith("test_"):
                    callback(_f, cls, method)


def print_callback(file_name, cls, method):
    print("%s.%s.%s" % (file_name, cls.__name__, method))
