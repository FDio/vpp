#!/usr/bin/env python3

import sys
import os
import re
import unittest
import importlib

# (file name, class name) pairs that _is_parameterized_base recognizes as
# parameterized.parameterized_class base classes. run_tests.py consults
# this set so that an exact filter naming the family keeps selecting the
# generated variants. The file name scopes each family to its module, so
# a family Foo in one test file does not make Foo a family name in
# another. Names that merely look like a family, such as an unrelated Foo
# and Foo_256 pair, keep their exact filter semantics.
parameterized_family_names = set()


def parameterized_variant_pattern(family_name):
    """Return the pattern matching the variant class names that
    parameterized.parameterized_class generates for family_name:
    "<family>_<index>", with a "<suffix>" appended when a parameter
    carries a string value ({"af": "ip4"} generates Foo_0_ip4). The
    suffix is limited to [a-zA-Z0-9_] by parameterized.to_safe_name.
    """
    return re.compile(r"%s_\d+(?:_\w+)?" % re.escape(family_name))


def _is_parameterized_base(name, cls, test_classes):
    """Detect a base class left behind by parameterized.parameterized_class.

    parameterized_class generates direct subclasses carrying generated
    variant names and leaves the base class in place, stripped only of
    the test methods it owns directly. A base that inherits its tests
    from mixins keeps them all, so the runner would execute the base as
    a duplicate of the first variant. Requiring the subclass to be direct
    keeps indirect classes from hiding the base, such as a Foo_0_extra
    class deriving from Foo_0, or a Foo_2 class deriving from Foo and
    another base. A hand-written direct single-base Foo_2(Foo) remains
    indistinguishable from a generated variant. A same-prefix Foo_256
    that does not derive from the base never matches.
    """
    pattern = parameterized_variant_pattern(name)
    return any(
        sub_cls.__bases__ == (cls,)
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
        parameterized_family_names.update((_f, name) for name in skipped)
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
