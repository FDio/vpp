#!/usr/bin/env python

import sys
import os
import select
import unittest
import argparse
from multiprocessing import Process, Pipe
from framework import VppTestRunner
from debug import spawn_gdb
from log import global_logger
from discover_tests import discover_tests


def test_runner_wrapper(suite, keep_alive_pipe, result_pipe):
    result = not VppTestRunner(
        pipe=keep_alive_pipe,
        verbosity=verbose,
        failfast=failfast).run(suite).wasSuccessful()
    result_pipe.send(result)
    result_pipe.close()
    keep_alive_pipe.close()


class add_to_suite_callback:
    def __init__(self, suite):
        self.suite = suite

    def __call__(self, file_name, cls, method):
        suite.addTest(cls(method))


def run_forked(suite):
    keep_alive_parent_end, keep_alive_child_end = Pipe(duplex=False)
    result_parent_end, result_child_end = Pipe(duplex=False)

    child = Process(target=test_runner_wrapper,
                    args=(suite, keep_alive_child_end, result_child_end))
    child.start()
    last_test_temp_dir = None
    last_test_vpp_binary = None
    last_test = None
    result = None
    while result is None:
        readable = select.select([keep_alive_parent_end.fileno(),
                                  result_parent_end.fileno(),
                                  ],
                                 [], [], test_timeout)[0]
        if result_parent_end.fileno() in readable:
            result = result_parent_end.recv()
        elif keep_alive_parent_end.fileno() in readable:
            while keep_alive_parent_end.poll():
                last_test, last_test_vpp_binary, last_test_temp_dir =\
                    keep_alive_parent_end.recv()
        else:
            global_logger.critical("Timeout while waiting for child test "
                                   "runner process (last test running was "
                                   "`%s' in `%s')!" %
                                   (last_test, last_test_temp_dir))
            if last_test_temp_dir and last_test_vpp_binary:
                core_path = "%s/core" % last_test_temp_dir
                if os.path.isfile(core_path):
                    global_logger.error("Core-file exists in test temporary "
                                        "directory: %s!" % core_path)
                    if d and d.lower() == "core":
                        spawn_gdb(last_test_vpp_binary, core_path,
                                  global_logger)
            child.terminate()
            result = -1
    keep_alive_parent_end.close()
    result_parent_end.close()
    return result


if __name__ == '__main__':

    try:
        verbose = int(os.getenv("V", 0))
    except:
        verbose = 0

    default_test_timeout = 600  # 10 minutes
    try:
        test_timeout = int(os.getenv("TIMEOUT", default_test_timeout))
    except:
        test_timeout = default_test_timeout

    try:
        debug = os.getenv("DEBUG")
    except:
        debug = None

    parser = argparse.ArgumentParser(description="VPP unit tests")
    parser.add_argument("-f", "--failfast", action='count',
                        help="fast failure flag")
    parser.add_argument("-d", "--dir", action='append', type=str,
                        help="directory containing test files "
                             "(may be specified multiple times)")
    args = parser.parse_args()
    failfast = True if args.failfast == 1 else False

    suite = unittest.TestSuite()
    cb = add_to_suite_callback(suite)
    for d in args.dir:
        global_logger.info("Adding tests from directory tree %s" % d)
        discover_tests(d, cb)

    if debug is None or debug.lower() not in ["gdb", "gdbserver"]:
        sys.exit(run_forked(suite))

    # don't fork if debugging..
    sys.exit(not VppTestRunner(verbosity=verbose,
                               failfast=failfast).run(suite).wasSuccessful())
