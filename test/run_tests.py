#!/usr/bin/env python

import datetime
import sys
import shutil
import os
import select
import unittest
import argparse
import time
import threading
from multiprocessing import Process, Pipe, cpu_count
from framework import VppTestRunner, running_extended_tests, parse_test_option,\
    Filter_by_test_option
from debug import spawn_gdb
from log import get_parallel_logger
from discover_tests import discover_tests
from subprocess import check_output, CalledProcessError
from util import check_core_path

# timeout which controls how long the child has to finish after seeing
# a core dump in test temporary directory. If this is exceeded, parent assumes
# that child process is stuck (e.g. waiting for shm mutex, which will never
# get unlocked) and kill the child
core_timeout = 3

def test_runner_wrapper(suite, keep_alive_pipe, result_pipe, failed_pipe,
                        stdouterr_pipe):
    # redirect stdout to pipe in child process
    os.dup2(stdouterr_pipe, sys.stdout.fileno())
    # redirect stderr to pipe in child process
    os.dup2(stdouterr_pipe, sys.stderr.fileno())
    result = VppTestRunner(
        keep_alive_pipe=keep_alive_pipe,
        failed_pipe=failed_pipe,
        verbosity=verbose,
        failfast=failfast).run(suite).wasSuccessful()
    result_pipe.send(result)
    result_pipe.close()
    keep_alive_pipe.close()
    failed_pipe.close()


class TestCaseWrapper(object):
    def __init__(self, testcase_suite):
        self.keep_alive_parent_end, self.keep_alive_child_end = Pipe(duplex=False)
        self.result_parent_end, self.result_child_end = Pipe(duplex=False)
        self.failed_parent_end, self.failed_child_end = Pipe(duplex=False)
        self.stdouterr_out, self.stdouterr_in = os.pipe()
        self.stdouterr_in_stream = os.fdopen(self.stdouterr_in, 'w')
        self.testcase_suite = testcase_suite
        self.child = Process(target=test_runner_wrapper,
                             args=(testcase_suite, self.keep_alive_child_end,
                                   self.result_child_end, self.failed_child_end,
                                   self.stdouterr_in))
        self.child.start()
        self.pid = self.child.pid
        self.last_test_temp_dir = None
        self.last_test_vpp_binary = None
        self.last_test = None
        self.result = None
        self.last_heard = time.time()
        # self.logger = get_parallel_logger(self.stdouterr_in_stream)
        self.core_detected_at = None
        self.stderr_read = False
        self.stdout_read = False

    def close_child_pipes(self):
        self.stdouterr_in_stream.close()

    def close_pipes(self):
        self.keep_alive_parent_end.close()
        self.result_parent_end.close()
        self.failed_parent_end.close()


def stdouterr_reader_wrapper(wrapped_testcases, read_testcases, lock):
    read_testcase = None
    while read_testcases.is_set() or len(wrapped_testcases) > 0:
        if not read_testcase and len(wrapped_testcases) > 0:
            lock.acquire()
            read_testcase = wrapped_testcases.pop(0)
            lock.release()
        if read_testcase:
            fd = read_testcase.stdouterr_out
            c = os.read(fd, 1)
            print('{}: In read loop'.format(datetime.datetime.now()))
            while c:
                sys.stdout.write(c)
                c = os.read(fd, 1)

            print('{}: Closing fd'.format(datetime.datetime.now()))
            os.close(fd)
            print('{}: Finished reading'.format(datetime.datetime.now()))
            read_testcase = None


def run_forked(testcases):
    wrapped_testcase_suites = set()

    # suites are unhashable, need to use list
    failed = []
    debug_core = os.getenv("DEBUG", "").lower() == "core"
    concurrent_tests = cpu_count()
    full_result = 0
    testcases_to_be_read = []
    for i in range(concurrent_tests):
        if len(testcases) > 0:
            wrapped_testcase_suite = TestCaseWrapper(testcases.pop(0))
            wrapped_testcase_suites.add(wrapped_testcase_suite)
            testcases_to_be_read.append(wrapped_testcase_suite)
            # time.sleep(1)
        else:
            break

    testcase_pop_lock = threading.Lock()
    read_testcases = threading.Event()
    read_testcases.set()
    stdouterr_thread = threading.Thread(target=stdouterr_reader_wrapper,
                                     args=(testcases_to_be_read, read_testcases, testcase_pop_lock))
    stdouterr_thread.start()

    while len(wrapped_testcase_suites) > 0:
        finished_testcase_suites = set()
        for wrapped_testcase_suite in wrapped_testcase_suites:
            readable = select.select([wrapped_testcase_suite.keep_alive_parent_end.fileno(),
                                      wrapped_testcase_suite.result_parent_end.fileno(),
                                      wrapped_testcase_suite.failed_parent_end.fileno(),
                                      ],
                                     [], [], 1)[0]
            if wrapped_testcase_suite.result_parent_end.fileno() in readable:
                if not wrapped_testcase_suite.result_parent_end.recv():
                    full_result = 1
                finished_testcase_suites.add(wrapped_testcase_suite)
                continue
            if wrapped_testcase_suite.keep_alive_parent_end.fileno() in readable:
                while wrapped_testcase_suite.keep_alive_parent_end.poll():
                    wrapped_testcase_suite.last_test,\
                        wrapped_testcase_suite.last_test_vpp_binary,\
                        wrapped_testcase_suite.last_test_temp_dir,\
                        wrapped_testcase_suite.vpp_pid = wrapped_testcase_suite.keep_alive_parent_end.recv()
                wrapped_testcase_suite.last_heard = time.time()
            if wrapped_testcase_suite.failed_parent_end.fileno() in readable:
                while wrapped_testcase_suite.failed_parent_end.poll():
                    # fix rerun of tests, not whole suites
                    failed_test = wrapped_testcase_suite.failed_parent_end.recv()
                    failed.append(wrapped_testcase_suite.testcase_suite)
                wrapped_testcase_suite.last_heard = time.time()
            fail = False
            if wrapped_testcase_suite.last_heard + test_timeout < time.time() and \
                    not os.path.isfile("%s/_core_handled" % wrapped_testcase_suite.last_test_temp_dir):
                fail = True
                wrapped_testcase_suite.logger.critical("Timeout while waiting for child test "
                                       "runner process (last test running was "
                                       "`%s' in `%s')!" %
                                       (wrapped_testcase_suite.last_test, wrapped_testcase_suite.last_test_temp_dir))
            elif not wrapped_testcase_suite.child.is_alive():
                fail = True
                wrapped_testcase_suite.logger.critical("Child python process unexpectedly died "
                                       "(last test running was `%s' in `%s')!" %
                                       (wrapped_testcase_suite.last_test, wrapped_testcase_suite.last_test_temp_dir))
            elif wrapped_testcase_suite.last_test_temp_dir and wrapped_testcase_suite.last_test_vpp_binary:
                core_path = "%s/core" % wrapped_testcase_suite.last_test_temp_dir
                if os.path.isfile(core_path):
                    if wrapped_testcase_suite.core_detected_at is None:
                        wrapped_testcase_suite.core_detected_at = time.time()
                    elif wrapped_testcase_suite.core_detected_at + core_timeout < time.time():
                        if not os.path.isfile(
                                        "%s/_core_handled" % wrapped_testcase_suite.last_test_temp_dir):
                            wrapped_testcase_suite.logger.critical(
                                "Child python process unresponsive and core-file "
                                "exists in test temporary directory!")
                            fail = True

            if fail:
                failed.append(wrapped_testcase_suite.testcase_suite)
                failed_dir = os.getenv('VPP_TEST_FAILED_DIR')
                lttd = wrapped_testcase_suite.last_test_temp_dir.split("/")[-1]
                link_path = '%s%s-FAILED' % (failed_dir, lttd)
                wrapped_testcase_suite.logger.error("Creating a link to the failed " +
                                    "test: %s -> %s" % (link_path, lttd))
                try:
                    os.symlink(wrapped_testcase_suite.last_test_temp_dir, link_path)
                except Exception:
                    pass
                api_post_mortem_path = "/tmp/api_post_mortem.%d" % wrapped_testcase_suite.vpp_pid
                if os.path.isfile(api_post_mortem_path):
                    wrapped_testcase_suite.logger.error("Copying api_post_mortem.%d to %s" %
                                        (wrapped_testcase_suite.vpp_pid, wrapped_testcase_suite.last_test_temp_dir))
                    shutil.copy2(api_post_mortem_path, wrapped_testcase_suite.last_test_temp_dir)
                if wrapped_testcase_suite.last_test_temp_dir and wrapped_testcase_suite.last_test_vpp_binary:
                    core_path = "%s/core" % wrapped_testcase_suite.last_test_temp_dir
                    if os.path.isfile(core_path):
                        wrapped_testcase_suite.logger.error("Core-file exists in test temporary "
                                            "directory: %s!" % core_path)
                        check_core_path(wrapped_testcase_suite.logger, core_path)
                        wrapped_testcase_suite.logger.debug("Running `file %s':" % core_path)
                        try:
                            info = check_output(["file", core_path])
                            wrapped_testcase_suite.logger.debug(info)
                        except CalledProcessError as e:
                            wrapped_testcase_suite.logger.error(
                                "Could not run `file' utility on core-file, "
                                "rc=%s" % e.returncode)
                            pass
                        if debug_core:
                            spawn_gdb(wrapped_testcase_suite.last_test_vpp_binary, core_path,
                                      wrapped_testcase_suite.logger)
                wrapped_testcase_suite.child.terminate()
                full_result = -1
                finished_testcase_suites.add(wrapped_testcase_suite)

        for finished_testcase in finished_testcase_suites:
            finished_testcase.close_pipes()
            # finished_testcase.logger.removeHandler(finished_testcase.logger.handlers[0])
            finished_testcase.close_child_pipes()
            wrapped_testcase_suites.remove(finished_testcase)
            if len(testcases) > 0:
                new_testcase = TestCaseWrapper(testcases.pop(0))
                wrapped_testcase_suites.add(new_testcase)
                testcase_pop_lock.acquire()
                testcases_to_be_read.append(new_testcase)
                testcase_pop_lock.release()

    read_testcases.clear()
    stdouterr_thread.join(test_timeout)
    return full_result, failed


class split_to_suites_callback:
    def __init__(self, filter_callback):
        self.suites = {}
        self.filter_callback = filter_callback
        self.filtered = unittest.TestSuite()

    def __call__(self, file_name, cls, method):
        test_method = cls(method)
        if self.filter_callback(file_name, cls.__name__, method):
            if cls.__name__ not in self.suites:
                self.suites[cls.__name__] = unittest.TestSuite()
            self.suites[cls.__name__].addTest(test_method)
        else:
            self.filtered.addTest(test_method)


def filter_tests(tests, filter_cb):
    result = unittest.suite.TestSuite()
    for t in tests:
        if isinstance(t, unittest.suite.TestSuite):
            # this is a bunch of tests, recursively filter...
            x = filter_tests(t, filter_cb)
            if x.countTestCases() > 0:
                result.addTest(x)
        elif isinstance(t, unittest.TestCase):
            # this is a single test
            parts = t.id().split('.')
            # t.id() for common cases like this:
            # test_classifier.TestClassifier.test_acl_ip
            # apply filtering only if it is so
            if len(parts) == 3:
                if not filter_cb(parts[0], parts[1], parts[2]):
                    continue
            result.addTest(t)
        else:
            # unexpected object, don't touch it
            result.addTest(t)
    return result


class Filter_by_class_list:
    def __init__(self, class_list):
        self.class_list = class_list

    def __call__(self, file_name, class_name, func_name):
        return class_name in self.class_list


def suite_from_failed(suite, failed):
    filter_cb = Filter_by_class_list(failed)
    suite = filter_tests(suite, filter_cb)
    if 0 == suite.countTestCases():
        raise Exception("Suite is empty after filtering out the failed tests!")
    return suite


if __name__ == '__main__':

    try:
        verbose = int(os.getenv("V", 0))
    except ValueError:
        verbose = 0

    default_test_timeout = 600  # 10 minutes
    try:
        test_timeout = int(os.getenv("TIMEOUT", default_test_timeout))
    except ValueError:
        test_timeout = default_test_timeout

    debug = os.getenv("DEBUG")

    s = os.getenv("STEP", "n")
    step = True if s.lower() in ("y", "yes", "1") else False

    parallel = True if os.getenv("PARALLEL", "n").lower() in ("y", "yes", "1") else False

    parser = argparse.ArgumentParser(description="VPP unit tests")
    parser.add_argument("-f", "--failfast", action='count',
                        help="fast failure flag")
    parser.add_argument("-d", "--dir", action='append', type=str,
                        help="directory containing test files "
                             "(may be specified multiple times)")
    args = parser.parse_args()
    failfast = True if args.failfast == 1 else False

    print("Running tests using custom test runner")  # debug message
    filter_file, filter_class, filter_func = parse_test_option()
    print("Active filters: file=%s, class=%s, function=%s" % (
        filter_file, filter_class, filter_func))
    filter_cb = Filter_by_test_option(
        filter_file, filter_class, filter_func)
    cb = split_to_suites_callback(filter_cb)
    for d in args.dir:
        print("Adding tests from directory tree %s" % d)
        discover_tests(d, cb)
    # suites are not hashable, need to use list
    suites = []
    tests_amount = 0
    for testcase_suite in cb.suites.values():
        tests_amount += testcase_suite.countTestCases()
        suites.append(testcase_suite)
    print("%s out of %s tests match specified filters" % (
        tests_amount, tests_amount + cb.filtered.countTestCases()))
    if not running_extended_tests():
        print("Not running extended tests (some tests will be skipped)")

    try:
        retries = int(os.getenv("RETRIES", 0))
    except ValueError:
        retries = 0

    try:
        force_foreground = int(os.getenv("FORCE_FOREGROUND", 0))
    except ValueError:
        force_foreground = 0
    attempts = retries + 1
    if attempts > 1:
        print("Perform %s attempts to pass the suite..." % attempts)
    if (debug is not None and debug.lower() in ["gdb", "gdbserver"]) or step \
            or force_foreground:
        # don't fork if requiring interactive terminal..
        suite = unittest.TestSuite()
        map(suite.addTest, suites)
        sys.exit(not VppTestRunner(
            verbosity=verbose, failfast=failfast).run(suite).wasSuccessful())
    else:
        result = 1
        if not parallel:
            suite = unittest.TestSuite()
            map(suite.addTest, suites)
            suites = suite
        while len(suites) > 0 and attempts > 0:
            tests_amount = sum([x.countTestCases() for x in suites])
            result, failed = run_forked(suites)
            attempts -= 1
            print("Executed %s tests" % tests_amount)
            print("%s test(s) failed, %s attempt(s) left" %
                  (sum([x.countTestCases() for x in failed]), attempts))
            suites = failed
        sys.exit(result)
