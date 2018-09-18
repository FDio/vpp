#!/usr/bin/env python

import sys
import shutil
import os
import select
import unittest
import argparse
import time
import threading
import signal
import psutil
from multiprocessing import Process, Pipe, cpu_count
from multiprocessing.queues import Queue
from multiprocessing.managers import BaseManager
from framework import VppTestRunner, running_extended_tests, VppTestCase, \
    get_testcase_doc_name, get_test_description
from debug import spawn_gdb
from log import get_parallel_logger, double_line_delim, RED, YELLOW, GREEN, \
    colorize
from discover_tests import discover_tests
from subprocess import check_output, CalledProcessError
from util import check_core_path

# timeout which controls how long the child has to finish after seeing
# a core dump in test temporary directory. If this is exceeded, parent assumes
# that child process is stuck (e.g. waiting for shm mutex, which will never
# get unlocked) and kill the child
core_timeout = 3
min_req_shm = 536870912  # min 512MB shm required
# 128MB per extra process
shm_per_process = 134217728


class StreamQueue(Queue):
    def write(self, msg):
        self.put(msg)

    def flush(self):
        sys.__stdout__.flush()
        sys.__stderr__.flush()

    def fileno(self):
        return self._writer.fileno()


class StreamQueueManager(BaseManager):
    pass


StreamQueueManager.register('Queue', StreamQueue)


def test_runner_wrapper(suite, keep_alive_pipe, result_pipe, stdouterr_queue,
                        partial_result_queue, logger):
    sys.stdout = stdouterr_queue
    sys.stderr = stdouterr_queue
    VppTestCase.logger = logger
    result = VppTestRunner(keep_alive_pipe=keep_alive_pipe,
                           descriptions=descriptions,
                           verbosity=verbose,
                           results_pipe=partial_result_queue,
                           failfast=failfast).run(suite)
    result_pipe.send(result)
    result_pipe.close()
    keep_alive_pipe.close()


class TestCaseWrapper(object):
    def __init__(self, testcase_suite, manager):
        self.keep_alive_parent_end, self.keep_alive_child_end = Pipe(
            duplex=False)
        self.result_parent_end, self.result_child_end = Pipe(duplex=False)
        self.partial_result_parent_end, self.partial_result_child_end = Pipe(
            duplex=False)
        self.testcase_suite = testcase_suite
        self.stdouterr_queue = manager.Queue()
        self.logger = get_parallel_logger(self.stdouterr_queue)
        self.child = Process(target=test_runner_wrapper,
                             args=(testcase_suite, self.keep_alive_child_end,
                                   self.result_child_end, self.stdouterr_queue,
                                   self.partial_result_child_end, self.logger)
                             )
        self.child.start()
        self.pid = self.child.pid
        self.last_test_temp_dir = None
        self.last_test_vpp_binary = None
        self.last_test = None
        self.result = None
        self.vpp_pid = None
        self.last_heard = time.time()
        self.core_detected_at = None
        self.failed_tests = []
        self.partial_result = None

    def close_pipes(self):
        self.keep_alive_child_end.close()
        self.result_child_end.close()
        self.partial_result_child_end.close()
        self.keep_alive_parent_end.close()
        self.result_parent_end.close()
        self.partial_result_parent_end.close()


def stdouterr_reader_wrapper(unread_testcases, finished_unread_testcases,
                             read_testcases):
    read_testcase = None
    while read_testcases.is_set() or len(unread_testcases) > 0:
        if not read_testcase:
            if len(finished_unread_testcases) > 0:
                read_testcase = finished_unread_testcases.pop()
                unread_testcases.remove(read_testcase)
            elif len(unread_testcases) > 0:
                read_testcase = unread_testcases.pop()
        if read_testcase:
            data = ''
            while data is not None:
                sys.stdout.write(data)
                data = read_testcase.stdouterr_queue.get()

            read_testcase.stdouterr_queue.close()
            finished_unread_testcases.discard(read_testcase)
            read_testcase = None


def run_forked(testcase_suites):
    wrapped_testcase_suites = set()

    # suites are unhashable, need to use list
    results = []
    debug_core = os.getenv("DEBUG", "").lower() == "core"
    unread_testcases = set()
    finished_unread_testcases = set()
    manager = StreamQueueManager()
    manager.start()
    for i in range(concurrent_tests):
        if len(testcase_suites) > 0:
            wrapped_testcase_suite = TestCaseWrapper(testcase_suites.pop(0),
                                                     manager)
            wrapped_testcase_suites.add(wrapped_testcase_suite)
            unread_testcases.add(wrapped_testcase_suite)
            # time.sleep(1)
        else:
            break

    read_from_testcases = threading.Event()
    read_from_testcases.set()
    stdouterr_thread = threading.Thread(target=stdouterr_reader_wrapper,
                                        args=(unread_testcases,
                                              finished_unread_testcases,
                                              read_from_testcases))
    stdouterr_thread.start()

    while len(wrapped_testcase_suites) > 0:
        finished_testcase_suites = set()
        for wrapped_testcase_suite in wrapped_testcase_suites:
            readable = select.select(
                [wrapped_testcase_suite.keep_alive_parent_end.fileno(),
                 wrapped_testcase_suite.result_parent_end.fileno(),
                 wrapped_testcase_suite.partial_result_parent_end.fileno()],
                [], [], 1)[0]
            if wrapped_testcase_suite.result_parent_end.fileno() in readable:
                results.append(
                    (wrapped_testcase_suite.testcase_suite,
                     wrapped_testcase_suite.result_parent_end.recv()))
                finished_testcase_suites.add(wrapped_testcase_suite)
                continue

            if wrapped_testcase_suite.partial_result_parent_end.fileno() \
                    in readable:
                while wrapped_testcase_suite.partial_result_parent_end.poll():
                    wrapped_testcase_suite.partial_result = \
                        wrapped_testcase_suite.partial_result_parent_end.recv()
                    wrapped_testcase_suite.last_heard = time.time()

            if wrapped_testcase_suite.keep_alive_parent_end.fileno() \
                    in readable:
                while wrapped_testcase_suite.keep_alive_parent_end.poll():
                    wrapped_testcase_suite.last_test, \
                        wrapped_testcase_suite.last_test_vpp_binary, \
                        wrapped_testcase_suite.last_test_temp_dir, \
                        wrapped_testcase_suite.vpp_pid = \
                        wrapped_testcase_suite.keep_alive_parent_end.recv()
                wrapped_testcase_suite.last_heard = time.time()

            fail = False
            if wrapped_testcase_suite.last_heard + test_timeout < time.time() \
                    and not os.path.isfile(
                                "%s/_core_handled" %
                                wrapped_testcase_suite.last_test_temp_dir):
                fail = True
                wrapped_testcase_suite.logger.critical(
                    "Timeout while waiting for child test "
                    "runner process (last test running was "
                    "`%s' in `%s')!" %
                    (wrapped_testcase_suite.last_test,
                     wrapped_testcase_suite.last_test_temp_dir))
            elif not wrapped_testcase_suite.child.is_alive():
                fail = True
                wrapped_testcase_suite.logger.critical(
                    "Child python process unexpectedly died "
                    "(last test running was `%s' in `%s')!" %
                    (wrapped_testcase_suite.last_test,
                     wrapped_testcase_suite.last_test_temp_dir))
            elif wrapped_testcase_suite.last_test_temp_dir and \
                    wrapped_testcase_suite.last_test_vpp_binary:
                core_path = "%s/core" % \
                            wrapped_testcase_suite.last_test_temp_dir
                if os.path.isfile(core_path):
                    if wrapped_testcase_suite.core_detected_at is None:
                        wrapped_testcase_suite.core_detected_at = time.time()
                    elif wrapped_testcase_suite.core_detected_at + \
                            core_timeout < time.time():
                        if not os.path.isfile(
                                        "%s/_core_handled" %
                                        wrapped_testcase_suite.
                                        last_test_temp_dir):
                            wrapped_testcase_suite.logger.critical(
                                "Child python process unresponsive and core-"
                                "file exists in test temporary directory!")
                            fail = True

            if fail:
                failed_dir = os.getenv('VPP_TEST_FAILED_DIR')
                if wrapped_testcase_suite.last_test_temp_dir:
                    lttd = os.path.basename(
                        wrapped_testcase_suite.last_test_temp_dir)
                else:
                    lttd = None
                link_path = '%s%s-FAILED' % (failed_dir, lttd)
                wrapped_testcase_suite.logger.error(
                    "Creating a link to the failed test: %s -> %s" %
                    (link_path, lttd))
                if not os.path.exists(link_path) \
                        and wrapped_testcase_suite.last_test_temp_dir:
                    os.symlink(wrapped_testcase_suite.last_test_temp_dir,
                               link_path)
                api_post_mortem_path = "/tmp/api_post_mortem.%d" % \
                                       wrapped_testcase_suite.vpp_pid
                if os.path.isfile(api_post_mortem_path):
                    wrapped_testcase_suite.logger.error(
                        "Copying api_post_mortem.%d to %s" %
                        (wrapped_testcase_suite.vpp_pid,
                         wrapped_testcase_suite.last_test_temp_dir))
                    shutil.copy2(api_post_mortem_path,
                                 wrapped_testcase_suite.last_test_temp_dir)
                if wrapped_testcase_suite.last_test_temp_dir and \
                        wrapped_testcase_suite.last_test_vpp_binary:
                    core_path = "%s/core" % \
                                wrapped_testcase_suite.last_test_temp_dir
                    if os.path.isfile(core_path):
                        wrapped_testcase_suite.logger.error(
                            "Core-file exists in test temporary directory: %s!"
                            % core_path)
                        check_core_path(wrapped_testcase_suite.logger,
                                        core_path)
                        wrapped_testcase_suite.logger.debug(
                            "Running `file %s':" % core_path)
                        try:
                            info = check_output(["file", core_path])
                            wrapped_testcase_suite.logger.debug(info)
                        except CalledProcessError as e:
                            wrapped_testcase_suite.logger.error(
                                "Could not run `file' utility on core-file, "
                                "rc=%s" % e.returncode)
                            pass
                        if debug_core:
                            spawn_gdb(
                                wrapped_testcase_suite.last_test_vpp_binary,
                                core_path, wrapped_testcase_suite.logger)
                wrapped_testcase_suite.child.terminate()
                try:
                    # terminating the child process tends to leave orphan
                    # VPP process around
                    os.kill(wrapped_testcase_suite.vpp_pid, signal.SIGTERM)
                except OSError:
                    # already dead
                    pass
                results.append((wrapped_testcase_suite.testcase_suite,
                                wrapped_testcase_suite.partial_result))
                finished_testcase_suites.add(wrapped_testcase_suite)

        for finished_testcase in finished_testcase_suites:
            finished_testcase.child.join()
            finished_testcase.close_pipes()
            wrapped_testcase_suites.remove(finished_testcase)
            finished_unread_testcases.add(finished_testcase)
            finished_testcase.stdouterr_queue.put(None)
            if len(testcase_suites) > 0:
                new_testcase = TestCaseWrapper(testcase_suites.pop(0), manager)
                wrapped_testcase_suites.add(new_testcase)
                unread_testcases.add(new_testcase)

    read_from_testcases.clear()
    stdouterr_thread.join(test_timeout)
    manager.shutdown()
    return results


class SplitToSuitesCallback:
    def __init__(self, filter_callback):
        self.suites = {}
        self.suite_name = 'default'
        self.filter_callback = filter_callback
        self.filtered = unittest.TestSuite()

    def __call__(self, file_name, cls, method):
        test_method = cls(method)
        if self.filter_callback(file_name, cls.__name__, method):
            self.suite_name = file_name + cls.__name__
            if self.suite_name not in self.suites:
                self.suites[self.suite_name] = unittest.TestSuite()
            self.suites[self.suite_name].addTest(test_method)

        else:
            self.filtered.addTest(test_method)


test_option = "TEST"


def parse_test_option():
    f = os.getenv(test_option, None)
    filter_file_name = None
    filter_class_name = None
    filter_func_name = None
    if f:
        if '.' in f:
            parts = f.split('.')
            if len(parts) > 3:
                raise Exception("Unrecognized %s option: %s" %
                                (test_option, f))
            if len(parts) > 2:
                if parts[2] not in ('*', ''):
                    filter_func_name = parts[2]
            if parts[1] not in ('*', ''):
                filter_class_name = parts[1]
            if parts[0] not in ('*', ''):
                if parts[0].startswith('test_'):
                    filter_file_name = parts[0]
                else:
                    filter_file_name = 'test_%s' % parts[0]
        else:
            if f.startswith('test_'):
                filter_file_name = f
            else:
                filter_file_name = 'test_%s' % f
    if filter_file_name:
        filter_file_name = '%s.py' % filter_file_name
    return filter_file_name, filter_class_name, filter_func_name


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


class FilterByTestOption:
    def __init__(self, filter_file_name, filter_class_name, filter_func_name):
        self.filter_file_name = filter_file_name
        self.filter_class_name = filter_class_name
        self.filter_func_name = filter_func_name

    def __call__(self, file_name, class_name, func_name):
        if self.filter_file_name and file_name != self.filter_file_name:
            return False
        if self.filter_class_name and class_name != self.filter_class_name:
            return False
        if self.filter_func_name and func_name != self.filter_func_name:
            return False
        return True


class FilterByClassList:
    def __init__(self, classes_with_filenames):
        self.classes_with_filenames = classes_with_filenames

    def __call__(self, file_name, class_name, func_name):
        return '.'.join([file_name, class_name]) in self.classes_with_filenames


def suite_from_failed(suite, failed):
    failed = {x.rsplit('.', 1)[0] for x in failed}
    filter_cb = FilterByClassList(failed)
    suite = filter_tests(suite, filter_cb)
    return suite


class NonPassedResults(dict):
    def __init__(self):
        super(NonPassedResults, self).__init__()
        self.all_testcases = 0
        self.results_per_suite = {}
        self.failures_id = 'failures'
        self.errors_id = 'errors'
        self.crashes_id = 'crashes'
        self.skipped_id = 'skipped'
        self.expectedFailures_id = 'expectedFailures'
        self.unexpectedSuccesses_id = 'unexpectedSuccesses'
        self.rerun = []
        self.passed = 0
        self[self.failures_id] = 0
        self[self.errors_id] = 0
        self[self.skipped_id] = 0
        self[self.expectedFailures_id] = 0
        self[self.unexpectedSuccesses_id] = 0

    def _add_result(self, test, result_id):
        if isinstance(test, VppTestCase):
            parts = test.id().split('.')
            if len(parts) == 3:
                tc_class = get_testcase_doc_name(test)
                if tc_class not in self.results_per_suite:
                    # failed, errored, skipped, expectedly failed,
                    # unexpectedly passed
                    self.results_per_suite[tc_class] = \
                        {self.failures_id: [],
                         self.errors_id: [],
                         self.skipped_id: [],
                         self.expectedFailures_id: [],
                         self.unexpectedSuccesses_id: []}
                self.results_per_suite[tc_class][result_id].append(test)
                return True
        return False

    def add_results(self, testcases, testcase_result_id):
        for failed_testcase, _ in testcases:
            if self._add_result(failed_testcase, testcase_result_id):
                self[testcase_result_id] += 1

    def add_result(self, testcase_suite, result):
        retval = 0
        if result:
            self.all_testcases += result.testsRun
            self.passed += len(result.passed)
            if not len(result.passed) + len(result.skipped) \
                    == testcase_suite.countTestCases():
                retval = 1

            self.add_results(result.failures, self.failures_id)
            self.add_results(result.errors, self.errors_id)
            self.add_results(result.skipped, self.skipped_id)
            self.add_results(result.expectedFailures,
                             self.expectedFailures_id)
            self.add_results(result.unexpectedSuccesses,
                             self.unexpectedSuccesses_id)
        else:
            retval = -1

        if retval != 0:
            if concurrent_tests == 1:
                if result:
                    rerun_ids = set([])
                    skipped = [x.id() for (x, _) in result.skipped]
                    for testcase in testcase_suite:
                        tc_id = testcase.id()
                        if tc_id not in result.passed and \
                                tc_id not in skipped:
                            rerun_ids.add(tc_id)
                    if len(rerun_ids) > 0:
                        self.rerun.append(suite_from_failed(testcase_suite,
                                                            rerun_ids))
                else:
                    self.rerun.append(testcase_suite)
            else:
                self.rerun.append(testcase_suite)

        return retval

    def print_results(self):
        print('')
        print(double_line_delim)
        print('TEST RESULTS:')
        print('        Executed tests: {}'.format(self.all_testcases))
        print('          Passed tests: {}'.format(
            colorize(str(self.passed), GREEN)))
        if self[self.failures_id] > 0:
            print('              Failures: {}'.format(
                colorize(str(self[self.failures_id]), RED)))
        if self[self.errors_id] > 0:
            print('                Errors: {}'.format(
                colorize(str(self[self.errors_id]), RED)))
        if self[self.skipped_id] > 0:
            print('         Skipped tests: {}'.format(
                colorize(str(self[self.skipped_id]), YELLOW)))
        if self[self.expectedFailures_id] > 0:
            print('     Expected failures: {}'.format(
                colorize(str(self[self.expectedFailures_id]), GREEN)))
        if self[self.unexpectedSuccesses_id] > 0:
            print('  Unexpected successes: {}'.format(
                colorize(str(self[self.unexpectedSuccesses_id]), YELLOW)))

        if self.all_failed > 0:
            print('FAILED TESTS:')
            for testcase_class, suite_results in \
                    self.results_per_suite.items():
                failed_testcases = suite_results[
                    self.failures_id]
                errored_testcases = suite_results[
                    self.errors_id]
                if len(failed_testcases) or len(errored_testcases):
                    print('  Testcase name: {}'.format(
                        colorize(testcase_class, RED)))
                    for failed_test in failed_testcases:
                        print('     FAILED: {}'.format(
                            colorize(get_test_description(
                                descriptions, failed_test), RED)))
                    for failed_test in errored_testcases:
                        print('    ERRORED: {}'.format(
                            colorize(get_test_description(
                                descriptions, failed_test), RED)))

        print(double_line_delim)
        print('')

    @property
    def all_failed(self):
        return self[self.failures_id] + self[self.errors_id]


def parse_results(results):
    """
    Prints the number of executed, passed, failed, errored, skipped,
    expectedly failed and unexpectedly passed tests and details about
    failed, errored, expectedly failed and unexpectedly passed tests.

    Also returns any suites where any test failed.

    :param results:
    :return:
    """

    results_per_suite = NonPassedResults()
    crashed = False
    failed = False
    for testcase_suite, result in results:
        result_code = results_per_suite.add_result(testcase_suite, result)
        if result_code == 1:
            failed = True
        elif result_code == -1:
            crashed = True

    results_per_suite.print_results()

    if crashed:
        return_code = -1
    elif failed:
        return_code = 1
    else:
        return_code = 0
    return return_code, results_per_suite.rerun


def parse_digit_env(env_var, default):
    value = os.getenv(env_var, default)
    if value != default:
        if value.isdigit():
            value = int(value)
        else:
            print('WARNING: unsupported value "%s" for env var "%s",'
                  'defaulting to %s' % (value, env_var, default))
            value = default
    return value


if __name__ == '__main__':

    verbose = parse_digit_env("V", 0)

    test_timeout = parse_digit_env("TIMEOUT", 600)  # default = 10 minutes

    retries = parse_digit_env("RETRIES", 0)

    debug = os.getenv("DEBUG", "n").lower() in ["gdb", "gdbserver"]

    step = os.getenv("STEP", "n").lower() in ("y", "yes", "1")

    force_foreground = \
        os.getenv("FORCE_FOREGROUND", "n").lower() in ("y", "yes", "1")

    run_interactive = debug or step or force_foreground

    test_jobs = os.getenv("TEST_JOBS", "1").lower()  # default = 1 process
    if test_jobs == 'auto':
        if run_interactive:
            concurrent_tests = 1
            print('Interactive mode required, running on one core')
        else:
            shm_free = psutil.disk_usage('/dev/shm').free
            shm_max_processes = 1
            if shm_free < min_req_shm:
                raise Exception('Not enough free space in /dev/shm. Required '
                                'free space is at least %sM.'
                                % (min_req_shm >> 20))
            else:
                extra_shm = shm_free - min_req_shm
                shm_max_processes += extra_shm / shm_per_process
            concurrent_tests = min(cpu_count(), shm_max_processes)
            print('Found enough resources to run tests with %s cores'
                  % concurrent_tests)
    elif test_jobs.isdigit():
        concurrent_tests = int(test_jobs)
    else:
        concurrent_tests = 1

    if run_interactive and concurrent_tests > 1:
        raise NotImplementedError(
            'Running tests interactively (DEBUG, STEP or FORCE_FOREGROUND is '
            'set) in parallel (TEST_JOBS is more than 1) is not '
            'supported')

    parser = argparse.ArgumentParser(description="VPP unit tests")
    parser.add_argument("-f", "--failfast", action='store_true',
                        help="fast failure flag")
    parser.add_argument("-d", "--dir", action='append', type=str,
                        help="directory containing test files "
                             "(may be specified multiple times)")
    args = parser.parse_args()
    failfast = args.failfast
    descriptions = True

    print("Running tests using custom test runner")  # debug message
    filter_file, filter_class, filter_func = parse_test_option()

    print("Active filters: file=%s, class=%s, function=%s" % (
        filter_file, filter_class, filter_func))

    filter_cb = FilterByTestOption(filter_file, filter_class, filter_func)

    cb = SplitToSuitesCallback(filter_cb)
    for d in args.dir:
        print("Adding tests from directory tree %s" % d)
        discover_tests(d, cb)

    # suites are not hashable, need to use list
    suites = []
    tests_amount = 0
    for testcase_suite in cb.suites.values():
        tests_amount += testcase_suite.countTestCases()
        suites.append(testcase_suite)

    if concurrent_tests == 1:
        new_suite = unittest.TestSuite()
        for suite in suites:
            new_suite.addTests(suite)

        suites = [new_suite]

    print("%s out of %s tests match specified filters" % (
        tests_amount, tests_amount + cb.filtered.countTestCases()))

    if not running_extended_tests():
        print("Not running extended tests (some tests will be skipped)")

    attempts = retries + 1
    if attempts > 1:
        print("Perform %s attempts to pass the suite..." % attempts)

    if run_interactive:
        # don't fork if requiring interactive terminal
        sys.exit(not VppTestRunner(
            verbosity=verbose, failfast=failfast)
                 .run(suites[0]).wasSuccessful())
    else:
        exit_code = 0
        while len(suites) > 0 and attempts > 0:
            tests_amount = sum([x.countTestCases() for x in suites])
            results = run_forked(suites)
            exit_code, suites = parse_results(results)
            attempts -= 1
            if exit_code == 0:
                print('Test run was successful')
            else:
                print('%s attempt(s) left.' % attempts)
        sys.exit(exit_code)
