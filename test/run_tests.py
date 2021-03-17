#!/usr/bin/env python3

import sys
import shutil
import os
import fnmatch
import unittest
import argparse
import time
import threading
import signal
import psutil
import re
import multiprocessing
from multiprocessing import Process, Pipe, cpu_count
from multiprocessing.queues import Queue
from multiprocessing.managers import BaseManager
import framework
from framework import VppTestRunner, running_extended_tests, VppTestCase, \
    get_testcase_doc_name, get_test_description, PASS, FAIL, ERROR, SKIP, \
    TEST_RUN
from debug import spawn_gdb
from log import get_parallel_logger, double_line_delim, RED, YELLOW, GREEN, \
    colorize, single_line_delim
from discover_tests import discover_tests
from subprocess import check_output, CalledProcessError
from util import check_core_path, get_core_path, is_core_present

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


StreamQueueManager.register('StreamQueue', StreamQueue)


class TestResult(dict):
    def __init__(self, testcase_suite, testcases_by_id=None):
        super(TestResult, self).__init__()
        self[PASS] = []
        self[FAIL] = []
        self[ERROR] = []
        self[SKIP] = []
        self[TEST_RUN] = []
        self.crashed = False
        self.testcase_suite = testcase_suite
        self.testcases = [testcase for testcase in testcase_suite]
        self.testcases_by_id = testcases_by_id

    def was_successful(self):
        return 0 == len(self[FAIL]) == len(self[ERROR]) \
            and len(self[PASS] + self[SKIP]) \
            == self.testcase_suite.countTestCases() == len(self[TEST_RUN])

    def no_tests_run(self):
        return 0 == len(self[TEST_RUN])

    def process_result(self, test_id, result):
        self[result].append(test_id)

    def suite_from_failed(self):
        rerun_ids = set([])
        for testcase in self.testcase_suite:
            tc_id = testcase.id()
            if tc_id not in self[PASS] and tc_id not in self[SKIP]:
                rerun_ids.add(tc_id)
        if rerun_ids:
            return suite_from_failed(self.testcase_suite, rerun_ids)

    def get_testcase_names(self, test_id):
        # could be tearDownClass (test_ipsec_esp.TestIpsecEsp1)
        setup_teardown_match = re.match(
            r'((tearDownClass)|(setUpClass)) \((.+\..+)\)', test_id)
        if setup_teardown_match:
            test_name, _, _, testcase_name = setup_teardown_match.groups()
            if len(testcase_name.split('.')) == 2:
                for key in self.testcases_by_id.keys():
                    if key.startswith(testcase_name):
                        testcase_name = key
                        break
            testcase_name = self._get_testcase_doc_name(testcase_name)
        else:
            test_name = self._get_test_description(test_id)
            testcase_name = self._get_testcase_doc_name(test_id)

        return testcase_name, test_name

    def _get_test_description(self, test_id):
        if test_id in self.testcases_by_id:
            desc = get_test_description(descriptions,
                                        self.testcases_by_id[test_id])
        else:
            desc = test_id
        return desc

    def _get_testcase_doc_name(self, test_id):
        if test_id in self.testcases_by_id:
            doc_name = get_testcase_doc_name(self.testcases_by_id[test_id])
        else:
            doc_name = test_id
        return doc_name


def test_runner_wrapper(suite, keep_alive_pipe, stdouterr_queue,
                        finished_pipe, result_pipe, logger):
    sys.stdout = stdouterr_queue
    sys.stderr = stdouterr_queue
    VppTestCase.parallel_handler = logger.handlers[0]
    result = VppTestRunner(keep_alive_pipe=keep_alive_pipe,
                           descriptions=descriptions,
                           verbosity=verbose,
                           result_pipe=result_pipe,
                           failfast=failfast,
                           print_summary=False).run(suite)
    finished_pipe.send(result.wasSuccessful())
    finished_pipe.close()
    keep_alive_pipe.close()


class TestCaseWrapper(object):
    def __init__(self, testcase_suite, manager):
        self.keep_alive_parent_end, self.keep_alive_child_end = Pipe(
            duplex=False)
        self.finished_parent_end, self.finished_child_end = Pipe(duplex=False)
        self.result_parent_end, self.result_child_end = Pipe(duplex=False)
        self.testcase_suite = testcase_suite
        if sys.version[0] == '2':
            self.stdouterr_queue = manager.StreamQueue()
        else:
            from multiprocessing import get_context
            self.stdouterr_queue = manager.StreamQueue(ctx=get_context())
        self.logger = get_parallel_logger(self.stdouterr_queue)
        self.child = Process(target=test_runner_wrapper,
                             args=(testcase_suite,
                                   self.keep_alive_child_end,
                                   self.stdouterr_queue,
                                   self.finished_child_end,
                                   self.result_child_end,
                                   self.logger)
                             )
        self.child.start()
        self.last_test_temp_dir = None
        self.last_test_vpp_binary = None
        self._last_test = None
        self.last_test_id = None
        self.vpp_pid = None
        self.last_heard = time.time()
        self.core_detected_at = None
        self.testcases_by_id = {}
        self.testclasess_with_core = {}
        for testcase in self.testcase_suite:
            self.testcases_by_id[testcase.id()] = testcase
        self.result = TestResult(testcase_suite, self.testcases_by_id)

    @property
    def last_test(self):
        return self._last_test

    @last_test.setter
    def last_test(self, test_id):
        self.last_test_id = test_id
        if test_id in self.testcases_by_id:
            testcase = self.testcases_by_id[test_id]
            self._last_test = testcase.shortDescription()
            if not self._last_test:
                self._last_test = str(testcase)
        else:
            self._last_test = test_id

    def add_testclass_with_core(self):
        if self.last_test_id in self.testcases_by_id:
            test = self.testcases_by_id[self.last_test_id]
            class_name = unittest.util.strclass(test.__class__)
            test_name = "'{}' ({})".format(get_test_description(descriptions,
                                                                test),
                                           self.last_test_id)
        else:
            test_name = self.last_test_id
            class_name = re.match(r'((tearDownClass)|(setUpClass)) '
                                  r'\((.+\..+)\)', test_name).groups()[3]
        if class_name not in self.testclasess_with_core:
            self.testclasess_with_core[class_name] = (
                test_name,
                self.last_test_vpp_binary,
                self.last_test_temp_dir)

    def close_pipes(self):
        self.keep_alive_child_end.close()
        self.finished_child_end.close()
        self.result_child_end.close()
        self.keep_alive_parent_end.close()
        self.finished_parent_end.close()
        self.result_parent_end.close()

    def was_successful(self):
        return self.result.was_successful()


def stdouterr_reader_wrapper(unread_testcases, finished_unread_testcases,
                             read_testcases):
    read_testcase = None
    while read_testcases.is_set() or unread_testcases:
        if finished_unread_testcases:
            read_testcase = finished_unread_testcases.pop()
            unread_testcases.remove(read_testcase)
        elif unread_testcases:
            read_testcase = unread_testcases.pop()
        if read_testcase:
            data = ''
            while data is not None:
                sys.stdout.write(data)
                data = read_testcase.stdouterr_queue.get()

            read_testcase.stdouterr_queue.close()
            finished_unread_testcases.discard(read_testcase)
            read_testcase = None


def handle_failed_suite(logger, last_test_temp_dir, vpp_pid):
    if last_test_temp_dir:
        # Need to create link in case of a timeout or core dump without failure
        lttd = os.path.basename(last_test_temp_dir)
        failed_dir = os.getenv('FAILED_DIR')
        link_path = '%s%s-FAILED' % (failed_dir, lttd)
        if not os.path.exists(link_path):
            os.symlink(last_test_temp_dir, link_path)
        logger.error("Symlink to failed testcase directory: %s -> %s"
                     % (link_path, lttd))

        # Report core existence
        core_path = get_core_path(last_test_temp_dir)
        if os.path.exists(core_path):
            logger.error(
                "Core-file exists in test temporary directory: %s!" %
                core_path)
            check_core_path(logger, core_path)
            logger.debug("Running 'file %s':" % core_path)
            try:
                info = check_output(["file", core_path])
                logger.debug(info)
            except CalledProcessError as e:
                logger.error("Subprocess returned with return code "
                             "while running `file' utility on core-file "
                             "returned: "
                             "rc=%s", e.returncode)
            except OSError as e:
                logger.error("Subprocess returned with OS error while "
                             "running 'file' utility "
                             "on core-file: "
                             "(%s) %s", e.errno, e.strerror)
            except Exception as e:
                logger.exception("Unexpected error running `file' utility "
                                 "on core-file")
            logger.error("gdb %s %s" %
                         (os.getenv('VPP_BIN', 'vpp'), core_path))

    if vpp_pid:
        # Copy api post mortem
        api_post_mortem_path = "/tmp/api_post_mortem.%d" % vpp_pid
        if os.path.isfile(api_post_mortem_path):
            logger.error("Copying api_post_mortem.%d to %s" %
                         (vpp_pid, last_test_temp_dir))
            shutil.copy2(api_post_mortem_path, last_test_temp_dir)


def check_and_handle_core(vpp_binary, tempdir, core_crash_test):
    if is_core_present(tempdir):
        if debug_core:
            print('VPP core detected in %s. Last test running was %s' %
                  (tempdir, core_crash_test))
            print(single_line_delim)
            spawn_gdb(vpp_binary, get_core_path(tempdir))
            print(single_line_delim)
        elif compress_core:
            print("Compressing core-file in test directory `%s'" % tempdir)
            os.system("gzip %s" % get_core_path(tempdir))


def handle_cores(failed_testcases):
    for failed_testcase in failed_testcases:
        tcs_with_core = failed_testcase.testclasess_with_core
        if tcs_with_core:
            for test, vpp_binary, tempdir in tcs_with_core.values():
                check_and_handle_core(vpp_binary, tempdir, test)


def process_finished_testsuite(wrapped_testcase_suite,
                               finished_testcase_suites,
                               failed_wrapped_testcases,
                               results):
    results.append(wrapped_testcase_suite.result)
    finished_testcase_suites.add(wrapped_testcase_suite)
    stop_run = False
    if failfast and not wrapped_testcase_suite.was_successful():
        stop_run = True

    if not wrapped_testcase_suite.was_successful():
        failed_wrapped_testcases.add(wrapped_testcase_suite)
        handle_failed_suite(wrapped_testcase_suite.logger,
                            wrapped_testcase_suite.last_test_temp_dir,
                            wrapped_testcase_suite.vpp_pid)

    return stop_run


def run_forked(testcase_suites):
    wrapped_testcase_suites = set()
    solo_testcase_suites = []
    total_test_runners = 0

    # suites are unhashable, need to use list
    results = []
    unread_testcases = set()
    finished_unread_testcases = set()
    manager = StreamQueueManager()
    manager.start()
    total_test_runners = 0
    while total_test_runners < concurrent_tests:
        if testcase_suites:
            a_suite = testcase_suites.pop(0)
            if a_suite.is_tagged_run_solo:
                solo_testcase_suites.append(a_suite)
                continue
            wrapped_testcase_suite = TestCaseWrapper(a_suite,
                                                     manager)
            wrapped_testcase_suites.add(wrapped_testcase_suite)
            unread_testcases.add(wrapped_testcase_suite)
            total_test_runners = total_test_runners + 1
        else:
            break

    while total_test_runners < 1 and solo_testcase_suites:
        if solo_testcase_suites:
            a_suite = solo_testcase_suites.pop(0)
            wrapped_testcase_suite = TestCaseWrapper(a_suite,
                                                     manager)
            wrapped_testcase_suites.add(wrapped_testcase_suite)
            unread_testcases.add(wrapped_testcase_suite)
            total_test_runners = total_test_runners + 1
        else:
            break

    read_from_testcases = threading.Event()
    read_from_testcases.set()
    stdouterr_thread = threading.Thread(target=stdouterr_reader_wrapper,
                                        args=(unread_testcases,
                                              finished_unread_testcases,
                                              read_from_testcases))
    stdouterr_thread.start()

    failed_wrapped_testcases = set()
    stop_run = False

    try:
        while wrapped_testcase_suites:
            finished_testcase_suites = set()
            for wrapped_testcase_suite in wrapped_testcase_suites:
                while wrapped_testcase_suite.result_parent_end.poll():
                    wrapped_testcase_suite.result.process_result(
                        *wrapped_testcase_suite.result_parent_end.recv())
                    wrapped_testcase_suite.last_heard = time.time()

                while wrapped_testcase_suite.keep_alive_parent_end.poll():
                    wrapped_testcase_suite.last_test, \
                        wrapped_testcase_suite.last_test_vpp_binary, \
                        wrapped_testcase_suite.last_test_temp_dir, \
                        wrapped_testcase_suite.vpp_pid = \
                        wrapped_testcase_suite.keep_alive_parent_end.recv()
                    wrapped_testcase_suite.last_heard = time.time()

                if wrapped_testcase_suite.finished_parent_end.poll():
                    wrapped_testcase_suite.finished_parent_end.recv()
                    wrapped_testcase_suite.last_heard = time.time()
                    stop_run = process_finished_testsuite(
                        wrapped_testcase_suite,
                        finished_testcase_suites,
                        failed_wrapped_testcases,
                        results) or stop_run
                    continue

                fail = False
                if wrapped_testcase_suite.last_heard + test_timeout < \
                        time.time():
                    fail = True
                    wrapped_testcase_suite.logger.critical(
                        "Child test runner process timed out "
                        "(last test running was `%s' in `%s')!" %
                        (wrapped_testcase_suite.last_test,
                         wrapped_testcase_suite.last_test_temp_dir))
                elif not wrapped_testcase_suite.child.is_alive():
                    fail = True
                    wrapped_testcase_suite.logger.critical(
                        "Child test runner process unexpectedly died "
                        "(last test running was `%s' in `%s')!" %
                        (wrapped_testcase_suite.last_test,
                         wrapped_testcase_suite.last_test_temp_dir))
                elif wrapped_testcase_suite.last_test_temp_dir and \
                        wrapped_testcase_suite.last_test_vpp_binary:
                    if is_core_present(
                            wrapped_testcase_suite.last_test_temp_dir):
                        wrapped_testcase_suite.add_testclass_with_core()
                        if wrapped_testcase_suite.core_detected_at is None:
                            wrapped_testcase_suite.core_detected_at = \
                                time.time()
                        elif wrapped_testcase_suite.core_detected_at + \
                                core_timeout < time.time():
                            wrapped_testcase_suite.logger.critical(
                                "Child test runner process unresponsive and "
                                "core-file exists in test temporary directory "
                                "(last test running was `%s' in `%s')!" %
                                (wrapped_testcase_suite.last_test,
                                 wrapped_testcase_suite.last_test_temp_dir))
                            fail = True

                if fail:
                    wrapped_testcase_suite.child.terminate()
                    try:
                        # terminating the child process tends to leave orphan
                        # VPP process around
                        if wrapped_testcase_suite.vpp_pid:
                            os.kill(wrapped_testcase_suite.vpp_pid,
                                    signal.SIGTERM)
                    except OSError:
                        # already dead
                        pass
                    wrapped_testcase_suite.result.crashed = True
                    wrapped_testcase_suite.result.process_result(
                        wrapped_testcase_suite.last_test_id, ERROR)
                    stop_run = process_finished_testsuite(
                        wrapped_testcase_suite,
                        finished_testcase_suites,
                        failed_wrapped_testcases,
                        results) or stop_run

            for finished_testcase in finished_testcase_suites:
                # Somewhat surprisingly, the join below may
                # timeout, even if client signaled that
                # it finished - so we note it just in case.
                join_start = time.time()
                finished_testcase.child.join(test_finished_join_timeout)
                join_end = time.time()
                if join_end - join_start >= test_finished_join_timeout:
                    finished_testcase.logger.error(
                        "Timeout joining finished test: %s (pid %d)" %
                        (finished_testcase.last_test,
                         finished_testcase.child.pid))
                finished_testcase.close_pipes()
                wrapped_testcase_suites.remove(finished_testcase)
                finished_unread_testcases.add(finished_testcase)
                finished_testcase.stdouterr_queue.put(None)
                total_test_runners = total_test_runners - 1
                if stop_run:
                    while testcase_suites:
                        results.append(TestResult(testcase_suites.pop(0)))
                elif testcase_suites:
                    a_testcase = testcase_suites.pop(0)
                    while a_testcase and a_testcase.is_tagged_run_solo:
                        solo_testcase_suites.append(a_testcase)
                        if testcase_suites:
                            a_testcase = testcase_suites.pop(0)
                        else:
                            a_testcase = None
                    if a_testcase:
                        new_testcase = TestCaseWrapper(a_testcase,
                                                       manager)
                        wrapped_testcase_suites.add(new_testcase)
                        total_test_runners = total_test_runners + 1
                        unread_testcases.add(new_testcase)
                if solo_testcase_suites and total_test_runners == 0:
                    a_testcase = solo_testcase_suites.pop(0)
                    new_testcase = TestCaseWrapper(a_testcase,
                                                   manager)
                    wrapped_testcase_suites.add(new_testcase)
                    total_test_runners = total_test_runners + 1
                    unread_testcases.add(new_testcase)
            time.sleep(0.1)
    except Exception:
        for wrapped_testcase_suite in wrapped_testcase_suites:
            wrapped_testcase_suite.child.terminate()
            wrapped_testcase_suite.stdouterr_queue.put(None)
        raise
    finally:
        read_from_testcases.clear()
        stdouterr_thread.join(test_timeout)
        manager.shutdown()

    handle_cores(failed_wrapped_testcases)
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
                self.suites[self.suite_name].is_tagged_run_solo = False
            self.suites[self.suite_name].addTest(test_method)
            if test_method.is_tagged_run_solo():
                self.suites[self.suite_name].is_tagged_run_solo = True

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
        if self.filter_file_name:
            fn_match = fnmatch.fnmatch(file_name, self.filter_file_name)
            if not fn_match:
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


class AllResults(dict):
    def __init__(self):
        super(AllResults, self).__init__()
        self.all_testcases = 0
        self.results_per_suite = []
        self[PASS] = 0
        self[FAIL] = 0
        self[ERROR] = 0
        self[SKIP] = 0
        self[TEST_RUN] = 0
        self.rerun = []
        self.testsuites_no_tests_run = []

    def add_results(self, result):
        self.results_per_suite.append(result)
        result_types = [PASS, FAIL, ERROR, SKIP, TEST_RUN]
        for result_type in result_types:
            self[result_type] += len(result[result_type])

    def add_result(self, result):
        retval = 0
        self.all_testcases += result.testcase_suite.countTestCases()
        self.add_results(result)

        if result.no_tests_run():
            self.testsuites_no_tests_run.append(result.testcase_suite)
            if result.crashed:
                retval = -1
            else:
                retval = 1
        elif not result.was_successful():
            retval = 1

        if retval != 0:
            self.rerun.append(result.testcase_suite)

        return retval

    def print_results(self):
        print('')
        print(double_line_delim)
        print('TEST RESULTS:')
        print('     Scheduled tests: {}'.format(self.all_testcases))
        print('      Executed tests: {}'.format(self[TEST_RUN]))
        print('        Passed tests: {}'.format(
            colorize(str(self[PASS]), GREEN)))
        if self[SKIP] > 0:
            print('       Skipped tests: {}'.format(
                colorize(str(self[SKIP]), YELLOW)))
        if self.not_executed > 0:
            print('  Not Executed tests: {}'.format(
                colorize(str(self.not_executed), RED)))
        if self[FAIL] > 0:
            print('            Failures: {}'.format(
                colorize(str(self[FAIL]), RED)))
        if self[ERROR] > 0:
            print('              Errors: {}'.format(
                colorize(str(self[ERROR]), RED)))

        if self.all_failed > 0:
            print('FAILURES AND ERRORS IN TESTS:')
            for result in self.results_per_suite:
                failed_testcase_ids = result[FAIL]
                errored_testcase_ids = result[ERROR]
                old_testcase_name = None
                if failed_testcase_ids:
                    for failed_test_id in failed_testcase_ids:
                        new_testcase_name, test_name = \
                            result.get_testcase_names(failed_test_id)
                        if new_testcase_name != old_testcase_name:
                            print('  Testcase name: {}'.format(
                                colorize(new_testcase_name, RED)))
                            old_testcase_name = new_testcase_name
                        print('    FAILURE: {} [{}]'.format(
                            colorize(test_name, RED), failed_test_id))
                if errored_testcase_ids:
                    for errored_test_id in errored_testcase_ids:
                        new_testcase_name, test_name = \
                            result.get_testcase_names(errored_test_id)
                        if new_testcase_name != old_testcase_name:
                            print('  Testcase name: {}'.format(
                                colorize(new_testcase_name, RED)))
                            old_testcase_name = new_testcase_name
                        print('      ERROR: {} [{}]'.format(
                            colorize(test_name, RED), errored_test_id))
        if self.testsuites_no_tests_run:
            print('TESTCASES WHERE NO TESTS WERE SUCCESSFULLY EXECUTED:')
            tc_classes = set()
            for testsuite in self.testsuites_no_tests_run:
                for testcase in testsuite:
                    tc_classes.add(get_testcase_doc_name(testcase))
            for tc_class in tc_classes:
                print('  {}'.format(colorize(tc_class, RED)))

        print(double_line_delim)
        print('')

    @property
    def not_executed(self):
        return self.all_testcases - self[TEST_RUN]

    @property
    def all_failed(self):
        return self[FAIL] + self[ERROR]


def parse_results(results):
    """
    Prints the number of scheduled, executed, not executed, passed, failed,
    errored and skipped tests and details about failed and errored tests.

    Also returns all suites where any test failed.

    :param results:
    :return:
    """

    results_per_suite = AllResults()
    crashed = False
    failed = False
    for result in results:
        result_code = results_per_suite.add_result(result)
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

    test_finished_join_timeout = 15

    retries = parse_digit_env("RETRIES", 0)

    debug = os.getenv("DEBUG", "n").lower() in ["gdb", "gdbserver"]

    debug_core = os.getenv("DEBUG", "").lower() == "core"
    compress_core = framework.BoolEnvironmentVariable("CORE_COMPRESS")

    step = framework.BoolEnvironmentVariable("STEP")
    force_foreground = framework.BoolEnvironmentVariable("FORCE_FOREGROUND")

    run_interactive = debug or step or force_foreground

    try:
        num_cpus = len(os.sched_getaffinity(0))
    except AttributeError:
        num_cpus = multiprocessing.cpu_count()
    shm_free = psutil.disk_usage('/dev/shm').free

    print('OS reports %s available cpu(s). Free shm: %s' % (
        num_cpus, "{:,}MB".format(shm_free / (1024 * 1024))))

    test_jobs = os.getenv("TEST_JOBS", "1").lower()  # default = 1 process
    if test_jobs == 'auto':
        if run_interactive:
            concurrent_tests = 1
            print('Interactive mode required, running on one core')
        else:
            shm_max_processes = 1
            if shm_free < min_req_shm:
                raise Exception('Not enough free space in /dev/shm. Required '
                                'free space is at least %sM.'
                                % (min_req_shm >> 20))
            else:
                extra_shm = shm_free - min_req_shm
                shm_max_processes += extra_shm // shm_per_process
            concurrent_tests = min(cpu_count(), shm_max_processes)
            print('Found enough resources to run tests with %s cores'
                  % concurrent_tests)
    elif test_jobs.isdigit():
        concurrent_tests = int(test_jobs)
        print("Running on %s core(s) as set by 'TEST_JOBS'." %
              concurrent_tests)
    else:
        concurrent_tests = 1
        print('Running on one core.')

    if run_interactive and concurrent_tests > 1:
        raise NotImplementedError(
            'Running tests interactively (DEBUG is gdb or gdbserver or STEP '
            'is set) in parallel (TEST_JOBS is more than 1) is not supported')

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

    ignore_path = os.getenv("VENV_PATH", None)
    cb = SplitToSuitesCallback(filter_cb)
    for d in args.dir:
        print("Adding tests from directory tree %s" % d)
        discover_tests(d, cb, ignore_path)

    # suites are not hashable, need to use list
    suites = []
    tests_amount = 0
    for testcase_suite in cb.suites.values():
        tests_amount += testcase_suite.countTestCases()
        suites.append(testcase_suite)

    print("%s out of %s tests match specified filters" % (
        tests_amount, tests_amount + cb.filtered.countTestCases()))

    if not running_extended_tests:
        print("Not running extended tests (some tests will be skipped)")

    attempts = retries + 1
    if attempts > 1:
        print("Perform %s attempts to pass the suite..." % attempts)

    if run_interactive and suites:
        # don't fork if requiring interactive terminal
        print('Running tests in foreground in the current process')
        full_suite = unittest.TestSuite()
        full_suite.addTests(suites)
        result = VppTestRunner(verbosity=verbose,
                               failfast=failfast,
                               print_summary=True).run(full_suite)
        was_successful = result.wasSuccessful()
        if not was_successful:
            for test_case_info in result.failed_test_cases_info:
                handle_failed_suite(test_case_info.logger,
                                    test_case_info.tempdir,
                                    test_case_info.vpp_pid)
                if test_case_info in result.core_crash_test_cases_info:
                    check_and_handle_core(test_case_info.vpp_bin_path,
                                          test_case_info.tempdir,
                                          test_case_info.core_crash_test)

        sys.exit(not was_successful)
    else:
        print('Running each VPPTestCase in a separate background process'
              ' with {} parallel process(es)'.format(concurrent_tests))
        exit_code = 0
        while suites and attempts > 0:
            results = run_forked(suites)
            exit_code, suites = parse_results(results)
            attempts -= 1
            if exit_code == 0:
                print('Test run was successful')
            else:
                print('%s attempt(s) left.' % attempts)
        sys.exit(exit_code)
