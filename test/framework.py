#!/usr/bin/env python

import subprocess
import unittest
import tempfile
import time
import resource
from time import sleep
from collections import deque
from threading import Thread
from inspect import getdoc
import multiprocessing
import pickle

from scapy.packet import Raw

from hook import StepHook, PollHook
from vpp_pg_interface import VppPGInterface
from vpp_lo_interface import VppLoInterface
from vpp_papi_provider import VppPapiProvider
from log import *

"""
  Test framework module.

  The module provides a set of tools for constructing and running tests and
  representing the results.
"""


class _PacketInfo(object):

    """Private class to create packet info object.

    Help process information about the next packet.
    Set variables to default values.
    """
    #: Store the index of the packet.
    index = -1
    #: Store the index of the source packet generator interface of the packet.
    src = -1
    #: Store the index of the destination packet generator interface
    #: of the packet.
    dst = -1
    #: Store the copy of the former packet.
    data = None

    def __eq__(self, other):
        index = self.index == other.index
        src = self.src == other.src
        dst = self.dst == other.dst
        data = self.data == other.data
        return index and src and dst and data


def pump_output(out, deque):
    for line in iter(out.readline, b''):
        deque.append(line)


class VppDebugOptions(object):
    def __init__(self, step, debug_core, debug_gdb, debug_gdbserver):
        self.step = step
        self.debug_core = debug_core
        self.debug_gdb = debug_gdb
        self.debug_gdbserver = debug_gdbserver


class VppTestCase(unittest.TestCase):

    """This subclass is a base class for VPP test cases that are implemented as
    classes. It provides methods to create and run test case.
    """

    @property
    def logger(self):
        return self._logger

    # Logger is set up automatically before setUp and setUpClass methods
    @logger.setter
    def logger(self, value):
        self._logger = value

    @property
    def tempdir(self):
        return self.tempdir

    # Tempdir is set up automatically before setUp and setUpClass methods
    @tempdir.setter
    def tempdir(self, value):
        self._tempdir = value

    @property
    def debug_options(self):
        return self._debug_options

    # Debug options are set up automatically before setUp and setUpClass methods
    @debug_options.setter
    def debug_options(self, value):
        self._debug_options = value

    @property
    def packet_infos(self):
        """List of packet infos"""
        return self._packet_infos

    @packet_infos.setter
    def packet_infos(self, value):
        self._packet_infos = value

    @classmethod
    def instance(cls):
        """Return the instance of this testcase"""
        return cls.test_instance

    def short_description_with_options(self):
        return self.options.test_method_doc(self._testMethodDoc)

    @classmethod
    def setUpConstants(cls):
        """ Set-up the test case class based on environment variables """
        cls.vpp_bin = os.getenv('VPP_TEST_BIN', "vpp")
        cls.plugin_path = os.getenv('VPP_TEST_PLUGIN_PATH')
        debug_cli = ""
        dopt = cls.debug_options
        if dopt.step or dopt.debug_gdb or dopt.debug_gdbserver:
            debug_cli = "cli-listen localhost:5002"
        cls.vpp_cmdline = [cls.vpp_bin, "unix", "{", "nodaemon", debug_cli, "}",
                           "api-segment", "{", "prefix", cls.shm_prefix, "}"]
        cls.vpp_cmdline.extend(cls.options.optional_vpp_args)
        if cls.plugin_path is not None:
            cls.vpp_cmdline.extend(["plugin_path", cls.plugin_path])
        cls.logger.info("vpp_cmdline: %s" % cls.vpp_cmdline)

    @classmethod
    def wait_for_enter(cls):
        dopt = cls.debug_options
        if dopt.debug_gdbserver:
            print(double_line_delim)
            print("Spawned GDB server with PID: %d" % cls.vpp.pid)
        elif dopt.debug_gdb:
            print(double_line_delim)
            print("Spawned VPP with PID: %d" % cls.vpp.pid)
        else:
            cls.logger.debug("Spawned VPP with PID: %d" % cls.vpp.pid)
            return
        print(single_line_delim)
        print("You can debug the VPP using e.g.:")
        if dopt.debug_gdbserver:
            print("gdb " + cls.vpp_bin + " -ex 'target remote localhost:7777'")
            print("Now is the time to attach a gdb by running the above "
                  "command, set up breakpoints etc. and then resume VPP from "
                  "within gdb by issuing the 'continue' command")
        elif dopt.debug_gdb:
            print("gdb " + cls.vpp_bin + " -ex 'attach %s'" % cls.vpp.pid)
            print("Now is the time to attach a gdb by running the above "
                  "command and set up breakpoints etc.")
        print(single_line_delim)
        raw_input("Press ENTER to continue running the testcase...")

    @classmethod
    def run_vpp(cls):
        cmdline = cls.vpp_cmdline

        if cls.debug_options.debug_gdbserver:
            gdbserver = '/usr/bin/gdbserver'
            if not os.path.isfile(gdbserver) or \
                    not os.access(gdbserver, os.X_OK):
                raise Exception("gdbserver binary '%s' does not exist or is "
                                "not executable" % gdbserver)

            cmdline = [gdbserver, 'localhost:7777'] + cls.vpp_cmdline
            cls.logger.info("Gdbserver cmdline is %s", " ".join(cmdline))

        try:
            cls.vpp = subprocess.Popen(cmdline,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,
                                       bufsize=1)
        except Exception as e:
            cls.logger.critical("Couldn't start vpp: %s" % e)
            raise

        cls.wait_for_enter()

    @classmethod
    def setUpClass(cls):
        """
        Perform class setup before running the testcase
        Remove shared memory files, start vpp and connect the vpp-api
        """
        cls.shm_prefix = cls.tempdir.split("/")[-1]
        os.chdir(cls.tempdir)
        cls.logger.info("Temporary dir is %s, shm prefix is %s",
                        cls.tempdir, cls.shm_prefix)
        cls.setUpConstants()
        cls.pg_streams = []
        cls.packet_infos = {}
        cls._last_worker = None
        cls.verbose = 0
        cls.vpp_dead = False
        dopt = cls.debug_options
        # need to catch exceptions here because if we raise, then the cleanup
        # doesn't get called and we might end with a zombie vpp
        try:
            cls.run_vpp()
            cls.vpp_stdout_deque = deque()
            cls.vpp_stdout_reader_thread = Thread(target=pump_output, args=(
                cls.vpp.stdout, cls.vpp_stdout_deque))
            cls.vpp_stdout_reader_thread.start()
            cls.vpp_stderr_deque = deque()
            cls.vpp_stderr_reader_thread = Thread(target=pump_output, args=(
                cls.vpp.stderr, cls.vpp_stderr_deque))
            cls.vpp_stderr_reader_thread.start()
            cls.vapi = VppPapiProvider(cls.shm_prefix, cls.shm_prefix, cls)
            if dopt.step:
                hook = StepHook(cls)
            else:
                hook = PollHook(cls)
            cls.vapi.register_hook(hook)
            time.sleep(0.1)
            hook.poll_vpp()
            try:
                cls.vapi.connect()
            except:
                if dopt.debug_gdbserver:
                    print(colorize("You're running VPP inside gdbserver but "
                                   "VPP-API connection failed, did you forget "
                                   "to 'continue' VPP from within gdb?", RED))
                raise
        except:
            t, v, tb = sys.exc_info()
            try:
                cls.quit()
            except:
                pass
            raise t, v, tb

    @classmethod
    def quit(cls):
        """
        Disconnect vpp-api, kill vpp and cleanup shared memory files
        """
        dopt = cls.debug_options
        if (dopt.debug_gdbserver or dopt.debug_gdb) and hasattr(cls, 'vpp'):
            cls.vpp.poll()
            if cls.vpp.returncode is None:
                print(double_line_delim)
                print("VPP or GDB server is still running")
                print(single_line_delim)
                raw_input("When done debugging, press ENTER to kill the process"
                          " and finish running the testcase...")

        if hasattr(cls, 'vpp'):
            if hasattr(cls, 'vapi'):
                cls.vapi.disconnect()
            cls.vpp.poll()
            if cls.vpp.returncode is None:
                cls.vpp.terminate()
            del cls.vpp

        if hasattr(cls, 'vpp_stdout_deque'):
            cls.logger.info(single_line_delim)
            cls.logger.info('VPP output to stdout while running %s:',
                            cls.__name__)
            cls.logger.info(single_line_delim)
            f = open(cls.tempdir + '/vpp_stdout.txt', 'w')
            vpp_output = "".join(cls.vpp_stdout_deque)
            f.write(vpp_output)
            cls.logger.info('\n%s', vpp_output)
            cls.logger.info(single_line_delim)

        if hasattr(cls, 'vpp_stderr_deque'):
            cls.logger.info(single_line_delim)
            cls.logger.info('VPP output to stderr while running %s:',
                            cls.__name__)
            cls.logger.info(single_line_delim)
            f = open(cls.tempdir + '/vpp_stderr.txt', 'w')
            vpp_output = "".join(cls.vpp_stderr_deque)
            f.write(vpp_output)
            cls.logger.info('\n%s', vpp_output)
            cls.logger.info(single_line_delim)

    @classmethod
    def tearDownClass(cls):
        """ Perform final cleanup after running all tests in this test-case """
        cls.quit()

    def tearDown(self):
        """ Show various debug prints after each test """
        if not self.vpp_dead:
            self.logger.debug(self.vapi.cli("show trace"))
            self.logger.info(self.vapi.ppcli("show int"))
            self.logger.info(self.vapi.ppcli("show hardware"))
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show run"))

    def setUp(self):
        """ Clear trace before running each test"""
        if self.vpp_dead:
            raise Exception("VPP is dead when setting up the test")
        time.sleep(.1)
        self.vpp_stdout_deque.append(
            "--- test setUp() for %s.%s(%s) starts here ---\n" %
            (self.__class__.__name__, self._testMethodName,
             self._testMethodDoc))
        self.vpp_stderr_deque.append(
            "--- test setUp() for %s.%s(%s) starts here ---\n" %
            (self.__class__.__name__, self._testMethodName,
             self._testMethodDoc))
        self.vapi.cli("clear trace")
        # store the test instance inside the test class - so that objects
        # holding the class can access instance methods (like assertEqual)
        type(self).test_instance = self

    @classmethod
    def pick_worker(cls):
        if cls.options.number_of_workers == 0:
            return None
        if cls._last_worker is None:
            next_worker = 0
        else:
            next_worker = (cls._last_worker + 1) % cls.options.number_of_workers
        cls._last_worker = next_worker
        return next_worker

    @classmethod
    def pg_enable_capture(cls, interfaces):
        """
        Enable capture on packet-generator interfaces

        :param interfaces: iterable interface indexes

        """
        for i in interfaces:
            i.enable_capture()

    @classmethod
    def pg_start(cls, sleep_time=1):
        """
        Enable the packet-generator and send all prepared packet streams
        Remove the packet streams afterwards
        """
        cls.vapi.cli("trace add pg-input 50")  # 50 is maximum
        cls.vapi.cli('packet-generator enable')
        sleep(sleep_time)  # give VPP some time to process the packets
        for stream in cls.pg_streams:
            cls.vapi.cli('packet-generator delete %s' % stream)
        cls.pg_streams = []

    @classmethod
    def create_pg_interfaces(cls, interfaces):
        """
        Create packet-generator interfaces

        :param interfaces: iterable indexes of the interfaces

        """
        result = []
        for i in interfaces:
            intf = VppPGInterface(cls, i)
            setattr(cls, intf.name, intf)
            result.append(intf)
        cls.pg_interfaces = result
        return result

    @classmethod
    def create_loopback_interfaces(cls, interfaces):
        """
        Create loopback interfaces

        :param interfaces: iterable indexes of the interfaces

        """
        result = []
        for i in interfaces:
            intf = VppLoInterface(cls, i)
            setattr(cls, intf.name, intf)
            result.append(intf)
        cls.lo_interfaces = result
        return result

    @staticmethod
    def extend_packet(packet, size):
        """
        Extend packet to given size by padding with spaces
        NOTE: Currently works only when Raw layer is present.

        :param packet: packet
        :param size: target size

        """
        packet_len = len(packet) + 4
        extend = size - packet_len
        if extend > 0:
            packet[Raw].load += ' ' * extend

    def add_packet_info_to_list(self, info):
        """
        Add packet info to the testcase's packet info list

        :param info: packet info

        """
        info.index = len(self.packet_infos)
        self.packet_infos[info.index] = info

    def create_packet_info(self, src_pg_index, dst_pg_index):
        """
        Create packet info object containing the source and destination indexes
        and add it to the testcase's packet info list

        :param src_pg_index: source packet-generator index
        :param dst_pg_index: destination packet-generator index

        :returns: _PacketInfo object

        """
        info = _PacketInfo()
        self.add_packet_info_to_list(info)
        info.src = src_pg_index
        info.dst = dst_pg_index
        return info

    @staticmethod
    def info_to_payload(info):
        """
        Convert _PacketInfo object to packet payload

        :param info: _PacketInfo object

        :returns: string containing serialized data from packet info
        """
        return "%d %d %d" % (info.index, info.src, info.dst)

    @staticmethod
    def payload_to_info(payload):
        """
        Convert packet payload to _PacketInfo object

        :param payload: packet payload

        :returns: _PacketInfo object containing de-serialized data from payload

        """
        numbers = payload.split()
        info = _PacketInfo()
        info.index = int(numbers[0])
        info.src = int(numbers[1])
        info.dst = int(numbers[2])
        return info

    def get_next_packet_info(self, info):
        """
        Iterate over the packet info list stored in the testcase
        Start iteration with first element if info is None
        Continue based on index in info if info is specified

        :param info: info or None
        :returns: next info in list or None if no more infos
        """
        if info is None:
            next_index = 0
        else:
            next_index = info.index + 1
        if next_index == len(self.packet_infos):
            return None
        else:
            return self.packet_infos[next_index]

    def get_next_packet_info_for_interface(self, src_index, info):
        """
        Search the packet info list for the next packet info with same source
        interface index

        :param src_index: source interface index to search for
        :param info: packet info - where to start the search
        :returns: packet info or None

        """
        while True:
            info = self.get_next_packet_info(info)
            if info is None:
                return None
            if info.src == src_index:
                return info

    def get_next_packet_info_for_interface2(self, src_index, dst_index, info):
        """
        Search the packet info list for the next packet info with same source
        and destination interface indexes

        :param src_index: source interface index to search for
        :param dst_index: destination interface index to search for
        :param info: packet info - where to start the search
        :returns: packet info or None

        """
        while True:
            info = self.get_next_packet_info_for_interface(src_index, info)
            if info is None:
                return None
            if info.dst == dst_index:
                return info

    def assert_equal(self, real_value, expected_value, name_or_class=None):
        if name_or_class is None:
            self.assertEqual(real_value, expected_value, msg)
            return
        try:
            msg = "Invalid %s: %d('%s') does not match expected value %d('%s')"
            msg = msg % (getdoc(name_or_class).strip(),
                         real_value, str(name_or_class(real_value)),
                         expected_value, str(name_or_class(expected_value)))
        except:
            msg = "Invalid %s: %s does not match expected value %s" % (
                name_or_class, real_value, expected_value)

        self.assertEqual(real_value, expected_value, msg)

    def assert_in_range(
            self,
            real_value,
            expected_min,
            expected_max,
            name=None):
        if name is None:
            msg = None
        else:
            msg = "Invalid %s: %s out of range <%s,%s>" % (
                name, real_value, expected_min, expected_max)
        self.assertTrue(expected_min <= real_value <= expected_max, msg)


class VppTestRunner(unittest.TextTestRunner):

    """
    A basic test runner implementation which prints results on standard error.
    """

    def __init__(self, stream=sys.stderr, descriptions=True, verbosity=1,
                 enabled_multiprocessing=False, failfast=False, buffer=False,
                 resultclass=None):
        super(VppTestRunner, self).__init__(
            stream, descriptions, verbosity, failfast, buffer, resultclass)
        self.enabled_multiprocessing = enabled_multiprocessing

    @property
    def resultclass(self):
        """Class maintaining the results of the tests"""
        return VppTestResult

    def _makeResult(self):
        return self.resultclass(self.stream, self.descriptions, self.verbosity,
                                self.enabled_multiprocessing)

    def run(self, test):
        """
        Run the tests

        :param test:

        """
        return super(VppTestRunner, self).run(test)


class VppTestResult(unittest.TestResult):

    """
    @property result_string
     String variable to store the test case result string.
    @property errors
     List variable containing 2-tuples of TestCase instances and strings
     holding formatted tracebacks. Each tuple represents a test which
     raised an unexpected exception.
    @property failures
     List variable containing 2-tuples of TestCase instances and strings
     holding formatted tracebacks. Each tuple represents a test where
     a failure was explicitly signalled using the TestCase.assert*()
     methods.
    """

    def __init__(self, stream, descriptions, verbosity, enabled_multiprocessing):
        """
        :param stream File descriptor to store where to report test results. Set
            to the standard error stream by default.
        :param descriptions Boolean variable to store information if to use test
            case descriptions.
        :param verbosity Integer variable to store required verbosity level.
        """
        unittest.TestResult.__init__(self, stream, descriptions, verbosity)
        self.stream = stream
        self.descriptions = descriptions
        self.verbosity = verbosity
        self.enabled_multiprocessing = enabled_multiprocessing
        self.result_string = None

    def addSuccess(self, test):
        """
        Record a test succeeded result

        :param test:

        """
        unittest.TestResult.addSuccess(self, test)
        self.result_string = colorize("OK", GREEN)

    def addSkip(self, test, reason):
        """
        Record a test skipped.

        :param test:
        :param reason:

        """
        unittest.TestResult.addSkip(self, test, reason)
        self.result_string = colorize("SKIP", YELLOW)

    def addFailure(self, test, err):
        """
        Record a test failed result

        :param test:
        :param err: error message

        """
        unittest.TestResult.addFailure(self, test, err)
        if hasattr(test, 'tempdir'):
            self.result_string = colorize("FAIL", RED) + \
                ' [ temp dir used by test case: ' + test.tempdir + ' ]'
        else:
            self.result_string = colorize("FAIL", RED) + ' [no temp dir]'

    def addError(self, test, err):
        """
        Record a test error result

        :param test:
        :param err: error message

        """
        unittest.TestResult.addError(self, test, err)
        if hasattr(test, 'tempdir'):
            self.result_string = colorize("ERROR", RED) + \
                ' [ temp dir used by test case: ' + test.tempdir + ' ]'
        else:
            self.result_string = colorize("ERROR", RED) + ' [no temp dir]'

    def mergeWithResult(self, result):
        self.errors.extend(result.errors)
        self.failures.extend(result.failures)
        self.skipped.extend(result.skipped)
        self.expectedFailures.extend(result.expectedFailures)
        self.unexpectedSuccesses.extend(result.unexpectedSuccesses)
        self.testsRun += result.testsRun

    def getDescription(self, test):
        """
        Get test description

        :param test:
        :returns: test description

        """
        # TODO: if none print warning not raise exception
        if self.enabled_multiprocessing:
            short_description = test.short_description_with_options()
        else:
            short_description = test.shortDescription()
        if self.descriptions and short_description:
            return short_description
        else:
            return str(test)

    def startTest(self, test):
        """
        Start a test

        :param test:

        """
        unittest.TestResult.startTest(self, test)
        if self.verbosity > 0 and not self.enabled_multiprocessing:
            self.stream.writeln(
                "Starting " + self.getDescription(test) + " ...")
            self.stream.writeln(single_line_delim)

    def stopTest(self, test):
        """
        Stop a test

        :param test:

        """
        unittest.TestResult.stopTest(self, test)
        if self.verbosity > 0 and not self.enabled_multiprocessing:
            self.stream.writeln(single_line_delim)
            self.stream.writeln("%-60s%s" %
                                (self.getDescription(test), self.result_string))
            self.stream.writeln(single_line_delim)
        else:
            self.stream.writeln("%-60s%s" %
                                (self.getDescription(test), self.result_string))

    def printErrors(self):
        """
        Print errors from running the test case
        """
        self.stream.writeln()
        self.printErrorList('ERROR', self.errors)
        self.printErrorList('FAIL', self.failures)

    def printErrorList(self, flavour, errors):
        """
        Print error list to the output stream together with error type
        and test case description.

        :param flavour: error type
        :param errors: iterable errors

        """
        for test, err in errors:
            self.stream.writeln(double_line_delim)
            self.stream.writeln("%s: %s" %
                                (flavour, self.getDescription(test)))
            self.stream.writeln(single_line_delim)
            self.stream.writeln("%s" % err)


class PickleableVppTestResult(object):

    def __init__(self, result, mp_helper):
        self._mp_helper = mp_helper

        self.errors = self._convert_to_id(result.errors)
        self.failures = self._convert_to_id(result.failures)
        self.skipped = self._convert_to_id(result.skipped)
        self.expectedFailures = self._convert_to_id(result.expectedFailures)
        self.unexpectedSuccesses = self._convert_to_id(
            result.unexpectedSuccesses)

        self.testsRun = result.testsRun

        self.descriptions = result.descriptions
        self.verbosity = result.verbosity
        self.enabled_multiprocessing = result.enabled_multiprocessing

        del self._mp_helper

    def _convert_to_id(self, tuples):
        res = []
        for tuple in tuples:
            if isinstance(tuple[0], unittest.suite._ErrorHolder):
                a = tuple[0]
            else:
                a = self._mp_helper.get_id_of_object(tuple[0])
            res.append((a, tuple[1]))
        return res

    def _convert_to_object(self, tuples):
        res = []
        for tuple in tuples:
            if isinstance(tuple[0], unittest.suite._ErrorHolder):
                a = tuple[0]
            else:
                a = (self._mp_helper.get_object_by_id(tuple[0]))
            res.append((a, tuple[1]))
        return res

    def to_vpp_test_result(self, result, mp_helper):
        self._mp_helper = mp_helper

        result.errors = self._convert_to_object(self.errors)
        result.failures = self._convert_to_object(self.failures)
        result.skipped = self._convert_to_object(self.skipped)
        result.expectedFailures = self._convert_to_object(
            self.expectedFailures)
        result.unexpectedSuccesses = self._convert_to_object(
            self.unexpectedSuccesses)
        result.testsRun = self.testsRun

        del self._mp_helper


class MultiprocessingHelper(object):

    def __init__(self):
        self.object_to_id = dict()
        self.id_to_object = dict()

    def add_object(self, an_object):
        assert (an_object not in self.object_to_id)
        new_id = len(self.object_to_id)
        self.object_to_id[an_object] = new_id
        self.id_to_object[new_id] = an_object

    def get_object_by_id(self, id):
        return self.id_to_object[id]

    def get_id_of_object(self, an_object):
        return self.object_to_id[an_object]


class TestCaseProcess(multiprocessing.Process):

    def __init__(self, name, suite, result, mp_helper):
        assert(isinstance(suite, TestCaseClassTestSuite))
        super(TestCaseProcess, self).__init__()
        self.name = name
        self.suite = suite
        self.inner_result = result.__class__(stream=result.stream,
                                             descriptions=result.descriptions,
                                             verbosity=result.verbosity,
                                             enabled_multiprocessing
                                             =result.enabled_multiprocessing)
        self.result = None
        self.mp_helper = mp_helper
        self._is_alive = True
        self.tempdir = self.suite.cls.tempdir
        self.result_file = self.tempdir + '/result'

    def is_alive(self):
        if not self._is_alive:
            return False
        self._is_alive = super(TestCaseProcess, self).is_alive()
        return self._is_alive

    def run(self):
        self.suite(self.inner_result)
        result = PickleableVppTestResult(self.inner_result, self.mp_helper)
        pickle.dump(result, open(self.result_file, 'wb'))

    def read_result(self):
        assert (not self.is_alive())
        self.result = VppTestResult(self.inner_result.stream,
                                    self.inner_result.descriptions,
                                    self.inner_result.verbosity,
                                    self.inner_result.enabled_multiprocessing)
        res = pickle.load(open(self.result_file, 'rb'))
        res.to_vpp_test_result(self.result, self.mp_helper)
        return self.result


class TestCaseProcessPool(object):

    def __init__(self, max_n):
        self.max_n = max_n
        self.processes = set()
        self.finished_processes = set()
        self.mp_helper = MultiprocessingHelper()

    def __iter__(self):
        return self.processes.__iter__()

    def full(self):
        return len(self.processes) == self.max_n

    def empty(self):
        return len(self.processes) == 0

    def update(self):
        finished = filter(lambda proc: not proc.is_alive(), self.processes)
        map(lambda proc: self.processes.remove(proc), finished)
        self.finished_processes.update(finished)

    def wait(self):
        try:
            (pid, status) = os.wait()
            for proc in self.processes:
                if proc.pid == pid:
                    proc._is_alive = False
        except:
            pass
        self.update()

    def wait_not_full(self):
        """Wait until pool is not full"""
        self.update()
        while self.full():
            self.wait()

    def start_new_process(self, test, result):
        assert (not self.full())
        proc = TestCaseProcess(test.name, test, result, self.mp_helper)
        self.processes.add(proc)
        proc.start()
        return proc


class ParallelTestSuite(unittest.TestSuite):

    def __init__(self, tests=()):
        super(ParallelTestSuite, self).__init__(tests)
        self.process_pool = None

    def set_process_pool(self, process_pool):
        self.process_pool = process_pool

    def _enabled_multiprocessing(self):
        return self.process_pool is not None

    @staticmethod
    def _has_test(test_suite):
        for test in test_suite:
            return True
        return False

    def _run_child(self, test, result):
        if test.__class__.__name__ == 'ModuleImportFailure':
            return
        if not self._has_test(test):
            return
        if not isinstance(test, TestCaseClassTestSuite):
            test(result)
            return
        test.cls.tempdir = tempfile.mkdtemp(prefix=test.cls._tmpdir_prefix)
        if not self._enabled_multiprocessing():
            test(result)
            return
        self.process_pool.wait_not_full()
        self.process_pool.start_new_process(test, result)
        while self.process_pool.finished_processes:
            proc = self.process_pool.finished_processes.pop()
            proc_result = proc.read_result()
            result.mergeWithResult(proc_result)

    def run(self, result, debug=False):
        topLevel = False
        if getattr(result, '_testRunEntered', False) is False:
            result._testRunEntered = topLevel = True

        for test in self:
            if result.shouldStop:
                break

            if not debug:
                self._run_child(test, result)
            else:
                test.debug()

        if topLevel:
            result._testRunEntered = False
            if self._enabled_multiprocessing():
                while not self.process_pool.empty():
                    self.process_pool.wait()
                    while self.process_pool.finished_processes:
                        proc = self.process_pool.finished_processes.pop()
                        proc_result = proc.read_result()
                        result.mergeWithResult(proc_result)
        return result


class TestCaseClassTestSuite(unittest.TestSuite):

    def __init__(self, tests=()):
        super(TestCaseClassTestSuite, self).__init__(tests)
        self.process_pool = None

    def set_process_pool(self, process_pool):
        self.process_pool = process_pool

    def _enabled_multiprocessing(self):
        return self.process_pool is not None

    def _tearDownClass(self, test, result):
        currentClass = test.__class__
        tearDownClass = getattr(currentClass, 'tearDownClass', None)
        if tearDownClass is not None:
            unittest.suite._call_if_exists(result, '_setupStdout')
            try:
                tearDownClass()
            except Exception, e:
                if isinstance(result, unittest.suite._DebugResult):
                    raise
                className = unittest.suite.util.strclass(currentClass)
                errorName = 'tearDownClass (%s)' % className
                self._addClassOrModuleLevelException(result, e, errorName)
            finally:
                unittest.suite._call_if_exists(result, '_restoreStdout')

    def _do_class_setup(self, test, result):
        cls = test.__class__
        logger = getLogger(cls.__name__)
        cls.logger = logger
        if self._enabled_multiprocessing():
            handler = logging.FileHandler(cls.tempdir + '/log')
            logger.addHandler(handler)
            logger.propagate = False
            scapy_logger.addHandler(handler)
            scapy_logger.propagate = False
        self._handleClassSetUp(test, result)
        if (getattr(test.__class__, '_classSetupFailed', False)):
            return False
        return True

    def _do_test_setup(self, test):
        if self._enabled_multiprocessing():
            name = test._testMethodName
            logger = getLogger(test.__class__.__name__ + '.' + name)
            test.logger = logger
            handler = logging.FileHandler("%s/%s.log" % (test.tempdir, name))
            logger.addHandler(handler)
            logger.propagate = False

    def _do_class_teardown(self, test, result):
        self._tearDownClass(test, result)

    def run(self, result, debug=False):
        topLevel = False
        if getattr(result, '_testRunEntered', False) is False:
            result._testRunEntered = topLevel = True

        first_test = None
        for test in self:
            if result.shouldStop:
                break

            assert(unittest.suite._isnotsuite(test))

            if first_test is None:
                if not self._enabled_multiprocessing():
                    print(double_line_delim)
                    print(colorize(getdoc(test.__class__).splitlines()[0], YELLOW))
                    print(double_line_delim)
                if not self._do_class_setup(test, result):
                    if topLevel:
                        result._testRunEntered = False
                    return result
                first_test = test

            assert(test.__class__ == first_test.__class__)

            self._do_test_setup(test)
            if not debug:
                test(result)
            else:
                test.debug()

        if first_test is not None:
            self._do_class_teardown(test, result)

        if topLevel:
            result._testRunEntered = False
        return result


class VppTestLoader(unittest.TestLoader):

    def __init__(self, options_list, process_pool, debug_options):
        self.suiteClass = ParallelTestSuite
        self.options_list = options_list
        self.process_pool = process_pool
        self.debug_options = debug_options

    def _enabled_multiprocessing(self):
        return self.process_pool is not None

    def loadTestsFromTestCase(self, testCaseClass):
        """Return a suite of all tests cases contained in testCaseClass"""
        if issubclass(testCaseClass, unittest.TestSuite):
            raise TypeError("Test cases should not be derived from TestSuite."
                            " Maybe you meant to derive from TestCase?")
        testCaseNames = self.getTestCaseNames(testCaseClass)
        if not testCaseNames and hasattr(testCaseClass, 'runTest'):
            testCaseNames = ['runTest']
        suits = []
        if testCaseNames != []:
            for options in self.options_list:
                on = options.name
                if on == '':
                    on = 'Default'
                doc = options.class_doc(testCaseClass.__doc__)
                testCaseClassWithOptions = type(testCaseClass.__name__ + on, (
                    testCaseClass,), {'options': options, "__doc__": doc})
                test_list = map(testCaseClassWithOptions, testCaseNames)
                testCaseClassWithOptions._tmpdir_prefix =\
                    'vpp-unittest-' + on + '-' + testCaseClass.__name__ + '-'
                testCaseClassWithOptions.debug_options = self.debug_options
                loaded_suite = TestCaseClassTestSuite(test_list)
                loaded_suite.set_process_pool(self.process_pool)
                loaded_suite.name = testCaseClassWithOptions.__name__
                loaded_suite.cls = testCaseClassWithOptions
                if self.process_pool is not None:
                    for tc in loaded_suite:
                        self.process_pool.mp_helper.add_object(tc)
                suits.append(loaded_suite)
        rv = ParallelTestSuite(suits)
        rv.set_process_pool(self.process_pool)
        rv.name = testCaseClass.__name__
        return rv

    def discover(self, start_dir, pattern='test*.py', top_level_dir=None):
        test_suite = super(VppTestLoader, self).discover(
            start_dir, pattern, top_level_dir)
        test_suite.process_pool = self.process_pool
        return test_suite


class VppTestCaseOptions(object):

    def __init__(self, name, class_doc=None):
        if class_doc is None:
            class_doc = name
        self._name = name
        self._class_doc = class_doc
        self._optional_vpp_args = []
        self._number_of_workers = 0

    @property
    def name(self):
        return self._name

    def add_optional_vpp_args(self, args):
        self._optional_vpp_args += args

    @property
    def optional_vpp_args(self):
        return self._optional_vpp_args

    @property
    def number_of_workers(self):
        return self._number_of_workers

    @number_of_workers.setter
    def number_of_workers(self, n):
        self._number_of_workers = n

    def test_method_doc(self, orig_doc):
        if self._name != '':
            orig_doc = orig_doc.split('\n')[0].strip()
            if orig_doc[-1] != ' ':
                orig_doc += ' '
            return orig_doc + '(' + self._name + ')'
        else:
            return orig_doc

    def class_doc(self, orig_doc):
        if self._class_doc != '':
            orig_doc = orig_doc.split('\n')[0].strip()
            if orig_doc[-1] != ' ':
                orig_doc += ' '
            return orig_doc + '(' + self._class_doc + ')'
        else:
            return orig_doc


class VppTestProgram(unittest.TestProgram):

    def __init__(self, module='__main__', defaultTest=None, argv=None,
                 test_runner=None, test_loader=None, exit=True, verbosity=None,
                 jobs=None, failfast=None, catchbreak=None, buffer=None):

        if verbosity is None:
            try:
                V = os.getenv("V", verbosity)
                verbosity = int(V)
            except:
                verbosity = 0
        if verbosity < 0 or verbosity >= 3:
            print "Variable V has allowed values: 0 1 2"
            sys.exit(1)

        if jobs is None:
            try:
                jobs = os.getenv("JOBS", '')
                jobs = int(jobs)
            except:
                jobs = 1
        if jobs <= 0:
            print "Minimal value for JOBS variable is 1"
            sys.exit(1)
        if jobs == 1:
            enabled_multiprocessing = False
            process_pool = None
        else:
            enabled_multiprocessing = True
            process_pool = TestCaseProcessPool(jobs)

        try:
            s = os.getenv("STEP")
            step = True if s.lower() in ("y", "yes", "1") else False
        except:
            step = False
        if step is True and enabled_multiprocessing:
            print "Options STEP=True and JOBS>=2 are incompatible"
            sys.exit(1)
        try:
            d = os.getenv("DEBUG")
        except:
            d = None
        if d is not None and enabled_multiprocessing:
            print "Setting DEBUG variable is incompatible with JOBS>=2"
            sys.exit(1)
        self.set_debug_flags(d)
        debug_options = VppDebugOptions(step=step,
                                        debug_core=self.debug_core,
                                        debug_gdb=self.debug_gdb,
                                        debug_gdbserver=self.debug_gdbserver)

        options_list = self._get_options_list()

        if test_loader is None:
            test_loader = VppTestLoader(options_list, process_pool,
                                        debug_options)

        if test_runner is None:
            test_runner = VppTestRunner(verbosity=verbosity, failfast=failfast,
                                        buffer=buffer,
                                        enabled_multiprocessing
                                        =enabled_multiprocessing)

        super(VppTestProgram, self).__init__(module, defaultTest, argv,
                                             test_runner, test_loader, exit,
                                             verbosity, failfast, catchbreak,
                                             buffer)

    def _get_options_list(self):
        try:
            VPP_ARGS = os.getenv("VPP_ARGS")
            options_custom = VppTestCaseOptions('')
            options_custom.add_optional_vpp_args(VPP_ARGS.split())
            options_list1 = [options_custom]
        except:
            options_list1 = []

        all_options = self._create_options()
        options_list2 = self._read_options_list(all_options)

        if options_list1 and options_list2:
            print "Setting VPP_ARGS variable is incompatible " \
                  "with setting OPTIONS variable"
            sys.exit(1)

        if options_list1:
            return options_list1
        elif options_list2:
            return options_list2
        else:
            return [self.options_default]

    @staticmethod
    def _read_options_list(all_options):
        try:
            OPTIONS = os.getenv('OPTIONS')
            options_names_list = OPTIONS.split(' ')
        except:
            options_names_list = []
        options_list = []
        for options_name in options_names_list:
            if options_name == '':
                continue
            found = None
            for options in all_options:
                if options.name.lower() == options_name.lower():
                    found = options
                    break
            if found is not None:
                options_list.append(options)
            else:
                raise Exception("Options name '%s' not defined" % options_name)
        return options_list

    @staticmethod
    def _read_n_cores():
        proc = subprocess.Popen('nproc', stdout=subprocess.PIPE)
        str = proc.stdout.read()
        proc.terminate()
        return int(str)

    def _create_options(self):
        options_default = VppTestCaseOptions('Default')
        self.options_default = options_default

        n_cores = VppTestProgram._read_n_cores()
        n_of_workers = n_cores - 1
        getLogger().info('%s cores available on the system' % n_cores)
        options_multithreaded = VppTestCaseOptions('MultiThreaded')
        options_multithreaded.add_optional_vpp_args(['cpu', '{', 'workers',
                                                     str(n_of_workers), '}'])
        options_multithreaded.number_of_workers = n_of_workers

        return [options_default, options_multithreaded]

    @classmethod
    def set_debug_flags(cls, d):
        cls.debug_core = False
        cls.debug_gdb = False
        cls.debug_gdbserver = False
        if d is None:
            return
        dl = d.lower()
        if dl == "core":
            if resource.getrlimit(resource.RLIMIT_CORE)[0] <= 0:
                # give a heads up if this is actually useless
                cls.logger.critical("WARNING: core size limit is set 0, core "
                                    "files will NOT be created")
            cls.debug_core = True
        elif dl == "gdb":
            cls.debug_gdb = True
        elif dl == "gdbserver":
            cls.debug_gdbserver = True
        else:
            raise Exception("Unrecognized DEBUG option: '%s'" % d)
