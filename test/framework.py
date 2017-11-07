#!/usr/bin/env python

from __future__ import print_function
import gc
import sys
import os
import select
import unittest
import tempfile
import time
import resource
import faulthandler
import random
from collections import deque
from threading import Thread, Event
from inspect import getdoc, isclass
from traceback import format_exception
from logging import FileHandler, DEBUG, Formatter
from scapy.packet import Raw
from hook import StepHook, PollHook
from vpp_pg_interface import VppPGInterface
from vpp_sub_interface import VppSubInterface
from vpp_lo_interface import VppLoInterface
from vpp_papi_provider import VppPapiProvider
from log import *
from vpp_object import VppObjectRegistry
if os.name == 'posix' and sys.version_info[0] < 3:
    # using subprocess32 is recommended by python official documentation
    # @ https://docs.python.org/2/library/subprocess.html
    import subprocess32 as subprocess
else:
    import subprocess

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
    #: Store expected ip version
    ip = -1
    #: Store expected upper protocol
    proto = -1
    #: Store the copy of the former packet.
    data = None

    def __eq__(self, other):
        index = self.index == other.index
        src = self.src == other.src
        dst = self.dst == other.dst
        data = self.data == other.data
        return index and src and dst and data


def pump_output(testclass):
    """ pump output from vpp stdout/stderr to proper queues """
    stdout_fragment = ""
    stderr_fragment = ""
    while not testclass.pump_thread_stop_flag.wait(0):
        readable = select.select([testclass.vpp.stdout.fileno(),
                                  testclass.vpp.stderr.fileno(),
                                  testclass.pump_thread_wakeup_pipe[0]],
                                 [], [])[0]
        if testclass.vpp.stdout.fileno() in readable:
            read = os.read(testclass.vpp.stdout.fileno(), 102400)
            if len(read) > 0:
                split = read.splitlines(True)
                if len(stdout_fragment) > 0:
                    split[0] = "%s%s" % (stdout_fragment, split[0])
                if len(split) > 0 and split[-1].endswith("\n"):
                    limit = None
                else:
                    limit = -1
                    stdout_fragment = split[-1]
                testclass.vpp_stdout_deque.extend(split[:limit])
                if not testclass.cache_vpp_output:
                    for line in split[:limit]:
                        testclass.logger.debug(
                            "VPP STDOUT: %s" % line.rstrip("\n"))
        if testclass.vpp.stderr.fileno() in readable:
            read = os.read(testclass.vpp.stderr.fileno(), 102400)
            if len(read) > 0:
                split = read.splitlines(True)
                if len(stderr_fragment) > 0:
                    split[0] = "%s%s" % (stderr_fragment, split[0])
                if len(split) > 0 and split[-1].endswith("\n"):
                    limit = None
                else:
                    limit = -1
                    stderr_fragment = split[-1]
                testclass.vpp_stderr_deque.extend(split[:limit])
                if not testclass.cache_vpp_output:
                    for line in split[:limit]:
                        testclass.logger.debug(
                            "VPP STDERR: %s" % line.rstrip("\n"))
        # ignoring the dummy pipe here intentionally - the flag will take care
        # of properly terminating the loop


def running_extended_tests():
    try:
        s = os.getenv("EXTENDED_TESTS")
        return True if s.lower() in ("y", "yes", "1") else False
    except:
        return False
    return False


def running_on_centos():
    try:
        os_id = os.getenv("OS_ID")
        return True if "centos" in os_id.lower() else False
    except:
        return False
    return False


class KeepAliveReporter(object):
    """
    Singleton object which reports test start to parent process
    """
    _shared_state = {}

    def __init__(self):
        self.__dict__ = self._shared_state

    @property
    def pipe(self):
        return self._pipe

    @pipe.setter
    def pipe(self, pipe):
        if hasattr(self, '_pipe'):
            raise Exception("Internal error - pipe should only be set once.")
        self._pipe = pipe

    def send_keep_alive(self, test):
        """
        Write current test tmpdir & desc to keep-alive pipe to signal liveness
        """
        if self.pipe is None:
            # if not running forked..
            return

        if isclass(test):
            desc = test.__name__
        else:
            desc = test.shortDescription()
            if not desc:
                desc = str(test)

        self.pipe.send((desc, test.vpp_bin, test.tempdir, test.vpp.pid))


class VppTestCase(unittest.TestCase):
    """This subclass is a base class for VPP test cases that are implemented as
    classes. It provides methods to create and run test case.
    """

    @property
    def packet_infos(self):
        """List of packet infos"""
        return self._packet_infos

    @classmethod
    def get_packet_count_for_if_idx(cls, dst_if_index):
        """Get the number of packet info for specified destination if index"""
        if dst_if_index in cls._packet_count_for_dst_if_idx:
            return cls._packet_count_for_dst_if_idx[dst_if_index]
        else:
            return 0

    @classmethod
    def instance(cls):
        """Return the instance of this testcase"""
        return cls.test_instance

    @classmethod
    def set_debug_flags(cls, d):
        cls.debug_core = False
        cls.debug_gdb = False
        cls.debug_gdbserver = False
        if d is None:
            return
        dl = d.lower()
        if dl == "core":
            cls.debug_core = True
        elif dl == "gdb":
            cls.debug_gdb = True
        elif dl == "gdbserver":
            cls.debug_gdbserver = True
        else:
            raise Exception("Unrecognized DEBUG option: '%s'" % d)

    @classmethod
    def setUpConstants(cls):
        """ Set-up the test case class based on environment variables """
        try:
            s = os.getenv("STEP")
            cls.step = True if s.lower() in ("y", "yes", "1") else False
        except:
            cls.step = False
        try:
            d = os.getenv("DEBUG")
        except:
            d = None
        try:
            c = os.getenv("CACHE_OUTPUT", "1")
            cls.cache_vpp_output = \
                False if c.lower() in ("n", "no", "0") else True
        except:
            cls.cache_vpp_output = True
        cls.set_debug_flags(d)
        cls.vpp_bin = os.getenv('VPP_TEST_BIN', "vpp")
        cls.plugin_path = os.getenv('VPP_TEST_PLUGIN_PATH')
        cls.extern_plugin_path = os.getenv('EXTERN_PLUGINS')
        plugin_path = None
        if cls.plugin_path is not None:
            if cls.extern_plugin_path is not None:
                plugin_path = "%s:%s" % (
                    cls.plugin_path, cls.extern_plugin_path)
            else:
                plugin_path = cls.plugin_path
        elif cls.extern_plugin_path is not None:
            plugin_path = cls.extern_plugin_path
        debug_cli = ""
        if cls.step or cls.debug_gdb or cls.debug_gdbserver:
            debug_cli = "cli-listen localhost:5002"
        coredump_size = None
        try:
            size = os.getenv("COREDUMP_SIZE")
            if size is not None:
                coredump_size = "coredump-size %s" % size
        except:
            pass
        if coredump_size is None:
            coredump_size = "coredump-size unlimited"
        cls.vpp_cmdline = [cls.vpp_bin, "unix",
                           "{", "nodaemon", debug_cli, "full-coredump",
                           coredump_size, "}", "api-trace", "{", "on", "}",
                           "api-segment", "{", "prefix", cls.shm_prefix, "}",
                           "plugins", "{", "plugin", "dpdk_plugin.so", "{",
                           "disable", "}", "}"]
        if plugin_path is not None:
            cls.vpp_cmdline.extend(["plugin_path", plugin_path])
        cls.logger.info("vpp_cmdline: %s" % cls.vpp_cmdline)

    @classmethod
    def wait_for_enter(cls):
        if cls.debug_gdbserver:
            print(double_line_delim)
            print("Spawned GDB server with PID: %d" % cls.vpp.pid)
        elif cls.debug_gdb:
            print(double_line_delim)
            print("Spawned VPP with PID: %d" % cls.vpp.pid)
        else:
            cls.logger.debug("Spawned VPP with PID: %d" % cls.vpp.pid)
            return
        print(single_line_delim)
        print("You can debug the VPP using e.g.:")
        if cls.debug_gdbserver:
            print("gdb " + cls.vpp_bin + " -ex 'target remote localhost:7777'")
            print("Now is the time to attach a gdb by running the above "
                  "command, set up breakpoints etc. and then resume VPP from "
                  "within gdb by issuing the 'continue' command")
        elif cls.debug_gdb:
            print("gdb " + cls.vpp_bin + " -ex 'attach %s'" % cls.vpp.pid)
            print("Now is the time to attach a gdb by running the above "
                  "command and set up breakpoints etc.")
        print(single_line_delim)
        raw_input("Press ENTER to continue running the testcase...")

    @classmethod
    def run_vpp(cls):
        cmdline = cls.vpp_cmdline

        if cls.debug_gdbserver:
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
        gc.collect()  # run garbage collection first
        random.seed()
        cls.logger = getLogger(cls.__name__)
        cls.tempdir = tempfile.mkdtemp(
            prefix='vpp-unittest-%s-' % cls.__name__)
        cls.file_handler = FileHandler("%s/log.txt" % cls.tempdir)
        cls.file_handler.setFormatter(
            Formatter(fmt='%(asctime)s,%(msecs)03d %(message)s',
                      datefmt="%H:%M:%S"))
        cls.file_handler.setLevel(DEBUG)
        cls.logger.addHandler(cls.file_handler)
        cls.shm_prefix = cls.tempdir.split("/")[-1]
        os.chdir(cls.tempdir)
        cls.logger.info("Temporary dir is %s, shm prefix is %s",
                        cls.tempdir, cls.shm_prefix)
        cls.setUpConstants()
        cls.reset_packet_infos()
        cls._captures = []
        cls._zombie_captures = []
        cls.verbose = 0
        cls.vpp_dead = False
        cls.registry = VppObjectRegistry()
        cls.vpp_startup_failed = False
        cls.reporter = KeepAliveReporter()
        # need to catch exceptions here because if we raise, then the cleanup
        # doesn't get called and we might end with a zombie vpp
        try:
            cls.run_vpp()
            cls.reporter.send_keep_alive(cls)
            cls.vpp_stdout_deque = deque()
            cls.vpp_stderr_deque = deque()
            cls.pump_thread_stop_flag = Event()
            cls.pump_thread_wakeup_pipe = os.pipe()
            cls.pump_thread = Thread(target=pump_output, args=(cls,))
            cls.pump_thread.daemon = True
            cls.pump_thread.start()
            cls.vapi = VppPapiProvider(cls.shm_prefix, cls.shm_prefix, cls)
            if cls.step:
                hook = StepHook(cls)
            else:
                hook = PollHook(cls)
            cls.vapi.register_hook(hook)
            cls.sleep(0.1, "after vpp startup, before initial poll")
            try:
                hook.poll_vpp()
            except:
                cls.vpp_startup_failed = True
                cls.logger.critical(
                    "VPP died shortly after startup, check the"
                    " output to standard error for possible cause")
                raise
            try:
                cls.vapi.connect()
            except:
                if cls.debug_gdbserver:
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
        if (cls.debug_gdbserver or cls.debug_gdb) and hasattr(cls, 'vpp'):
            cls.vpp.poll()
            if cls.vpp.returncode is None:
                print(double_line_delim)
                print("VPP or GDB server is still running")
                print(single_line_delim)
                raw_input("When done debugging, press ENTER to kill the "
                          "process and finish running the testcase...")

        os.write(cls.pump_thread_wakeup_pipe[1], 'ding dong wake up')
        cls.pump_thread_stop_flag.set()
        if hasattr(cls, 'pump_thread'):
            cls.logger.debug("Waiting for pump thread to stop")
            cls.pump_thread.join()
        if hasattr(cls, 'vpp_stderr_reader_thread'):
            cls.logger.debug("Waiting for stdderr pump to stop")
            cls.vpp_stderr_reader_thread.join()

        if hasattr(cls, 'vpp'):
            if hasattr(cls, 'vapi'):
                cls.vapi.disconnect()
                del cls.vapi
            cls.vpp.poll()
            if cls.vpp.returncode is None:
                cls.logger.debug("Sending TERM to vpp")
                cls.vpp.terminate()
                cls.logger.debug("Waiting for vpp to die")
                cls.vpp.communicate()
            del cls.vpp

        if cls.vpp_startup_failed:
            stdout_log = cls.logger.info
            stderr_log = cls.logger.critical
        else:
            stdout_log = cls.logger.info
            stderr_log = cls.logger.info

        if hasattr(cls, 'vpp_stdout_deque'):
            stdout_log(single_line_delim)
            stdout_log('VPP output to stdout while running %s:', cls.__name__)
            stdout_log(single_line_delim)
            vpp_output = "".join(cls.vpp_stdout_deque)
            with open(cls.tempdir + '/vpp_stdout.txt', 'w') as f:
                f.write(vpp_output)
            stdout_log('\n%s', vpp_output)
            stdout_log(single_line_delim)

        if hasattr(cls, 'vpp_stderr_deque'):
            stderr_log(single_line_delim)
            stderr_log('VPP output to stderr while running %s:', cls.__name__)
            stderr_log(single_line_delim)
            vpp_output = "".join(cls.vpp_stderr_deque)
            with open(cls.tempdir + '/vpp_stderr.txt', 'w') as f:
                f.write(vpp_output)
            stderr_log('\n%s', vpp_output)
            stderr_log(single_line_delim)

    @classmethod
    def tearDownClass(cls):
        """ Perform final cleanup after running all tests in this test-case """
        cls.quit()
        cls.file_handler.close()

    def tearDown(self):
        """ Show various debug prints after each test """
        self.logger.debug("--- tearDown() for %s.%s(%s) called ---" %
                          (self.__class__.__name__, self._testMethodName,
                           self._testMethodDoc))
        if not self.vpp_dead:
            self.logger.debug(self.vapi.cli("show trace"))
            self.logger.info(self.vapi.ppcli("show interface"))
            self.logger.info(self.vapi.ppcli("show hardware"))
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show run"))
            self.registry.remove_vpp_config(self.logger)
            # Save/Dump VPP api trace log
            api_trace = "vpp_api_trace.%s.log" % self._testMethodName
            tmp_api_trace = "/tmp/%s" % api_trace
            vpp_api_trace_log = "%s/%s" % (self.tempdir, api_trace)
            self.logger.info(self.vapi.ppcli("api trace save %s" % api_trace))
            self.logger.info("Moving %s to %s\n" % (tmp_api_trace,
                                                    vpp_api_trace_log))
            os.rename(tmp_api_trace, vpp_api_trace_log)
            self.logger.info(self.vapi.ppcli("api trace dump %s" %
                                             vpp_api_trace_log))
        else:
            self.registry.unregister_all(self.logger)

    def setUp(self):
        """ Clear trace before running each test"""
        self.reporter.send_keep_alive(self)
        self.logger.debug("--- setUp() for %s.%s(%s) called ---" %
                          (self.__class__.__name__, self._testMethodName,
                           self._testMethodDoc))
        if self.vpp_dead:
            raise Exception("VPP is dead when setting up the test")
        self.sleep(.1, "during setUp")
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
    def pg_enable_capture(cls, interfaces):
        """
        Enable capture on packet-generator interfaces

        :param interfaces: iterable interface indexes

        """
        for i in interfaces:
            i.enable_capture()

    @classmethod
    def register_capture(cls, cap_name):
        """ Register a capture in the testclass """
        # add to the list of captures with current timestamp
        cls._captures.append((time.time(), cap_name))
        # filter out from zombies
        cls._zombie_captures = [(stamp, name)
                                for (stamp, name) in cls._zombie_captures
                                if name != cap_name]

    @classmethod
    def pg_start(cls):
        """ Remove any zombie captures and enable the packet generator """
        # how long before capture is allowed to be deleted - otherwise vpp
        # crashes - 100ms seems enough (this shouldn't be needed at all)
        capture_ttl = 0.1
        now = time.time()
        for stamp, cap_name in cls._zombie_captures:
            wait = stamp + capture_ttl - now
            if wait > 0:
                cls.sleep(wait, "before deleting capture %s" % cap_name)
                now = time.time()
            cls.logger.debug("Removing zombie capture %s" % cap_name)
            cls.vapi.cli('packet-generator delete %s' % cap_name)

        cls.vapi.cli("trace add pg-input 50")  # 50 is maximum
        cls.vapi.cli('packet-generator enable')
        cls._zombie_captures = cls._captures
        cls._captures = []

    @classmethod
    def create_pg_interfaces(cls, interfaces):
        """
        Create packet-generator interfaces.

        :param interfaces: iterable indexes of the interfaces.
        :returns: List of created interfaces.

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
        Create loopback interfaces.

        :param interfaces: iterable indexes of the interfaces.
        :returns: List of created interfaces.
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

    @classmethod
    def reset_packet_infos(cls):
        """ Reset the list of packet info objects and packet counts to zero """
        cls._packet_infos = {}
        cls._packet_count_for_dst_if_idx = {}

    @classmethod
    def create_packet_info(cls, src_if, dst_if):
        """
        Create packet info object containing the source and destination indexes
        and add it to the testcase's packet info list

        :param VppInterface src_if: source interface
        :param VppInterface dst_if: destination interface

        :returns: _PacketInfo object

        """
        info = _PacketInfo()
        info.index = len(cls._packet_infos)
        info.src = src_if.sw_if_index
        info.dst = dst_if.sw_if_index
        if isinstance(dst_if, VppSubInterface):
            dst_idx = dst_if.parent.sw_if_index
        else:
            dst_idx = dst_if.sw_if_index
        if dst_idx in cls._packet_count_for_dst_if_idx:
            cls._packet_count_for_dst_if_idx[dst_idx] += 1
        else:
            cls._packet_count_for_dst_if_idx[dst_idx] = 1
        cls._packet_infos[info.index] = info
        return info

    @staticmethod
    def info_to_payload(info):
        """
        Convert _PacketInfo object to packet payload

        :param info: _PacketInfo object

        :returns: string containing serialized data from packet info
        """
        return "%d %d %d %d %d" % (info.index, info.src, info.dst,
                                   info.ip, info.proto)

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
        info.ip = int(numbers[3])
        info.proto = int(numbers[4])
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
        if next_index == len(self._packet_infos):
            return None
        else:
            return self._packet_infos[next_index]

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
            self.assertEqual(real_value, expected_value)
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

    def assert_in_range(self,
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

    @classmethod
    def sleep(cls, timeout, remark=None):
        if hasattr(cls, 'logger'):
            cls.logger.debug("Starting sleep for %ss (%s)" % (timeout, remark))
        before = time.time()
        time.sleep(timeout)
        after = time.time()
        if after - before > 2 * timeout:
            cls.logger.error("unexpected time.sleep() result - "
                             "slept for %ss instead of ~%ss!" % (
                                 after - before, timeout))
        if hasattr(cls, 'logger'):
            cls.logger.debug(
                "Finished sleep (%s) - slept %ss (wanted %ss)" % (
                    remark, after - before, timeout))


class TestCasePrinter(object):
    _shared_state = {}

    def __init__(self):
        self.__dict__ = self._shared_state
        if not hasattr(self, "_test_case_set"):
            self._test_case_set = set()

    def print_test_case_heading_if_first_time(self, case):
        if case.__class__ not in self._test_case_set:
            print(double_line_delim)
            print(colorize(getdoc(case.__class__).splitlines()[0], YELLOW))
            print(double_line_delim)
            self._test_case_set.add(case.__class__)


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

    def __init__(self, stream, descriptions, verbosity):
        """
        :param stream File descriptor to store where to report test results.
            Set to the standard error stream by default.
        :param descriptions Boolean variable to store information if to use
            test case descriptions.
        :param verbosity Integer variable to store required verbosity level.
        """
        unittest.TestResult.__init__(self, stream, descriptions, verbosity)
        self.stream = stream
        self.descriptions = descriptions
        self.verbosity = verbosity
        self.result_string = None
        self.printer = TestCasePrinter()

    def addSuccess(self, test):
        """
        Record a test succeeded result

        :param test:

        """
        if hasattr(test, 'logger'):
            test.logger.debug("--- addSuccess() %s.%s(%s) called"
                              % (test.__class__.__name__,
                                 test._testMethodName,
                                 test._testMethodDoc))
        unittest.TestResult.addSuccess(self, test)
        self.result_string = colorize("OK", GREEN)

    def addSkip(self, test, reason):
        """
        Record a test skipped.

        :param test:
        :param reason:

        """
        if hasattr(test, 'logger'):
            test.logger.debug("--- addSkip() %s.%s(%s) called, reason is %s"
                              % (test.__class__.__name__,
                                 test._testMethodName,
                                 test._testMethodDoc,
                                 reason))
        unittest.TestResult.addSkip(self, test, reason)
        self.result_string = colorize("SKIP", YELLOW)

    def symlink_failed(self, test):
        logger = None
        if hasattr(test, 'logger'):
            logger = test.logger
        if hasattr(test, 'tempdir'):
            try:
                failed_dir = os.getenv('VPP_TEST_FAILED_DIR')
                link_path = '%s/%s-FAILED' % (failed_dir,
                                              test.tempdir.split("/")[-1])
                if logger:
                    logger.debug("creating a link to the failed test")
                    logger.debug("os.symlink(%s, %s)" %
                                 (test.tempdir, link_path))
                os.symlink(test.tempdir, link_path)
            except Exception as e:
                if logger:
                    logger.error(e)

    def send_failure_through_pipe(self, test):
        if hasattr(self, 'test_framework_failed_pipe'):
            pipe = self.test_framework_failed_pipe
            if pipe:
                pipe.send(test.__class__)

    def addFailure(self, test, err):
        """
        Record a test failed result

        :param test:
        :param err: error message

        """
        if hasattr(test, 'logger'):
            test.logger.debug("--- addFailure() %s.%s(%s) called, err is %s"
                              % (test.__class__.__name__,
                                 test._testMethodName,
                                 test._testMethodDoc, err))
            test.logger.debug("formatted exception is:\n%s" %
                              "".join(format_exception(*err)))
        unittest.TestResult.addFailure(self, test, err)
        if hasattr(test, 'tempdir'):
            self.result_string = colorize("FAIL", RED) + \
                ' [ temp dir used by test case: ' + test.tempdir + ' ]'
            self.symlink_failed(test)
        else:
            self.result_string = colorize("FAIL", RED) + ' [no temp dir]'

        self.send_failure_through_pipe(test)

    def addError(self, test, err):
        """
        Record a test error result

        :param test:
        :param err: error message

        """
        if hasattr(test, 'logger'):
            test.logger.debug("--- addError() %s.%s(%s) called, err is %s"
                              % (test.__class__.__name__,
                                 test._testMethodName,
                                 test._testMethodDoc, err))
            test.logger.debug("formatted exception is:\n%s" %
                              "".join(format_exception(*err)))
        unittest.TestResult.addError(self, test, err)
        if hasattr(test, 'tempdir'):
            self.result_string = colorize("ERROR", RED) + \
                ' [ temp dir used by test case: ' + test.tempdir + ' ]'
            self.symlink_failed(test)
        else:
            self.result_string = colorize("ERROR", RED) + ' [no temp dir]'

        self.send_failure_through_pipe(test)

    def getDescription(self, test):
        """
        Get test description

        :param test:
        :returns: test description

        """
        # TODO: if none print warning not raise exception
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
        self.printer.print_test_case_heading_if_first_time(test)
        unittest.TestResult.startTest(self, test)
        if self.verbosity > 0:
            self.stream.writeln(
                "Starting " + self.getDescription(test) + " ...")
            self.stream.writeln(single_line_delim)

    def stopTest(self, test):
        """
        Stop a test

        :param test:

        """
        unittest.TestResult.stopTest(self, test)
        if self.verbosity > 0:
            self.stream.writeln(single_line_delim)
            self.stream.writeln("%-73s%s" % (self.getDescription(test),
                                             self.result_string))
            self.stream.writeln(single_line_delim)
        else:
            self.stream.writeln("%-73s%s" % (self.getDescription(test),
                                             self.result_string))

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


class Filter_by_test_option:
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


class VppTestRunner(unittest.TextTestRunner):
    """
    A basic test runner implementation which prints results to standard error.
    """
    @property
    def resultclass(self):
        """Class maintaining the results of the tests"""
        return VppTestResult

    def __init__(self, keep_alive_pipe=None, failed_pipe=None,
                 stream=sys.stderr, descriptions=True,
                 verbosity=1, failfast=False, buffer=False, resultclass=None):
        # ignore stream setting here, use hard-coded stdout to be in sync
        # with prints from VppTestCase methods ...
        super(VppTestRunner, self).__init__(sys.stdout, descriptions,
                                            verbosity, failfast, buffer,
                                            resultclass)
        reporter = KeepAliveReporter()
        reporter.pipe = keep_alive_pipe
        # this is super-ugly, but very simple to implement and works as long
        # as we run only one test at the same time
        VppTestResult.test_framework_failed_pipe = failed_pipe

    test_option = "TEST"

    def parse_test_option(self):
        try:
            f = os.getenv(self.test_option)
        except:
            f = None
        filter_file_name = None
        filter_class_name = None
        filter_func_name = None
        if f:
            if '.' in f:
                parts = f.split('.')
                if len(parts) > 3:
                    raise Exception("Unrecognized %s option: %s" %
                                    (self.test_option, f))
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
        return filter_file_name, filter_class_name, filter_func_name

    @staticmethod
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

    def run(self, test):
        """
        Run the tests

        :param test:

        """
        faulthandler.enable()  # emit stack trace to stderr if killed by signal
        print("Running tests using custom test runner")  # debug message
        filter_file, filter_class, filter_func = self.parse_test_option()
        print("Active filters: file=%s, class=%s, function=%s" % (
            filter_file, filter_class, filter_func))
        filter_cb = Filter_by_test_option(
            filter_file, filter_class, filter_func)
        filtered = self.filter_tests(test, filter_cb)
        print("%s out of %s tests match specified filters" % (
            filtered.countTestCases(), test.countTestCases()))
        if not running_extended_tests():
            print("Not running extended tests (some tests will be skipped)")
        return super(VppTestRunner, self).run(filtered)


class Worker(Thread):
    def __init__(self, args, logger):
        self.logger = logger
        self.args = args
        self.result = None
        super(Worker, self).__init__()

    def run(self):
        executable = self.args[0]
        self.logger.debug("Running executable w/args `%s'" % self.args)
        env = os.environ.copy()
        env["CK_LOG_FILE_NAME"] = "-"
        self.process = subprocess.Popen(
            self.args, shell=False, env=env, preexec_fn=os.setpgrp,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = self.process.communicate()
        self.logger.debug("Finished running `%s'" % executable)
        self.logger.info("Return code is `%s'" % self.process.returncode)
        self.logger.info(single_line_delim)
        self.logger.info("Executable `%s' wrote to stdout:" % executable)
        self.logger.info(single_line_delim)
        self.logger.info(out)
        self.logger.info(single_line_delim)
        self.logger.info("Executable `%s' wrote to stderr:" % executable)
        self.logger.info(single_line_delim)
        self.logger.error(err)
        self.logger.info(single_line_delim)
        self.result = self.process.returncode
