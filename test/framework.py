#!/usr/bin/env python

from abc import *
import os
import sys
import subprocess
import unittest
import tempfile
import resource
from time import sleep
from inspect import getdoc
from hook import PollHook
from vpp_pg_interface import VppPGInterface
from vpp_papi_provider import VppPapiProvider

from scapy.packet import Raw

from logging import *

"""
  Test framework module.

  The module provides a set of tools for constructing and running tests and
  representing the results.
"""

handler = StreamHandler(sys.stdout)
getLogger().addHandler(handler)
try:
    verbose = int(os.getenv("V", 0))
except:
    verbose = 0
# 40 = ERROR, 30 = WARNING, 20 = INFO, 10 = DEBUG, 0 = NOTSET (all messages)
getLogger().setLevel(40 - 10 * verbose)
getLogger("scapy.runtime").addHandler(handler)
getLogger("scapy.runtime").setLevel(ERROR)

# Static variables to store color formatting strings.
#
# These variables (RED, GREEN, YELLOW and LPURPLE) are used to configure
# the color of the text to be printed in the terminal. Variable COLOR_RESET
# is used to revert the text color to the default one.
if hasattr(sys.stdout, 'isatty') and sys.stdout.isatty():
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    LPURPLE = '\033[94m'
    COLOR_RESET = '\033[0m'
else:
    RED = ''
    GREEN = ''
    YELLOW = ''
    LPURPLE = ''
    COLOR_RESET = ''


""" @var formatting delimiter consisting of '=' characters """
double_line_delim = '=' * 70
""" @var formatting delimiter consisting of '-' characters """
single_line_delim = '-' * 70


class _PacketInfo(object):
    """Private class to create packet info object.

    Help process information about the next packet.
    Set variables to default values.
    @property index
      Integer variable to store the index of the packet.
    @property src
      Integer variable to store the index of the source packet generator
      interface of the packet.
    @property dst
      Integer variable to store the index of the destination packet generator
      interface of the packet.
    @property data
      Object variable to store the copy of the former packet.


    """
    index = -1
    src = -1
    dst = -1
    data = None


class VppTestCase(unittest.TestCase):
    """
    Subclass of the python unittest.TestCase class.

    This subclass is a base class for test cases that are implemented as classes
    It provides methods to create and run test case.

    """

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

    @classmethod
    def setUpConstants(cls):
        """ Set-up the test case class based on environment variables """
        try:
            cls.interactive = True if int(os.getenv("I")) > 0 else False
        except:
            cls.interactive = False
        if cls.interactive and resource.getrlimit(resource.RLIMIT_CORE)[0] <= 0:
            # give a heads up if this is actually useless
            critical("WARNING: core size limit is set 0, core files will NOT "
                     "be created")
        cls.vpp_bin = os.getenv('VPP_TEST_BIN', "vpp")
        cls.plugin_path = os.getenv('VPP_TEST_PLUGIN_PATH')
        cls.vpp_cmdline = [cls.vpp_bin, "unix", "nodaemon",
                           "api-segment", "{", "prefix", cls.shm_prefix, "}"]
        if cls.plugin_path is not None:
            cls.vpp_cmdline.extend(["plugin_path", cls.plugin_path])
        info("vpp_cmdline: %s" % cls.vpp_cmdline)

    @classmethod
    def setUpClass(cls):
        """
        Perform class setup before running the testcase
        Remove shared memory files, start vpp and connect the vpp-api
        """
        cls.tempdir = tempfile.mkdtemp(
            prefix='vpp-unittest-' + cls.__name__ + '-')
        cls.shm_prefix = cls.tempdir.split("/")[-1]
        os.chdir(cls.tempdir)
        info("Temporary dir is %s, shm prefix is %s",
             cls.tempdir, cls.shm_prefix)
        cls.setUpConstants()
        cls.pg_streams = []
        cls.packet_infos = {}
        cls.verbose = 0
        print(double_line_delim)
        print(YELLOW + getdoc(cls) + COLOR_RESET)
        print(double_line_delim)
        # need to catch exceptions here because if we raise, then the cleanup
        # doesn't get called and we might end with a zombie vpp
        try:
            cls.vpp = subprocess.Popen(cls.vpp_cmdline, stderr=subprocess.PIPE)
            debug("Spawned VPP with PID: %d" % cls.vpp.pid)
            cls.vpp_dead = False
            cls.vapi = VppPapiProvider(cls.shm_prefix, cls.shm_prefix)
            cls.vapi.register_hook(PollHook(cls))
            cls.vapi.connect()
        except:
            cls.vpp.terminate()
            del cls.vpp

    @classmethod
    def quit(cls):
        """
        Disconnect vpp-api, kill vpp and cleanup shared memory files
        """
        if hasattr(cls, 'vpp'):
            cls.vapi.disconnect()
            cls.vpp.poll()
            if cls.vpp.returncode is None:
                cls.vpp.terminate()
            del cls.vpp

    @classmethod
    def tearDownClass(cls):
        """ Perform final cleanup after running all tests in this test-case """
        cls.quit()

    def tearDown(self):
        """ Show various debug prints after each test """
        if not self.vpp_dead:
            info(self.vapi.cli("show int"))
            info(self.vapi.cli("show trace"))
            info(self.vapi.cli("show hardware"))
            info(self.vapi.cli("show error"))
            info(self.vapi.cli("show run"))

    def setUp(self):
        """ Clear trace before running each test"""
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
    def pg_start(cls):
        """
        Enable the packet-generator and send all prepared packet streams
        Remove the packet streams afterwards
        """
        cls.vapi.cli("trace add pg-input 50")  # 50 is maximum
        cls.vapi.cli('packet-generator enable')
        sleep(1)  # give VPP some time to process the packets
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
        self.result_string = None

    def addSuccess(self, test):
        """
        Record a test succeeded result

        :param test:

        """
        unittest.TestResult.addSuccess(self, test)
        self.result_string = GREEN + "OK" + COLOR_RESET

    def addSkip(self, test, reason):
        """
        Record a test skipped.

        :param test:
        :param reason:

        """
        unittest.TestResult.addSkip(self, test, reason)
        self.result_string = YELLOW + "SKIP" + COLOR_RESET

    def addFailure(self, test, err):
        """
        Record a test failed result

        :param test:
        :param err: error message

        """
        unittest.TestResult.addFailure(self, test, err)
        if hasattr(test, 'tempdir'):
            self.result_string = RED + "FAIL" + COLOR_RESET + \
                ' [ temp dir used by test case: ' + test.tempdir + ' ]'
        else:
            self.result_string = RED + "FAIL" + COLOR_RESET + ' [no temp dir]'

    def addError(self, test, err):
        """
        Record a test error result

        :param test:
        :param err: error message

        """
        unittest.TestResult.addError(self, test, err)
        if hasattr(test, 'tempdir'):
            self.result_string = RED + "ERROR" + COLOR_RESET + \
                ' [ temp dir used by test case: ' + test.tempdir + ' ]'
        else:
            self.result_string = RED + "ERROR" + COLOR_RESET + ' [no temp dir]'

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


class VppTestRunner(unittest.TextTestRunner):
    """
    A basic test runner implementation which prints results on standard error.
    """
    @property
    def resultclass(self):
        """Class maintaining the results of the tests"""
        return VppTestResult

    def run(self, test):
        """
        Run the tests

        :param test:

        """
        print("Running tests using custom test runner")  # debug message
        return super(VppTestRunner, self).run(test)
