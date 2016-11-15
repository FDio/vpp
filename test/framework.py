#!/usr/bin/env python

import subprocess
import unittest
import tempfile
import time
import resource
from time import sleep
from Queue import Queue
from threading import Thread
from inspect import getdoc
from hook import StepHook, PollHook
from vpp_pg_interface import VppPGInterface
from vpp_lo_interface import VppLoInterface
from vpp_papi_provider import VppPapiProvider
from scapy.packet import Raw
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


def pump_output(out, queue):
    for line in iter(out.readline, b''):
        queue.put(line)


class VppTestCase(unittest.TestCase):
    """This subclass is a base class for VPP test cases that are implemented as
    classes. It provides methods to create and run test case.
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
        cls.set_debug_flags(d)
        cls.vpp_bin = os.getenv('VPP_TEST_BIN', "vpp")
        cls.plugin_path = os.getenv('VPP_TEST_PLUGIN_PATH')
        debug_cli = ""
        if cls.step or cls.debug_gdb or cls.debug_gdbserver:
            debug_cli = "cli-listen localhost:5002"
        cls.vpp_cmdline = [cls.vpp_bin, "unix", "{", "nodaemon", debug_cli, "}",
                           "api-segment", "{", "prefix", cls.shm_prefix, "}"]
        if cls.plugin_path is not None:
            cls.vpp_cmdline.extend(["plugin_path", cls.plugin_path])
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
        cls.logger = getLogger(cls.__name__)
        cls.tempdir = tempfile.mkdtemp(
            prefix='vpp-unittest-' + cls.__name__ + '-')
        cls.shm_prefix = cls.tempdir.split("/")[-1]
        os.chdir(cls.tempdir)
        cls.logger.info("Temporary dir is %s, shm prefix is %s",
                        cls.tempdir, cls.shm_prefix)
        cls.setUpConstants()
        cls.pg_streams = []
        cls.packet_infos = {}
        cls.verbose = 0
        print(double_line_delim)
        print(colorize(getdoc(cls).splitlines()[0], YELLOW))
        print(double_line_delim)
        # need to catch exceptions here because if we raise, then the cleanup
        # doesn't get called and we might end with a zombie vpp
        try:
            cls.run_vpp()
            cls.vpp_dead = False
            cls.vapi = VppPapiProvider(cls.shm_prefix, cls.shm_prefix)
            if cls.step:
                cls.vapi.register_hook(StepHook(cls))
            else:
                cls.vapi.register_hook(PollHook(cls))
            time.sleep(0.1)
            try:
                cls.vapi.connect()
            except:
                if cls.debug_gdbserver:
                    print(colorize("You're running VPP inside gdbserver but "
                                   "VPP-API connection failed, did you forget "
                                   "to 'continue' VPP from within gdb?", RED))
                raise
            cls.vpp_stdout_queue = Queue()
            cls.vpp_stdout_reader_thread = Thread(
                target=pump_output, args=(cls.vpp.stdout, cls.vpp_stdout_queue))
            cls.vpp_stdout_reader_thread.start()
            cls.vpp_stderr_queue = Queue()
            cls.vpp_stderr_reader_thread = Thread(
                target=pump_output, args=(cls.vpp.stderr, cls.vpp_stderr_queue))
            cls.vpp_stderr_reader_thread.start()
        except:
            if hasattr(cls, 'vpp'):
                cls.vpp.terminate()
                del cls.vpp
            raise

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
                raw_input("When done debugging, press ENTER to kill the process"
                          " and finish running the testcase...")

        if hasattr(cls, 'vpp'):
            cls.vapi.disconnect()
            cls.vpp.poll()
            if cls.vpp.returncode is None:
                cls.vpp.terminate()
            del cls.vpp

        if hasattr(cls, 'vpp_stdout_queue'):
            cls.logger.info(single_line_delim)
            cls.logger.info('VPP output to stdout while running %s:',
                            cls.__name__)
            cls.logger.info(single_line_delim)
            f = open(cls.tempdir + '/vpp_stdout.txt', 'w')
            while not cls.vpp_stdout_queue.empty():
                line = cls.vpp_stdout_queue.get_nowait()
                f.write(line)
                cls.logger.info('VPP stdout: %s' % line.rstrip('\n'))

        if hasattr(cls, 'vpp_stderr_queue'):
            cls.logger.info(single_line_delim)
            cls.logger.info('VPP output to stderr while running %s:',
                            cls.__name__)
            cls.logger.info(single_line_delim)
            f = open(cls.tempdir + '/vpp_stderr.txt', 'w')
            while not cls.vpp_stderr_queue.empty():
                line = cls.vpp_stderr_queue.get_nowait()
                f.write(line)
                cls.logger.info('VPP stderr: %s' % line.rstrip('\n'))
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
