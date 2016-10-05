#!/usr/bin/env python
## @package framework
#  Module to handle test case execution.
#
#  The module provides a set of tools for constructing and running tests and
#  representing the results.

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import os
import subprocess
import unittest
from inspect import getdoc

from scapy.utils import wrpcap, rdpcap
from scapy.packet import Raw

## Static variables to store color formatting strings.
#
#  These variables (RED, GREEN, YELLOW and LPURPLE) are used to configure
#  the color of the text to be printed in the terminal. Variable END is used
#  to revert the text color to the default one.
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
LPURPLE = '\033[94m'
END = '\033[0m'

## Private class to create packet info object.
#
#  Help process information about the next packet.
#  Set variables to default values.
class _PacketInfo(object):
    index = -1
    src = -1
    dst = -1
    data = None
    ## @var index
    #  Integer variable to store the index of the packet.
    ## @var src
    #  Integer variable to store the index of the source packet generator
    #  interface of the packet.
    ## @var dst
    #  Integer variable to store the index of the destination packet generator
    #  interface of the packet.
    ## @var data
    #  Object variable to store the copy of the former packet.

## Subclass of the python unittest.TestCase class.
#
#  This subclass is a base class for test cases that are implemented as classes.
#  It provides methods to create and run test case.
class VppTestCase(unittest.TestCase):

    ## Class method to set class constants necessary to run test case.
    #  @param cls The class pointer.
    @classmethod
    def setUpConstants(cls):
        cls.vpp_bin = os.getenv('VPP_TEST_BIN', "vpp")
        cls.vpp_api_test_bin = os.getenv("VPP_TEST_API_TEST_BIN",
                                         "vpp-api-test")
        cls.vpp_cmdline = [cls.vpp_bin, "unix", "nodaemon", "api-segment", "{",
                           "prefix", "unittest", "}"]
        cls.vpp_api_test_cmdline = [cls.vpp_api_test_bin, "chroot", "prefix",
                                    "unittest"]
        try:
            cls.verbose = int(os.getenv("V", 0))
        except:
            cls.verbose = 0

        ## @var vpp_bin
        #  String variable to store the path to vpp (vector packet processor).
        ## @var vpp_api_test_bin
        #  String variable to store the path to vpp_api_test (vpp API test tool).
        ## @var vpp_cmdline
        #  List of command line attributes for vpp.
        ## @var vpp_api_test_cmdline
        #  List of command line attributes for vpp_api_test.
        ## @var verbose
        #  Integer variable to store required verbosity level.

    ## Class method to start the test case.
    #  1. Initiate test case constants and set test case variables to default
    #  values.
    #  2. Remove files from the shared memory.
    #  3. Start vpp as a subprocess.
    #  @param cls The class pointer.
    @classmethod
    def setUpClass(cls):
        cls.setUpConstants()
        cls.pg_streams = []
        cls.MY_MACS = {}
        cls.MY_IP4S = {}
        cls.MY_IP6S = {}
        cls.VPP_MACS = {}
        cls.VPP_IP4S = {}
        cls.VPP_IP6S = {}
        cls.packet_infos = {}
        print "=================================================================="
        print YELLOW + getdoc(cls) + END
        print "=================================================================="
        os.system("rm -f /dev/shm/unittest-global_vm")
        os.system("rm -f /dev/shm/unittest-vpe-api")
        os.system("rm -f /dev/shm/unittest-db")
        cls.vpp = subprocess.Popen(cls.vpp_cmdline, stderr=subprocess.PIPE)
        ## @var pg_streams
        #  List variable to store packet-generator streams for interfaces.
        ## @var MY_MACS
        #  Dictionary variable to store host MAC addresses connected to packet
        #  generator interfaces.
        ## @var MY_IP4S
        #  Dictionary variable to store host IPv4 addresses connected to packet
        #  generator interfaces.
        ## @var MY_IP6S
        #  Dictionary variable to store host IPv6 addresses connected to packet
        #  generator interfaces.
        ## @var VPP_MACS
        #  Dictionary variable to store VPP MAC addresses of the packet
        #  generator interfaces.
        ## @var VPP_IP4S
        #  Dictionary variable to store VPP IPv4 addresses of the packet
        #  generator interfaces.
        ## @var VPP_IP6S
        #  Dictionary variable to store VPP IPv6 addresses of the packet
        #  generator interfaces.
        ## @var vpp
        #  Test case object variable to store file descriptor of running vpp
        #  subprocess with open pipe to the standard error stream per
        #  VppTestCase object.

    ## Class method to do cleaning when all tests (test_) defined for
    #  VppTestCase class are finished.
    #  1. Terminate vpp and kill all vpp instances.
    #  2. Remove files from the shared memory.
    #  @param cls The class pointer.
    @classmethod
    def quit(cls):
        cls.vpp.terminate()
        cls.vpp = None
        os.system("rm -f /dev/shm/unittest-global_vm")
        os.system("rm -f /dev/shm/unittest-vpe-api")
        os.system("rm -f /dev/shm/unittest-db")

    ## Class method to define tear down action of the VppTestCase class.
    #  @param cls The class pointer.
    @classmethod
    def tearDownClass(cls):
        cls.quit()

    ## Method to define tear down VPP actions of the test case.
    #  @param self The object pointer.
    def tearDown(self):
        self.cli(2, "show int")
        self.cli(2, "show trace")
        self.cli(2, "show hardware")
        self.cli(2, "show ip arp")
        self.cli(2, "show ip fib")
        self.cli(2, "show error")
        self.cli(2, "show run")

    ## Method to define setup action of the test case.
    #  @param self The object pointer.
    def setUp(self):
        self.cli(2, "clear trace")

    ## Class method to print logs.
    #  Based on set level of verbosity print text in the terminal.
    #  @param cls The class pointer.
    #  @param s String variable to store text to be printed.
    #  @param v Integer variable to store required level of verbosity.
    @classmethod
    def log(cls, s, v=1):
        if cls.verbose >= v:
            print "LOG: " + LPURPLE + s + END

    ## Class method to execute api commands.
    #  Based on set level of verbosity print the output of the api command in
    #  the terminal.
    #  @param cls The class pointer.
    #  @param s String variable to store api command string.
    @classmethod
    def api(cls, s):
        p = subprocess.Popen(cls.vpp_api_test_cmdline,
                             stdout=subprocess.PIPE,
                             stdin=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        if cls.verbose > 0:
            print "API: " + RED + s + END
        p.stdin.write(s)
        out = p.communicate()[0]
        out = out.replace("vat# ", "", 2)
        if cls.verbose > 0:
            if len(out) > 1:
                print YELLOW + out + END
        ## @var p
        #  Object variable to store file descriptor of vpp_api_test subprocess
        #  with open pipes to the standard output, inputs and error streams.
        ## @var out
        #  Tuple variable to store standard output of vpp_api_test subprocess
        #  where the string "vat# " is replaced by empty string later.

    ## Class method to execute cli commands.
    #  Based on set level of verbosity of the log and verbosity defined by
    #  environmental variable execute the cli command and print the output in
    #  the terminal.
    #  CLI command is executed via vpp API test tool (exec + cli_command)
    #  @param cls The class pointer.
    #  @param v Integer variable to store required level of verbosity.
    #  @param s String variable to store cli command string.
    @classmethod
    def cli(cls, v, s):
        if cls.verbose < v:
            return
        p = subprocess.Popen(cls.vpp_api_test_cmdline,
                             stdout=subprocess.PIPE,
                             stdin=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        if cls.verbose > 0:
            print "CLI: " + RED + s + END
        p.stdin.write('exec ' + s)
        out = p.communicate()[0]
        out = out.replace("vat# ", "", 2)
        if cls.verbose > 0:
            if len(out) > 1:
                print YELLOW + out + END
        ## @var p
        #  Object variable to store file descriptor of vpp_api_test subprocess
        #  with open pipes to the standard output, inputs and error streams.
        ## @var out
        #  Tuple variable to store standard output of vpp_api_test subprocess
        #  where the string "vat# " is replaced by empty string later.

    ## Class method to create incoming packet stream for the packet-generator
    #  interface.
    #  Delete old /tmp/pgX_in.pcap file if exists and create the empty one and
    #  fill it with provided packets and add it to pg_streams list.
    #  @param cls The class pointer.
    #  @param i Integer variable to store the index of the packet-generator
    #  interface to create packet stream for.
    #  @param pkts List variable to store packets to be added to the stream.
    @classmethod
    def pg_add_stream(cls, i, pkts):
        os.system("rm -f /tmp/pg%u_in.pcap" % i)
        wrpcap("/tmp/pg%u_in.pcap" % i, pkts)
        # no equivalent API command
        cls.cli(0, "packet-generator new pcap /tmp/pg%u_in.pcap source pg%u"
                   " name pcap%u" % (i, i, i))
        cls.pg_streams.append('pcap%u' % i)

    ## Class method to enable packet capturing for the packet-generator
    #  interface.
    #  Delete old /tmp/pgX_out.pcap file if exists and set the packet-generator
    #  to capture outgoing packets to /tmp/pgX_out.pcap file.
    #  @param cls The class pointer.
    #  @param args List variable to store the indexes of the packet-generator
    #  interfaces to start packet capturing for.
    @classmethod
    def pg_enable_capture(cls, args):
        for i in args:
            os.system("rm -f /tmp/pg%u_out.pcap" % i)
            cls.cli(0, "packet-generator capture pg%u pcap /tmp/pg%u_out.pcap"
                    % (i, i))

    ## Class method to start packet sending.
    #  Start to send packets for all defined pg streams. Delete every stream
    #  from the stream list when sent and clear the pg_streams list.
    #  @param cls The class pointer.
    @classmethod
    def pg_start(cls):
        cls.cli(2, "trace add pg-input 50")  # 50 is maximum
        cls.cli(0, 'packet-generator enable')
        for stream in cls.pg_streams:
            cls.cli(0, 'packet-generator delete %s' % stream)
        cls.pg_streams = []

    ## Class method to return captured packets.
    #  Return packet captured for the defined packet-generator interface. Open
    #  the corresponding pcap file (/tmp/pgX_out.pcap), read the content and
    #  store captured packets to output variable.
    #  @param cls The class pointer.
    #  @param o Integer variable to store the index of the packet-generator
    #  interface.
    #  @return output List of packets captured on the defined packet-generator
    #  interface. If the corresponding pcap file (/tmp/pgX_out.pcap) does not
    #  exist return empty list.
    @classmethod
    def pg_get_capture(cls, o):
        pcap_filename = "/tmp/pg%u_out.pcap" % o
        try:
            output = rdpcap(pcap_filename)
        except IOError:  # TODO
            cls.log("WARNING: File %s does not exist, probably because no"
                    " packets arrived" % pcap_filename)
            return []
        return output
        ## @var pcap_filename
        #  File descriptor to the corresponding pcap file.

    ## Class method to create packet-generator interfaces.
    #  Create packet-generator interfaces and add host MAC addresses connected
    #  to these packet-generator interfaces to the MY_MACS dictionary.
    #  @param cls The class pointer.
    #  @param args List variable to store the indexes of the packet-generator
    #  interfaces to be created.
    @classmethod
    def create_interfaces(cls, args):
        for i in args:
            cls.MY_MACS[i] = "02:00:00:00:ff:%02x" % i
            cls.log("My MAC address is %s" % (cls.MY_MACS[i]))
            cls.api("pg_create_interface if_id %u" % i)
            cls.api("sw_interface_set_flags pg%u admin-up" % i)

    ## Static method to extend packet to specified size
    #  Extend provided packet to the specified size (including Ethernet FCS).
    #  The packet is extended by adding corresponding number of spaces to the
    #  packet payload.
    #  NOTE: Currently works only when Raw layer is present.
    #  @param packet Variable to store packet object.
    #  @param size Integer variable to store the required size of the packet.
    @staticmethod
    def extend_packet(packet, size):
        packet_len = len(packet) + 4
        extend = size - packet_len
        if extend > 0:
            packet[Raw].load += ' ' * extend
        ## @var packet_len
        #  Integer variable to store the current packet length including
        #  Ethernet FCS.
        ## @var extend
        #  Integer variable to store the size of the packet extension.

    ## Method to add packet info object to the packet_infos list.
    #  Extend the existing packet_infos list with the given information from
    #  the packet.
    #  @param self The object pointer.
    #  @param info Object to store required information from the packet.
    def add_packet_info_to_list(self, info):
        info.index = len(self.packet_infos)
        self.packet_infos[info.index] = info
        ## @var info.index
        # Info object attribute to store the packet order in the stream.
        ## @var packet_infos
        #  List variable to store required information from packets.

    ## Method to create packet info object.
    #  Create the existing packet_infos list with the given information from
    #  the packet.
    #  @param self The object pointer.
    #  @param pg_id Integer variable to store the index of the packet-generator
    #  interface.
    def create_packet_info(self, pg_id, target_id):
        info = _PacketInfo()
        self.add_packet_info_to_list(info)
        info.src = pg_id
        info.dst = target_id
        return info
        ## @var info
        #  Object to store required information from packet.
        ## @var info.src
        #  Info object attribute to store the index of the source packet
        #  generator interface of the packet.
        ## @var info.dst
        #  Info object attribute to store the index of the destination packet
        #  generator interface of the packet.

    ## Static method to return packet info string.
    #  Create packet info string from the provided info object that will be put
    #  to the packet payload.
    #  @param info Object to store required information from the packet.
    #  @return String of information about packet's order in the stream, source
    #  and destination packet generator interface.
    @staticmethod
    def info_to_payload(info):
        return "%d %d %d" % (info.index, info.src, info.dst)

    ## Static method to create packet info object from the packet payload.
    #  Create packet info object and set its attribute values based on data
    #  gained from the packet payload.
    #  @param payload String variable to store packet payload.
    #  @return info Object to store required information about the packet.
    @staticmethod
    def payload_to_info(payload):
        numbers = payload.split()
        info = _PacketInfo()
        info.index = int(numbers[0])
        info.src = int(numbers[1])
        info.dst = int(numbers[2])
        return info
        ## @var info.index
        #  Info object attribute to store the packet order in the stream.
        ## @var info.src
        #  Info object attribute to store the index of the source packet
        #  generator interface of the packet.
        ## @var info.dst
        #  Info object attribute to store the index of the destination packet
        #  generator interface of the packet.

    ## Method to return packet info object of the next packet in
    #  the packet_infos list.
    #  Get the next packet info object from the packet_infos list by increasing
    #  the packet_infos list index by one.
    #  @param self The object pointer.
    #  @param info Object to store required information about the packet.
    #  @return packet_infos[next_index] Next info object from the packet_infos
    #  list with stored information about packets. Return None if the end of
    #  the list is reached.
    def get_next_packet_info(self, info):
        if info is None:
            next_index = 0
        else:
            next_index = info.index + 1
        if next_index == len(self.packet_infos):
            return None
        else:
            return self.packet_infos[next_index]
        ## @var next_index
        #  Integer variable to store the index of the next info object.

    ## Method to return packet info object of the next packet with the required
    #  source packet generator interface.
    #  Iterate over the packet_infos list and search for the next packet info
    #  object with the required source packet generator interface.
    #  @param self The object pointer.
    #  @param src_pg Integer variable to store index of requested source packet
    #  generator interface.
    #  @param info Object to store required information about the packet.
    #  @return packet_infos[next_index] Next info object from the packet_infos
    #  list with stored information about packets. Return None if the end of
    #  the list is reached.
    def get_next_packet_info_for_interface(self, src_pg, info):
        while True:
            info = self.get_next_packet_info(info)
            if info is None:
                return None
            if info.src == src_pg:
                return info
        ## @var info.src
        #  Info object attribute to store the index of the source packet
        #  generator interface of the packet.

    ## Method to return packet info object of the next packet with required
    #  source and destination packet generator interfaces.
    #  Search for the next packet info object with the required source and
    #  destination packet generator interfaces.
    #  @param self The object pointer.
    #  @param src_pg Integer variable to store the index of the requested source
    #  packet generator interface.
    #  @param dst_pg Integer variable to store the index of the requested source
    #  packet generator interface.
    #  @param info Object to store required information about the packet.
    #  @return info Object with the info about the next packet with with
    #  required source and destination packet generator interfaces. Return None
    #  if there is no other packet with required data.
    def get_next_packet_info_for_interface2(self, src_pg, dst_pg, info):
        while True:
            info = self.get_next_packet_info_for_interface(src_pg, info)
            if info is None:
                return None
            if info.dst == dst_pg:
                return info
        ## @var info.dst
        #  Info object attribute to store the index of the destination packet
        #  generator interface of the packet.


## Subclass of the python unittest.TestResult class.
#
#  This subclass provides methods to compile information about which tests have
#  succeeded and which have failed.
class VppTestResult(unittest.TestResult):
    ## The constructor.
    #  @param stream File descriptor to store where to report test results. Set
    #  to the standard error stream by default.
    #  @param descriptions Boolean variable to store information if to use test
    #  case descriptions.
    #  @param verbosity Integer variable to store required verbosity level.
    def __init__(self, stream, descriptions, verbosity):
        unittest.TestResult.__init__(self, stream, descriptions, verbosity)
        self.stream = stream
        self.descriptions = descriptions
        self.verbosity = verbosity
        self.result_string = None
        ## @var result_string
        #  String variable to store the test case result string.


    ## Method called when the test case succeeds.
    #  Run the default implementation (that does nothing) and set the result
    #  string in case of test case success.
    #  @param self The object pointer.
    #  @param test Object variable to store the test case instance.
    def addSuccess(self, test):
        unittest.TestResult.addSuccess(self, test)
        self.result_string = GREEN + "OK" + END
        ## @var result_string
        #  String variable to store the test case result string.

    ## Method called when the test case signals a failure.
    #  Run the default implementation that appends a tuple (test, formatted_err)
    #  to the instance's failures attribute, where formatted_err is a formatted
    #  traceback derived from err and set the result string in case of test case
    #  success.
    #  @param self The object pointer.
    #  @param test Object variable to store the test case instance.
    #  @param err Tuple variable to store the error data:
    #  (type, value, traceback).
    def addFailure(self, test, err):
        unittest.TestResult.addFailure(self, test, err)
        self.result_string = RED + "FAIL" + END
        ## @var result_string
        #  String variable to store the test case result string.

    ## Method called when the test case raises an unexpected exception.
    #  Run the default implementation that appends a tuple (test, formatted_err)
    #  to the instance's error attribute, where formatted_err is a formatted
    #  traceback derived from err and set the result string in case of test case
    #  unexpected failure.
    #  @param self The object pointer.
    #  @param test Object variable to store the test case instance.
    #  @param err Tuple variable to store the error data:
    #  (type, value, traceback).
    def addError(self, test, err):
        unittest.TestResult.addError(self, test, err)
        self.result_string = RED + "ERROR" + END
        ## @var result_string
        #  String variable to store the test case result string.

    ## Method to get the description of the test case.
    #  Used to get the description string from the test case object.
    #  @param self The object pointer.
    #  @param test Object variable to store the test case instance.
    #  @return String of the short description if exist otherwise return test
    #  case name string.
    def getDescription(self, test):
        # TODO: if none print warning not raise exception
        short_description = test.shortDescription()
        if self.descriptions and short_description:
            return short_description
        else:
            return str(test)
        ## @var short_description
        #  String variable to store the short description of the test case.

    ## Method called when the test case is about to be run.
    #  Run the default implementation and based on the set verbosity level write
    #  the starting string to the output stream.
    #  @param self The object pointer.
    #  @param test Object variable to store the test case instance.
    def startTest(self, test):
        unittest.TestResult.startTest(self, test)
        if self.verbosity > 0:
            self.stream.writeln("Starting " + self.getDescription(test) + " ...")
            self.stream.writeln("------------------------------------------------------------------")

    ## Method called after the test case has been executed.
    #  Run the default implementation and based on the set verbosity level write
    #  the result string to the output stream.
    #  @param self The object pointer.
    #  @param test Object variable to store the test case instance.
    def stopTest(self, test):
        unittest.TestResult.stopTest(self, test)
        if self.verbosity > 0:
            self.stream.writeln("------------------------------------------------------------------")
            self.stream.writeln("%-60s%s" % (self.getDescription(test), self.result_string))
            self.stream.writeln("------------------------------------------------------------------")
        else:
            self.stream.writeln("%-60s%s" % (self.getDescription(test), self.result_string))

    ## Method to write errors and failures information to the output stream.
    #  Write content of errors and failures lists to the output stream.
    #  @param self The object pointer.
    def printErrors(self):
        self.stream.writeln()
        self.printErrorList('ERROR', self.errors)
        self.printErrorList('FAIL', self.failures)
        ## @var errors
        #  List variable containing 2-tuples of TestCase instances and strings
        #  holding formatted tracebacks. Each tuple represents a test which
        #  raised an unexpected exception.
        ## @var failures
        #  List variable containing 2-tuples of TestCase instances and strings
        #  holding formatted tracebacks. Each tuple represents a test where
        #  a failure was explicitly signalled using the TestCase.assert*()
        #  methods.

    ## Method to write the error information to the output stream.
    #  Write content of error lists to the output stream together with error
    #  type and test case description.
    #  @param self The object pointer.
    #  @param flavour String variable to store error type.
    #  @param errors List variable to store 2-tuples of TestCase instances and
    #  strings holding formatted tracebacks.
    def printErrorList(self, flavour, errors):
        for test, err in errors:
            self.stream.writeln('=' * 70)
            self.stream.writeln("%s: %s" % (flavour, self.getDescription(test)))
            self.stream.writeln('-' * 70)
            self.stream.writeln("%s" % err)
        ## @var test
        #  Object variable to store the test case instance.
        ## @var err
        #  String variable to store formatted tracebacks.


## Subclass of the python unittest.TextTestRunner class.
#
#  A basic test runner implementation which prints results on standard error.
class VppTestRunner(unittest.TextTestRunner):
    ##  Class object variable to store the results of a set of tests.
    resultclass = VppTestResult

    ## Method to run the test.
    #  Print debug message in the terminal and run the standard run() method
    #  of the test runner collecting the result into the test result object.
    #  @param self The object pointer.
    #  @param test Object variable to store the test case instance.
    #  @return Test result object of the VppTestRunner.
    def run(self, test):
        print "Running tests using custom test runner"  # debug message
        return super(VppTestRunner, self).run(test)
