#!/usr/bin/env python
# @package framework
#  Module to handle test case execution.
#
#  The module provides a set of tools for constructing and running tests and
#  representing the results.

from abc import *
import time
import os
import sys
import subprocess
import unittest
from inspect import getdoc
from vpp_papi_provider import VppPapiProvider
from hook import Hook

from scapy.utils import wrpcap, rdpcap
from scapy.packet import Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr

from logging import *
import socket

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
#  These variables (RED, GREEN, YELLOW and LPURPLE) are used to configure
#  the color of the text to be printed in the terminal. Variable END is used
#  to revert the text color to the default one.
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
LPURPLE = '\033[94m'
END = '\033[0m'

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


class PollHook(Hook):
    """ Hook which periodically checks if the vpp subprocess is alive """

    def __init__(self, vpp_subprocess):
        self.vpp = vpp_subprocess

    def poll_vpp(self):
        """
        Poll the vpp status and throw an exception if it's not running
        @throws exception if VPP is not running anymore
        """
        self.vpp.poll()
        if self.vpp.returncode is not None:
            msg = "VPP subprocess died unexpectedly with returncode %s" % repr(
                self.vpp.returncode)
            critical(msg)
            raise Exception(msg)

    def after_api(self, api_name, api_args):
        """
        Check if VPP died after executing an API

        @param api_name: name of the API
        @param api_args: tuple containing the API arguments
        @throws exception if VPP is not running anymore

        """
        super(PollHook, self).after_api(api_name, api_args)
        self.poll_vpp()

    def after_cli(self, cli):
        """
        Check if VPP died after executing a CLI

        @param cli: CLI string
        @throws exception if VPP is not running anymore

        """
        super(PollHook, self).after_cli(cli)
        self.poll_vpp()

"""
@property vapi: VPP-api provider
"""
vapi = VppPapiProvider()


class VppInterface(object):
    """
    Generic VPP interface

    @property sw_if_index: interface index assigned by VPP
    @property my_mac: MAC-address of the VPP interface
    @property local_ip4: local IPv4 address on VPP interface (string)
    @property local_ip4n: local IPv4 address - raw, suitable as API parameter
    @property remote_ip4: IPv4 address of remote peer "connected" to this
        interface
    @property remote_ip4: remote IPv4 address - raw, suitable as API parameter
    @property name: name of the interface
    @property dump: raw result of sw_interface_dump for this interface
    """
    __metaclass__ = ABCMeta

    def post_init_setup(self):
        """ """
        self.my_mac = "02:00:00:00:ff:%02x" % self.sw_if_index
        self.local_ip4 = "172.16.%u.1" % self.sw_if_index
        self.local_ip4n = socket.inet_pton(socket.AF_INET, self.local_ip4)
        self.remote_ip4 = "172.16.%u.2" % self.sw_if_index
        self.remote_ip4n = socket.inet_pton(socket.AF_INET, self.remote_ip4)
        r = vapi.sw_interface_dump()
        found = False
        for intf in r:
            if intf.sw_if_index == self.sw_if_index:
                found = True
                self.name = intf.interface_name.split(b'\0', 1)[0]
                self.dump = intf
                break
        if not found:
            raise Exception("Could not find interface with sw_if_index %d "
                            "in interface dump %s" % (self.sw_if_index, repr(r)))

    @abstractmethod
    def __init__(self, cls, index):
        self.post_init_setup()
        info("New VppInterface, MAC=%s, remote_ip4=%s, local_ip4=%s" %
             (self.my_mac, self.remote_ip4, self.local_ip4))

    def config_ip4(self):
        """Configure IPv4 address on the VPP interface"""
        addr = self.local_ip4n
        addr_len = 24
        vapi.sw_interface_add_del_address(self.sw_if_index, addr, addr_len)

    def config_ip6(self):
        """Configure IPv6 address on the VPP interface"""
        addr = self.vpp_ip6n
        addr_len = 64
        vapi.sw_interface_add_del_address(
            self.sw_if_index, addr, addr_len, is_ipv6=1)

    def create_arp_req(self):
        """Create ARP request applicable for this interface"""
        return (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.my_mac) /
                ARP(op=ARP.who_has, pdst=self.local_ip4,
                    psrc=self.remote_ip4, hwsrc=self.my_mac))

    def resolve_arp(self, pg_interface=None):
        """Resolve ARP using provided packet-generator interface

        @param pg_interface: interface used to resolve, if None then this
            interface is used

        """
        if pg_interface is None:
            pg_interface = self
        info("Sending ARP request for %s on port %s" %
             (self.local_ip4, pg_interface.name))
        arp_req = self.create_arp_req()
        pg_interface.add_stream(arp_req)
        pg_interface.enable_capture()
        self.test.pg_start()
        info(vapi.cli("show trace"))
        arp_reply = pg_interface.get_capture()
        if arp_reply is None or len(arp_reply) == 0:
            info("No ARP received on port %s" % pg_interface.name)
            return
        arp_reply = arp_reply[0]
        if arp_reply[ARP].op == ARP.is_at:
            info("VPP %s MAC address is %s " %
                 (self.name, arp_reply[ARP].hwsrc))
            self.vpp_mac = arp_reply[ARP].hwsrc
        else:
            info("No ARP received on port %s" % pg_interface.name)

    def admin_up(self):
        """ Put interface ADMIN-UP """
        vapi.sw_interface_set_flags(self.sw_if_index, admin_up_down=1)

    def add_sub_if(self, sub_if):
        """
        Register a sub-interface with this interface

        @param sub_if: sub-interface

        """
        if not hasattr(self, 'sub_if'):
            self.sub_if = sub_if
        else:
            if type(self.sub_if) is list:
                self.sub_if.append(sub_if)
            else:
                self.sub_if = sub_if


class VppPGInterface(VppInterface):
    """
    VPP packet-generator interface

    @property pg_index: packet-generator interface index assigned by VPP
    @property out_path: file path to captured packets
    @property in_path: file path to injected packets
    @property capture_cli: CLI string to start capture on this interface
    @property cap_name: capture name for this interface
    @property input_cli: CLI string to load the injected packets
    """

    def post_init_setup(self):
        """ Perform post-init setup for super class and add our own setup """
        super(VppPGInterface, self).post_init_setup()
        self.out_path = "/tmp/pg%u_out.pcap" % self.sw_if_index
        self.in_path = "/tmp/pg%u_in.pcap" % self.sw_if_index
        self.capture_cli = "packet-generator capture pg%u pcap %s" % (
            self.pg_index, self.out_path)
        self.cap_name = "pcap%u" % self.sw_if_index
        self.input_cli = "packet-generator new pcap %s source pg%u name %s" % (
            self.in_path, self.pg_index, self.cap_name)

    def __init__(self, test, pg_index):
        """ Create VPP packet-generator interface """
        self.test = test
        self.pg_index = pg_index
        r = vapi.pg_create_interface(self.pg_index)
        self.sw_if_index = r.sw_if_index
        self.post_init_setup()

    def enable_capture(self):
        """ Enable capture on this packet-generator interface"""
        try:
            os.unlink(self.out_path)
        except:
            pass
        # FIXME this should be an API, but no such exists atm
        vapi.cli(self.capture_cli)

    def add_stream(self, pkts):
        """
        Add a stream of packets to this packet-generator

        @param pkts: iterable packets

        """
        try:
            os.remove(self.in_path)
        except:
            pass
        wrpcap(self.in_path, pkts)
        # FIXME this should be an API, but no such exists atm
        vapi.cli(self.input_cli)
        self.test.pg_streams.append(self.cap_name)
        vapi.cli("trace add pg-input %d" % len(pkts))

    def get_capture(self):
        """
        Get captured packets 

        @return: iterable packets
        """
        try:
            output = rdpcap(self.out_path)
        except IOError:  # TODO
            error("File %s does not exist, probably because no"
                  " packets arrived" % self.out_path)
            return []
        return output


class VppTestCase(unittest.TestCase):
    """
    Subclass of the python unittest.TestCase class.

    This subclass is a base class for test cases that are implemented as classes.
    It provides methods to create and run test case.

    @property packet_infos List of packet infos
    """

    @classmethod
    def setUpConstants(cls):
        """ Set-up the test case class based on environment variables """
        cls.vpp_bin = os.getenv('VPP_TEST_BIN', "vpp")
        cls.plugin_path = os.getenv('VPP_TEST_PLUGIN_PATH')
        cls.vpp_cmdline = [cls.vpp_bin, "unix", "nodaemon",
                           "api-segment", "{", "prefix", "unittest", "}"]
        if cls.plugin_path is not None:
            cls.vpp_cmdline.extend(["plugin_path", cls.plugin_path])
        info("vpp_cmdline: %s" % cls.vpp_cmdline)

    @classmethod
    def setUpClass(cls):
        """
        Perform class setup before running the testcase
        Remove shared memory files, start vpp and connect the vpp-api
        """
        cls.setUpConstants()
        cls.pg_streams = []
        cls.packet_infos = {}
        cls.verbose = 0
        print double_line_delim
        print YELLOW + getdoc(cls) + END
        print double_line_delim
        os.system("rm -f /dev/shm/unittest-global_vm")
        os.system("rm -f /dev/shm/unittest-vpe-api")
        os.system("rm -f /dev/shm/unittest-db")
        cls.vpp = subprocess.Popen(cls.vpp_cmdline, stderr=subprocess.PIPE)
        debug("Spawned VPP with PID: %d" % cls.vpp.pid)
        vapi.register_hook(PollHook(cls.vpp))
        vapi.connect()

    @classmethod
    def quit(cls):
        """ 
        Disconnect vpp-api, kill vpp and cleanup shared memory files
        """
        vapi.disconnect()
        cls.vpp.terminate()
        cls.vpp = None
        os.system("rm -f /dev/shm/unittest-global_vm")
        os.system("rm -f /dev/shm/unittest-vpe-api")
        os.system("rm -f /dev/shm/unittest-db")

    @classmethod
    def tearDownClass(cls):
        """ Perform final cleanup after running all tests in this test-case """
        cls.quit()

    def tearDown(self):
        """ Show various debug prints after each test """
        info(vapi.cli("show int"))
        info(vapi.cli("show trace"))
        info(vapi.cli("show hardware"))
        info(vapi.cli("show ip arp"))
        info(vapi.cli("show ip fib"))
        info(vapi.cli("show error"))
        info(vapi.cli("show run"))

    def setUp(self):
        """ Clear trace before running each test"""
        vapi.cli("clear trace")

    @classmethod
    def pg_enable_capture(cls, interfaces):
        """
        Enable capture on packet-generator interfaces

        @param interfaces: iterable interface indexes

        """
        for i in interfaces:
            i.enable_capture()

    @classmethod
    def pg_start(cls):
        """
        Enable the packet-generator and send all prepared packet streams
        Remove the packet streams afterwards
        """
        vapi.cli("trace add pg-input 50")  # 50 is maximum
        vapi.cli('packet-generator enable')
        for stream in cls.pg_streams:
            vapi.cli('packet-generator delete %s' % stream)
        cls.pg_streams = []

    @classmethod
    def create_pg_interfaces(cls, interfaces):
        """
        Create packet-generator interfaces

        @param interfaces: iterable indexes of the interfaces

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

        @param packet: packet
        @param size: target size

        """
        packet_len = len(packet) + 4
        extend = size - packet_len
        if extend > 0:
            packet[Raw].load += ' ' * extend

    def add_packet_info_to_list(self, info):
        """
        Add packet info to the testcase's packet info list

        @param info: packet info

        """
        info.index = len(self.packet_infos)
        self.packet_infos[info.index] = info

    def create_packet_info(self, src_pg_index, dst_pg_index):
        """
        Create packet info object containing the source and destination indexes
        and add it to the testcase's packet info list

        @param src_pg_index: source packet-generator index
        @param dst_pg_index: destination packet-generator index

        @return: _PacketInfo object

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

        @param info: _PacketInfo object

        @return: string containing serialized data from packet info
        """
        return "%d %d %d" % (info.index, info.src, info.dst)

    @staticmethod
    def payload_to_info(payload):
        """
        Convert packet payload to _PacketInfo object

        @param payload: packet payload

        @return: _PacketInfo object containing de-serialized data from payload

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

        @param info: info or None
        @return: next info in list or None if no more infos
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

        @param src_index: source interface index to search for
        @param info: packet info - where to start the search
        @return: packet info or None

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

        @param src_index: source interface index to search for
        @param dst_index: destination interface index to search for 
        @param info: packet info - where to start the search
        @return: packet info or None

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
        @param stream File descriptor to store where to report test results. Set
            to the standard error stream by default.
        @param descriptions Boolean variable to store information if to use test
            case descriptions.
        @param verbosity Integer variable to store required verbosity level.
        """
        unittest.TestResult.__init__(self, stream, descriptions, verbosity)
        self.stream = stream
        self.descriptions = descriptions
        self.verbosity = verbosity
        self.result_string = None

    def addSuccess(self, test):
        """
        Record a test succeeded result

        @param test:

        """
        unittest.TestResult.addSuccess(self, test)
        self.result_string = GREEN + "OK" + END

    def addFailure(self, test, err):
        """
        Record a test failed result

        @param test:
        @param err: error message

        """
        unittest.TestResult.addFailure(self, test, err)
        self.result_string = RED + "FAIL" + END

    def addError(self, test, err):
        """
        Record a test error result

        @param test:
        @param err: error message

        """
        unittest.TestResult.addError(self, test, err)
        self.result_string = RED + "ERROR" + END

    def getDescription(self, test):
        """
        Get test description

        @param test:
        @return: test description

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

        @param test: 

        """
        unittest.TestResult.startTest(self, test)
        if self.verbosity > 0:
            self.stream.writeln(
                "Starting " + self.getDescription(test) + " ...")
            self.stream.writeln(single_line_delim)

    def stopTest(self, test):
        """
        Stop a test

        @param test: 

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


        @param flavour: error type
        @param errors: iterable errors

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

    @property resultclass: variable to store the results of a set of tests.
    """
    resultclass = VppTestResult

    def run(self, test):
        """
        Run the tests

        @param test: 

        """
        print "Running tests using custom test runner"  # debug message
        return super(VppTestRunner, self).run(test)
