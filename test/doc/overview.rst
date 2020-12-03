.. _unittest: https://docs.python.org/2/library/unittest.html
.. _TestCase: https://docs.python.org/2/library/unittest.html#unittest.TestCase
.. _AssertionError: https://docs.python.org/2/library/exceptions.html#exceptions.AssertionError
.. _SkipTest: https://docs.python.org/2/library/unittest.html#unittest.SkipTest
.. _virtualenv: http://docs.python-guide.org/en/latest/dev/virtualenvs/
.. _scapy: http://www.secdev.org/projects/scapy/
.. _logging: https://docs.python.org/2/library/logging.html
.. _process: https://docs.python.org/2/library/multiprocessing.html#the-process-class
.. _pipes: https://docs.python.org/2/library/multiprocessing.html#multiprocessing.Pipe
.. _managed: https://docs.python.org/2/library/multiprocessing.html#managers

.. |vtf| replace:: VPP Test Framework

|vtf|
=====

.. contents::
   :local:
   :depth: 1

Overview
########

The goal of the |vtf| is to ease writing, running and debugging
unit tests for the VPP. For this, python was chosen as a high level language
allowing rapid development with scapy_ providing the necessary tool for creating
and dissecting packets.

Anatomy of a test case
######################

Python's unittest_ is used as the base framework upon which the VPP test
framework is built. A test suite in the |vtf| consists of multiple classes
derived from `VppTestCase`, which is itself derived from TestCase_.
The test class defines one or more test functions, which act as test cases.

Function flow when running a test case is:

1. `setUpClass <VppTestCase.setUpClass>`:
   This function is called once for each test class, allowing a one-time test
   setup to be executed. If this functions throws an exception,
   none of the test functions are executed.
2. `setUp <VppTestCase.setUp>`:
   The setUp function runs before each of the test functions. If this function
   throws an exception other than AssertionError_ or SkipTest_, then this is
   considered an error, not a test failure.
3. *test_<name>*:
   This is the guts of the test case. It should execute the test scenario
   and use the various assert functions from the unittest framework to check
   necessary. Multiple test_<name> methods can exist in a test case.
4. `tearDown <VppTestCase.tearDown>`:
   The tearDown function is called after each test function with the purpose
   of doing partial cleanup.
5. `tearDownClass <VppTestCase.tearDownClass>`:
   Method called once after running all of the test functions to perform
   the final cleanup.

Logging
#######

Each test case has a logger automatically created for it, stored in
'logger' property, based on logging_. Use the logger's standard methods
debug(), info(), error(), ... to emit log messages to the logger.

All the log messages go always into a log file in temporary directory
(see below).

To control the messages printed to console, specify the V= parameter.

.. code-block:: shell

   make test         # minimum verbosity
   make test V=1     # moderate verbosity
   make test V=2     # maximum verbosity

Parallel test execution
#######################

|vtf| test suites can be run in parallel. Each test suite is executed
in a separate process spawned by Python multiprocessing process_.

The results from child test suites are sent to parent through pipes_, which are
aggregated and summarized at the end of the run.

Stdout, stderr and logs logged in child processes are redirected to individual
parent managed_ queues. The data from these queues are then emitted to stdout
of the parent process in the order the test suites have finished. In case there
are no finished test suites (such as at the beginning of the run), the data
from last started test suite are emitted in real time.

To enable parallel test run, specify the number of parallel processes:

.. code-block:: shell

   make test TEST_JOBS=n       # at most n processes will be spawned
   make test TEST_JOBS=auto    # chosen based on the number of cores
                               # and the size of shared memory

Test temporary directory and VPP life cycle
###########################################

Test separation is achieved by separating the test files and vpp instances.
Each test creates a temporary directory and it's name is used to create
a shared memory prefix which is used to run a VPP instance.
The temporary directory name contains the testcase class name for easy
reference, so for testcase named 'TestVxlan' the directory could be named
e.g. vpp-unittest-TestVxlan-UNUP3j.
This way, there is no conflict between any other VPP instances running
on the box and the test VPP. Any temporary files created by the test case
are stored in this temporary test directory.

The test temporary directory holds the following interesting files:

* log.txt - this contains the logger output on max verbosity
* pg*_in.pcap - last injected packet stream into VPP, named after the interface,
  so for pg0, the file will be named pg0_in.pcap
* pg*_out.pcap - last capture file created by VPP for interface, similarly,
  named after the interface, so for e.g. pg1, the file will be named
  pg1_out.pcap
* history files - whenever the capture is restarted or a new stream is added,
  the existing files are rotated and renamed, soo all the pcap files
  are always saved for later debugging if needed
* core - if vpp dumps a core, it'll be stored in the temporary directory
* vpp_stdout.txt - file containing output which vpp printed to stdout
* vpp_stderr.txt - file containing output which vpp printed to stderr

*NOTE*: existing temporary directories named vpp-unittest-* are automatically
removed when invoking 'make test*' or 'make retest*' to keep the temporary
directory clean.

Virtual environment
###################

Virtualenv_ is a python module which provides a means to create an environment
containing the dependencies required by the |vtf|, allowing a separation
from any existing system-wide packages. |vtf|'s Makefile automatically
creates a virtualenv_ inside build-root and installs the required packages
in that environment. The environment is entered whenever executing a test
via one of the make test targets.

Naming conventions
##################

Most unit tests do some kind of packet manipulation - sending and receiving
packets between VPP and virtual hosts connected to the VPP. Referring
to the sides, addresses, etc. is always done as if looking from the VPP side,
thus:

* *local_* prefix is used for the VPP side.
  So e.g. `local_ip4 <VppInterface.local_ip4>` address is the IPv4 address
  assigned to the VPP interface.
* *remote_* prefix is used for the virtual host side.
  So e.g. `remote_mac <VppInterface.remote_mac>` address is the MAC address
  assigned to the virtual host connected to the VPP.

Automatically generated addresses
#################################

To send packets, one needs to typically provide some addresses, otherwise
the packets will be dropped. The interface objects in |vtf| automatically
provide addresses based on (typically) their indexes, which ensures
there are no conflicts and eases debugging by making the addressing scheme
consistent.

The developer of a test case typically doesn't need to work with the actual
numbers, rather using the properties of the objects. The addresses typically
come in two flavors: '<address>' and '<address>n' - note the 'n' suffix.
The former address is a Python string, while the latter is translated using
socket.inet_pton to raw format in network byte order - this format is suitable
for passing as an argument to VPP APIs.

e.g. for the IPv4 address assigned to the VPP interface:

* local_ip4 - Local IPv4 address on VPP interface (string)
* local_ip4n - Local IPv4 address - raw, suitable as API parameter.

These addresses need to be configured in VPP to be usable using e.g.
`config_ip4` API. Please see the documentation to `VppInterface` for more
details.

By default, there is one remote address of each kind created for L3:
remote_ip4 and remote_ip6. If the test needs more addresses, because it's
simulating more remote hosts, they can be generated using
`generate_remote_hosts` API and the entries for them inserted into the ARP
table using `configure_ipv4_neighbors` API.

Packet flow in the |vtf|
########################

Test framework -> VPP
~~~~~~~~~~~~~~~~~~~~~

|vtf| doesn't send any packets to VPP directly. Traffic is instead injected
using packet-generator interfaces, represented by the `VppPGInterface` class.
Packets are written into a temporary .pcap file, which is then read by the VPP
and the packets are injected into the VPP world.

To add a list of packets to an interface, call the `add_stream` method on that
interface. Once everything is prepared, call `pg_start` method to start
the packet generator on the VPP side.

VPP -> test framework
~~~~~~~~~~~~~~~~~~~~~

Similarly, VPP doesn't send any packets to |vtf| directly. Instead, packet
capture feature is used to capture and write traffic to a temporary .pcap file,
which is then read and analyzed by the |vtf|.

The following APIs are available to the test case for reading pcap files.

* `get_capture`: this API is suitable for bulk & batch style of test, where
  a list of packets is prepared & sent, then the received packets are read
  and verified. The API needs the number of packets which are expected to
  be captured (ignoring filtered packets - see below) to know when the pcap
  file is completely written by the VPP. If using packet infos for verifying
  packets, then the counts of the packet infos can be automatically used
  by `get_capture` to get the proper count (in this case the default value
  None can be supplied as expected_count or ommitted altogether).
* `wait_for_packet`: this API is suitable for interactive style of test,
  e.g. when doing session management, three-way handsakes, etc. This API waits
  for and returns a single packet, keeping the capture file in place
  and remembering context. Repeated invocations return following packets
  (or raise Exception if timeout is reached) from the same capture file
  (= packets arriving on the same interface).

*NOTE*: it is not recommended to mix these APIs unless you understand how they
work internally. None of these APIs rotate the pcap capture file, so calling
e.g. `get_capture` after `wait_for_packet` will return already read packets.
It is safe to switch from one API to another after calling `enable_capture`
as that API rotates the capture file.

Automatic filtering of packets:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Both APIs (`get_capture` and `wait_for_packet`) by default filter the packet
capture, removing known uninteresting packets from it - these are IPv6 Router
Advertisments and IPv6 Router Alerts. These packets are unsolicitated
and from the point of |vtf| are random. If a test wants to receive these
packets, it should specify either None or a custom filtering function
as the value to the 'filter_out_fn' argument.

Common API flow for sending/receiving packets:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We will describe a simple scenario, where packets are sent from pg0 to pg1
interface, assuming that the interfaces were created using
`create_pg_interfaces` API.

1. Create a list of packets for pg0::

     packet_count = 10
     packets = create_packets(src=self.pg0, dst=self.pg1,
                              count=packet_count)

2. Add that list of packets to the source interface::

     self.pg0.add_stream(packets)

3. Enable capture on the destination interface::

     self.pg1.enable_capture()

4. Start the packet generator::

     self.pg_start()

5. Wait for capture file to appear and read it::

     capture = self.pg1.get_capture(expected_count=packet_count)

6. Verify packets match sent packets::

     self.verify_capture(send=packets, captured=capture)

Test framework objects
######################

The following objects provide VPP abstraction and provide a means to do
common tasks easily in the test cases.

* `VppInterface`: abstract class representing generic VPP interface
  and contains some common functionality, which is then used by derived classes
* `VppPGInterface`: class representing VPP packet-generator interface.
  The interface is created/destroyed when the object is created/destroyed.
* `VppSubInterface`: VPP sub-interface abstract class, containing common
  functionality for e.g. `VppDot1QSubint` and `VppDot1ADSubint` classes

How VPP APIs/CLIs are called
############################

Vpp provides python bindings in a python module called vpp-papi, which the test
framework installs in the virtual environment. A shim layer represented by
the `VppPapiProvider` class is built on top of the vpp-papi, serving these
purposes:

1. Automatic return value checks:
   After each API is called, the return value is checked against the expected
   return value (by default 0, but can be overridden) and an exception
   is raised if the check fails.
2. Automatic call of hooks:

   a. `before_cli <Hook.before_cli>` and `before_api <Hook.before_api>` hooks
      are used for debug logging and stepping through the test
   b. `after_cli <Hook.after_cli>` and `after_api <Hook.after_api>` hooks
      are used for monitoring the vpp process for crashes
3. Simplification of API calls:
   Many of the VPP APIs take a lot of parameters and by providing sane defaults
   for these, the API is much easier to use in the common case and the code is
   more readable. E.g. ip_add_del_route API takes ~25 parameters, of which
   in the common case, only 3 are needed.

Utility methods
###############

Some interesting utility methods are:

* `ppp`: 'Pretty Print Packet' - returns a string containing the same output
  as Scapy's packet.show() would print
* `ppc`: 'Pretty Print Capture' - returns a string containing printout of
  a capture (with configurable limit on the number of packets printed from it)
  using `ppp`

*NOTE*: Do not use Scapy's packet.show() in the tests, because it prints
the output to stdout. All output should go to the logger associated with
the test case.

Example: how to add a new test
##############################

In this example, we will describe how to add a new test case which tests
basic IPv4 forwarding.

1. Add a new file called test_ip4_fwd.py in the test directory, starting
   with a few imports::

     from framework import VppTestCase
     from scapy.layers.l2 import Ether
     from scapy.packet import Raw
     from scapy.layers.inet import IP, UDP
     from random import randint

2. Create a class inherited from the VppTestCase::

     class IP4FwdTestCase(VppTestCase):
         """ IPv4 simple forwarding test case """

3. Add a setUpClass function containing the setup needed for our test to run::

         @classmethod
         def setUpClass(self):
             super(IP4FwdTestCase, self).setUpClass()
             self.create_pg_interfaces(range(2))  #  create pg0 and pg1
             for i in self.pg_interfaces:
                 i.admin_up()  # put the interface up
                 i.config_ip4()  # configure IPv4 address on the interface
                 i.resolve_arp()  # resolve ARP, so that we know VPP MAC

4. Create a helper method to create the packets to send::

         def create_stream(self, src_if, dst_if, count):
             packets = []
             for i in range(count):
                 # create packet info stored in the test case instance
                 info = self.create_packet_info(src_if, dst_if)
                 # convert the info into packet payload
                 payload = self.info_to_payload(info)
                 # create the packet itself
                 p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                      IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4) /
                      UDP(sport=randint(1000, 2000), dport=5678) /
                      Raw(payload))
                 # store a copy of the packet in the packet info
                 info.data = p.copy()
                 # append the packet to the list
                 packets.append(p)

             # return the created packet list
             return packets

5. Create a helper method to verify the capture::

         def verify_capture(self, src_if, dst_if, capture):
             packet_info = None
             for packet in capture:
                 try:
                     ip = packet[IP]
                     udp = packet[UDP]
                     # convert the payload to packet info object
                     payload_info = self.payload_to_info(packet[Raw])
                     # make sure the indexes match
                     self.assert_equal(payload_info.src, src_if.sw_if_index,
                                       "source sw_if_index")
                     self.assert_equal(payload_info.dst, dst_if.sw_if_index,
                                       "destination sw_if_index")
                     packet_info = self.get_next_packet_info_for_interface2(
                                       src_if.sw_if_index,
                                       dst_if.sw_if_index,
                                       packet_info)
                     # make sure we didn't run out of saved packets
                     self.assertIsNotNone(packet_info)
                     self.assert_equal(payload_info.index, packet_info.index,
                                       "packet info index")
                     saved_packet = packet_info.data  # fetch the saved packet
                     # assert the values match
                     self.assert_equal(ip.src, saved_packet[IP].src,
                                       "IP source address")
                     # ... more assertions here
                     self.assert_equal(udp.sport, saved_packet[UDP].sport,
                                       "UDP source port")
                 except:
                     self.logger.error(ppp("Unexpected or invalid packet:",
                                       packet))
                     raise
             remaining_packet = self.get_next_packet_info_for_interface2(
                        src_if.sw_if_index,
                        dst_if.sw_if_index,
                        packet_info)
             self.assertIsNone(remaining_packet,
                               "Interface %s: Packet expected from interface "
                               "%s didn't arrive" % (dst_if.name, src_if.name))

6. Add the test code to test_basic function::

         def test_basic(self):
             count = 10
             # create the packet stream
             packets = self.create_stream(self.pg0, self.pg1, count)
             # add the stream to the source interface
             self.pg0.add_stream(packets)
             # enable capture on both interfaces
             self.pg0.enable_capture()
             self.pg1.enable_capture()
             # start the packet generator
             self.pg_start()
             # get capture - the proper count of packets was saved by
             # create_packet_info() based on dst_if parameter
             capture = self.pg1.get_capture()
             # assert nothing captured on pg0 (always do this last, so that
             # some time has already passed since pg_start())
             self.pg0.assert_nothing_captured()
             # verify capture
             self.verify_capture(self.pg0, self.pg1, capture)

7. Run the test by issuing 'make test' or, to run only this specific
   test, issue 'make test TEST=test_ip4_fwd'.
