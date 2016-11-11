.. _unittest: https://docs.python.org/2/library/unittest.html
.. _TestCase: https://docs.python.org/2/library/unittest.html#unittest.TestCase
.. _AssertionError: https://docs.python.org/2/library/exceptions.html#exceptions.AssertionError
.. _SkipTest: https://docs.python.org/2/library/unittest.html#unittest.SkipTest
.. _virtualenv: http://docs.python-guide.org/en/latest/dev/virtualenvs/
.. _scapy: http://www.secdev.org/projects/scapy/

.. |vtf| replace:: VPP Test Framework

|vtf|
=====

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
   necessary.
4. `tearDown <VppTestCase.tearDown>`:
   The tearDown function is called after each test function with the purpose
   of doing partial cleanup.
5. `tearDownClass <VppTestCase.tearDownClass>`:
   Method called once after running all of the test functions to perform
   the final cleanup.

Test temporary directory and VPP life cycle
###########################################

Test separation is achieved by separating the test files and vpp instances.
Each test creates a temporary directory and it's name is used to create
a shared memory prefix which is used to run a VPP instance.
This way, there is no conflict between any other VPP instances running
on the box and the test VPP. Any temporary files created by the test case
are stored in this temporary test directory.

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

Packet flow in the |vtf|
########################

Test framework -> VPP
~~~~~~~~~~~~~~~~~~~~~

|vtf| doesn't send any packets to VPP directly. Traffic is instead injected
using packet-generator interfaces, represented by the `VppPGInterface` class.
Packets are written into a temporary .pcap file, which is then read by the VPP
and the packets are injected into the VPP world.

VPP -> test framework
~~~~~~~~~~~~~~~~~~~~~

Similarly, VPP doesn't send any packets to |vtf| directly. Instead, packet
capture feature is used to capture and write traffic to a temporary .pcap file,
which is then read and analyzed by the |vtf|.

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

How VPP API/CLI is called
#########################

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

Example: how to add a new test
##############################

In this example, we will describe how to add a new test case which tests VPP...

1. Add a new file called...
2. Add a setUpClass function containing...
3. Add the test code in test...
4. Run the test...

|vtf| module documentation
##########################
 
.. toctree::
   :maxdepth: 2
   :glob:

   modules.rst

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

