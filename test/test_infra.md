# VPP Functional Test Infra

## Running VPP tests
VPP functional tests are triggered by `make test` command run in the git vpp source directory. Following Linux environment variables are used by the current VPP functional test infrastructure:

- `TEST=<name>` - run only specific test identified by filename `test/test_<name>.py`
-  `V=[0|1|2]` - set verbosity level. `0` for minimal verbosity, `1` for increased verbosity, `2` for maximum verbosity. Default value is 0.

Example of running tests:

```
~/src/vpp-test-infra$ make test V=1 TEST=vxlan
```

All tests listed in `test/` directory are run by default. To run selected tests you can set variable TEST when starting tests.

## Overview
The main functionality of the test framework is defined in [framework.py](test/framework.py) file. The implementation of the test framework uses classes and methods from Python module *unittest*.

Three main classes are defined to support the overall test automation:

* **class VppTestCase(unittest.TestCase)** - a sub-class of *unittest.TestCase* class. Provides methods to create and run test case. These methods can be divided into 5 groups:
    1. Methods to control test case setup and tear down:
        * *def setUpConstants(cls):*
        * *def setUpClass(cls):*
        * *def quit(cls):*
        * *def tearDownClass(cls):*
        * *def tearDown(self):*
        * *def setUp(self):*

    2. Methods to create VPP packet generator interfaces:
        * *def create_interfaces(cls, args):*

    3. Methods to execute VPP commands and print logs in the output (terminal for now):
        * *def log(cls, s, v=1):*
        * *def api(cls, s):*
        * *def cli(cls, v, s):*

    4. Methods to control packet stream generation and capturing:
        * *def pg_add_stream(cls, i, pkts):*
        * *def pg_enable_capture(cls, args):*
        * *def pg_start(cls):*
        * *def pg_get_capture(cls, o):*

    5. Methods to create and verify packets:
        * *def extend_packet(packet, size):*
        * *def add_packet_info_to_list(self, info):*
        * *def create_packet_info(self, pg_id, target_id):*
        * *def info_to_payload(info):*
        * *def payload_to_info(payload):*
        * *def get_next_packet_info(self, info):*
        * *def get_next_packet_info_for_interface(self, src_pg, info):*
        * *def get_next_packet_info_for_interface2(self, src_pg, dst_pg, info):*

* **class VppTestResult(unittest.TestResult)** - a sub-class of *unittest.TestResult* class. Provides methods to compile information about the tests that have succeeded and the ones that have failed. These methods can be divided into 4 groups:
    1. Processing test case result:
        * *def addSuccess(self, test):*
        * *def addFailure(self, test, err):*
        * *def addError(self, test, err):*

    2. Processing test case description:
        * *def getDescription(self, test):*

    3. Processing test case start and stop:
        * *def startTest(self, test):*
        * *def stopTest(self, test):*

    4. Printing error and failure information:
        * *def printErrors(self):*
        * *def printErrorList(self, flavour, errors):*

* **class VppTestRunner(unittest.TextTestRunner)** - a sub-class of *unittest.TextTestRunner* class. Provides basic test runner implementation that prints results on standard error stream. Contains one method:
    * *def run(self, test):*

In addition [util.py] (test/util.py) file defines number of common methods useful for many test cases. All of these methods are currently contained in one class:

* **class Util(object)**:
    * *def resolve_arp(cls, args):*
    * *def resolve_icmpv6_nd(cls, args):*
    * *def config_ip4(cls, args):*
    * *def config_ip6(cls, args):*

## Interaction with VPP
VPP is started from command line as a sub-process during the test case setup phase. Command line attributes to start VPP are stored in class variable *vpp_cmdline*.
To get an overview of VPP command line attributes, visit section [Command-line Arguments](https://wiki.fd.io/view/VPP/Command-line_Arguments) on VPP wiki page.

Current VPP test infrastructure is using two ways to interact with VPP for configuration, operational status check, tracing and logging.

### Using API commands
API commands are executed by VPP API test tool that is started from command line as a sub-process. Command line attributes to start VPP API test tool are stored in class variable *vpp_api_test_cmdline*.
When executed, API command and its possible output are printed in the terminal if verbosity level is greater then 0.

Example:

```
cls.api("sw_interface_set_flags pg1 admin-up")
```

will print in the terminal

```
API: sw_interface_set_flags pg1 admin-up
```

### Using CLI commands
CLI commands are executed via VPP API test tool by sending API command "*exec + cli_command*". It is possible to set verbosity level for executing specific CLI commands, so that the CLI command is executed only and only if its associated verbosity level is equal or lower then the verbosity level set in the system.

Similarly to API commands, when executed, CLI command and its possible output are printed in the terminal if verbosity level is greater then 0.

Example I - CLI command will be executed always (its verbosity is 0):

```
cls.cli(0, "show l2fib")
```

Example II - CLI command will be executed only if the verbosity level is set to 2:

```
self.cli(2, "show l2fib verbose")
```

## Logging
It is possible to log some additional information in the terminal for different verbosity levels.

Example I - verbosity level of the log is set to default value (0):

```
self.log("Verifying capture %u" % i)
```

will be always printed in the terminal:

```
LOG: Verifying capture 0
```

Example II - the log will be printed in the terminal only if the verbosity level is set to 2:

```
self.log("Got packet on port %u: src=%u (id=%u)"
                         % (o, payload_info.src, payload_info.index), 2)
```

---
***END***
