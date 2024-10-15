Host stack test framework
=========================

Overview
--------

The goal of the Host stack test framework (**hs-test**) is to ease writing and running end-to-end tests for VPP's Host Stack.
End-to-end tests often want multiple VPP instances, network namespaces, different types of interfaces
and to execute external tools or commands. With such requirements the existing VPP test framework is not sufficient.
For this, ``Go`` was chosen as a high level language, allowing rapid development, with ``Docker`` and ``ip`` being the tools for creating required topology.

`Ginkgo`_ forms the base framework upon which the *hs-test* is built and run.
All tests are technically in a single suite because we are only using ``package main``. We simulate suite behavior by grouping tests by the topology they require.
This allows us to run those mentioned groups in parallel, but not individual tests in parallel.


Anatomy of a test case
----------------------

**Prerequisites**:

* Install hs-test dependencies with ``make install-deps``
* Tests use *hs-test*'s own docker image, so building it before starting tests is a prerequisite. Run ``make build[-debug]`` to do so
* Docker has to be installed and Go has to be in path of both the running user and root
* Root privileges are required to run tests as it uses Linux ``ip`` command for configuring topology

**Action flow when running a test case**:

#. It starts with running ``make test``. Optional arguments are VERBOSE, PERSIST (topology configuration isn't cleaned up after test run, use ``make cleanup-hst`` to clean up),
   TEST=<test-name> to run a specific test and PARALLEL=[n-cpus]. If you want to run multiple specific tests, separate their names with a comma.
#. ``make list-tests`` (or ``make help``) shows all tests.
#. ``Ginkgo`` looks for a spec suite in the current directory and then compiles it to a .test binary.
#. The Ginkgo test framework runs each function that was registered manually using ``Register[SuiteName]Test()``. Each of these functions correspond to a suite.
#. Ginkgo's ``RunSpecs(t, "Suite description")`` function is the entry point and does the following:

  #. Ginkgo compiles the spec, builds a spec tree
  #. ``Describe`` container nodes in suite\_\*.go files are run (in series by default, or in parallel with the argument PARALLEL=[n-cpus])
  #. Suite is initialized. The topology is loaded and configured in this step
  #. Registered tests are run in generated ``It`` subject nodes
  #. Execute tear-down functions, which currently consists of stopping running containers
     and clean-up of test topology

Adding a test case
------------------

This describes adding a new test case to an existing suite.
For adding a new suite, please see `Modifying the framework`_ below.

#. To write a new test case, create a file whose name ends with ``_test.go`` or pick one that already exists
#. Declare method whose name ends with ``Test`` and specifies its parameter as a pointer to the suite's struct (defined in ``infra/suite_*.go``)
#. Implement test behaviour inside the test method. This typically includes the following:

   #. Import ``. "fd.io/hs-test/infra"``
   #. Retrieve a running container in which to run some action. Method ``GetContainerByName``
      from ``HstSuite`` struct serves this purpose
   #. Interact with VPP through the ``VppInstance`` struct embedded in container. It provides ``Vppctl`` method to access debug CLI
   #. Run arbitrary commands inside the containers with ``Exec`` method
   #. Run other external tool with one of the preexisting functions in the ``infra/utils.go`` file.
      For example, use ``wget`` with ``StartWget`` function
   #. Use ``exechelper`` or just plain ``exec`` packages to run whatever else
   #. Verify results of your tests using ``Assert`` methods provided by the test suite.

#. Create an ``init()`` function and register the test using ``Register[SuiteName]Tests(testCaseFunction)``


**Example test case**

Assumed are two docker containers, each with its own VPP instance running. One VPP then pings the other.
This can be put in file ``extras/hs-test/my_test.go`` and run with command ``make test TEST=MyTest``.

::

        package main

        import (
                . "fd.io/hs-test/infra"
        )

        func init(){
                RegisterMySuiteTest(MyTest)
        }

        func MyTest(s *MySuite) {
                clientVpp := s.GetContainerByName("client-vpp").VppInstance

                serverVethAddress := s.NetInterfaces["server-iface"].Ip4AddressString()

                result := clientVpp.Vppctl("ping " + serverVethAddress)
                s.Log(result)
                s.AssertNotNil(result)
        }


Filtering test cases
--------------------

The framework allows us to filter test cases in a few different ways, using ``make test TEST=``:

        * Suite name
        * File name
        * Test name
        * All of the above as long as they are ordered properly, e.g. ``make test TEST=VethsSuite.http_test.go.HeaderServerTest``

**Names are case sensitive!**

Names don't have to be complete, as long as they are last:
This is valid and will run all tests in every ``http`` file (if there is more than one):

* ``make test TEST=VethsSuite.http``

This is not valid:

* ``make test TEST=Veths.http``

They can also be left out:

* ``make test TEST=http_test.go`` will run every test in ``http_test.go``
* ``make test TEST=Nginx`` will run everything that has 'Nginx' in its name - suites, files and tests.
* ``make test TEST=HeaderServerTest`` will only run the header server test


Modifying the framework
-----------------------

**Adding a test suite**

.. _test-convention:

#. To add a new suite, create a new file in the ``infra/`` folder. Naming convention for the suite files is ``suite_[name].go``.

#. Make a ``struct``, in the suite file, with at least ``HstSuite`` struct as its member.
   HstSuite provides functionality that can be shared for all suites, like starting containers

#. Create a new map that will contain a file name where a test is located and test functions with a pointer to the suite's struct: ``var myTests = map[string][]func(s *MySuite){}``

        ::

                var myTests = map[string][]func(s *MySuite){}

                type MySuite struct {
                        HstSuite
                }


#. Then create a new function that will add tests to that map:

        ::

                func RegisterMyTests(tests ...func(s *MySuite)) {
	                myTests[getTestFilename()] = tests
                }


#. In suite file, implement ``SetupSuite`` method which Ginkgo runs once before starting any of the tests.
   It's important here to call ``ConfigureNetworkTopology()`` method,
   pass the topology name to the function in a form of file name of one of the *yaml* files in ``topo-network`` folder.
   Without the extension. In this example, *myTopology* corresponds to file ``extras/hs-test/topo-network/myTopology.yaml``
   This will ensure network topology, such as network interfaces and namespaces, will be created.
   Another important method to call is ``LoadContainerTopology()`` which will load
   containers and shared volumes used by the suite. This time the name passed to method corresponds
   to file in ``extras/hs-test/topo-containers`` folder

        ::

                func (s *MySuite) SetupSuite() {
                        s.HstSuite.SetupSuite()

                        // Add custom setup code here

                        s.ConfigureNetworkTopology("myNetworkTopology")
                        s.LoadContainerTopology("myContainerTopology")
                }

#. In suite file, implement ``SetupTest`` method which gets executed before each test. Starting containers and
   configuring VPP is usually placed here

        ::

                func (s *MySuite) SetupTest() {
                        s.HstSuite.setupTest()
                        s.SetupVolumes()
                        s.SetupContainers()
                }

#. In order for ``Ginkgo`` to run this suite, we need to create a ``Describe`` container node with setup nodes and an ``It`` subject node.
   Place them at the end of the suite file

   * Declare a suite struct variable before anything else
   * To use ``BeforeAll()`` and ``AfterAll()``, the container has to be marked as ``Ordered``
   * Because the container is now marked as Ordered, if a test fails, all the subsequent tests are skipped.
     To override this behavior, decorate the container node with ``ContinueOnFailure``

        ::

                var _ = Describe("MySuite", Ordered, ContinueOnFailure, func() {
        	var s MySuite
        	BeforeAll(func() {
        		s.SetupSuite()
        	})
        	BeforeEach(func() {
        		s.SetupTest()
        	})
        	AfterAll(func() {
        		s.TearDownSuite()
        	})
        	AfterEach(func() {
        		s.TearDownTest()
        	})

        	for filename, tests := range myTests {
        		for _, test := range tests {
        			test := test
        			pc := reflect.ValueOf(test).Pointer()
        			funcValue := runtime.FuncForPC(pc)
        			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
        			It(testName, func(ctx SpecContext) {
        				s.Log(testName + ": BEGIN")
        				test(&s)
        			}, SpecTimeout(TestTimeout))
        		}
        	}
                })

#. Notice the loop - it will generate multiple ``It`` nodes, each running a different test.
   ``test := test`` is necessary, otherwise only the last test in a suite will run.
   For a more detailed description, check Ginkgo's documentation: https://onsi.github.io/ginkgo/#dynamically-generating-specs\.

#. ``testName`` contains the test name in the following format: ``[name]_test.go/MyTest``.

#. To run certain tests solo, create a register function and a map that will only contain tests that have to run solo.
   Add a ``Serial`` decorator to the container node and ``Label("SOLO")`` to the ``It`` subject node:

        ::

                var _ = Describe("MySuiteSolo", Ordered, ContinueOnFailure, Serial, func() {
                        ...
                        It(testName, Label("SOLO"), func(ctx SpecContext) {
                                s.Log(testName + ": BEGIN")
			        test(&s)
		        }, SpecTimeout(TestTimeout))
                })

#. Next step is to add test cases to the suite. For that, see section `Adding a test case`_ above

**Adding a topology element**

Topology configuration exists as ``yaml`` files in the ``extras/hs-test/topo-network`` and
``extras/hs-test/topo-containers`` folders. Processing of a network topology file for a particular test suite
is started by the ``configureNetworkTopology`` method depending on which file's name is passed to it.
Specified file is loaded and converted into internal data structures which represent various elements of the topology.
After parsing the configuration, framework loops over the elements and configures them one by one on the host system.

These are currently supported types of network elements.

* ``netns`` - network namespace
* ``veth`` - veth network interface, optionally with target network namespace or IPv4 address
* ``bridge`` - ethernet bridge to connect created interfaces, optionally with target network namespace
* ``tap`` - tap network interface with IP address

Similarly, container topology is started by ``loadContainerTopology()``, configuration file is processed
so that test suite retains map of defined containers and uses that to start them at the beginning
of each test case and stop containers after the test finishes. Container configuration can specify
also volumes which allow to share data between containers or between host system and containers.

Supporting a new type of topology element requires adding code to recognize the new element type during loading.
And adding code to set up the element in the host system with some Linux tool, such as *ip*.
This should be implemented in ``netconfig.go`` for network and in ``container.go`` for containers and volumes.

**Communicating between containers**

When two VPP instances or other applications, each in its own Docker container,
want to communicate there are typically two ways this can be done within *hs-test*.

* Network interfaces. Containers are being created with ``-d --network host`` options,
  so they are connected with interfaces created in host system
* Shared folders. Containers are being created with ``-v`` option to create shared `volumes`_ between host system and containers
  or just between containers

Host system connects to VPP instances running in containers using a shared folder
where binary API socket is accessible by both sides.

**Adding an external tool**

If an external program should be executed as part of a test case, it might be useful to wrap its execution in its own function.
These types of functions are placed in the ``utils.go`` file. If the external program is not available by default in Docker image,
add its installation to ``extras/hs-test/Dockerfile.vpp`` in ``apt-get install`` command.
Alternatively copy the executable from host system to the Docker image, similarly how the VPP executables and libraries are being copied.

**Skipping tests**

``HstSuite`` provides several methods that can be called in tests for skipping it conditionally or unconditionally such as:
``skip()``, ``SkipIfMultiWorker()``, ``SkipUnlessExtendedTestsBuilt()``. You can also use Ginkgo's ``Skip()``.
However the tests currently run under test suites which set up topology and containers before actual test is run. For the reason of saving
test run time it is not advisable to use aforementioned skip methods and instead, just don't register the test.

**External dependencies**

* Linux tools ``ip``, ``brctl``
* Standalone programs ``wget``, ``iperf3`` - since these are downloaded when Docker image is made,
  they are reasonably up-to-date automatically
* Programs in Docker images  - ``envoyproxy/envoy-contrib`` and ``nginx``
* ``http_server`` - homegrown application that listens on specified port and sends a test file in response
* Non-standard Go libraries - see ``extras/hs-test/go.mod``

Generally, these will be updated on a per-need basis, for example when a bug is discovered
or a new version incompatibility issue occurs.

Debugging a test
----------------

GDB
^^^

It is possible to debug VPP by attaching ``gdb`` before test execution by adding ``DEBUG=true`` like follows:

::

    $ make test TEST=LDPreloadIperfVppTest DEBUG=true
    ...
    run following command in different terminal:
    docker exec -it server-vpp2456109 gdb -ex "attach $(docker exec server-vpp2456109 pidof vpp)"
    Afterwards press CTRL+\ to continue

If a test consists of more VPP instances then this is done for each of them.

Utility methods
^^^^^^^^^^^^^^^

**Packet Capture**

It is possible to use VPP pcap trace to capture received and sent packets.
You just need to add ``EnablePcapTrace`` to ``SetupTest`` method in test suite and ``CollectPcapTrace`` to ``TearDownTest``.
This way pcap trace is enabled on all interfaces and to capture maximum 10000 packets.
Your pcap file will be located in the test execution directory.

**Event Logger**

``clib_warning`` is a handy way to add debugging output, but in some cases it's not appropriate for per-packet use in data plane code.
In this case VPP event logger is better option, for example you can enable it for TCP or session layer in build time.
To collect traces when test ends you just need to add ``CollectEventLogs`` method to ``TearDownTest`` in the test suite.
Your event logger file will be located in the test execution directory.
To view events you can use :ref:`G2 graphical event viewer <eventviewer>` or ``convert_evt`` tool, located in ``src/scripts/host-stack/``,
which convert event logs to human readable text.

Memory leak testing
^^^^^^^^^^^^^^^^^^^

It is possible to use VPP memory traces to diagnose if and where memory leaks happen by comparing of two traces at different point in time.
You can do it by test like following:

::

    func MemLeakTest(s *NoTopoSuite) {
    	s.SkipUnlessLeakCheck()  // test is excluded from usual test run
    	vpp := s.GetContainerByName("vpp").VppInstance
    	/* do your configuration here */
    	vpp.Disconnect()  // no goVPP less noise
    	vpp.EnableMemoryTrace()  // enable memory traces
    	traces1, err := vpp.GetMemoryTrace()  // get first sample
    	s.AssertNil(err, fmt.Sprint(err))
    	vpp.Vppctl("test mem-leak")  // execute some action
    	traces2, err := vpp.GetMemoryTrace()  // get second sample
    	s.AssertNil(err, fmt.Sprint(err))
    	vpp.MemLeakCheck(traces1, traces2)  // compare samples and generate report
    }

To get your memory leak report run following command:

::

    $ make test-leak TEST=MemLeakTest
    ...
    NoTopoSuiteSolo mem_leak_test.go/MemLeakTest [SOLO]
    /home/matus/vpp/extras/hs-test/infra/suite_no_topo.go:113

      Report Entries >>

      SUMMARY: 112 byte(s) leaked in 1 allocation(s)
       - /home/matus/vpp/extras/hs-test/infra/vppinstance.go:624 @ 07/19/24 15:53:33.539

        leak of 112 byte(s) in 1 allocation(s) from:
            #0 clib_mem_heap_alloc_aligned + 0x31
            #1 _vec_alloc_internal + 0x113
            #2 _vec_validate + 0x81
            #3 leak_memory_fn + 0x4f
            #4 0x7fc167815ac3
            #5 0x7fc1678a7850
      << Report Entries
    ------------------------------


.. _ginkgo: https://onsi.github.io/ginkgo/
.. _volumes: https://docs.docker.com/storage/volumes/
