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

#. It starts with running ``make test``. Optional arguments are VERBOSE, PERSIST (topology configuration isn't cleaned up after test run),
   TEST=<test-name> to run a specific test and PARALLEL=[n-cpus].
#. ``make list-tests`` (or ``make help``) shows all tests. The current `list of tests`_ is at the bottom of this document.
#. ``Ginkgo`` looks for a spec suite in the current directory and then compiles it to a .test binary
#. The Ginkgo test framework runs each function that was registered manually using ``registerMySuiteTest(s *MySuite)``. Each of these functions correspond to a suite
#. Ginkgo's ``RunSpecs(t, "Suite description")`` function is the entry point and does the following:

  #. Ginkgo compiles the spec, builds a spec tree
  #. ``Describe`` container nodes in suite\_\*_test.go files are run (in series by default, or in parallel with the argument PARALLEL=[n-cpus])
  #. Suite is initialized. The topology is loaded and configured in this step
  #. Registered tests are run in generated ``It`` subject nodes
  #. Execute tear-down functions, which currently consists of stopping running containers
     and clean-up of test topology

Adding a test case
------------------

This describes adding a new test case to an existing suite.
For adding a new suite, please see `Modifying the framework`_ below.

#. To write a new test case, create a file whose name ends with ``_test.go`` or pick one that already exists
#. Declare method whose name ends with ``Test`` and specifies its parameter as a pointer to the suite's struct (defined in ``suite_*_test.go``)
#. Implement test behaviour inside the test method. This typically includes the following:

   #. Retrieve a running container in which to run some action. Method ``getContainerByName``
      from ``HstSuite`` struct serves this purpose
   #. Interact with VPP through the ``VppInstance`` struct embedded in container. It provides ``vppctl`` method to access debug CLI
   #. Run arbitrary commands inside the containers with ``exec`` method
   #. Run other external tool with one of the preexisting functions in the ``utils.go`` file.
      For example, use ``wget`` with ``startWget`` function
   #. Use ``exechelper`` or just plain ``exec`` packages to run whatever else
   #. Verify results of your tests using ``assert`` methods provided by the test suite, implemented by HstSuite struct or use ``Gomega`` assert functions.

#. Create an ``init()`` function and register the test using ``register*SuiteTests(testCaseFunction)``


**Example test case**

Assumed are two docker containers, each with its own VPP instance running. One VPP then pings the other.
This can be put in file ``extras/hs-test/my_test.go`` and run with command ``make test TEST=MyTest`` or ``ginkgo -v --trace --focus MyTest``.

::

        package main

        import (
                "fmt"
        )

        func init(){
                registerMySuiteTest(MyTest)
        }

        func MyTest(s *MySuite) {
                clientVpp := s.getContainerByName("client-vpp").vppInstance

                serverVethAddress := s.netInterfaces["server-iface"].AddressString()

                result := clientVpp.vppctl("ping " + serverVethAddress)
                s.assertNotNil(result)
                s.log(result)
        }

Modifying the framework
-----------------------

**Adding a test suite**

.. _test-convention:

#. To add a new suite, create a new file. Naming convention for the suite files is ``suite_name_test.go`` where *name* will be replaced
   by the actual name

#. Make a ``struct``, in the suite file, with at least ``HstSuite`` struct as its member.
   HstSuite provides functionality that can be shared for all suites, like starting containers

        ::

                type MySuite struct {
                        HstSuite
                }

#. Create a new slice that will contain test functions with a pointer to the suite's struct: ``var myTests = []func(s *MySuite){}``

#. Then create a new function that will append test functions to that slice:

        ::

                func registerMySuiteTests(tests ...func(s *MySuite)) {
	                nginxTests = append(myTests, tests...)
                }

#. In suite file, implement ``SetupSuite`` method which Ginkgo runs once before starting any of the tests.
   It's important here to call ``configureNetworkTopology`` method,
   pass the topology name to the function in a form of file name of one of the *yaml* files in ``topo-network`` folder.
   Without the extension. In this example, *myTopology* corresponds to file ``extras/hs-test/topo-network/myTopology.yaml``
   This will ensure network topology, such as network interfaces and namespaces, will be created.
   Another important method to call is ``loadContainerTopology()`` which will load
   containers and shared volumes used by the suite. This time the name passed to method corresponds
   to file in ``extras/hs-test/topo-containers`` folder

        ::

                func (s *MySuite) SetupSuite() {
                        s.HstSuite.SetupSuite()

                        // Add custom setup code here

                        s.configureNetworkTopology("myTopology")
                        s.loadContainerTopology("2peerVeth")
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
	        for _, test := range mySuiteTests {
		        test := test
		        pc := reflect.ValueOf(test).Pointer()
		        funcValue := runtime.FuncForPC(pc)
		        It(strings.Split(funcValue.Name(), ".")[2], func(ctx SpecContext) {
			        test(&s)
		        }, SpecTimeout(time.Minute*5))
	        }
                })

#. Notice the loop - it will generate multiple ``It`` nodes, each running a different test.
   ``test := test`` is necessary, otherwise only the last test in a suite will run.
   For a more detailed description, check Ginkgo's documentation: https://onsi.github.io/ginkgo/#dynamically-generating-specs\.

#. ``funcValue.Name()`` returns the full name of a function (e.g. ``fd.io/hs-test.MyTest``), however, we only need the test name (``MyTest``).

#. To run certain tests solo, create a new slice that will only contain tests that have to run solo and a new register function.
   Add a ``Serial`` decorator to the container node and ``Label("SOLO")`` to the ``It`` subject node:

        ::

                var _ = Describe("MySuiteSolo", Ordered, ContinueOnFailure, Serial, func() {
                        ...
                        It(strings.Split(funcValue.Name(), ".")[2], Label("SOLO"), func(ctx SpecContext) {
			test(&s)
		        }, SpecTimeout(time.Minute*5))
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

**Debugging a test**

It is possible to debug VPP by attaching ``gdb`` before test execution by adding ``DEBUG=true`` like follows:

::

    $ make test TEST=LDPreloadIperfVppTest DEBUG=true
    ...
    run following command in different terminal:
    docker exec -it server-vpp2456109 gdb -ex "attach $(docker exec server-vpp2456109 pidof vpp)"
    Afterwards press CTRL+\ to continue

If a test consists of more VPP instances then this is done for each of them.


**Eternal dependencies**

* Linux tools ``ip``, ``brctl``
* Standalone programs ``wget``, ``iperf3`` - since these are downloaded when Docker image is made,
  they are reasonably up-to-date automatically
* Programs in Docker images  - ``envoyproxy/envoy-contrib`` and ``nginx``
* ``http_server`` - homegrown application that listens on specified port and sends a test file in response
* Non-standard Go libraries - see ``extras/hs-test/go.mod``

Generally, these will be updated on a per-need basis, for example when a bug is discovered
or a new version incompatibility issue occurs.


.. _ginkgo: https://onsi.github.io/ginkgo/
.. _volumes: https://docs.docker.com/storage/volumes/

**List of tests**

.. _list of tests:

Please update this list whenever you add a new test by pasting the output below.

* NsSuite/HttpTpsTest
* NsSuite/VppProxyHttpTcpTest
* NsSuite/VppProxyHttpTlsTest
* NsSuite/EnvoyProxyHttpTcpTest
* NginxSuite/MirroringTest
* VethsSuiteSolo TcpWithLossTest [SOLO]
* NoTopoSuiteSolo HttpStaticPromTest [SOLO]
* TapSuite/LinuxIperfTest
* NoTopoSuite/NginxHttp3Test
* NoTopoSuite/NginxAsServerTest
* NoTopoSuite/NginxPerfCpsTest
* NoTopoSuite/NginxPerfRpsTest
* NoTopoSuite/NginxPerfWrkTest
* VethsSuite/EchoBuiltinTest
* VethsSuite/HttpCliTest
* VethsSuite/LDPreloadIperfVppTest
* VethsSuite/VppEchoQuicTest
* VethsSuite/VppEchoTcpTest
* VethsSuite/VppEchoUdpTest
* VethsSuite/XEchoVclClientUdpTest
* VethsSuite/XEchoVclClientTcpTest
* VethsSuite/XEchoVclServerUdpTest
* VethsSuite/XEchoVclServerTcpTest
* VethsSuite/VclEchoTcpTest
* VethsSuite/VclEchoUdpTest
* VethsSuite/VclRetryAttachTest
