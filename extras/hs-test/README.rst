Host stack test framework
=========================

Overview
--------

The goal of the Host stack test framework (**hs-test**) is to ease writing and running end-to-end tests for VPP's Host Stack.
End-to-end tests often want multiple VPP instances, network namespaces, different types of interfaces
and to execute external tools or commands. With such requirements the existing VPP test framework is not sufficient.
For this, ``Go`` was chosen as a high level language, allowing rapid development, with ``Docker`` and ``ip`` being the tools for creating required topology.

Go's package `testing`_ together with `go test`_ command form the base framework upon which the *hs-test* is built and run.

Anatomy of a test case
----------------------

**Prerequisites**:

* Install hs-test dependencies with ``make install-deps``
* Tests use *hs-test*'s own docker image, so building it before starting tests is a prerequisite. Run ``make build[-debug]`` to do so
* Docker has to be installed and Go has to be in path of both the running user and root
* Root privileges are required to run tests as it uses Linux ``ip`` command for configuring topology

**Action flow when running a test case**:

#. It starts with running ``make test``. Optional arguments are VERBOSE, PERSIST (topoloy configuration isn't cleaned up after test run),
   and TEST=<test-name> to run specific test.
#. ``make list-tests`` (or ``make help``) shows all test names.
#. ``go test`` compiles package ``main`` along with any files with names matching the file pattern ``*_test.go``
   and then runs the resulting test binaries
#. The go test framework runs each function matching :ref:`naming convention<test-convention>`. Each of these corresponds to a `test suite`_
#. Testify toolkit's ``suite.Run(t *testing.T, suite TestingSuite)`` function runs the suite and does the following:

  #. Suite is initialized. The topology is loaded and configured in this step
  #. Test suite runs all the tests attached to it
  #. Execute tear-down functions, which currently consists of stopping running containers
     and clean-up of test topology

Adding a test case
------------------

This describes adding a new test case to an existing suite.
For adding a new suite, please see `Modifying the framework`_ below.

#. To write a new test case, create a file whose name ends with ``_test.go`` or pick one that already exists
#. Declare method whose name starts with ``Test`` and specifies its receiver as a pointer to the suite's struct (defined in ``framework_test.go``)
#. Implement test behaviour inside the test method. This typically includes the following:

  #. Retrieve a running container in which to run some action. Function ``getContainerByName(name string)``
     from ``HstSuite`` struct serves this purpose
     an object representing a container and start it with ``run()`` method
  #. Execute *hs-test* action(s) inside any of the running containers.
     Function ``execAction(args string)`` from ``container.go`` does this by using ``docker exec`` command to run ``hs-test`` executable.
     For starting an VPP instance inside a container, the ``VppInstance`` struct can be used instead
  #. Run arbitrary commands inside the containers with ``exec(cmd string)``
  #. Run other external tool with one of the preexisting functions in the ``utils.go`` file.
     For example, use ``wget`` with ``startWget(..)`` function
  #. Use ``exechelper`` or just plain ``exec`` packages to run whatever else
  #. Verify results of your tests using ``assert`` methods provided by the test suite,
     implemented by HstSuite struct

**Example test case**

Two docker containers, each with its own VPP instance running. One VPP then pings the other.
This can be put in file ``extras/hs-test/my_test.go`` and run with command ``./test -run TestMySuite``.

::

        package main

        import (
                "fmt"
        )

        func (s *MySuite) TestMyCase() {
                serverVppContainer := s.getContainerByName("server-vpp")

                serverVpp := NewVppInstance(serverContainer)
                serverVpp.set2VethsServer()
                serverVpp.start()

                clientVppContainer := s.getContainerByName("client-vpp")

                clientVpp:= NewVppInstance(clientContainer)
                serverVpp.set2VethsClient()
                clientVpp.start()

                result, err := clientVpp.vppctl("ping 10.10.10.2")
                s.assertNil(err, "ping resulted in error")
                fmt.Println(result)
        }

Modifying the framework
-----------------------

**Adding a test suite**

.. _test-convention:

#. Adding a new suite takes place in ``framework_test.go`` and by creating a new file for the suite.
   Naming convention for the suite files is ``suite-name-test.go`` where *name* will be replaced
   by the actual name

#. Make a ``struct`` with at least ``HstSuite`` struct as its member.
   HstSuite provides functionality that can be shared for all suites, like starting containers

        ::

                type MySuite struct {
                        HstSuite
                }

#. Implement SetupSuite method which testify runs before running the tests.
   It's important here to call ``setupSuite(s *suite.Suite, topologyName string)`` and assign its result to the suite's ``teardownSuite`` member.
   Pass the topology name to the function in the form of file name of one of the *yaml* files in ``topo-network`` folder.
   Without the extension. In this example, *myTopology* corresponds to file ``extras/hs-test/topo-network/myTopology.yaml``
   This will ensure network topology, such as network interfaces and namespaces, will be created.
   Another important method to call is ``loadContainerTopology(topologyName string)`` which will load
   containers and shared volumes used by the suite. This time the name passed to method corresponds
   to file in ``extras/hs-test/topo-containers`` folder

        ::

                func (s *MySuite) SetupSuite() {
                        // Add custom setup code here

                        s.teardownSuite = setupSuite(&s.Suite, "myTopology")
                        s.loadContainerTopology("2peerVeth")
                }

#. In order for ``go test`` to run this suite, we need to create a normal test function and pass our suite to ``suite.Run``.
   This is being at the end of ``framework_test.go``

        ::

                func TestMySuite(t *testing.T) {
                        var m MySuite
                        suite.Run(t, &m)
                }

#. Next step is to add test cases to the suite. For that, see section `Adding a test case`_ above

**Adding a topology element**

Topology configuration exists as ``yaml`` files in the ``extras/hs-test/topo-network`` and
``extras/hs-test/topo-containers`` folders. Processing of a network topology file for a particular test suite
is started by the ``setupSuite`` function depending on which file's name is passed to it.
Specified file is loaded by ``LoadTopology()`` function and converted into internal data structures which represent various elements of the topology.
After parsing the configuration, ``Configure()`` method loops over array of topology elements and configures them one by one.

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

**Adding a hs-test action**

Executing more complex or long running jobs is made easier by *hs-test* actions.
These are functions that compartmentalize configuration and execution together for a specific task.
For example, starting up VPP or running VCL echo client.

The actions are located in ``extras/hs-test/actions.go``. To add one, create a new method that has its receiver as a pointer to ``Actions`` struct.

Run it from test case with container's method ``execAction(args)`` where ``args`` is the action method's name.
This then executes the ``hs-test`` binary inside of the container and it then runs selected action.
Action is specified by its name as first argument for the binary.

*Note*: When ``execAction(args)`` runs some action from a test case, the execution of ``hs-test`` inside the container
is asynchronous. The action might take many seconds to finish, while the test case execution context continues to run.
To mitigate this, ``execAction(args)`` waits pre-defined arbitrary number of seconds for a *sync file* to be written by ``hs-test``
at the end of its run. The test case context and container use Docker volume to share the file.

**Adding an external tool**

If an external program should be executed as part of a test case, it might be useful to wrap its execution in its own function.
These types of functions are placed in the ``utils.go`` file. If the external program is not available by default in Docker image,
add its installation to ``extras/hs-test/Dockerfile.vpp`` in ``apt-get install`` command.
Alternatively copy the executable from host system to the Docker image, similarly how the VPP executables and libraries are being copied.

**Eternal dependencies**

* Linux tools ``ip``, ``brctl``
* Standalone programs ``wget``, ``iperf3`` - since these are downloaded when Docker image is made,
  they are reasonably up-to-date automatically
* Programs in Docker images  - see ``envoyproxy/envoy-contrib`` in ``utils.go``
* ``http_server`` - homegrown application that listens on specified address and sends a test file in response
* Non-standard Go libraries - see ``extras/hs-test/go.mod``

Generally, these will be updated on a per-need basis, for example when a bug is discovered
or a new version incompatibility issue occurs.


.. _testing: https://pkg.go.dev/testing
.. _go test: https://pkg.go.dev/cmd/go#hdr-Test_packages
.. _test suite: https://github.com/stretchr/testify#suite-package
.. _volumes: https://docs.docker.com/storage/volumes/

