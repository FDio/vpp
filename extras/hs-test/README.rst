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

* Compiled VPP
* Docker has to be installed and Go has to be in path of both the running user and root
* Tests use *hs-test*'s own docker image, so building it before starting tests is a prerequisite.
  Run ``sudo make`` in ``extras/hs-test`` directory to do so
* Root privileges are required to run tests as it uses Linux ``ip`` command for configuring topology

**Action flow when running a test case**:

#. It starts with running ``./test``. This script is basically a wrapper for ``go test`` and accepts its parameters,
   for example following runs a specific test: ``./test -run TestNs/TestHttpTps``
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

  #. Retrieve a running container in which to run some action. Method ``getContainerByName``
     from ``HstSuite`` struct serves this purpose
  #. Interact with VPP through the ``VppInstance`` struct embedded in container. It provides ``vppctl`` method to access debug CLI
  #. Run arbitrary commands inside the containers with ``exec`` method
  #. Run other external tool with one of the preexisting functions in the ``utils.go`` file.
     For example, use ``wget`` with ``startWget`` function
  #. Use ``exechelper`` or just plain ``exec`` packages to run whatever else
  #. Verify results of your tests using ``assert`` methods provided by the test suite,
     implemented by HstSuite struct

**Example test case**

Assumed are two docker containers, each with its own VPP instance running. One VPP then pings the other.
This can be put in file ``extras/hs-test/my_test.go`` and run with command ``./test -run TestMySuite/TestMyCase``.

::

        package main

        import (
                "fmt"
        )

        func (s *MySuite) TestMyCase() {
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

#. Adding a new suite takes place in ``framework_test.go`` and by creating a new file for the suite.
   Naming convention for the suite files is ``suite_name_test.go`` where *name* will be replaced
   by the actual name

#. Make a ``struct``, in the suite file, with at least ``HstSuite`` struct as its member.
   HstSuite provides functionality that can be shared for all suites, like starting containers

        ::

                type MySuite struct {
                        HstSuite
                }

#. In suite file, implement ``SetupSuite`` method which testify runs once before starting any of the tests.
   It's important here to call ``configureNetworkTopology`` method,
   pass the topology name to the function in a form of file name of one of the *yaml* files in ``topo-network`` folder.
   Without the extension. In this example, *myTopology* corresponds to file ``extras/hs-test/topo-network/myTopology.yaml``
   This will ensure network topology, such as network interfaces and namespaces, will be created.
   Another important method to call is ``loadContainerTopology()`` which will load
   containers and shared volumes used by the suite. This time the name passed to method corresponds
   to file in ``extras/hs-test/topo-containers`` folder

        ::

                func (s *MySuite) SetupSuite() {
                        // Add custom setup code here

                        s.configureNetworkTopology("myTopology")
                        s.loadContainerTopology("2peerVeth")
                }

#. In suite file, implement ``SetupTest`` method which gets executed before each test. Starting containers and
   configuring VPP is usually placed here

        ::

                func (s *MySuite) SetupTest() {
                        s.SetupVolumes()
                        s.SetupContainers()
                }

#. In order for ``go test`` to run this suite, we need to create a normal test function and pass our suite to ``suite.Run``.
   These functions are placed at the end of ``framework_test.go``

        ::

                func TestMySuite(t *testing.T) {
                        var m MySuite
                        suite.Run(t, &m)
                }

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

**Eternal dependencies**

* Linux tools ``ip``, ``brctl``
* Standalone programs ``wget``, ``iperf3`` - since these are downloaded when Docker image is made,
  they are reasonably up-to-date automatically
* Programs in Docker images  - ``envoyproxy/envoy-contrib`` and ``nginx``
* ``http_server`` - homegrown application that listens on specified port and sends a test file in response
* Non-standard Go libraries - see ``extras/hs-test/go.mod``

Generally, these will be updated on a per-need basis, for example when a bug is discovered
or a new version incompatibility issue occurs.


.. _testing: https://pkg.go.dev/testing
.. _go test: https://pkg.go.dev/cmd/go#hdr-Test_packages
.. _test suite: https://github.com/stretchr/testify#suite-package
.. _volumes: https://docs.docker.com/storage/volumes/

