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

* Tests use *hs-test*'s own docker image, so building it before starting tests is a prerequisite. Run ``sudo make`` to do so
* Docker has to be installed and Go has to be in path of both the running user and root
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

  #. Start docker container(s) as needed. Function ``dockerRun(instance, args string)``
     from ``utils.go`` serves this purpose. Alternatively use suite struct's ``NewContainer(name string)`` method
  #. Execute *hs-test* action(s) inside any of the running containers.
     Function ``hstExec`` from ``utils.go`` does this by using ``docker exec`` command to run ``hs-test`` executable.
     For starting an VPP instance inside a container, the ``Vpp`` struct can be used as a forward-looking alternative
  #. Run arbitrary commands inside the containers with ``dockerExec(cmd string, instance string)``
  #. Run other external tool with one of the preexisting functions in the ``utils.go`` file.
     For example, use ``wget`` with ``startWget(..)`` function
  #. Use ``exechelper`` or just plain ``exec`` packages to run whatever else
  #. ``defer func() { exechelper.Run("docker stop <container-name>) }()`` inside the method body,
     to stop the running container(s). It's not necessary to do this if containers were created
     with suite's ``NewContainer(..)`` method

**Example test case**

Two docker containers, each with its own VPP instance running. One VPP then pings the other.
This can be put in file ``extras/hs-test/my_test.go`` and run with command ``./test -run TestMySuite``.

::

        package main

        import (
                "fmt"
                "github.com/edwarnicke/exechelper"
        )

        func (s *MySuite) TestMyCase() {
                t := s.T()

                vpp1Instance := "vpp-1"
                vpp2Instance := "vpp-2"

                err := dockerRun(vpp1Instance, "")
                if err != nil {
                        t.Errorf("%v", err)
                        return
                }
                defer func() { exechelper.Run("docker stop " + vpp1Instance) }()

                err = dockerRun(vpp2Instance, "")
                if err != nil {
                        t.Errorf("%v", err)
                        return
                }
                defer func() { exechelper.Run("docker stop " + vpp2Instance) }()

                _, err = hstExec("Configure2Veths srv", vpp1Instance)
                if err != nil {
                        t.Errorf("%v", err)
                        return
                }

                _, err = hstExec("Configure2Veths cln", vpp2Instance)
                if err != nil {
                        t.Errorf("%v", err)
                        return
                }

                // ping one VPP from the other
                //
                // not using dockerExec because it executes in detached mode
                // and we want to capture output from ping and show it
                command := "docker exec --detach=false vpp-1 vppctl -s /tmp/2veths/var/run/vpp/cli.sock ping 10.10.10.2"
                output, err := exechelper.CombinedOutput(command)
                if err != nil {
                        t.Errorf("ping failed: %v", err)
                }
                fmt.Println(string(output))
        }

Modifying the framework
-----------------------

**Adding a test suite**

.. _test-convention:

#. Adding a new suite takes place in ``framework_test.go``

#. Make a ``struct`` with at least ``HstSuite`` struct and a ``teardownSuite`` function as its members.
   HstSuite provides functionality that can be shared for all suites, like starting containers

        ::

                type MySuite struct {
                        HstSuite
                        teardownSuite func()
                }

#. Implement SetupSuite method which testify runs before running the tests.
   It's important here to call ``setupSuite(s *suite.Suite, topologyName string)`` and assign its result to the suite's ``teardownSuite`` member.
   Pass the topology name to the function in the form of file name of one of the *yaml* files in ``topo`` folder.
   Without the extension. In this example, *myTopology* corresponds to file ``extras/hs-test/topo/myTopology.yaml``

        ::

                func (s *MySuite) SetupSuite() {
                        // Add custom setup code here

                        s.teardownSuite = setupSuite(&s.Suite, "myTopology")
                }

#. Implement TearDownSuite method which testify runs after the tests, to clean-up.
   It's good idea to add at least the suite's own ``teardownSuite()``
   and HstSuite upper suite's ``stopContainers()`` methods

        ::

                func (s *MySuite) TearDownSuite() {
                        s.teardownSuite()
                        s.StopContainers()
                }

#. In order for ``go test`` to run this suite, we need to create a normal test function and pass our suite to ``suite.Run``

        ::

                func TestMySuite(t *testing.T) {
                        var m MySuite
                        suite.Run(t, &m)
                }

#. Next step is to add test cases to the suite. For that, see section `Adding a test case`_ above

**Adding a topology element**

Topology configuration exists as ``yaml`` files in the ``extras/hs-test/topo`` folder.
Processing of a file for a particular test suite is started by the ``setupSuite`` function depending on which file's name is passed to it.
Specified file is loaded by ``LoadTopology()`` function and converted into internal data structures which represent various elements of the topology.
After parsing the configuration, ``Configure()`` method loops over array of topology elements and configures them one by one.

These are currently supported types of elements.

* ``netns`` - network namespace
* ``veth`` - veth network interface, optionally with target network namespace or IPv4 address
* ``bridge`` - ethernet bridge to connect created interfaces, optionally with target network namespace
* ``tap`` - tap network interface with IP address

Supporting a new type of topology element requires adding code to recognize the new element type during loading.
And adding code to set up the element in the host system with some Linux tool, such as *ip*. This should be implemented in ``netconfig.go``.

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

Run it from test case with ``hstExec(args, instance)`` where ``args`` is the action method's name and ``instance`` is target Docker container's name.
This then executes the ``hs-test`` binary inside of the container and it then runs selected action.
Action is specified by its name as first argument for the binary.

*Note*: When ``hstExec(..)`` runs some action from a test case, the execution of ``hs-test`` inside the container
is asynchronous. The action might take many seconds to finish, while the test case execution context continues to run.
To mitigate this, ``hstExec(..)`` waits pre-defined arbitrary number of seconds for a *sync file* to be written by ``hs-test``
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

