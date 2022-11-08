Host stack test framework
=========================

Overview
--------

The goal of the Host stack test framework (**hstf**) is to ease writing and running end-to-end tests for VPP's Host Stack.
End-to-end tests often want multiple VPP instances, network namespaces, different types of interfaces
and to execute external tools or commands. With such requirements the existing VPP test framework is not sufficient.
For this, ``Go`` was chosen as a high level language, allowing rapid development, with ``Docker`` and ``ip`` being the tools for creating required topology.

Go's package `testing`_ together with `go test`_ command form the base framework upon which the *hstf* is built and run.

Anatomy of a test case
----------------------

**Prerequisites**:

* Tests use *hstf*'s own docker image, so building it before starting tests is a prerequisite. Run ``sudo make`` to do so
* Docker has to be installed and Go has to be in path of both the running user and root
* Root privileges are required to run tests as it uses Linux ``ip`` command for configuring topology

**Action flow when running a test case is**:

#. ``./test``: this script is basically a wrapper for ``go test`` and accepts its parameters, for example following runs a specific test: ``./test -run Veth/EchoBuilt``
#. ``go test`` recompiles package ``main`` along with any files with names matching the file pattern ``*_test.go`` and then runs the resulting test binaries.
#. The go test framework runs each function matching :ref:`naming convention<test-convention>`. Each of these corresponds to a `test suite`_
#. Testify toolkit's ``suite.Run(t *testing.T, suite TestingSuite)`` function run the suite and does the following:

  #. Suite is initialized. The topology is loaded and configured in this step
  #. Test suite runs all the tests attached to it
  #. Execute tear-down function, which currently consists of just clean-up of test topology

``TODO`` is #2 correct? I don't see where the binary is. Is it all in hs-test?

Adding a test case
------------------

This describes adding a new test case to an existing suite.
For adding a new suite, please see `Modifying the framework`_ below.
``TODO`` add real examples, maybe pinging between VPPs

#. To write a new test case, create a file whose name ends ``_test.go`` or pick one that already exists
#. Declare method whose name starts with ``Test`` and specifies its receiver as a pointer to the suite's struct (defined in ``framework_test.go``)
#. Implement test behaviour inside the test method. This typically includes the following.

  #. Start docker container(s) as needed. Function ``dockerRun(instance, args string)`` from ``utils.go`` serves this purpose
  #. Execute *hstf* action(s) inside any of the running containers.
     Function ``hstExec`` from ``utils.go`` does this by using ``docker exec`` command to run ``hs-test`` executable.
  #. Run arbitrary commands inside the containers with ``dockerExec(cmd string, instance string)``
  #. | Run other external tool with one of the preexisting functions in the ``utils.go`` file.
     | For example, use ``wget`` with ``startWget(..)`` function
  #. ``defer func() { exechelper.Run("docker stop <container-name>) }()`` inside the method body, to stop the running container(s)



Modifying the framework
-----------------------

**Adding a test suite**

.. _test-convention:

#. Adding a new suite takes place in ``framework_test.go``

#. Make a ``struct`` with at least ``Suite`` from testify toolkit and a ``teardownSuite`` function as its members.

        ::

                type MySuite struct {
                        suite.Suite
                        teardownSuite func()
                }

#. Implement SetupSuite method which testify runs before running the tests.
   It's important here to call ``setupSuite(s *suite.Suite, topologyName string)`` and assign its result to the suite's ``teardownSuite`` member.
   Pass the topology name to the function in the form of file name of one of the *yaml* files in ``topo`` folder. Without the extension.

        ::

                func (s *MySuite) SetupSuite() {
                        // Add custom setup code here

                        s.teardownSuite = setupSuite(&s.Suite, "myTopology")
                }

#. Implement TearDownSuite method which testify runs after the tests, to clean-up.

        ::

                func (s *MySuite) TearDownSuite() {
                        s.teardownSuite()
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
* ``bridge`` - ethernet bridge, optionally with target netwoork namespace
* ``tap`` - tap network interface with IP address

Supporting new type of topology element requires adding code to recognize the new element type during loading.
And adding code to set up the element in the host system with some Linux tool, such as *ip*. This should be implemented in ``netconfig.go``.

**Adding a hstf action**

``TODO`` *hstf* action explanation (hs-test binary, specifying action with first argument, actions defined in ``actions.go``, sync-files, etc.

**Adding an external tool**

If an external program should be executed as part of a test case, it might be useful to wrap its execution in its own function.
These types of functions are placed in the ``utils.go`` file. If the external program is not available by default in Docker image,
add its installation to ``extras/hs-test/Dockerfile.vpp`` in ``apt-get install`` command.
Alternatively copy the executable from host system to the Docker image, similarly how the VPP executables and libraries are being copied.

**Mention external dependencies**

* Linux tools ``ip``, ``brctl``
* Standalone programs ``wget``, ``iperf3``, ``TODO envoy?`` - since these are downloaded when Docker image is made,
  they are kept reasonable up-to-date
* http_server - homegrown application that listens on specified address and sends a test file in response
* | Non-standard Go libraries - see ``extras/hs-test/go.mod``
  | ``TODO`` do we want to specify here when should these be updated? For example, after each release, ...


.. _testing: https://pkg.go.dev/testing
.. _go test: https://pkg.go.dev/cmd/go#hdr-Test_packages
.. _test suite: https://github.com/stretchr/testify#suite-package

