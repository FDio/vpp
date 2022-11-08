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
   [TODO: is this correct? I don't see where the binary is. Is it all in hs-test?]
#. The go test framework runs each function matching :ref:`naming convention<test-convention>`. Each of these corresponds to a `test suite`_
#. Testify toolkit's ``suite.Run(t *testing.T, suite TestingSuite)`` function run the suite and does the following:

  #. Suite is initialized. The topology is loaded and configured in this step
  #. Test suite runs all the tests attached to it
  #. Execute tear-down function, which currently consists of just clean-up of test topology

TODO activity diagram of running the framework?

Adding a test case
------------------

This describes adding a new test case to an existing suite. TODO add real examples, maybe pinging between VPPs
For adding a new suite, please see `Modifying the framework`_ below.


#. To write a new test case, create a file whose name ends ``_test.go`` or pick one that already exists
#. Declare method whose name starts with ``Test`` and specifies its receiver as a pointer to the suite's struct (defined in ``framework_test.go``)
#. Implement test behaviour inside the test method. This typically includes the following.

  #. Start docker container(s) as needed. Function ``dockerRun(instance, args string)`` from ``utils.go`` serves this purpose
  #. Execute *hstf* action(s) inside any of the running containers. Function ``hstExec`` from ``utils.go`` does this by using ``docker exec`` command to run ``hs-test`` executable.
  #. Run arbitrary commands inside the containers with ``dockerExec(cmd string, instance string)``
  #. Run other external tool with one of the preexisting functions in the ``utils.go`` file. For example, use ``wget`` with ``startWget(..)`` function
  #. Stop used docker containers with ``defer func() { exechelper.Run("docker stop <container-name>) }()`` inside the method body



Modifying the framework
-----------------------

**Adding a test suite**

.. _test-convention:

#. In order for 'go test' to run this suite, we need to create a normal test function and pass our suite to suite.Run
#. implementing SetupSuite
#. etc.

**Adding a topology element**

TODO add description of topo files + topo.go
...each test suite has its topology in the ``topo`` folder

**Adding a *hstf* action**

TODO *hstf* action explanation (hs-test binary, specifying action with first argument, actions defined in ``actions.go``, etc.

**Adding an external tool**

TODO maybe mention that it has to be added to the docker container apt install list?

**Mention external dependencies**
TODO (helper and https://github.com/stretchr/testify libraries) and possibly define plan for keeping them up to date


.. _testing: https://pkg.go.dev/testing
.. _go test: https://pkg.go.dev/cmd/go#hdr-Test_packages
.. _test suite: https://github.com/stretchr/testify#suite-package
