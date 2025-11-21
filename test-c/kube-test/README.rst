Kubernetes test framework
=========================

Overview
--------

This framework is heavily based on (**hs-test**) with the main difference being, that (**kube-test**) deploys pods on an already running (**CalicoVPP**) KinD/bare-metal cluster,
and tests performance and connectivity.
`Ginkgo`_ is used as a testing "engine".

Initial setup
-------------

* Start by running ``make install-kube-deps``, which installs all necessary dependencies.
* [KinD only] Create a cluster using ``make master-cluster`` or ``make release-cluster``.
  ``make release-cluster`` uses the latest CalicoVPP release available. Run ``make cluster-help`` for more info.

Running tests
-------------

Simply run ``make test`` to run all tests. For more options, run ``make help`` .

Filtering test cases
--------------------

The framework allows us to filter test cases in a few different ways, using ``make test TEST=xyz SKIP=xyz``:

        * Suite name
        * File name
        * Test name
        * All of the above as long as they are ordered properly, e.g. ``make test TEST=KubeSuite.kube_test.go.KubeTcpIperfVclTest``
        * Multiple tests/suites: ``make test TEST=KubeTcpIperfVclTest,KubeSuite``

All of the above also applies to ``SKIP``

**Names are case sensitive!**

Names don't have to be complete, as long as they are last:
This is valid and will run all tests in every ``kube`` file (if there is more than one):

* ``make test TEST=KubeSuite.kube``

This is not valid:

* ``make test TEST=Kube.kube``

They can also be left out:

* ``make test TEST=felix_test.go`` will run every test in ``felix_test.go``
* ``make test TEST=Nginx`` will run everything that has 'Nginx' in its name - suites, files and tests.
* ``make test TEST=KubeTcpIperfVclTest`` will only run the KubeTcpIperfVcl test


Adding a test case
------------------

This describes adding a new test case to an existing suite.
For adding a new suite, please see `Modifying the framework`_ below.

#. To write a new test case, create a file whose name ends with ``_test.go`` or pick one that already exists
#. Declare method whose name ends with ``Test`` and specifies its parameter as a pointer to the suite's struct (defined in ``infra/suite_*.go``)
#. Implement test behaviour inside the test method. This typically includes the following:

   #. Import ``. "fd.io/kube-test/infra"``
   #. Retrieve a running pod in which to run some action. Each suite has a struct called ``Pods``
   #. Interact with pods/containers/nodes using ``s.Pods.XYZ.Exec``, ``s.ExecInKubeContainer`` or ``s.ExecVppctlInKubeNode``
   #. Verify results of your tests using ``Assert`` methods provided by the test suite.

#. Create an ``init()`` function and register the test using ``Register[SuiteName]Tests(testCaseFunction)``


**Example test case**

Below is one of the tests in ``kube_test.go`` with added comments.

::

        package main

        import (
            "context"
	    "time"
            "errors"
            . "fd.io/kube-test/infra"
        )

        func init(){
                RegisterKubeTests(NginxRpsTest)
        }

        func NginxRpsTest(s *KubeSuite) {
	        ctx, cancel := context.WithTimeout(s.MainContext, time.Minute*3)
	        defer cancel()

            // deploy pods defined in kubernetes/pod-definitions-template.yaml
            // and initialized in infra/pod.go/initPods()
	        s.DeployPod(s.Pods.Nginx)
	        s.DeployPod(s.Pods.Ab)

            // helper function
	        s.CreateNginxConfig(s.Pods.Nginx)

            // goroutine to start nginx server
	        go func() {
	        	defer GinkgoRecover()
	        	out, err := s.Pods.Nginx.Exec(ctx, []string{"/bin/bash", "-c", "nginx -c /nginx.conf"})
	        	if !errors.Is(err, context.Canceled) {
	        		s.AssertNil(err, out)
	        	}
	        }()

	        // wait for nginx to start up
	        time.Sleep(time.Second * 2)
            // run ab 
	        out, err = s.Pods.Ab.Exec(ctx, []string{"ab", "-k", "-r", "-n", "1000000", "-c", "1000", "http://" + s.Pods.Nginx.IpAddress + ":8081/64B.json"})
	        s.Log(out)
	        s.AssertNil(err)
        }


Modifying the framework
-----------------------

**Adding a test suite**

.. _test-convention:

#. First, add new pod definitions in ``pod-definitions-template.yaml`` if necessary. You can specify what image a pod will use and which worker it will run on.

#. To add a new suite, create a new file in the ``infra/`` folder. Naming convention for the suite files is ``suite_[name].go``.

#. Make a ``struct``, in the suite file, with at least ``BaseSuite`` and ``Pods`` structs as its members.
   BaseSuite provides functionality that can be shared for all suites, like starting pods. The ``Pods`` struct
   is used to provide simpler access to pods.

#. Initialize the pods by adding them to ``infra/pods.go/initPods()`` (only if new pods were added).

#. In the new suite file, create a new map that will contain a file name where a test is located and test functions with a pointer to the suite's struct: ``var myTests = map[string][]func(s *MySuite){}``

        ::

                var myTests = map[string][]func(s *MySuite){}

                type MySuite struct {
                        BaseSuite
                        Pods struct {
		                Server *Pod
		                Client *Pod
                                ...
	                        }
                }


#. Then create a new function that will add tests to that map:

        ::

                func RegisterMyTests(tests ...func(s *MySuite)) {
	                myTests[getTestFilename()] = tests
                }


#. In suite file, implement ``SetupSuite`` method which Ginkgo runs once before starting any of the tests.

        ::

                func (s *MySuite) SetupSuite() {
                        s.BaseSuite.SetupSuite()

                        // Add custom setup code here
                }

#. In suite file, implement ``SetupTest`` method which gets executed before each test.

        ::

                func (s *MySuite) SetupTest() {
                        s.MainContext = context.Background()
	                s.BaseSuite.SetupTest()

                        // Add custom setup code here 
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
        		s.TeardownSuite()
        	})
        	AfterEach(func() {
        		s.TeardownTest()
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

#TODO: config updates
