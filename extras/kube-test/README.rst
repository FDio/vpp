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
* [Bare-metal only] When testing on a bare-metal cluster, Kube-test expects a running cluster.
  Run ``make bm-images`` or ``./script/quick-import.sh`` to build Kube-test and CalicoVPP images and import them to nodes.

Running tests
-------------

[KinD only] Run ``make test-kind`` to run all tests. Running with ``VERBOSE=true`` is highly recommended. For more options, run ``make help`` .

[Bare-metal only] When running tests for the first time, you must set ``KIND_WRK1``, ``KIND_WRK2``, ``CALICOVPP_VERSION`` and ``CALICOVPP_INTERFACE``
variables first.
For example, let's assume that the first node's hostname is ``vpp_node1`` and the second one is ``vpp_node2``.
We want to test master images, so the version is ``kt-master``, and the cluster uses interface ``ens3f0np0``.
The final command will look like this:
``make test-bm VERBOSE=true KUBE_WRK1=vpp_node1 KUBE_WRK2=vpp_node2 CALICOVPP_VERSION=kt-master CALICOVPP_INTERFACE=ens3f0np0``
After the first run, you can run tests with just ``make test-bm VERBOSE=true``. The variables are written to ``kubernetes/.vars`` and
``kubernetes/pod-definitions.yaml``

Filtering test cases
--------------------

The framework allows us to filter test cases in a few different ways, using ``make test-bm TEST=xyz SKIP=xyz``:

        * Suite name
        * File name
        * Test name
        * All of the above as long as they are ordered properly, e.g. ``make test-bm TEST=KubeSuite.kube_test.go.KubeTcpIperfVclTest``
        * Multiple tests/suites: ``make test-bm TEST=KubeTcpIperfVclTest,KubeSuite``

All of the above also applies to ``SKIP``

**Names are case sensitive!**

Names don't have to be complete, as long as they are last:
This is valid and will run all tests in every ``kube`` file (if there is more than one):

* ``make test-bm TEST=KubeSuite.kube``

This is not valid:

* ``make test-bm TEST=Kube.kube``

They can also be left out:

* ``make test-bm TEST=felix_test.go`` will run every test in ``felix_test.go``
* ``make test-bm TEST=Nginx`` will run everything that has 'Nginx' in its name - suites, files and tests.
* ``make test-bm TEST=KubeTcpIperfVclTest`` will only run the KubeTcpIperfVcl test


Adding a test case
------------------

This describes adding a new test case to an existing suite.
For adding a new suite, please see :ref:`Modifying the framework` below.

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
	                s.DeployPod(s.Pods.Nginx)
	                s.DeployPod(s.Pods.Ab)

                        // helper function
	                s.CreateNginxConfig(s.Pods.Nginx)

                        // goroutine to start nginx server
	                go func() {
	                	defer GinkgoRecover()
	                	out, err := s.Pods.Nginx.Exec(ctx, []string{"/bin/bash", "-c", "nginx -c /nginx.conf"})
	                	if !errors.Is(err, context.Canceled) {
	                		AssertNil(err, out)
	                	}
	                }()

	                // wait for nginx to start up
	                time.Sleep(time.Second * 2)
                        // run ab
	                out, err = s.Pods.Ab.Exec(ctx, []string{"ab", "-k", "-r", "-n", "1000000", "-c", "1000", "http://" + s.Pods.Nginx.IpAddress + ":8081/64B.json"})
	                Log(out)
	                AssertNil(err)
                }


.. _`Modifying the framework`:

Modifying the framework
-----------------------

**Adding a test suite**

#. First, add new pod definitions in ``pod-definitions-template.yaml`` if necessary. You can specify what image a pod will use and which worker it will run on.

#. To add a new suite, create a new file in the ``infra/`` folder. Naming convention for the suite files is ``suite_[name].go``.

#. Make a ``struct``, in the suite file, with at least ``BaseSuite`` and ``Pods`` structs as its members.
   BaseSuite provides functionality that can be shared for all suites, like starting pods. The ``Pods`` struct
   is used to provide simpler access to pods.

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
   Initialize all pods that are in the ``Pods`` struct using ``s.getPodsByName([name from kubernetes/pod-definitions-template.yaml])``.
   ``s.SetMtuAndRestart()`` sets Calico's and VPP's MTU. However, it is also possible to add more options to VPP's stanza, like worker count.
   It is necessary to call this function; otherwise, the cluster will keep the previous configuration.

        ::

                func (s *MySuite) SetupSuite() {
                        s.BaseSuite.SetupSuite()
                        // initialize pods
                        s.Pods.Client = s.getPodsByName("client-generic")
	                s.Pods.Server = s.getPodsByName("server-generic")
                        ...
                        s.SetMtuAndRestart("mtu: 0", "tcp { mtu 8960 }\n    cpu { workers 0 }")
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
        				Log("[* TEST BEGIN]: " + testName)
        				test(&s)
        			}, SpecTimeout(TestTimeout))
        		}
        	}
                })

#. Notice the loop - it will generate multiple ``It`` nodes, each running a different test.
   ``test := test`` is necessary, otherwise only the last test in a suite will run.
   For a more detailed description, check Ginkgo's documentation: https://onsi.github.io/ginkgo/#dynamically-generating-specs\.

#. ``testName`` contains the test name in the following format: ``[name]_test.go/MyTest``.


.. _ginkgo: https://onsi.github.io/ginkgo/