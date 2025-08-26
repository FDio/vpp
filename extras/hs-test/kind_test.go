package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	. "fd.io/hs-test/infra/common"
	. "fd.io/hs-test/infra/kind"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterKindTests(KindTcpIperfVclTest, KindUdpIperfVclTest, NginxRpsTest, NginxProxyMirroringTest,
		FelixCniServerRaceTest, FelixPolicyChurnTest, FelixPodChurnTest, FinalizerTests)
	RegisterLargeMtuTests(KindTcpIperfVclLargeMTUTest)
}

const vcl string = "VCL_CONFIG=/vcl.conf"
const ldp string = "LD_PRELOAD=/usr/lib/libvcl_ldpreload.so"

func kindIperfVclTest(s *KindSuite, clientArgs string) IPerfResult {
	s.DeployPod(s.Pods.ClientGeneric)
	s.DeployPod(s.Pods.ServerGeneric)
	ctx, cancel := context.WithTimeout(s.MainContext, time.Second*40)
	defer cancel()

	_, err := s.Pods.ClientGeneric.Exec(ctx, []string{"/bin/bash", "-c", VclConfIperf})
	s.AssertNil(err)
	_, err = s.Pods.ServerGeneric.Exec(ctx, []string{"/bin/bash", "-c", VclConfIperf})
	s.AssertNil(err)

	s.FixVersionNumber(s.Pods.ClientGeneric, s.Pods.ServerGeneric)

	iperfClientCmd := fmt.Sprintf("%s %s iperf3 %s -J -b 40g -c %s",
		vcl, ldp, clientArgs, s.Pods.ServerGeneric.IpAddress)

	o, err := s.Pods.ServerGeneric.Exec(ctx, []string{"/bin/bash", "-c",
		vcl + " " + ldp + " iperf3 -s -D -4 -B " + s.Pods.ServerGeneric.IpAddress})
	s.AssertNil(err, o)
	o, err = s.Pods.ClientGeneric.Exec(ctx, []string{"/bin/bash", "-c", iperfClientCmd})

	s.AssertNil(err, o)
	result := s.ParseJsonIperfOutput([]byte(o))
	s.LogJsonIperfOutput(result)
	return result
}

// TODO: use interfaces to avoid duplicated code
func kindIperfVclMtuTest(s *LargeMtuSuite, clientArgs string) IPerfResult {
	s.DeployPod(s.Pods.ClientGeneric)
	s.DeployPod(s.Pods.ServerGeneric)
	ctx, cancel := context.WithTimeout(s.MainContext, time.Second*40)
	defer cancel()

	_, err := s.Pods.ClientGeneric.Exec(ctx, []string{"/bin/bash", "-c", VclConfIperf})
	s.AssertNil(err)
	_, err = s.Pods.ServerGeneric.Exec(ctx, []string{"/bin/bash", "-c", VclConfIperf})
	s.AssertNil(err)

	s.FixVersionNumber(s.Pods.ClientGeneric, s.Pods.ServerGeneric)

	iperfClientCmd := fmt.Sprintf("%s %s iperf3 %s -J -b 40g -c %s",
		vcl, ldp, clientArgs, s.Pods.ServerGeneric.IpAddress)

	o, err := s.Pods.ServerGeneric.Exec(ctx, []string{"/bin/bash", "-c",
		vcl + " " + ldp + " iperf3 -s -D -4 -B " + s.Pods.ServerGeneric.IpAddress})
	s.AssertNil(err, o)
	o, err = s.Pods.ClientGeneric.Exec(ctx, []string{"/bin/bash", "-c", iperfClientCmd})

	s.AssertNil(err, o)
	result := s.ParseJsonIperfOutput([]byte(o))
	s.LogJsonIperfOutput(result)
	return result
}

func KindTcpIperfVclTest(s *KindSuite) {
	s.AssertIperfMinTransfer(kindIperfVclTest(s, "-M 1460"), 2000)
}

func KindTcpIperfVclLargeMTUTest(s *LargeMtuSuite) {
	s.AssertIperfMinTransfer(kindIperfVclMtuTest(s, "-M 8960"), 2000)
}

func KindUdpIperfVclTest(s *KindSuite) {
	s.AssertIperfMinTransfer(kindIperfVclTest(s, "-l 1460 -u"), 2000)
}

func NginxRpsTest(s *KindSuite) {
	ctx, cancel := context.WithCancel(s.MainContext)
	defer cancel()

	s.DeployPod(s.Pods.Nginx)
	s.DeployPod(s.Pods.Ab)
	s.CreateNginxConfig(s.Pods.Nginx)

	out, err := s.Pods.Nginx.Exec(ctx, []string{"/bin/bash", "-c", VclConfNginx})
	s.AssertNil(err, out)

	go func() {
		defer GinkgoRecover()
		out, err := s.Pods.Nginx.Exec(ctx, []string{"/bin/bash", "-c", "nginx -c /nginx.conf"})
		if !errors.Is(err, context.Canceled) {
			s.AssertNil(err, out)
		}
	}()

	// wait for nginx to start up
	time.Sleep(time.Second * 2)
	out, err = s.Pods.Ab.Exec(ctx, []string{"ab", "-k", "-r", "-n", "1000000", "-c", "1000", "http://" + s.Pods.Nginx.IpAddress + ":8081/64B.json"})
	s.Log(out)
	s.AssertNil(err)
}

func NginxProxyMirroringTest(s *KindSuite) {
	ctx, cancel := context.WithCancel(s.MainContext)
	defer cancel()

	s.DeployPod(s.Pods.Nginx)
	s.DeployPod(s.Pods.NginxProxy)
	s.DeployPod(s.Pods.ClientGeneric)
	s.CreateNginxConfig(s.Pods.Nginx)
	s.CreateNginxProxyConfig(s.Pods.NginxProxy)

	out, err := s.Pods.Nginx.Exec(ctx, []string{"/bin/bash", "-c", VclConfNginx})
	s.AssertNil(err, out)
	out, err = s.Pods.NginxProxy.Exec(ctx, []string{"/bin/bash", "-c", VclConfNginx})
	s.AssertNil(err, out)

	go func() {
		defer GinkgoRecover()
		out, err := s.Pods.Nginx.Exec(ctx, []string{"/bin/bash", "-c", ldp + " " + vcl + " nginx -c /nginx.conf"})
		if !errors.Is(err, context.Canceled) {
			s.AssertNil(err, out)
		}
	}()

	go func() {
		defer GinkgoRecover()
		out, err := s.Pods.NginxProxy.Exec(ctx, []string{"/bin/bash", "-c", "nginx -c /nginx.conf"})
		if !errors.Is(err, context.Canceled) {
			s.AssertNil(err, out)
		}
	}()

	// wait for nginx to start up
	time.Sleep(time.Second * 2)
	out, err = s.Pods.ClientGeneric.Exec(ctx, []string{"curl", "-v", "--noproxy", "'*'", "--insecure", "http://" + s.Pods.NginxProxy.IpAddress + ":8080/64B.json"})
	s.Log(out)
	s.AssertNil(err)
}

func FelixCniServerRaceTest(s *KindSuite) {
	ctx, cancel := context.WithTimeout(s.MainContext, time.Minute*2)
	defer cancel()

	// Clean up resources at the end
	defer func() {
		// Clean up jobs with finalizers using helper function
		err := s.CleanupJobsWithFinalizers(context.Background(), s.Namespace)
		s.AssertNil(err, "Failed to cleanup jobs with finalizers")

		// Clean up NetworkPolicies using helper function
		s.CleanupNetworkPolicies(s.Namespace)
	}()

	// Create sample NetworkPolicies with different rules
	err := s.CreateDefaultNetworkPolicies(ctx, s.Namespace)
	s.AssertNil(err, "Failed to create default network policies")

	s.Log("Starting Felix CNI server race test ...")

	// Start a goroutine to dynamically create NetworkPolicies during the test
	go func() {
		defer GinkgoRecover()

		policyCreateTicker := time.NewTicker(time.Second * 4) // Create 3 policies every 4 seconds
		defer policyCreateTicker.Stop()

		counter := 1
		endTime := time.Now().Add(time.Second * 40)

		for {
			<-policyCreateTicker.C
			if time.Now().After(endTime) {
				return
			}

			for i := 0; i < 3; i++ {
				port := 20000 + counter
				err := s.CreateNetworkPolicy(ctx, s.Namespace, int32(port))
				s.AssertNil(err, "Failed to create dynamic network policy")
				s.Log("Created dynamic network policy %d with port %d", counter, port)
				counter++
			}
		}
	}()

	// Start a goroutine to create jobs during the test
	go func() {
		defer GinkgoRecover()

		jobCreateTicker := time.NewTicker(time.Second * 4) // Create 3 jobs every 4 seconds
		defer jobCreateTicker.Stop()

		counter := 1
		endTime := time.Now().Add(time.Second * 40)

		for {
			<-jobCreateTicker.C
			if time.Now().After(endTime) {
				return
			}

			for i := 0; i < 3; i++ {
				jobName := fmt.Sprintf("race-job-%d-%d", time.Now().Unix(), counter)
				err := s.CreateDynamicJob(ctx, s.Namespace, jobName, "hst-felix-cni-race-test", "kind-worker")
				s.AssertNil(err, "Failed to create dynamic job")
				s.Log("Created job %d: %s", counter, jobName)
				counter++
			}
		}
	}()

	// Wait for 90 seconds to reproduce the race condition
	s.Log("Waiting for 90 seconds for job creation to complete...")
	time.Sleep(time.Second * 90)

	// Verify all pods have been cleaned up
	finalPods, err := s.ListPodsInNamespace(ctx, s.Namespace)
	s.AssertNil(err)
	s.AssertEqual(0, len(finalPods))

	// Verify all jobs have been cleaned up (no finalizers!)
	finalJobs, err := s.ListJobsInNamespace(ctx, s.Namespace)
	s.AssertNil(err)
	s.AssertEqual(0, len(finalJobs))

	// Test result based on cleanup success
	if len(finalPods) == 0 && len(finalJobs) == 0 {
		s.Log("SUCCESS: All test pods and jobs have been cleaned up")
	} else {
		s.Log("FAILURE: %d pods and %d jobs still remain (this may be expected due to timing)", len(finalPods), len(finalJobs))
	}
}

func FelixPodChurnTest(s *KindSuite) {
	ctx, cancel := context.WithTimeout(s.MainContext, time.Minute*1)
	defer cancel()

	var createCounter int = 1
	var deleteCounter int = 1

	// Start pod churn testing
	s.Log("Starting Pod churn test for 30 seconds...")

	// Start a goroutine to create 1 pod every second for 20 seconds
	go func() {
		defer GinkgoRecover()

		podCreateTicker := time.NewTicker(time.Second) // Create 1 pod every second
		defer podCreateTicker.Stop()

		endTime := time.Now().Add(time.Second * 20)

		for {
			<-podCreateTicker.C
			if time.Now().After(endTime) {
				return
			}

			// Create a unique pod
			podName := fmt.Sprintf("churn-pod-%d", createCounter)
			err := s.CreateDynamicPod(ctx, s.Namespace, podName, "hst-churn-test")
			s.AssertNil(err, "Failed to create dynamic pod")
			s.Log("Created dynamic pod %s", podName)
			createCounter++
		}
	}()

	// Start a goroutine to delete pods in order (1,2,3...) every second for 10 seconds
	go func() {
		defer GinkgoRecover()

		// Wait for 10 seconds before starting deletion
		s.Log("Deletion goroutine: waiting 10 seconds before starting deletion...")
		time.Sleep(time.Second * 10)

		podDeleteTicker := time.NewTicker(time.Second) // Delete 1 pod every second
		defer podDeleteTicker.Stop()

		endTime := time.Now().Add(time.Second * 10)

		for {
			<-podDeleteTicker.C
			if time.Now().After(endTime) {
				return
			}

			podToDelete := fmt.Sprintf("churn-pod-%d", deleteCounter)
			err := s.DeleteDynamicPod(ctx, s.Namespace, podToDelete)
			s.AssertNil(err, "Failed to delete dynamic pod")
			s.Log("Deleted dynamic pod %s", podToDelete)
			deleteCounter++
		}
	}()

	// Wait for 30 seconds for pod churn to complete
	s.Log("Waiting for 30 seconds for pod churn...")
	time.Sleep(time.Second * 30)

	// Get all remaining pods in namespace
	remainingPods, err := s.ListPodsInNamespace(ctx, s.Namespace)
	s.AssertNil(err, "Failed to list pods in test namespace")
	s.Log("=== All Pods in Namespace %s ===", s.Namespace)
	s.Log("Found %d pods in namespace", len(remainingPods))
	for i, podName := range remainingPods {
		s.Log("  %d. %s", i+1, podName)
	}

	s.Log("=== Pod Churn Summary ===")
	// Log created and deleted pod counts
	s.Log("Pods created: %d", createCounter-1)
	s.Log("Pods deleted: %d", deleteCounter-1)
	s.Log("Pod churn test completed. Found %d pods remaining in namespace", len(remainingPods))

	// Clean up any remaining pods
	s.Log("=== Cleaning up remaining dynamic pods ===")
	for _, podName := range remainingPods {
		err := s.DeleteDynamicPod(ctx, s.Namespace, podName)
		s.AssertNil(err, "Failed to delete dynamic pod")
	}
}

func FelixPolicyChurnTest(s *KindSuite) {
	ctx, cancel := context.WithTimeout(s.MainContext, time.Minute*1)
	defer cancel()

	// Create sample NetworkPolicies with different rules
	err := s.CreateDefaultNetworkPolicies(ctx, s.Namespace)
	s.AssertNil(err, "Failed to create default network policies")

	// Clean up NetworkPolicies at the end of the test
	defer func() {
		s.CleanupNetworkPolicies(s.Namespace)
	}()

	// Deploy pods for the NetworkPolicies to apply to
	s.DeployPod(s.Pods.ClientGeneric)
	s.DeployPod(s.Pods.ServerGeneric)

	// Start network policy churn testing for 25 seconds
	s.Log("Starting NetworkPolicy churn test for 25 seconds...")

	// Track created dynamic policies for deletion
	var createdPolicies []string
	var policiesMutex sync.Mutex

	// Start a goroutine to dynamically create 3 NetworkPolicies every second
	go func() {
		defer GinkgoRecover()

		policyCreateTicker := time.NewTicker(time.Second) // Create 3 policies every second
		defer policyCreateTicker.Stop()

		updateCounter := 1
		endTime := time.Now().Add(time.Second * 20)

		for {
			<-policyCreateTicker.C
			if time.Now().After(endTime) {
				return
			}

			// Create 3 unique policies with incrementing ports
			for i := 0; i < 3; i++ {
				port := 20000 + updateCounter
				err := s.CreateNetworkPolicy(ctx, s.Namespace, int32(port))
				s.AssertNil(err, "Failed to create dynamic network policy")
				// Track created policies for deletion
				policyName := fmt.Sprintf("hst-network-policy-%d", port)
				policiesMutex.Lock()
				createdPolicies = append(createdPolicies, policyName)
				policiesMutex.Unlock()
				updateCounter++
			}
		}
	}()

	// Start a goroutine to randomly delete 2 NetworkPolicies every second
	go func() {
		defer GinkgoRecover()

		policyDeleteTicker := time.NewTicker(time.Second) // Delete 2 policies every second
		defer policyDeleteTicker.Stop()

		endTime := time.Now().Add(time.Second * 20)

		for {
			<-policyDeleteTicker.C
			if time.Now().After(endTime) {
				return
			}

			// Delete 2 random policies
			for i := 0; i < 2; i++ {
				if len(createdPolicies) > 0 {
					policiesMutex.Lock()
					randIndex := time.Now().UnixNano() % int64(len(createdPolicies))
					policyToDelete := createdPolicies[randIndex]
					createdPolicies = append(createdPolicies[:randIndex], createdPolicies[randIndex+1:]...)
					policiesMutex.Unlock()

					// Delete the policy
					s.DeleteNetworkPolicy(ctx, s.Namespace, policyToDelete)
				} else {
					s.Log("No dynamic policies available to delete")
				}
			}
		}
	}()

	// Wait for 25 seconds for policy churn to complete
	s.Log("Waiting for 25 seconds for policy churn to complete...")
	time.Sleep(time.Second * 25)

	// Log remaining created policies after churn completes
	s.Log("=== Policy Churn Summary ===")
	s.Log("Remaining dynamic policies count: %d", len(createdPolicies))
	if len(createdPolicies) > 0 {
		s.Log("Remaining dynamic policy names:")
		for i, policyName := range createdPolicies {
			s.Log("  %d. %s", i+1, policyName)
		}
	}
	s.Log("")

	// Check rules on kind-worker and kind-worker2
	out, err := s.ExecVppctlInKindNode("kind-worker", "show", "capo", "rules")
	s.AssertNil(err, "Failed to run 'show capo rules' on kind-worker")
	// Verify the expected network policy patterns are present
	ret, _ := s.VerifyDefaultNetworkPolicies(string(out), "kind-worker")
	s.AssertEqual(true, ret)
	// Verify that all remaining dynamic policies are present
	ret, _ = s.VerifyDynamicNetworkPolicies(string(out), "kind-worker", createdPolicies)
	s.AssertEqual(true, ret)

	out, err = s.ExecVppctlInKindNode("kind-worker2", "show", "capo", "rules")
	s.AssertNil(err, "Failed to run 'show capo rules' on kind-worker2")
	// Verify the expected network policy patterns are present
	ret, _ = s.VerifyDefaultNetworkPolicies(string(out), "kind-worker2")
	s.AssertEqual(true, ret)
	// Verify that all remaining dynamic policies are present
	ret, _ = s.VerifyDynamicNetworkPolicies(string(out), "kind-worker2", createdPolicies)
	s.AssertEqual(true, ret)
}

func FinalizerTests(s *KindSuite) {
	ctx, cancel := context.WithTimeout(s.MainContext, time.Minute*1)
	defer cancel()

	// Create sample NetworkPolicies once for all tests
	err := s.CreateDefaultNetworkPolicies(ctx, s.Namespace)
	s.AssertNil(err, "Failed to create default network policies")

	// Clean up NetworkPolicies at the end of all tests
	defer func() {
		s.CleanupNetworkPolicies(s.Namespace)
	}()

	// Define finalizer configurations
	finalizer := []string{"batch.kubernetes.io/job-tracking"}
	noFinalizer := []string{}

	var wg sync.WaitGroup
	wg.Add(8)

	// Test 1: ONLY Job Finalizer - Success Case
	go func() {
		defer wg.Done()
		defer GinkgoRecover()
		s.RunFinalizerTest(ctx, "hst-test-job-finalizer-success", finalizer, noFinalizer, true)
	}()

	// Test 2: ONLY Job Finalizer - Failure Case
	go func() {
		defer wg.Done()
		defer GinkgoRecover()
		s.RunFinalizerTest(ctx, "hst-test-job-finalizer-failure", finalizer, noFinalizer, false)
	}()

	// Test 3: ONLY Pod Finalizer - Success Case
	go func() {
		defer wg.Done()
		defer GinkgoRecover()
		s.RunFinalizerTest(ctx, "hst-test-pod-finalizer-success", noFinalizer, finalizer, true)
	}()

	// Test 4: ONLY Pod Finalizer - Failure Case
	go func() {
		defer wg.Done()
		defer GinkgoRecover()
		s.RunFinalizerTest(ctx, "hst-test-pod-finalizer-failure", noFinalizer, finalizer, false)
	}()

	// Test 5: BOTH Job and Pod Finalizers - Success Case
	go func() {
		defer wg.Done()
		defer GinkgoRecover()
		s.RunFinalizerTest(ctx, "hst-test-both-finalizers-success", finalizer, finalizer, true)
	}()

	// Test 6: BOTH Job and Pod Finalizers - Failure Case
	go func() {
		defer wg.Done()
		defer GinkgoRecover()
		s.RunFinalizerTest(ctx, "hst-test-both-finalizers-failure", finalizer, finalizer, false)
	}()

	// Test 7: No Finalizers - Success Case
	go func() {
		defer wg.Done()
		defer GinkgoRecover()
		s.RunFinalizerTest(ctx, "hst-test-no-finalizer-success", noFinalizer, noFinalizer, true)
	}()

	// Test 8: No Finalizers - Failure Case
	go func() {
		defer wg.Done()
		defer GinkgoRecover()
		s.RunFinalizerTest(ctx, "hst-test-no-finalizer-failure", noFinalizer, noFinalizer, false)
	}()

	s.Log("Starting all 8 finalizer tests in parallel...")
	wg.Wait()
	s.Log("All 8 finalizer tests completed successfully")

	// verify that no jobs remain in the namespace
	allJobs, err := s.ListJobsInNamespace(ctx, s.Namespace)
	s.AssertNil(err)
	s.AssertEqual(0, len(allJobs))
	s.Log("Checking jobs: No jobs remain in namespace %s", s.Namespace)
}
