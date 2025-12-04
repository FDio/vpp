package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	. "fd.io/kube-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

const appLabel = "Kube-Test"

func init() {
	RegisterFelixTests(FelixCniServerRaceTest, FelixPolicyChurnTest, FelixPodChurnTest, FinalizerTest)
}

func FelixCniServerRaceTest(s *FelixSuite) {
	ctx, cancel := context.WithTimeout(s.MainContext, time.Minute*3)
	defer cancel()

	defer func() {
		err := s.CleanupJobsWithFinalizers(context.Background(), s.Namespace)
		s.AssertNil(err, "Failed to cleanup jobs with finalizers")
		s.CleanupNetworkPolicies(s.Namespace, appLabel)
	}()

	err := s.CreateDefaultNetworkPolicies(ctx, s.Namespace, appLabel)
	s.AssertNil(err, "Failed to create default network policies")

	s.Log("Starting Felix CNI server race test ...")

	go func() {
		defer GinkgoRecover()
		policyCreateTicker := time.NewTicker(time.Second * 3)
		defer policyCreateTicker.Stop()
		counter := 1
		endTime := time.Now().Add(time.Second * 60)
		for {
			<-policyCreateTicker.C
			if time.Now().After(endTime) {
				return
			}
			for i := 0; i < 4; i++ {
				port := 20000 + counter
				err := s.CreateNetworkPolicy(ctx, s.Namespace, appLabel, int32(port))
				s.AssertNil(err, "Failed to create dynamic network policy")
				s.Log("Created dynamic network policy %d with port %d", counter, port)
				counter++
			}
		}
	}()

	go func() {
		defer GinkgoRecover()
		jobCreateTicker := time.NewTicker(time.Second * 3)
		defer jobCreateTicker.Stop()
		counter := 1
		endTime := time.Now().Add(time.Second * 60)
		for {
			<-jobCreateTicker.C
			if time.Now().After(endTime) {
				return
			}
			for i := 0; i < 4; i++ {
				jobName := fmt.Sprintf("race-job-%d-%d", time.Now().Unix(), counter)
				err := s.CreateDynamicJob(ctx, s.Namespace, jobName, appLabel, "any")
				s.AssertNil(err, "Failed to create dynamic job")
				s.Log("Created job %d: %s", counter, jobName)
				counter++
			}
		}
	}()

	s.Log("Waiting for 2 minutes for test to complete ...")
	time.Sleep(time.Minute * 2)

	finalPods, err := s.ListPodsInNamespace(ctx, s.Namespace)
	s.AssertNil(err)
	s.AssertEqual(0, len(finalPods))

	finalJobs, err := s.ListJobsInNamespace(ctx, s.Namespace)
	s.AssertNil(err)
	s.AssertEqual(0, len(finalJobs))
}

func FelixPodChurnTest(s *FelixSuite) {
	ctx, cancel := context.WithTimeout(s.MainContext, time.Minute*1)
	defer cancel()

	err := s.CreateDefaultNetworkPolicies(ctx, s.Namespace, appLabel)
	s.AssertNil(err, "Failed to create default network policies")
	defer func() {
		s.CleanupNetworkPolicies(s.Namespace, appLabel)
	}()

	var createCounter int = 1
	var deleteCounter int = 1

	s.Log("Starting Pod churn test ...")

	go func() {
		defer GinkgoRecover()
		podCreateTicker := time.NewTicker(time.Second)
		defer podCreateTicker.Stop()
		endTime := time.Now().Add(time.Second * 25)
		for {
			<-podCreateTicker.C
			if time.Now().After(endTime) {
				return
			}
			podName := fmt.Sprintf("churn-pod-%d", createCounter)
			err := s.CreateDynamicPod(ctx, s.Namespace, podName, appLabel)
			s.AssertNil(err, "Failed to create dynamic pod")
			createCounter++
		}
	}()

	go func() {
		defer GinkgoRecover()
		s.Log("Deletion goroutine: waiting 5 seconds before starting deletion ...")
		time.Sleep(time.Second * 5)
		podDeleteTicker := time.NewTicker(time.Second)
		defer podDeleteTicker.Stop()
		endTime := time.Now().Add(time.Second * 20)
		for {
			<-podDeleteTicker.C
			if time.Now().After(endTime) {
				return
			}
			podToDelete := fmt.Sprintf("churn-pod-%d", deleteCounter)
			err := s.DeleteDynamicPod(ctx, s.Namespace, podToDelete)
			s.AssertNil(err, "Failed to delete dynamic pod")
			deleteCounter++
		}
	}()

	s.Log("Waiting for 30 seconds for pod churn to complete ...")
	time.Sleep(time.Second * 30)

	remainingPods, err := s.ListPodsInNamespace(ctx, s.Namespace)
	s.AssertNil(err, "Failed to list pods in test namespace")

	s.Log("=== All Pods in Namespace %s ===", s.Namespace)
	s.Log("Found %d pods in namespace", len(remainingPods))
	for i, podName := range remainingPods {
		s.Log("  %d. %s", i+1, podName)
	}

	s.Log("=== Pod Churn Summary ===")
	s.Log("Pods created: %d", createCounter-1)
	s.Log("Pods deleted: %d", deleteCounter-1)
	s.Log("Pod churn test completed. Found %d pods remaining in namespace", len(remainingPods))
	for _, podName := range remainingPods {
		err := s.DeleteDynamicPod(ctx, s.Namespace, podName)
		s.AssertNil(err, "Failed to delete dynamic pod")
	}
}

func FelixPolicyChurnTest(s *FelixSuite) {
	ctx, cancel := context.WithTimeout(s.MainContext, time.Minute*1)
	defer cancel()

	err := s.CreateDefaultNetworkPolicies(ctx, s.Namespace, appLabel)
	s.AssertNil(err, "Failed to create default network policies")
	defer func() {
		s.CleanupNetworkPolicies(s.Namespace, appLabel)
	}()

	s.DeployPod(s.Pods.ClientGeneric)
	s.DeployPod(s.Pods.ServerGeneric)

	var createdPolicies []string
	var policiesMutex sync.Mutex

	s.Log("Starting NetworkPolicy churn test ...")

	go func() {
		defer GinkgoRecover()
		policyCreateTicker := time.NewTicker(time.Second)
		defer policyCreateTicker.Stop()
		updateCounter := 1
		endTime := time.Now().Add(time.Second * 20)
		for {
			<-policyCreateTicker.C
			if time.Now().After(endTime) {
				return
			}
			for i := 0; i < 5; i++ {
				port := 20000 + updateCounter
				err := s.CreateNetworkPolicy(ctx, s.Namespace, appLabel, int32(port))
				s.AssertNil(err, "Failed to create dynamic network policy")
				policyName := fmt.Sprintf("kube-test-network-policy-%d", port)
				policiesMutex.Lock()
				createdPolicies = append(createdPolicies, policyName)
				policiesMutex.Unlock()
				updateCounter++
			}
		}
	}()

	go func() {
		defer GinkgoRecover()
		policyDeleteTicker := time.NewTicker(time.Second)
		defer policyDeleteTicker.Stop()
		endTime := time.Now().Add(time.Second * 20)
		for {
			<-policyDeleteTicker.C
			if time.Now().After(endTime) {
				return
			}
			for i := 0; i < 3; i++ {
				if len(createdPolicies) > 0 {
					policiesMutex.Lock()
					randIndex := time.Now().UnixNano() % int64(len(createdPolicies))
					policyToDelete := createdPolicies[randIndex]
					createdPolicies = append(createdPolicies[:randIndex], createdPolicies[randIndex+1:]...)
					policiesMutex.Unlock()
					s.DeleteNetworkPolicy(ctx, s.Namespace, policyToDelete)
				} else {
					s.Log("No dynamic policies available to delete")
				}
			}
		}
	}()

	s.Log("Waiting for 30 seconds for policy churn to complete ...")
	time.Sleep(time.Second * 30)

	s.Log("=== Policy Churn Summary ===")
	s.Log("Remaining dynamic policies count: %d", len(createdPolicies))
	if len(createdPolicies) > 0 {
		s.Log("Remaining dynamic policy names:")
		for i, policyName := range createdPolicies {
			s.Log("  %d. %s", i+1, policyName)
		}
	}
	s.Log("")

	out, err := s.ExecVppctlInKubeNode(s.Pods.ClientGeneric.Worker, "show", "npol", "rules")
	s.AssertNil(err, fmt.Sprintf("Failed to run 'show npol rules' on %s", s.Pods.ClientGeneric.Worker))

	ret, _ := s.VerifyDefaultNetworkPolicies(string(out), s.Pods.ClientGeneric.Worker)
	s.AssertEqual(true, ret)

	ret, _ = s.VerifyDynamicNetworkPolicies(string(out), s.Pods.ClientGeneric.Worker, createdPolicies)
	s.AssertEqual(true, ret)

	out, err = s.ExecVppctlInKubeNode(s.Pods.ServerGeneric.Worker, "show", "npol", "rules")
	s.AssertNil(err, fmt.Sprintf("Failed to run 'show npol rules' on %s", s.Pods.ServerGeneric.Worker))

	ret, _ = s.VerifyDefaultNetworkPolicies(string(out), s.Pods.ServerGeneric.Worker)
	s.AssertEqual(true, ret)

	ret, _ = s.VerifyDynamicNetworkPolicies(string(out), s.Pods.ServerGeneric.Worker, createdPolicies)
	s.AssertEqual(true, ret)
}

func FinalizerTest(s *FelixSuite) {
	ctx, cancel := context.WithTimeout(s.MainContext, time.Minute*2)
	defer cancel()

	err := s.CreateDefaultNetworkPolicies(ctx, s.Namespace, appLabel)
	s.AssertNil(err, "Failed to create default network policies")
	defer func() {
		s.CleanupNetworkPolicies(s.Namespace, appLabel)
	}()

	finalizer := []string{"batch.kubernetes.io/job-tracking"}
	noFinalizer := []string{}
	var wg sync.WaitGroup
	wg.Add(8)

	go func() {
		defer wg.Done()
		defer GinkgoRecover()
		s.RunFinalizerTest(ctx, "kube-test-job-finalizer-success", finalizer, noFinalizer, true)
	}()

	go func() {
		defer wg.Done()
		defer GinkgoRecover()
		s.RunFinalizerTest(ctx, "kube-test-job-finalizer-failure", finalizer, noFinalizer, false)
	}()

	go func() {
		defer wg.Done()
		defer GinkgoRecover()
		s.RunFinalizerTest(ctx, "kube-test-pod-finalizer-success", noFinalizer, finalizer, true)
	}()

	go func() {
		defer wg.Done()
		defer GinkgoRecover()
		s.RunFinalizerTest(ctx, "kube-test-pod-finalizer-failure", noFinalizer, finalizer, false)
	}()

	go func() {
		defer wg.Done()
		defer GinkgoRecover()
		s.RunFinalizerTest(ctx, "kube-test-both-finalizers-success", finalizer, finalizer, true)
	}()

	go func() {
		defer wg.Done()
		defer GinkgoRecover()
		s.RunFinalizerTest(ctx, "kube-test-both-finalizers-failure", finalizer, finalizer, false)
	}()

	go func() {
		defer wg.Done()
		defer GinkgoRecover()
		s.RunFinalizerTest(ctx, "kube-test-no-finalizer-success", noFinalizer, noFinalizer, true)
	}()

	go func() {
		defer wg.Done()
		defer GinkgoRecover()
		s.RunFinalizerTest(ctx, "kube-test-no-finalizer-failure", noFinalizer, noFinalizer, false)
	}()

	s.Log("Starting all 8 finalizer tests in parallel ...")
	wg.Wait()
	s.Log("All 8 finalizer tests completed successfully")

	allJobs, err := s.ListJobsInNamespace(ctx, s.Namespace)
	s.AssertNil(err)
	s.AssertEqual(0, len(allJobs))
	s.Log("Checking jobs: No jobs remain in namespace %s", s.Namespace)
}
