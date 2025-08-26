package hst_kind

import (
	"context"
	"fmt"
	"os/exec"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Helper function to remove finalizers from a specific job in a namespace
func (s *KindSuite) CleanupJobFinalizers(ctx context.Context, namespace string, jobName string) {
	// Get the specific job by name
	job, err := s.ClientSet.BatchV1().Jobs(namespace).Get(ctx, jobName, metav1.GetOptions{})
	if err != nil {
		s.Log("Failed to get job %s for finalizer cleanup: %v", jobName, err)
		return
	}

	// Remove all finalizers from the job (if the job has them)
	if len(job.Finalizers) > 0 {
		job.Finalizers = []string{}
		_, err := s.ClientSet.BatchV1().Jobs(namespace).Update(ctx, job, metav1.UpdateOptions{})
		if err != nil {
			s.Log("Failed to remove finalizer from job %s: %v", job.Name, err)
		} else {
			s.Log("Removed finalizers from job %s", job.Name)
		}
	} else {
		s.Log("Job %s has no finalizers to remove", jobName)
	}
}

// Helper function to create a job with configurable finalizers
func (s *KindSuite) CreateTestJob(ctx context.Context, namespace, jobName string, jobFinalizers, podFinalizers []string, jobSuccess bool) (*batchv1.Job, error) {
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: namespace,
			Labels: map[string]string{
				"test-type": "hst-finalizer-test",
				"test-name": jobName,
			},
			Finalizers: jobFinalizers,
		},
		Spec: batchv1.JobSpec{
			// how long the job object should be kept after it finishes (succeeds or fails)
			TTLSecondsAfterFinished: int32Ptr(5),
			// maximum duration the job is allowed to run from the time it starts
			ActiveDeadlineSeconds: int64Ptr(25),
			// number of pods that should run to completion
			Completions: int32Ptr(1),
			// number of retries before marking job as failed
			BackoffLimit: int32Ptr(0),
			Template:     s.CreatePodTemplateSpec(podFinalizers, jobName, jobSuccess),
		},
	}

	return s.ClientSet.BatchV1().Jobs(namespace).Create(ctx, job, metav1.CreateOptions{})
}

// Helper function to create a pod template spec with configurable finalizers
func (s *KindSuite) CreatePodTemplateSpec(finalizers []string, testName string, jobSuccess bool) corev1.PodTemplateSpec {
	return corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"test-type": "hst-finalizer-test",
				"test-name": testName,
			},
			Finalizers: finalizers,
		},
		Spec: corev1.PodSpec{
			// containers are not restarted regardless of exit status
			RestartPolicy: corev1.RestartPolicyNever,
			// how long k8 will wait after sending a SIGTERM to containers before forcibly killing wiht SIGKILL
			TerminationGracePeriodSeconds: int64Ptr(5),
			// maximum duration in seconds the pod is allowed to run
			ActiveDeadlineSeconds: int64Ptr(20),
			Containers: []corev1.Container{
				{
					Name:  "hst-finalizer-test-container",
					Image: "busybox:1.35",
					Command: []string{
						"/bin/sh",
						"-c",
						func() string {
							if jobSuccess {
								return "echo \"Pod started at '$(date)'\"; sleep 5; echo \"Pod completing at '$(date)'\""
							} else {
								return "echo \"Pod started at '$(date)'\"; sleep 30; echo \"Pod completing at '$(date)'\""
							}
						}(),
					},
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: 5201,
						},
					},
					Resources: corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("32Mi"),
							corev1.ResourceCPU:    resource.MustParse("25m"),
						},
						Requests: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse("16Mi"),
							corev1.ResourceCPU:    resource.MustParse("10m"),
						},
					},
				},
			},
		},
	}
}

// Helper function to run finalizer test with given configuration
func (s *KindSuite) RunFinalizerTest(ctx context.Context, testName string, jobFinalizers, podFinalizers []string, jobSuccess bool) {
	// Create job with specified finalizers
	jobName := fmt.Sprintf("%s-job", testName)
	_, err := s.CreateTestJob(ctx, s.Namespace, jobName, jobFinalizers, podFinalizers, jobSuccess)
	s.AssertNil(err)
	s.Log("Created job %s with job finalizers: %v, pod finalizers: %v", jobName, jobFinalizers, podFinalizers)

	// Wait for pods to be created and ready
	s.Log("Waiting for pods to be created and ready...")
	cmd := exec.Command("kubectl", "wait", "--for=condition=Ready", "pod",
		"--selector=test-name="+jobName,
		"--namespace="+s.Namespace,
		"--timeout=30s")
	output, err := cmd.CombinedOutput()
	if err != nil {
		s.Log("kubectl wait failed: %v, output: %s", err, string(output))
	} else {
		s.Log("Pods are ready: %s", string(output))
	}

	// Check pods and their finalizers status
	pod, err := s.ClientSet.CoreV1().Pods(s.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("test-name=%s", jobName),
	})
	s.AssertNil(err)

	if len(pod.Items) > 0 {
		s.Log("Checking pods: %d pod remains", len(pod.Items))
	} else {
		s.Log("Checking pods: No pods remain in namespace %s", s.Namespace)
	}

	// Log pod finalizer status before cleanup
	for _, pod := range pod.Items {
		s.Log("Pod %s: phase=%s, finalizers=%v, deletionTimestamp=%v",
			pod.Name, pod.Status.Phase, pod.Finalizers, pod.DeletionTimestamp)
	}

	// Check jobs and their finalizers status
	job, err := s.ClientSet.BatchV1().Jobs(s.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("test-name=%s", jobName),
	})
	s.AssertNil(err)

	if !jobSuccess {
		// For failed jobs, expect jobs to remain initially due to TTL cleanup delay
		s.AssertEqual(len(job.Items), 1)
		s.Log("Job failed as expected, waiting for job completion or failure...")
		// Wait for job to complete (either succeed or fail)
		cmd := exec.Command("kubectl", "wait", "--for=condition=Complete", "job",
			"--selector=test-name="+jobName,
			"--namespace="+s.Namespace,
			"--timeout=10s")
		output, err := cmd.CombinedOutput()
		if err != nil {
			s.Log("kubectl wait for job completion failed: %v, output: %s", err, string(output))
			// Also try waiting for failure condition
			cmd = exec.Command("kubectl", "wait", "--for=condition=Failed", "job",
				"--selector=test-name="+jobName,
				"--namespace="+s.Namespace,
				"--timeout=10s")
			output, err = cmd.CombinedOutput()
			if err != nil {
				s.Log("kubectl wait for job failure failed: %v, output: %s", err, string(output))
			} else {
				s.Log("Job failed as expected: %s", string(output))
			}
		} else {
			s.Log("Job completed unexpectedly: %s", string(output))
		}
	}

	if len(jobFinalizers) > 0 {
		s.AssertEqual(len(job.Items), 1)
		s.Log("Checking jobs: Job (%s) remains because of finalizer %v", job.Items[0].Name, job.Items[0].Finalizers)
		s.CleanupJobFinalizers(ctx, s.Namespace, job.Items[0].Name)
	}

	// Log job finalizer status before cleanup
	for _, job := range job.Items {
		s.Log("Job %s: status=%+v, finalizers=%v, deletionTimestamp=%v",
			job.Name, job.Status, job.Finalizers, job.DeletionTimestamp)
	}
}
