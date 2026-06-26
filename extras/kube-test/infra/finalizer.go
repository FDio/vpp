package kube_test

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

// Helper function to remove finalizers from a specific job in a namespace
func (s *BaseSuite) CleanupJobFinalizers(ctx context.Context, namespace string, jobName string) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		job, err := ClientSet.BatchV1().Jobs(namespace).Get(ctx, jobName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			Log("Job %s already removed", jobName)
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to get job %s for finalizer cleanup: %w", jobName, err)
		}

		if len(job.Finalizers) == 0 {
			Log("Job %s has no finalizers to remove", jobName)
			return nil
		}

		job.Finalizers = nil
		if _, err := ClientSet.BatchV1().Jobs(namespace).Update(ctx, job, metav1.UpdateOptions{}); err != nil {
			if apierrors.IsNotFound(err) {
				Log("Job %s already removed", jobName)
				return nil
			}
			return fmt.Errorf("failed to remove finalizers from job %s: %w", jobName, err)
		}
		Log("Removed finalizers from job %s", job.Name)
		return nil
	})
}

func (s *BaseSuite) WaitForJobDeleted(ctx context.Context, namespace string, jobName string) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		job, err := ClientSet.BatchV1().Jobs(namespace).Get(ctx, jobName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			Log("Job %s deleted", jobName)
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to get job %s while waiting for deletion: %w", jobName, err)
		}

		Log("Waiting for job %s deletion: active=%d succeeded=%d failed=%d finalizers=%v deletionTimestamp=%v",
			job.Name, job.Status.Active, job.Status.Succeeded, job.Status.Failed, job.Finalizers, job.DeletionTimestamp)

		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for job %s deletion: %w", jobName, ctx.Err())
		case <-ticker.C:
		}
	}
}

// Helper function to create a job with configurable finalizers
func (s *BaseSuite) CreateTestJob(ctx context.Context, namespace, jobName string, jobFinalizers, podFinalizers []string, jobSuccess bool) (*batchv1.Job, error) {
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: namespace,
			Labels: map[string]string{
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

	return ClientSet.BatchV1().Jobs(namespace).Create(ctx, job, metav1.CreateOptions{})
}

// Helper function to create a pod template spec with configurable finalizers
func (s *BaseSuite) CreatePodTemplateSpec(finalizers []string, jobName string, jobSuccess bool) corev1.PodTemplateSpec {
	return corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"test-name": jobName,
				"app":       "Kube-Test",
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
					Name:  "kube-test-finalizer-test-container",
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
func (s *BaseSuite) RunFinalizerTest(ctx context.Context, testName string, jobFinalizers, podFinalizers []string, jobSuccess bool) {
	// Create job with specified finalizers
	jobName := fmt.Sprintf("%s-job", testName)
	_, err := s.CreateTestJob(ctx, s.Namespace, jobName, jobFinalizers, podFinalizers, jobSuccess)
	AssertNil(err)
	Log("Created job %s with job finalizers: %v, pod finalizers: %v", jobName, jobFinalizers, podFinalizers)

	// Wait for pods to be created and ready
	Log("[%s...] Waiting for pods to be created and ready...", jobName)
	cmd := exec.Command("kubectl", "wait", "--for=condition=Ready", "pod",
		"--selector=test-name="+jobName,
		"--namespace="+s.Namespace,
		"--timeout=30s")
	output, err := cmd.CombinedOutput()
	if err != nil {
		Log("[%s...] kubectl wait failed: %v, output: %s", jobName, err, string(output))
	}

	// Check pods and their finalizers status
	pod, err := ClientSet.CoreV1().Pods(s.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("test-name=%s", jobName),
	})
	AssertNil(err)

	// Log pod finalizer status before cleanup
	for _, pod := range pod.Items {
		Log("[%s...] Pod %s: phase=%s, finalizers=%v, deletionTimestamp=%v",
			jobName, pod.Name, pod.Status.Phase, pod.Finalizers, pod.DeletionTimestamp)
	}

	// Check jobs and their finalizers status
	job, err := ClientSet.BatchV1().Jobs(s.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("test-name=%s", jobName),
	})
	AssertNil(err)

	if !jobSuccess {
		// For failed jobs, expect jobs to remain initially due to TTL cleanup delay
		AssertEqual(len(job.Items), 1)
		Log("Job %s failed as expected, waiting for job completion (failure)...", jobName)
		// Wait for job to complete (either succeed or fail)
		cmd := exec.Command("kubectl", "wait", "--for=condition=Failed", "job",
			"--selector=test-name="+jobName,
			"--namespace="+s.Namespace,
			"--timeout=25s")
		output, err := cmd.CombinedOutput()
		if err != nil {
			Log("[%s...] kubectl wait failed: %v, output: %s", jobName, err, string(output))
		}

		// Sleep for 5 seconds to account for TTL job cleanup
		Log("[%s...] Sleeping for 5 seconds to account for TTL job cleanup...", jobName)
		time.Sleep(5 * time.Second)
	}

	if len(jobFinalizers) > 0 {
		AssertEqual(len(job.Items), 1)
		Log("Checking jobs: Job (%s) remains because of finalizer %v", job.Items[0].Name, job.Items[0].Finalizers)
		err := s.CleanupJobFinalizers(ctx, s.Namespace, job.Items[0].Name)
		AssertNil(err, "Failed to remove job finalizers")
	}

	// Log job finalizer status before cleanup
	for _, job := range job.Items {
		Log("Job %s: status=%+v, finalizers=%v, deletionTimestamp=%v",
			job.Name, job.Status, job.Finalizers, job.DeletionTimestamp)
	}

	err = s.WaitForJobDeleted(ctx, s.Namespace, jobName)
	AssertNil(err, "Failed waiting for job deletion")
}
