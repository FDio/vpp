package kube_test

import (
	"context"
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CreateDynamicJob creates a job that spawns a simple busybox pod for testing purposes
func (s *BaseSuite) CreateDynamicJob(ctx context.Context, namespace, jobName, appLabel, nodeName string) error {
	// Verify node exists if specified
	if nodeName != "" && nodeName != "any" {
		nodes, err := s.ClientSet.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("failed to list nodes: %v", err)
		}

		nodeExists := false
		for _, node := range nodes.Items {
			if node.Name == nodeName {
				nodeExists = true
				break
			}
		}

		if !nodeExists {
			return fmt.Errorf("node %s does not exist", nodeName)
		}
	}

	jobMeta := metav1.ObjectMeta{
		Name:      jobName,
		Namespace: namespace,
		Labels: map[string]string{
			"test-name": jobName,
		},
	}

	podSpec := corev1.PodSpec{
		RestartPolicy:                 corev1.RestartPolicyNever,
		TerminationGracePeriodSeconds: int64Ptr(5),  // 5 second termination grace period
		ActiveDeadlineSeconds:         int64Ptr(20), // Pod completes after 20 seconds
		Containers: []corev1.Container{
			{
				Name:  "test-container",
				Image: "busybox:1.35",
				Command: []string{
					"/bin/sh",
					"-c",
					fmt.Sprintf("echo 'Pod %s started at $(date)'; sleep 5; echo 'Pod %s completed at $(date)'", jobName, jobName),
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
	}

	// Add node selector if specified
	if nodeName != "" && nodeName != "any" {
		podSpec.NodeName = nodeName
	}

	job := &batchv1.Job{
		ObjectMeta: jobMeta,
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: int32Ptr(10), // Job TTL of 10 seconds after completion
			ActiveDeadlineSeconds:   int64Ptr(30), // Kill the job after 30 seconds max
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "Kube-Test",
					},
				},
				Spec: podSpec,
			},
		},
	}

	_, err := s.ClientSet.BatchV1().Jobs(namespace).Create(ctx, job, metav1.CreateOptions{})
	if err != nil {
		s.Log("Failed to create job %s: %v", jobName, err)
		return err
	}

	s.Log("Created dynamic job: %s", jobName)
	return nil
}

// DeleteDynamicJob deletes a job using Kubernetes API
func (s *BaseSuite) DeleteDynamicJob(ctx context.Context, namespace, jobName string) error {
	err := s.ClientSet.BatchV1().Jobs(namespace).Delete(ctx, jobName, metav1.DeleteOptions{})
	if err != nil {
		s.Log("Failed to delete job %s: %v", jobName, err)
		return err
	}

	s.Log("Deleted dynamic job: %s", jobName)
	return nil
}

// ListJobsInNamespace lists all jobs in a specific namespace
func (s *BaseSuite) ListJobsInNamespace(ctx context.Context, namespace string) ([]string, error) {
	jobList, err := s.ClientSet.BatchV1().Jobs(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var jobNames []string
	for _, job := range jobList.Items {
		jobNames = append(jobNames, job.Name)
	}

	return jobNames, nil
}

// CleanupJobsWithFinalizers removes finalizers from jobs before cleanup to prevent hanging resources
func (s *BaseSuite) CleanupJobsWithFinalizers(ctx context.Context, namespace string) error {
	jobs, err := s.ClientSet.BatchV1().Jobs(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, job := range jobs.Items {
		if len(job.Finalizers) > 0 {
			// Remove the finalizer
			job.Finalizers = []string{}
			_, err := s.ClientSet.BatchV1().Jobs(namespace).Update(ctx, &job, metav1.UpdateOptions{})
			if err != nil {
				s.Log("Failed to remove finalizer from job %s: %v", job.Name, err)
			} else {
				s.Log("Removed finalizer from job %s", job.Name)
			}
		}
	}

	return nil
}
