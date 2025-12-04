package kube_test

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// createNetworkPolicyPeer creates a network policy peer for "appLabel" pods
func createNetworkPolicyPeer(appLabel string) networkingv1.NetworkPolicyPeer {
	return networkingv1.NetworkPolicyPeer{
		PodSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				"app": appLabel,
			},
		},
	}
}
func createNetworkPolicyPort(protocol corev1.Protocol, port int32) networkingv1.NetworkPolicyPort {
	return networkingv1.NetworkPolicyPort{
		Protocol: &protocol,
		Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: port},
	}
}

// createIngressRule creates an ingress rule allowing traffic from "appLabel" pods on specified ports with protocol
func createIngressRule(appLabel string, protocol corev1.Protocol, ports ...int32) networkingv1.NetworkPolicyIngressRule {
	var policyPorts []networkingv1.NetworkPolicyPort
	for _, port := range ports {
		policyPorts = append(policyPorts, createNetworkPolicyPort(protocol, port))
	}

	return networkingv1.NetworkPolicyIngressRule{
		Ports: policyPorts,
		From:  []networkingv1.NetworkPolicyPeer{createNetworkPolicyPeer(appLabel)},
	}
}

// createEgressRule creates an egress rule allowing traffic to "appLabel" pods on specified ports with protocol
func createEgressRule(appLabel string, protocol corev1.Protocol, ports ...int32) networkingv1.NetworkPolicyEgressRule {
	var policyPorts []networkingv1.NetworkPolicyPort
	for _, port := range ports {
		policyPorts = append(policyPorts, createNetworkPolicyPort(protocol, port))
	}

	return networkingv1.NetworkPolicyEgressRule{
		Ports: policyPorts,
		To:    []networkingv1.NetworkPolicyPeer{createNetworkPolicyPeer(appLabel)},
	}
}

// PolicyConfig represents a network policy configuration
type PolicyConfig struct {
	Name        string
	Description string
	PolicyTypes []networkingv1.PolicyType
	Ingress     []networkingv1.NetworkPolicyIngressRule
	Egress      []networkingv1.NetworkPolicyEgressRule
	AppLabel    string
}

// createPolicyFromConfig creates a NetworkPolicy from PolicyConfig
func createPolicyFromConfig(config PolicyConfig, namespace string) *networkingv1.NetworkPolicy {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      config.Name,
			Namespace: namespace,
			Labels: map[string]string{
				"app":    config.AppLabel,
				"policy": config.AppLabel,
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": config.AppLabel,
				},
			},
		},
	}
	policy.Spec.PolicyTypes = config.PolicyTypes
	policy.Spec.Ingress = config.Ingress
	policy.Spec.Egress = config.Egress
	return policy
}

// createIngressOnlyPolicy creates a policy that only allows specific ingress rules
func createIngressOnlyPolicy(name, namespace, appLabel string, ingressRules ...networkingv1.NetworkPolicyIngressRule) *networkingv1.NetworkPolicy {
	return createPolicyFromConfig(PolicyConfig{
		Name:        name,
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		Ingress:     ingressRules,
		AppLabel:    appLabel,
	}, namespace)
}

// createEgressOnlyPolicy creates a policy that only allows specific egress rules
func createEgressOnlyPolicy(name, namespace, appLabel string, egressRules ...networkingv1.NetworkPolicyEgressRule) *networkingv1.NetworkPolicy {
	return createPolicyFromConfig(PolicyConfig{
		Name:        name,
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		Egress:      egressRules,
		AppLabel:    appLabel,
	}, namespace)
}

// createIngressEgressPolicy creates a policy that allows ingress and egress on the same port with specified protocols
func createIngressEgressPolicy(name, namespace, appLabel string, ingressProtocol, egressProtocol corev1.Protocol, port int32) *networkingv1.NetworkPolicy {
	return createPolicyFromConfig(PolicyConfig{
		Name: name,
		PolicyTypes: []networkingv1.PolicyType{
			networkingv1.PolicyTypeIngress,
			networkingv1.PolicyTypeEgress,
		},
		Ingress: []networkingv1.NetworkPolicyIngressRule{
			createIngressRule(appLabel, ingressProtocol, port),
		},
		Egress: []networkingv1.NetworkPolicyEgressRule{
			createEgressRule(appLabel, egressProtocol, port),
		},
		AppLabel: appLabel,
	}, namespace)
}

// createAndLogPolicy creates a network policy and logs the result
func (s *BaseSuite) createAndLogPolicy(ctx context.Context, policy *networkingv1.NetworkPolicy) error {
	created, err := s.ClientSet.NetworkingV1().NetworkPolicies(policy.Namespace).Create(ctx, policy, metav1.CreateOptions{})
	if err != nil {
		s.Log("Failed to create NetworkPolicy %s: %v", policy.Name, err)
		s.Log("Policy spec: %+v", policy)
		// Try to get more details if it's a status error
		if statusErr, ok := err.(interface{ Status() metav1.Status }); ok {
			s.Log("API Status: %+v", statusErr.Status())
		}
		return err
	}
	s.Log("Created NetworkPolicy: %s", created.Name)
	return nil
}

// CreateDefaultNetworkPolicies creates 4 sample NetworkPolicies with different rules
// Policy 1: Allow ingress on port 5201 (container port)
// Policy 2: Allow egress for DNS
// Policy 3: Allow HTTP 80 and HTTPS 443 ingress (TCP and UDP)
// Policy 4: Allow HTTP 80 and HTTPS 443 egress (TCP and UDP)
func (s *BaseSuite) CreateDefaultNetworkPolicies(ctx context.Context, namespace, appLabel string) error {
	s.Log("Creating default network policies in namespace: %s", namespace)
	policies := []*networkingv1.NetworkPolicy{
		createIngressOnlyPolicy("kube-test-network-policy-1", namespace, appLabel,
			createIngressRule(appLabel, corev1.ProtocolTCP, 5201)),
		createEgressOnlyPolicy("kube-test-network-policy-2", namespace, appLabel,
			createEgressRule(appLabel, corev1.ProtocolUDP, 53)),
		createIngressOnlyPolicy("kube-test-network-policy-3", namespace, appLabel,
			createIngressRule(appLabel, corev1.ProtocolTCP, 80, 443),
			createIngressRule(appLabel, corev1.ProtocolUDP, 80, 443)),
		createEgressOnlyPolicy("kube-test-network-policy-4", namespace, appLabel,
			createEgressRule(appLabel, corev1.ProtocolTCP, 80, 443),
			createEgressRule(appLabel, corev1.ProtocolUDP, 80, 443)),
	}

	for _, policy := range policies {
		if err := s.createAndLogPolicy(ctx, policy); err != nil {
			return err
		}
	}

	return nil
}

// CreateNetworkPolicy creates dynamic NetworkPolicies
// Policy: Allow TCP ingress and UDP egress on the same port to "appLabel" pods
func (s *BaseSuite) CreateNetworkPolicy(ctx context.Context, namespace, appLabel string, port int32) error {
	policyName := fmt.Sprintf("kube-test-network-policy-%d", port)

	policy := createIngressEgressPolicy(policyName, namespace, appLabel, corev1.ProtocolTCP, corev1.ProtocolUDP, port)
	return s.createAndLogPolicy(ctx, policy)
}

// GetNetworkPolicies retrieves all NetworkPolicies with app=HST label in the specified namespace
func (s *BaseSuite) GetNetworkPolicies(ctx context.Context, namespace, appLabel string) (*networkingv1.NetworkPolicyList, error) {
	return s.ClientSet.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("app=%s", appLabel),
	})
}

// DeleteNetworkPolicy deletes a specific NetworkPolicy by name and logs the result
func (s *BaseSuite) DeleteNetworkPolicy(ctx context.Context, namespace, policyName string) error {
	err := s.ClientSet.NetworkingV1().NetworkPolicies(namespace).Delete(ctx, policyName, metav1.DeleteOptions{})
	if err != nil {
		s.Log("Failed to delete NetworkPolicy %s: %v", policyName, err)
		return err
	} else {
		s.Log("Deleted NetworkPolicy: %s", policyName)
		return nil
	}
}

// CleanupNetworkPolicies deletes all NetworkPolicies with app=HST label in the specified namespace
func (s *BaseSuite) CleanupNetworkPolicies(namespace, appLabel string) {
	s.ClientSet.NetworkingV1().NetworkPolicies(namespace).DeleteCollection(
		context.Background(),
		metav1.DeleteOptions{},
		metav1.ListOptions{
			LabelSelector: fmt.Sprintf("app=%s", appLabel),
		},
	)
	s.Log("Cleaned up NetworkPolicies in namespace: %s (app=%s)", namespace, appLabel)
}

// VerifyDefaultNetworkPolicies verifies that VPP output contains expected network policy patterns
// Returns a summary of found/missing patterns and logs detailed results
func (s *BaseSuite) VerifyDefaultNetworkPolicies(output, nodeName string) (bool, []string) {
	expectedPatterns := []string{
		"[proto==TCP,dst==80,dst==443,src==[ipset#",
		"[proto==TCP,dst==80,dst==443,dst==[ipset#",
		"[proto==UDP,dst==80,dst==443,src==[ipset#",
		"[proto==UDP,dst==80,dst==443,dst==[ipset#",
		"[proto==UDP,dst==53,dst==[ipset#",
		"[proto==TCP,dst==5201,src==[ipset#",
	}

	s.Log("=== Verifying Default Network Policy Patterns on %s ===", nodeName)

	var missingPatterns []string
	allFound := true

	for _, pattern := range expectedPatterns {
		if strings.Contains(output, pattern) {
			s.Log("FOUND: %s", pattern)
		} else {
			missingPatterns = append(missingPatterns, pattern)
			s.Log("MISSING: %s", pattern)
			allFound = false
		}
	}

	if allFound {
		s.Log("SUCCESS: All expected default network policy patterns found on %s", nodeName)
	} else {
		s.Log("FAILURE: %d patterns missing on %s", len(missingPatterns), nodeName)
		s.Log("Missing patterns:")
		for _, missing := range missingPatterns {
			s.Log("  - %s", missing)
		}
	}

	s.Log("")
	return allFound, missingPatterns
}

// VerifyDynamicNetworkPolicies verifies that all remaining dynamic policies from createdPolicies
// are present in the VPP output with their expected UDP and TCP patterns
// Each policy should have both UDP and TCP rules for its specific port
func (s *BaseSuite) VerifyDynamicNetworkPolicies(output, nodeName string, createdPolicies []string) (bool, []string) {
	s.Log("=== Verifying Dynamic Network Policy Patterns on %s ===", nodeName)
	s.Log("Checking %d remaining dynamic policies", len(createdPolicies))

	// Build a set of expected ports for quick lookup and validation
	expectedPorts := make(map[string]bool)
	for _, policyName := range createdPolicies {
		if strings.HasPrefix(policyName, "kube-test-network-policy-") {
			port := strings.TrimPrefix(policyName, "kube-test-network-policy-")
			expectedPorts[port] = true
		} else {
			s.Log("Unexpected policy name format: %s", policyName)
		}
	}

	allFound := true
	var missingPolicyNames []string

	// Check if all expected policies are present
	for port := range expectedPorts {
		// Construct the policy name from the port
		policyName := fmt.Sprintf("kube-test-network-policy-%s", port)

		// Define expected patterns for this policy
		udpPattern := fmt.Sprintf("[proto==UDP,dst==%s,dst==[ipset#", port)
		tcpPattern := fmt.Sprintf("[proto==TCP,dst==%s,src==[ipset#", port)

		// Check if both patterns are present
		udpFound := strings.Contains(output, udpPattern)
		tcpFound := strings.Contains(output, tcpPattern)

		if udpFound && tcpFound {
			s.Log("FOUND: %s (port %s) - UDP and TCP patterns present", policyName, port)
		} else {
			missingPolicyNames = append(missingPolicyNames, policyName)
			allFound = false
			s.Log("FAILURE: %s (port %s) - UDP found: %t, TCP found: %t", policyName, port, udpFound, tcpFound)
		}
	}

	// Check for unexpected 200xx patterns that shouldn't be present
	s.Log("=== Checking for Unexpected 200xx Patterns ===")

	// Use regex to find all 200xx patterns in the output
	udpRegex := regexp.MustCompile(`\[proto==UDP,dst==(200\d\d),dst==\[ipset#`)
	tcpRegex := regexp.MustCompile(`\[proto==TCP,dst==(200\d\d),src==\[ipset#`)

	udpMatches := udpRegex.FindAllStringSubmatch(output, -1)
	tcpMatches := tcpRegex.FindAllStringSubmatch(output, -1)

	// Collect all found 200xx ports
	foundPorts := make(map[string]bool)
	for _, match := range udpMatches {
		if len(match) > 1 {
			foundPorts[match[1]] = true
		}
	}
	for _, match := range tcpMatches {
		if len(match) > 1 {
			foundPorts[match[1]] = true
		}
	}

	// Check for unexpected ports (found but not expected)
	unexpectedCount := 0
	for port := range foundPorts {
		if !expectedPorts[port] {
			if unexpectedCount == 0 {
				s.Log("FAILURE: Found unexpected 200xx patterns on %s", nodeName)
			}
			s.Log("  - Port %s (should have been deleted)", port)
			unexpectedCount++
			allFound = false
		}
	}

	if allFound {
		s.Log("SUCCESS: All remaining dynamic policies found and no unexpected patterns present on %s", nodeName)
	} else {
		s.Log("FAILURE on %s:", nodeName)
		if len(missingPolicyNames) > 0 {
			s.Log("  - %d dynamic policies missing", len(missingPolicyNames))
			for _, missing := range missingPolicyNames {
				s.Log("    * %s", missing)
			}
		}
		if unexpectedCount > 0 {
			s.Log("  - %d unexpected 200xx patterns found", unexpectedCount)
		}
	}

	s.Log("")
	return allFound, missingPolicyNames
}
