/*
Copyright 2025 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package e2e

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	e2eservice "k8s.io/kubernetes/test/e2e/framework/service"
	imageutils "k8s.io/kubernetes/test/utils/image"
)

// E2ETestHelper provides a helper for e2e tests.
type E2ETestHelper struct {
	kubeClient clientset.Interface

	// AWS helper
	awsHelper *E2ETestHelperAWS

	// service configuration
	cfgPortCount          int
	cfgPodPort            int32
	cfgPodProtocol        v1.Protocol
	cfgDefaultAnnotations map[string]string
	LBJig                 *e2eservice.TestJig

	// service instance
	svc *v1.Service

	// node discovery
	nodeSelector   string
	nodeCount      int
	sampleNodeName string
}

// NewE2ETestHelper creates a new E2ETestHelper instance.
func NewE2ETestHelper(ctx context.Context, cs clientset.Interface) (*E2ETestHelper, error) {
	awsHelper, err := NewAWSHelper(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS E2E test helper: %v", err)
	}

	return &E2ETestHelper{
		kubeClient:     cs,
		cfgPortCount:   2,
		cfgPodPort:     8080,
		cfgPodProtocol: v1.ProtocolTCP,
		cfgDefaultAnnotations: map[string]string{
			"aws-load-balancer-backend-protocol": "http",
			"aws-load-balancer-ssl-ports":        "https",
		},
		awsHelper: awsHelper,
	}, nil
}

func (e2e *E2ETestHelper) GetAWSHelper() *E2ETestHelperAWS {
	return e2e.awsHelper
}

func (e2e *E2ETestHelper) GetKubeClient() clientset.Interface {
	return e2e.kubeClient
}

func (e2e *E2ETestHelper) GetServicePodPort() int32 {
	return int32(e2e.cfgPodPort)
}

// buildService creates a service instance with custom annotations.
func (e2e *E2ETestHelper) buildService(portCount int, extraAnnotations map[string]string) *v1.Service {
	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   e2e.LBJig.Namespace,
			Name:        e2e.LBJig.Name,
			Labels:      e2e.LBJig.Labels,
			Annotations: make(map[string]string, len(e2e.cfgDefaultAnnotations)+len(extraAnnotations)),
		},
		Spec: v1.ServiceSpec{
			Type:            v1.ServiceTypeLoadBalancer,
			SessionAffinity: v1.ServiceAffinityNone,
			Selector:        e2e.LBJig.Labels,
		},
	}
	if portCount == 0 {
		portCount = e2e.cfgPortCount
	}
	for i := 0; i < portCount; i++ {
		svc.Spec.Ports = append(svc.Spec.Ports, v1.ServicePort{
			Name:       fmt.Sprintf("port-%d", i),
			Protocol:   v1.ProtocolTCP,
			Port:       int32(80 + i),
			TargetPort: intstr.FromInt32(e2e.cfgPodPort),
		})
	}

	// add default annotations - can be overriden by extra annotations
	for aK, aV := range e2e.cfgDefaultAnnotations {
		svc.Annotations[aK] = aV
	}

	// append test case annotations to the service
	for aK, aV := range extraAnnotations {
		svc.Annotations[aK] = aV
	}

	// Defensive: ensure Annotations is not nil
	if svc.Annotations == nil {
		svc.Annotations = map[string]string{}
	}

	return svc
}

// cleanup cleans up the e2e resources.
func (e *E2ETestHelper) cleanup(ctx context.Context) {
	framework.Logf("Cleaning up e2e resources")
	// TODO cleanup resources created by the test helper
}

// buildDeployment creates a deployment configuration to the network load balancer test framework.
// buildDeployment is based on newDTemplate() from the e2e test framework, which not provide
// customization to bind in non-privileged ports.
func (e2e *E2ETestHelper) buildDeployment(affinity bool) func(deployment *appsv1.Deployment) {
	return func(deployment *appsv1.Deployment) {
		var replicas int32 = 1
		var grace int64 = 3
		deployment.ObjectMeta = metav1.ObjectMeta{
			Namespace: e2e.LBJig.Namespace,
			Name:      e2e.LBJig.Name,
			Labels:    e2e.LBJig.Labels,
		}
		deployment.Spec = appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: e2e.LBJig.Labels,
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: e2e.LBJig.Labels,
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:  "netexec",
							Image: imageutils.GetE2EImage(imageutils.Agnhost),
							Args: []string{
								"netexec",
								fmt.Sprintf("--http-port=%d", e2e.cfgPodPort),
								fmt.Sprintf("--udp-port=%d", e2e.cfgPodPort),
							},
							ReadinessProbe: &v1.Probe{
								PeriodSeconds: 3,
								ProbeHandler: v1.ProbeHandler{
									HTTPGet: &v1.HTTPGetAction{
										Port: intstr.FromInt(int(e2e.cfgPodPort)),
										Path: "/hostName",
									},
								},
							},
						},
					},
					TerminationGracePeriodSeconds: &grace,
				},
			},
		}
		if affinity {
			deployment.Spec.Template.Spec.Affinity = &v1.Affinity{
				NodeAffinity: &v1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
						NodeSelectorTerms: []v1.NodeSelectorTerm{
							{
								MatchExpressions: []v1.NodeSelectorRequirement{
									{
										Key:      "kubernetes.io/hostname",
										Operator: v1.NodeSelectorOpIn,
										Values:   []string{e2e.sampleNodeName},
									},
								},
							},
						},
					},
				},
			}
		}
	}
}

// isNodeSchedulable checks if a node is schedulable by checking if it has any taints that prevent scheduling pods.
func (e2e *E2ETestHelper) isNodeSchedulable(node *v1.Node) bool {
	if node == nil {
		return false
	}
	if len(node.Spec.Taints) == 0 {
		return true
	}
	for _, taint := range node.Spec.Taints {
		if node.Spec.Unschedulable || taint.Effect == v1.TaintEffectNoSchedule || taint.Effect == v1.TaintEffectNoExecute {
			return false
		}
	}
	return true
}

// discoverClusterWorkerNode identifies and selects worker nodes in the cluster based on predefined node label selectors.
// It returns a ClusterNodeDiscovery struct with the discovered information.
func (e2e *E2ETestHelper) discoverClusterWorkerNode(ctx context.Context) {
	var workerNodeList []string
	framework.Logf("discovering node label used in the kubernetes distributions")

	// Step 1: Wait for at least one node to exist in the cluster (handles cluster initialization)
	// This retry is for the cluster itself, not for specific label selectors
	var allNodes *v1.NodeList
	var clusterErr error
	err := wait.PollUntilContextTimeout(ctx, 5*time.Second, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
		allNodes, clusterErr = e2e.kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if clusterErr != nil {
			framework.Logf("waiting for cluster nodes to be available: %v", clusterErr)
			return false, nil // Retry on API errors
		}
		if len(allNodes.Items) == 0 {
			framework.Logf("waiting for nodes to register in the cluster...")
			return false, nil // Retry if no nodes yet
		}
		return true, nil // Nodes exist, continue
	})
	if err != nil {
		framework.ExpectNoError(fmt.Errorf("timeout waiting for cluster nodes: %v (last error: %v)", err, clusterErr))
		return
	}

	// Diagnostic: Log node labels to help debug label selector issues
	framework.Logf("Found %d total nodes in cluster", len(allNodes.Items))
	for i, node := range allNodes.Items {
		if i < 3 { // Only log first 3 nodes to avoid spam
			framework.Logf("Node[%d] %s labels: %v", i, node.Name, node.Labels)
		}
	}

	// Step 2: Try each known label selector to find worker nodes
	// Don't retry here - if the selector doesn't match, try the next one immediately
	for _, selector := range lookupNodeSelectors {
		framework.Logf("trying node label selector: %s", selector)
		nodeList, err := e2e.kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{
			LabelSelector: selector,
		})
		if err != nil {
			framework.Logf("API error listing nodes with selector %s: %v, trying next selector", selector, err)
			continue
		}
		framework.Logf("found %d nodes matching selector %s", len(nodeList.Items), selector)

		if len(nodeList.Items) > 0 {
			// Filter for schedulable nodes
			for i := range nodeList.Items {
				node := &nodeList.Items[i]
				if !e2e.isNodeSchedulable(node) {
					framework.Logf("skipping node %s (has taints: %v)", node.Name, node.Spec.Taints)
					continue
				}
				workerNodeList = append(workerNodeList, node.Name)
			}

			// Check if we found any schedulable nodes
			if len(workerNodeList) > 0 {
				sort.Strings(workerNodeList)
				e2e.nodeCount = len(workerNodeList)
				e2e.sampleNodeName = workerNodeList[0]
				e2e.nodeSelector = selector
				framework.Logf("Successfully discovered %d schedulable worker nodes using selector: %s", e2e.nodeCount, selector)
				return
			}
			framework.Logf("selector %s matched %d nodes but all are unschedulable, trying next selector", selector, len(nodeList.Items))
		}
	}

	// No selector matched schedulable nodes - provide detailed error
	framework.ExpectNoError(fmt.Errorf("unable to find schedulable worker nodes with any known selector %v (found %d total nodes in cluster)", lookupNodeSelectors, len(allNodes.Items)))
}

// inClusterTestReachableHTTP creates a pod within the cluster to test HTTP connectivity to a target IP and port.
// It schedules a client pod on the specified node using node affinity to test the hairpin scenario.
// The client pod uses a curl-based container to perform the HTTP request to the target server (behind the load balancer)
// and validates the response.
// The function waits for the client pod to complete its execution and inspects its exit code to determine success or failure.
//
// Parameters:
// - target: The IP address or Hostname of the target HTTP server.
// - targetPort: The port number of the target HTTP server.
//
// Returns:
// - error: Returns an error if the pod creation, execution, or cleanup fails, or if the HTTP test fails unexpectedly.
//
// Behavior:
// - The function creates a client pod with a curl-based container to perform the HTTP request.
// - The client pod is scheduled on the specified node using node affinity.
// - Logs are periodically collected during the client pod's execution for troubleshooting.
// - Events are inspected if the client pod remains in a pending state for too long.
// - The function waits for the client pod to complete and inspects its exit code to determine success or failure.
//
// Acknowledgement:
// Documentation generated by Cursor AI, reviewed by Human.
// Function generated by Human, reviewed and verbosity increased by Cursor AI.
func (e2e *E2ETestHelper) inClusterTestReachableHTTP(ctx context.Context, target string, targetPort int) error {
	podName := "http-test-pod"

	// Enhanced curl configuration for better resilience
	// Total timeout calculation: 30 retries * 30s delay + 15min curl max time = ~25 minutes
	// This aligns with the 25-minute polling timeout below
	defaultMaxTime := "1200"
	if maxTime := os.Getenv("CCM_E2E_OVERRIDE_MAX_TIME"); maxTime != "" {
		defaultMaxTime = maxTime
	}
	curlArgs := []string{
		"--retry", "30", // Retry in case of transient network issues.
		"--retry-delay", "30", // Wait in seconds between retries.
		"--retry-max-time", defaultMaxTime, // Max time for retries.
		"--retry-all-errors",  // Retry on all errors
		"--retry-connrefused", // Retry connection refused
		"--connect-timeout", "30",
		"--max-time", "60", // Max time for each operation.
		"--trace-time", // Include timestamps in trace output for debugging
		"--verbose",
		"-w", "\\\"\\n---> HTTPCode=%{http_code} time_total('%{time_total}s') time_namelookup('%{time_namelookup}s') time_connect('%{time_connect}s') time_appconnect('%{time_appconnect}s') time_pretransfer('%{time_pretransfer}s') time_redirect('%{time_redirect}s') time_starttransfer('%{time_starttransfer}s') <---\\n\\\"",
		fmt.Sprintf("http://%s:%d/echo?msg=hello", target, targetPort),
	}

	// client http test (curl) pod spec.
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: e2e.svc.Namespace,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:    "curl",
					Image:   imageutils.GetE2EImage(imageutils.Agnhost),
					Command: []string{"curl"},
					Args:    curlArgs,
					SecurityContext: &v1.SecurityContext{
						AllowPrivilegeEscalation: aws.Bool(false),
						Capabilities: &v1.Capabilities{
							Drop: []v1.Capability{"ALL"},
						},
						ReadOnlyRootFilesystem: aws.Bool(true),
					},
				},
			},
			SecurityContext: &v1.PodSecurityContext{
				RunAsNonRoot: aws.Bool(true),
				RunAsUser:    aws.Int64(1000),
				RunAsGroup:   aws.Int64(1000),
				SeccompProfile: &v1.SeccompProfile{
					Type: v1.SeccompProfileTypeRuntimeDefault, // Enforces runtime default seccomp profile for syscall filtering.
				},
			},
			RestartPolicy: v1.RestartPolicyNever, // Prevents the pod from restarting automatically.
			Affinity: &v1.Affinity{
				NodeAffinity: &v1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
						NodeSelectorTerms: []v1.NodeSelectorTerm{
							{
								MatchExpressions: []v1.NodeSelectorRequirement{
									{
										Key:      "kubernetes.io/hostname",
										Operator: v1.NodeSelectorOpIn,
										Values:   []string{e2e.sampleNodeName},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	ct := pod.Spec.Containers[0]
	framework.Logf("In-Cluster test PodSpec Image=%v Command=%v Args=%v", ct.Image, ct.Command, ct.Args)

	// Create the pod
	_, err := e2e.kubeClient.CoreV1().Pods(e2e.svc.Namespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create HTTP test pod: %v", err)
	}
	// Clean up the pod
	defer func() {
		err = e2e.kubeClient.CoreV1().Pods(e2e.svc.Namespace).Delete(ctx, podName, metav1.DeleteOptions{})
		if err != nil {
			framework.Logf("Failed to delete pod %s: %v", podName, err)
		}
	}()

	// Wait for the test pod to complete. Align timeout with curl retry configuration
	// Curl timeout: 30 retries * 30s delay + 900s max = ~1800s (~25-30 minutes)
	// Pod polling timeout: 25 minutes + buffer = ~30 minutes
	waitCount := 0
	pendingCount := 0
	consecutiveErrorCount := 0
	maxConsecutiveErrors := 3
	lastLoggedPhase := ""
	podPollingTimeout := 30 * time.Minute

	framework.Logf("=== STARTING POD MONITORING ===")
	framework.Logf("Pod polling timeout: %v (aligned with curl timeout)", podPollingTimeout)

	err = wait.PollUntilContextTimeout(ctx, 25*time.Second, podPollingTimeout, true, func(ctx context.Context) (bool, error) {
		p, err := e2e.kubeClient.CoreV1().Pods(e2e.svc.Namespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			consecutiveErrorCount++
			framework.Logf("Error getting pod %s (attempt %d/%d): %v", podName, consecutiveErrorCount, maxConsecutiveErrors, err)

			// Debugging information for CI troubleshooting
			if consecutiveErrorCount == 1 {
				framework.Logf("=== CI Environment Debug Info ===")
				framework.Logf("Namespace: %s, PodName: %s, NodeName: %s", e2e.svc.Namespace, podName, e2e.sampleNodeName)
				framework.Logf("Error type: %T", err)
				framework.Logf("Error details: %v", err)
				framework.Logf("API server connectivity issue detected in CI environment")
			}

			// Check if this is a retriable error (API server issues, network problems, etc.)
			if isRetriableKubernetesError(err) && consecutiveErrorCount < maxConsecutiveErrors {
				framework.Logf("Treating as transient API server error, will retry in 15 seconds...")
				return false, nil // Continue polling, don't fail immediately
			}

			// If we've had too many consecutive errors or this is a non-retriable error, fail
			framework.Logf("Permanent error or too many consecutive errors (%d), failing test", consecutiveErrorCount)
			return false, err
		}

		consecutiveErrorCount = 0

		// Log phase changes
		if string(p.Status.Phase) != lastLoggedPhase {
			framework.Logf("Pod %s phase changed: %s -> %s", podName, lastLoggedPhase, p.Status.Phase)
			lastLoggedPhase = string(p.Status.Phase)
		}

		podFinished := p.Status.Phase == v1.PodSucceeded || p.Status.Phase == v1.PodFailed

		if p.Status.Phase == v1.PodFailed {
			framework.Logf("Pod entered Failed state - performing detailed analysis:")
			framework.Logf("%s", analyzePodFailure(p))
			framework.Logf("Recent logs from failed pod:\n%s", gatherPodLogs(ctx, e2e, podName, 50))
		}

		// Troubleshoot pending pods
		if p.Status.Phase == v1.PodPending {
			pendingCount++
		}
		if pendingCount%10 == 0 && pendingCount > 0 {
			framework.Logf("Pod %s is pending for too long, checking events...", podName)

			// Collect pod-specific events
			events, errE := e2e.kubeClient.CoreV1().Events(e2e.svc.Namespace).List(ctx, metav1.ListOptions{
				FieldSelector: fmt.Sprintf("involvedObject.name=%s", podName),
			})
			if errE != nil {
				framework.Logf("Failed to list events for pod %s: %v", podName, errE)
			} else {
				framework.Logf("Pod-specific events:")
				for _, event := range events.Items {
					framework.Logf("  [%s] %s: %s (Count: %d)",
						event.Type, event.Reason, event.Message, event.Count)
				}
			}

			// Collect node-level events if pod is scheduled
			if p.Spec.NodeName != "" {
				nodeEvents, errNE := e2e.kubeClient.CoreV1().Events(e2e.svc.Namespace).List(ctx, metav1.ListOptions{
					FieldSelector: fmt.Sprintf("involvedObject.name=%s", p.Spec.NodeName),
				})
				if errNE != nil {
					framework.Logf("Failed to list events for node %s: %v", p.Spec.NodeName, errNE)
				} else if len(nodeEvents.Items) > 0 {
					framework.Logf("Node %s recent events:", p.Spec.NodeName)
					for _, event := range nodeEvents.Items {
						framework.Logf("  [%s] %s: %s", event.Type, event.Reason, event.Message)
					}
				}
			}

			framework.Logf("Preliminary analysis for pending pod:")
			framework.Logf("%s", analyzePodFailure(p))
		}
		// frequently collect logs.
		if waitCount > 0 && waitCount%4 == 0 {
			framework.Logf("Tail logs for HTTP test pod:\n%s", gatherPodLogs(ctx, e2e, podName, 5))
		}
		if podFinished {
			framework.Logf("Tail logs for HTTP test pod:\n%s", gatherPodLogs(ctx, e2e, podName, 0))
		}
		waitCount++
		return podFinished, nil
	})
	if err != nil {
		return fmt.Errorf("error waiting for pod %s to complete: %v", podName, err)
	}

	// Inspect the pod's container status for exit code
	pod, errS := e2e.kubeClient.CoreV1().Pods(e2e.svc.Namespace).Get(ctx, podName, metav1.GetOptions{})
	if errS != nil {
		return fmt.Errorf("failed to get pod %s: %v", podName, errS)
	}

	framework.Logf("=== FINAL POD STATUS ANALYSIS ===")
	framework.Logf("Final pod phase: %s", pod.Status.Phase)

	if len(pod.Status.ContainerStatuses) == 0 {
		framework.Logf("WARNING: No container statuses found - this indicates a scheduling or node issue")
		framework.Logf("%s", analyzePodFailure(pod))
		return fmt.Errorf("no container statuses found for pod %s - check pod failure analysis above", podName)
	}

	containerStatus := pod.Status.ContainerStatuses[0]
	framework.Logf("Container state analysis:")
	framework.Logf("  Ready: %t", containerStatus.Ready)
	framework.Logf("  Restart count: %d", containerStatus.RestartCount)

	// Detailed termination analysis
	if containerStatus.State.Terminated != nil {
		termination := containerStatus.State.Terminated
		exitCode := termination.ExitCode
		framework.Logf("  Termination reason: %s", termination.Reason)
		framework.Logf("  Exit code: %d", exitCode)
		framework.Logf("  Termination message: %s", termination.Message)

		if exitCode != 0 {
			// Gather comprehensive failure information
			framework.Logf("=== CURL TEST FAILURE ANALYSIS ===")
			framework.Logf("Exit code %d indicates curl command failed", exitCode)
			framework.Logf("Common exit codes:")
			framework.Logf("  6: Couldn't resolve host")
			framework.Logf("  7: Failed to connect to host")
			framework.Logf("  28: Operation timeout")
			framework.Logf("  52: Empty reply from server")
			framework.Logf("  56: Failure in receiving network data")

			finalLogs := gatherPodLogs(ctx, e2e, podName, 0)
			framework.Logf("Final container logs:\n%s", finalLogs)

			// Provide specific guidance based on exit code
			var guidance string
			switch exitCode {
			case 6:
				guidance = "DNS resolution failure - check if target hostname is resolvable"
			case 7:
				guidance = "Connection refused - check if target service is accessible and load balancer is working"
			case 28:
				guidance = "Timeout - check if target service is responding or increase curl timeout"
			case 52:
				guidance = "Empty reply - target service might be misconfigured or not running"
			case 56:
				guidance = "Network data receive failure - possible network connectivity issues"
			default:
				guidance = "Check curl logs above for specific error details"
			}

			errmsg := fmt.Errorf("HTTP connectivity test failed: pod %s exited with code %d. Guidance: %s", podName, exitCode, guidance)
			framework.Logf("CONNECTIVITY TEST RESULT: FAILED - %s", errmsg.Error())
			return errmsg
		}
	} else if containerStatus.State.Waiting != nil {
		framework.Logf("Container still waiting: %s - %s",
			containerStatus.State.Waiting.Reason, containerStatus.State.Waiting.Message)
		framework.Logf("%s", analyzePodFailure(pod))
		return fmt.Errorf("pod %s container never started properly - check failure analysis above", podName)
	} else if containerStatus.State.Running != nil {
		framework.Logf("WARNING: Container still running - this shouldn't happen with RestartPolicy=Never")
		return fmt.Errorf("pod %s container still running after timeout - unexpected state", podName)
	}

	// Validate HTTP response format with enhanced checking
	// Expected format: CURL_SUMMARY: HTTPCode=200 Time=<time>s ConnectTime=<time>s DNSTime=<time>s
	response := gatherPodLogs(ctx, e2e, podName, 0)
	framework.Logf("=== HTTP RESPONSE VALIDATION ===")
	framework.Logf("Full curl output:\n%s", response)

	// Check for successful HTTP response
	if strings.Contains(response, "CURL_SUMMARY: HTTPCode=200") {
		framework.Logf("✓ HTTP connectivity test PASSED - Found HTTPCode=200")

		if strings.Contains(response, "DNSTime=") {
			lines := strings.Split(response, "\n")
			for _, line := range lines {
				if strings.Contains(line, "CURL_SUMMARY:") {
					framework.Logf("Connection timing: %s", strings.TrimSpace(line))
					break
				}
			}
		}
		return nil
	}

	// Check for partial success (HTTP response received but not 200)
	if strings.Contains(response, "HTTPCode=") {
		framework.Logf("HTTP response received but not successful")
		// Try to extract the actual HTTP code
		lines := strings.Split(response, "\n")
		for _, line := range lines {
			if strings.Contains(line, "HTTPCode=") && !strings.Contains(line, "HTTPCode=200") {
				framework.Logf("Received HTTP response: %s", strings.TrimSpace(line))
				break
			}
		}
		errmsg := fmt.Errorf("HTTP response validation failed: received non-200 response code")
		framework.Logf("CONNECTIVITY TEST RESULT: PARTIAL FAILURE - %s", errmsg.Error())
		return errmsg
	}

	// No HTTP response found at all
	errmsg := fmt.Errorf("HTTP response validation failed: no HTTP response detected in curl output")
	framework.Logf("CONNECTIVITY TEST RESULT: FAILED - %s", errmsg.Error())
	return errmsg
}

// Gather information from the cluster to help debug failures.
// - Resource events
// - All namespace events
// - Cloud controller manager logs
// - Service status
func (e2e *E2ETestHelper) gatherResourceEvents(ctx context.Context) {
	framework.Logf("=== Collecting resource events for debugging ===")
	events, err := e2e.kubeClient.CoreV1().Events(e2e.LBJig.Namespace).List(ctx, metav1.ListOptions{
		FieldSelector: "involvedObject.name=" + e2e.LBJig.Name,
	})
	if err != nil {
		framework.Logf("Error getting events for resource %q: %v", e2e.LBJig.Name, err)
	} else {
		framework.Logf("Resource events for %q:", e2e.LBJig.Name)
		for _, event := range events.Items {
			framework.Logf("  [%s] %s/%s: %s - %s", event.Type, event.Reason, event.InvolvedObject.Name, event.Message, event.FirstTimestamp)
		}
	}
}

func (e2e *E2ETestHelper) gatherAllEvents(ctx context.Context) {
	framework.Logf("=== Collecting all namespace events ===")
	allEvents, err := e2e.kubeClient.CoreV1().Events(e2e.LBJig.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		framework.Logf("Error getting all namespace events: %v", err)
	} else {
		framework.Logf("All events in namespace %q:", e2e.LBJig.Namespace)
		for _, event := range allEvents.Items {
			if strings.Contains(event.Message, "loadbalancer") || strings.Contains(event.Message, "LoadBalancer") ||
				strings.Contains(event.Reason, "LoadBalancer") || strings.Contains(event.Source.Component, "cloud-controller-manager") {
				framework.Logf("  [%s] %s/%s/%s: %s - %s", event.Type, event.Source.Component, event.Reason, event.InvolvedObject.Name, event.Message, event.FirstTimestamp)
			}
		}
	}
}

func (e2e *E2ETestHelper) gatherControllerLogs(ctx context.Context) {
	framework.Logf("=== Collecting cloud controller manager logs ===")
	ccmPods, err := e2e.kubeClient.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		LabelSelector: "app=cloud-controller-manager",
	})
	if err != nil {
		framework.Logf("Error listing cloud controller manager pods: %v", err)
	} else {
		for _, pod := range ccmPods.Items {
			framework.Logf("Found CCM pod: %s/%s (phase: %s)", pod.Namespace, pod.Name, pod.Status.Phase)

			// Get recent logs (last 50 lines)
			tailLines := int64(50)
			logOpts := &v1.PodLogOptions{
				TailLines: &tailLines,
				Previous:  false,
			}
			logs, err1 := e2e.kubeClient.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, logOpts).DoRaw(ctx)
			if err1 != nil {
				framework.Logf("Error getting logs for CCM pod %s/%s: %v", pod.Namespace, pod.Name, err)
			} else {
				framework.Logf("Recent logs from CCM pod %s/%s:", pod.Namespace, pod.Name)
				framework.Logf("%s", string(logs))
			}
		}
	}
}

func (e2e *E2ETestHelper) gatherServiceStatus(ctx context.Context) {
	framework.Logf("=== Service Status ===")
	currentSvc, err := e2e.kubeClient.CoreV1().Services(e2e.LBJig.Namespace).Get(ctx, e2e.LBJig.Name, metav1.GetOptions{})
	if err != nil {
		framework.Logf("Error getting current service status: %v", err)
	} else {
		framework.Logf("Service %s status:", currentSvc.Name)
		framework.Logf("  Annotations: %+v", currentSvc.Annotations)
		framework.Logf("  LoadBalancer status: %+v", currentSvc.Status.LoadBalancer)
		framework.Logf("  Conditions: %+v", currentSvc.Status.Conditions)
	}
}

// gatherEventsOnFailure gathers events on failure.
func (e2e *E2ETestHelper) GatherEventsOnFailure(ctx context.Context, msgState string) {
	framework.Logf("=== %s ===", msgState)
	e2e.GatherServiceInfo(ctx)
	e2e.gatherAllEvents(ctx)
	e2e.gatherControllerLogs(ctx)
	framework.Logf("=== End of %s ===", msgState)
}

// GatherServiceEvents gathers service events.
func (e2e *E2ETestHelper) GatherServiceInfo(ctx context.Context) {
	framework.Logf("=== Service Events ===")
	e2e.gatherResourceEvents(ctx)
	e2e.gatherServiceStatus(ctx)
	framework.Logf("=== End of Service Events ===")
}

// isRetriableKubernetesError checks if a Kubernetes API error is likely transient and worth retrying.
// This helps distinguish between temporary API server issues and permanent errors.
func isRetriableKubernetesError(err error) bool {
	if err == nil {
		return false
	}

	errMsg := err.Error()

	// Common transient error patterns in CI environments
	transientErrors := []string{
		"unknown", // Generic server error, often transient
		"connection refused",
		"connection reset",
		"timeout",
		"temporary failure",
		"server is currently unable to handle the request",
		"service unavailable",
		"internal error",
		"etcd",
		"context deadline exceeded",
		"i/o timeout",
		"dial tcp",
		"no such host",
	}

	lowerErrMsg := strings.ToLower(errMsg)
	for _, transientPattern := range transientErrors {
		if strings.Contains(lowerErrMsg, transientPattern) {
			return true
		}
	}

	// Check for specific Kubernetes API error types that are typically transient
	if errors.IsInternalError(err) ||
		errors.IsServerTimeout(err) ||
		errors.IsServiceUnavailable(err) ||
		errors.IsTooManyRequests(err) {
		return true
	}

	return false
}

// gatherPodLogs is a helper to collect recent logs, or all, from a test pod.
func gatherPodLogs(ctx context.Context, e2e *E2ETestHelper, podName string, tail int) string {
	opts := &v1.PodLogOptions{}
	if tail == 0 {
		tail = 20
	}
	opts.TailLines = aws.Int64(int64(tail))

	// Try multiple approaches to get logs
	logs, errL := e2e.kubeClient.CoreV1().Pods(e2e.svc.Namespace).GetLogs(podName, opts).DoRaw(ctx)
	if errL != nil {
		framework.Logf("Failed to retrieve pod logs (attempt 1): %v", errL)

		// Try without tail limit if that was the issue
		opts.TailLines = nil
		logs, errL = e2e.kubeClient.CoreV1().Pods(e2e.svc.Namespace).GetLogs(podName, opts).DoRaw(ctx)
		if errL != nil {
			framework.Logf("Failed to retrieve pod logs (attempt 2, no tail): %v", errL)

			// Try with different container if multi-container pod
			opts.Container = "curl"
			logs, errL = e2e.kubeClient.CoreV1().Pods(e2e.svc.Namespace).GetLogs(podName, opts).DoRaw(ctx)
			if errL != nil {
				framework.Logf("Failed to retrieve pod logs (attempt 3, explicit container): %v", errL)
				return fmt.Sprintf("[LOG COLLECTION FAILED: %v]", errL)
			}
		}
	}
	return string(logs)
}

// analyzePodFailure is a helper to analyze pod failure.
func analyzePodFailure(pod *v1.Pod) string {
	var analysis []string
	analysis = append(analysis, "=== POD FAILURE ANALYSIS ===")
	analysis = append(analysis, fmt.Sprintf("Pod Name: %s", pod.Name))
	analysis = append(analysis, fmt.Sprintf("Pod Phase: %s", pod.Status.Phase))
	analysis = append(analysis, fmt.Sprintf("Pod Reason: %s", pod.Status.Reason))
	analysis = append(analysis, fmt.Sprintf("Pod Message: %s", pod.Status.Message))

	// Analyze node scheduling
	if pod.Spec.NodeName != "" {
		analysis = append(analysis, fmt.Sprintf("Scheduled on Node: %s", pod.Spec.NodeName))
	} else {
		analysis = append(analysis, "WARNING: Pod not scheduled to any node")
	}

	// Analyze container statuses
	if len(pod.Status.ContainerStatuses) > 0 {
		for i, cs := range pod.Status.ContainerStatuses {
			analysis = append(analysis, fmt.Sprintf("Container[%d] %s:", i, cs.Name))
			analysis = append(analysis, fmt.Sprintf("  Ready: %t, Started: %t", cs.Ready, cs.Started != nil && *cs.Started))
			analysis = append(analysis, fmt.Sprintf("  Restart Count: %d", cs.RestartCount))

			if cs.State.Waiting != nil {
				analysis = append(analysis, fmt.Sprintf("  State: Waiting - Reason: %s", cs.State.Waiting.Reason))
				analysis = append(analysis, fmt.Sprintf("  Message: %s", cs.State.Waiting.Message))
			} else if cs.State.Running != nil {
				analysis = append(analysis, fmt.Sprintf("  State: Running since %s", cs.State.Running.StartedAt))
			} else if cs.State.Terminated != nil {
				analysis = append(analysis, fmt.Sprintf("  State: Terminated - Reason: %s", cs.State.Terminated.Reason))
				analysis = append(analysis, fmt.Sprintf("  Exit Code: %d", cs.State.Terminated.ExitCode))
				analysis = append(analysis, fmt.Sprintf("  Message: %s", cs.State.Terminated.Message))
				analysis = append(analysis, fmt.Sprintf("  Started: %s, Finished: %s",
					cs.State.Terminated.StartedAt, cs.State.Terminated.FinishedAt))
			}

			if cs.LastTerminationState.Terminated != nil {
				t := cs.LastTerminationState.Terminated
				analysis = append(analysis, fmt.Sprintf("  Last Termination: Reason: %s, Exit Code: %d", t.Reason, t.ExitCode))
			}
		}
	} else {
		analysis = append(analysis, "WARNING: No container statuses found")
	}

	// Analyze pod conditions
	if len(pod.Status.Conditions) > 0 {
		analysis = append(analysis, "Pod Conditions:")
		for _, cond := range pod.Status.Conditions {
			analysis = append(analysis, fmt.Sprintf("  %s: %s (%s) - %s",
				cond.Type, cond.Status, cond.Reason, cond.Message))
		}
	}

	// Check resource requests vs limits
	for _, container := range pod.Spec.Containers {
		if container.Resources.Requests != nil || container.Resources.Limits != nil {
			analysis = append(analysis, fmt.Sprintf("Container %s Resources:", container.Name))
			if req := container.Resources.Requests; req != nil {
				analysis = append(analysis, fmt.Sprintf("  Requests: CPU=%s, Memory=%s",
					req.Cpu(), req.Memory()))
			}
			if lim := container.Resources.Limits; lim != nil {
				analysis = append(analysis, fmt.Sprintf("  Limits: CPU=%s, Memory=%s",
					lim.Cpu(), lim.Memory()))
			}
		}
	}

	analysis = append(analysis, "=== END POD FAILURE ANALYSIS ===")
	return strings.Join(analysis, "\n")
}
