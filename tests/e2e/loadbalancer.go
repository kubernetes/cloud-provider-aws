/*
Copyright 2018 The Kubernetes Authors.
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
	"sort"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/framework"
	e2eservice "k8s.io/kubernetes/test/e2e/framework/service"
	imageutils "k8s.io/kubernetes/test/utils/image"
	admissionapi "k8s.io/pod-security-admission/api"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
)

const (
	annotationLBType             = "service.beta.kubernetes.io/aws-load-balancer-type"
	annotationLBTargetNodeLabels = "service.beta.kubernetes.io/aws-load-balancer-target-node-labels"
)

var (
	// lookupNodeSelectors are valid compute/node/worker selectors commonly used in different kubernetes
	// distributions.
	lookupNodeSelectors = []string{
		"node-role.kubernetes.io/worker", // used in must distributions
		"node-role.kubernetes.io/node",   // used in ccm-aws CI
	}
)

// ClusterNodeDiscovery holds information about discovered worker nodes.
type ClusterNodeDiscovery struct {
	Selector     string
	Count        int
	SingleWorker string
}

// loadbalancer tests
var _ = Describe("[cloud-provider-aws-e2e] loadbalancer", func() {
	f := framework.NewDefaultFramework("cloud-provider-aws")
	f.NamespacePodSecurityEnforceLevel = admissionapi.LevelPrivileged

	var (
		cs clientset.Interface
		ns *v1.Namespace
	)

	BeforeEach(func() {
		cs = f.ClientSet
		ns = f.Namespace
	})

	AfterEach(func() {
		// After each test
	})

	type loadBalancerTestCases struct {
		Name                           string
		ResourceSuffix                 string
		Annotations                    map[string]string
		PostConfigService              func(cfg *configServiceLB, svc *v1.Service, nodeDiscovery ClusterNodeDiscovery)
		PostRunValidation              func(cfg *configServiceLB, svc *v1.Service, nodeDiscovery ClusterNodeDiscovery)
		HookInClusterTestReachableHTTP bool
		RequireAffinity                bool
		SkipTestFailure                bool
	}
	cases := []loadBalancerTestCases{
		{
			Name:           "should configure the loadbalancer based on annotations",
			ResourceSuffix: "",
			Annotations:    map[string]string{},
		},
		{
			Name:           "NLB should configure the loadbalancer based on annotations",
			ResourceSuffix: "nlb",
			Annotations: map[string]string{
				annotationLBType: "nlb",
			},
		},
		{
			Name:           "NLB should configure the loadbalancer with target-node-labels",
			ResourceSuffix: "sg-nd",
			Annotations:    map[string]string{annotationLBType: "nlb"},
			PostConfigService: func(cfg *configServiceLB, svc *v1.Service, nodeDiscovery ClusterNodeDiscovery) {
				By(fmt.Sprintf("found %d nodes with selector %q\n", nodeDiscovery.Count, nodeDiscovery.Selector))
				if svc.Annotations == nil {
					svc.Annotations = map[string]string{}
				}
				svc.Annotations[annotationLBTargetNodeLabels] = nodeDiscovery.Selector
				By(fmt.Sprintf("using service with annotations: %v", svc.Annotations))
			},
			PostRunValidation: func(cfg *configServiceLB, svc *v1.Service, nodeDiscovery ClusterNodeDiscovery) {
				if len(svc.Status.LoadBalancer.Ingress) == 0 {
					framework.Failf("No ingress found in LoadBalancer status for service %s/%s", svc.Namespace, svc.Name)
				}
				lbDNS := svc.Status.LoadBalancer.Ingress[0].Hostname
				framework.ExpectNoError(getLBTargetCount(context.TODO(), lbDNS, nodeDiscovery.Count), "AWS LB target count validation failed")
			},
		},
		// hairpin connection tests for internal CLB and NLB services LBs.
		{
			Name:           "internal should support hairpin connection",
			ResourceSuffix: "hp-clb-int",
			Annotations: map[string]string{
				"service.beta.kubernetes.io/aws-load-balancer-internal": "true",
			},
			PostConfigService: func(cfg *configServiceLB, svc *v1.Service, nodeDiscovery ClusterNodeDiscovery) {
				if svc.Annotations == nil {
					svc.Annotations = map[string]string{}
				}
				svc.Annotations[annotationLBTargetNodeLabels] = fmt.Sprintf("kubernetes.io/hostname=%s", nodeDiscovery.SingleWorker)
				framework.Logf("Using service annotations: %v", svc.Annotations)
			},
			HookInClusterTestReachableHTTP: true,
			RequireAffinity:                true,
		},
		// FIXME: https://github.com/kubernetes/cloud-provider-aws/issues/1160
		// Hairpin connection work with target type as instance only when preserve client IP is disabled.
		// Currently CCM does not provide an interface to create a service with that setup, making an internal
		// Service to fail.
		{
			Name:           "NLB internal should support hairpin connection",
			ResourceSuffix: "hp-nlb-int",
			Annotations: map[string]string{
				annotationLBType: "nlb",
				"service.beta.kubernetes.io/aws-load-balancer-internal": "true",
			},
			PostConfigService: func(cfg *configServiceLB, svc *v1.Service, nodeDiscovery ClusterNodeDiscovery) {
				if svc.Annotations == nil {
					svc.Annotations = map[string]string{}
				}
				svc.Annotations[annotationLBTargetNodeLabels] = fmt.Sprintf("kubernetes.io/hostname=%s", nodeDiscovery.SingleWorker)
				framework.Logf("Using service annotations: %v", svc.Annotations)
			},
			HookInClusterTestReachableHTTP: true,
			RequireAffinity:                true,
			SkipTestFailure:                true,
		},
	}

	serviceNameBase := "lbconfig-test"
	for _, tc := range cases {
		It(tc.Name, func() {
			nodeDiscovery := discoverClusterWorkerNode(cs)
			loadBalancerCreateTimeout := e2eservice.GetServiceLoadBalancerCreationTimeout(cs)
			framework.Logf("Running tests against AWS with timeout %s", loadBalancerCreateTimeout)

			// Create Configuration
			serviceName := serviceNameBase
			if len(tc.ResourceSuffix) > 0 {
				serviceName = serviceName + "-" + tc.ResourceSuffix
			}
			framework.Logf("namespace for load balancer conig test: %s", ns.Name)

			By("creating a TCP service " + serviceName + " with type=LoadBalancerType in namespace " + ns.Name)
			lbConfig := newConfigServiceLB()
			lbConfig.LBJig = e2eservice.NewTestJig(cs, ns.Name, serviceName)

			// Hook annotations to support dynamic config
			lbServiceConfig := lbConfig.buildService(tc.Annotations)

			// Hook: PostConfigService patchs service configuration.
			if tc.PostConfigService != nil {
				tc.PostConfigService(lbConfig, lbServiceConfig, nodeDiscovery)
			}

			// Create Load Balancer
			By("creating loadbalancer for service " + lbServiceConfig.Namespace + "/" + lbServiceConfig.Name)
			if _, err := lbConfig.LBJig.Client.CoreV1().Services(lbConfig.LBJig.Namespace).Create(context.TODO(), lbServiceConfig, metav1.CreateOptions{}); err != nil {
				framework.ExpectNoError(fmt.Errorf("failed to create LoadBalancer Service %q: %v", lbServiceConfig.Name, err))
			}

			By("waiting for loadbalancer for service " + lbServiceConfig.Namespace + "/" + lbServiceConfig.Name)
			lbService, err := lbConfig.LBJig.WaitForLoadBalancer(loadBalancerCreateTimeout)
			framework.ExpectNoError(err)

			// Run Workloads
			By("creating a pod to be part of the TCP service " + serviceName)
			_, err = lbConfig.LBJig.Run(lbConfig.buildReplicationController(tc.RequireAffinity, nodeDiscovery))
			framework.ExpectNoError(err)

			// Hook: PostRunValidation performs LB validations after it is created (before test).
			if tc.PostRunValidation != nil {
				By("running post run validations")
				tc.PostRunValidation(lbConfig, lbService, nodeDiscovery)
			}

			// Test the Service Endpoint
			By("hitting the TCP service's LB External IP")
			if len(lbService.Spec.Ports) == 0 {
				framework.Failf("No ports found in service spec for service %s/%s", lbService.Namespace, lbService.Name)
			}
			if len(lbService.Status.LoadBalancer.Ingress) == 0 {
				framework.Failf("No ingress found in LoadBalancer status for service %s/%s", lbService.Namespace, lbService.Name)
			}
			svcPort := int(lbService.Spec.Ports[0].Port)
			ingressIP := e2eservice.GetIngressPoint(&lbService.Status.LoadBalancer.Ingress[0])
			framework.Logf("Load balancer's ingress IP: %s", ingressIP)

			// Hook: HookInClusterTestReachableHTTP changes the default test function to run the client in the cluster.
			if tc.HookInClusterTestReachableHTTP {
				err := inClusterTestReachableHTTP(cs, ns.Name, nodeDiscovery.SingleWorker, ingressIP, svcPort)
				if err != nil && tc.SkipTestFailure {
					Skip(err.Error())
				}
				framework.ExpectNoError(err)
			} else {
				e2eservice.TestReachableHTTP(ingressIP, svcPort, e2eservice.LoadBalancerLagTimeoutAWS)
			}

			// Update the service to cluster IP
			By("changing TCP service back to type=ClusterIP")
			_, err = lbConfig.LBJig.UpdateService(func(s *v1.Service) {
				s.Spec.Type = v1.ServiceTypeClusterIP
			})
			framework.ExpectNoError(err)

			// Wait for the load balancer to be destroyed asynchronously
			_, err = lbConfig.LBJig.WaitForLoadBalancerDestroy(ingressIP, svcPort, loadBalancerCreateTimeout)
			framework.ExpectNoError(err)
		})
	}
})

// configServiceLB hold loadbalancer test configurations used by e2e lib (jig).
type configServiceLB struct {
	PodPort            uint16
	PodProtocol        v1.Protocol
	DefaultAnnotations map[string]string

	LBJig *e2eservice.TestJig
}

func newConfigServiceLB() *configServiceLB {
	return &configServiceLB{
		PodPort:     8080,
		PodProtocol: v1.ProtocolTCP,
		DefaultAnnotations: map[string]string{
			"aws-load-balancer-backend-protocol": "http",
			"aws-load-balancer-ssl-ports":        "https",
		},
	}
}

// buildService creates a service instance with custom annotations.
func (s *configServiceLB) buildService(extraAnnotations map[string]string) *v1.Service {
	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   s.LBJig.Namespace,
			Name:        s.LBJig.Name,
			Labels:      s.LBJig.Labels,
			Annotations: make(map[string]string, len(s.DefaultAnnotations)+len(extraAnnotations)),
		},
		Spec: v1.ServiceSpec{
			Type:            v1.ServiceTypeLoadBalancer,
			SessionAffinity: v1.ServiceAffinityNone,
			Selector:        s.LBJig.Labels,
			Ports: []v1.ServicePort{
				{
					Name:       "http",
					Protocol:   v1.ProtocolTCP,
					Port:       int32(80),
					TargetPort: intstr.FromInt(int(s.PodPort)),
				},
				{
					Name:       "https",
					Protocol:   v1.ProtocolTCP,
					Port:       int32(443),
					TargetPort: intstr.FromInt(int(s.PodPort)),
				},
			},
		},
	}

	// add default annotations - can be overriden by extra annotations
	for aK, aV := range s.DefaultAnnotations {
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

// buildReplicationController creates a replication controller wrapper for the test framework.
// buildReplicationController is based on newRCTemplate() from the e2e test framework, which not provide
// customization to bind in non-privileged ports.
// TODO(mtulio): v1.33+[2][3] moved from RC to Deployments on tests, we must do the same to use Run()
// when the test framework is updated.
// [1] https://github.com/kubernetes/kubernetes/blob/89d95c9713a8fd189e8ad555120838b3c4f888d1/test/e2e/framework/service/jig.go#L636
// [2] https://github.com/kubernetes/kubernetes/issues/119021
// [3] https://github.com/kubernetes/cloud-provider-aws/blob/master/tests/e2e/go.mod#L14
func (s *configServiceLB) buildReplicationController(affinity bool, nodeDiscovery ClusterNodeDiscovery) func(rc *v1.ReplicationController) {
	return func(rc *v1.ReplicationController) {
		var replicas int32 = 1
		var grace int64 = 3
		rc.ObjectMeta = metav1.ObjectMeta{
			Namespace: s.LBJig.Namespace,
			Name:      s.LBJig.Name,
			Labels:    s.LBJig.Labels,
		}
		rc.Spec = v1.ReplicationControllerSpec{
			Replicas: &replicas,
			Selector: s.LBJig.Labels,
			Template: &v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: s.LBJig.Labels,
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:  "netexec",
							Image: imageutils.GetE2EImage(imageutils.Agnhost),
							Args: []string{
								"netexec",
								fmt.Sprintf("--http-port=%d", s.PodPort),
								fmt.Sprintf("--udp-port=%d", s.PodPort),
							},
							ReadinessProbe: &v1.Probe{
								PeriodSeconds: 3,
								ProbeHandler: v1.ProbeHandler{
									HTTPGet: &v1.HTTPGetAction{
										Port: intstr.FromInt(int(s.PodPort)),
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
			rc.Spec.Template.Spec.Affinity = &v1.Affinity{
				NodeAffinity: &v1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
						NodeSelectorTerms: []v1.NodeSelectorTerm{
							{
								MatchExpressions: []v1.NodeSelectorRequirement{
									{
										Key:      "kubernetes.io/hostname",
										Operator: v1.NodeSelectorOpIn,
										Values:   []string{nodeDiscovery.SingleWorker},
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

// getLBTargetCount verifies the number of registered targets for a given LBv2 DNS name matches the expected count.
// The steps includes:
// - Get Load Balancer ARN from DNS name extracted from service Status.LoadBalancer.Ingress[0].Hostname
// - List listeners for the load balancer
// - Get target groups attached to listeners
// - Count registered targets in target groups
// - Verify count matches number of worker nodes
func getLBTargetCount(ctx context.Context, lbDNSName string, expectedTargets int) error {
	// Load AWS config
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("unable to load AWS config: %v", err)
	}
	elbClient := elbv2.NewFromConfig(cfg)

	// Get Load Balancer ARN from DNS name
	describeLBs, err := elbClient.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{})
	if err != nil {
		return fmt.Errorf("failed to describe load balancers: %v", err)
	}
	var lbARN string
	for _, lb := range describeLBs.LoadBalancers {
		if strings.EqualFold(aws.ToString(lb.DNSName), lbDNSName) {
			lbARN = aws.ToString(lb.LoadBalancerArn)
			break
		}
	}
	if lbARN == "" {
		return fmt.Errorf("could not find LB with DNS name: %s", lbDNSName)
	}

	// List listeners for the load balancer
	listenersOut, err := elbClient.DescribeListeners(ctx, &elbv2.DescribeListenersInput{
		LoadBalancerArn: aws.String(lbARN),
	})
	if err != nil {
		return fmt.Errorf("failed to describe listeners: %v", err)
	}

	// Get target groups attached to listeners
	targetGroupARNs := map[string]struct{}{}
	for _, listener := range listenersOut.Listeners {
		if len(targetGroupARNs) > 0 {
			break
		}
		for _, action := range listener.DefaultActions {
			if action.TargetGroupArn != nil {
				targetGroupARNs[aws.ToString(action.TargetGroupArn)] = struct{}{}
				break
			}
		}
	}
	if len(targetGroupARNs) == 0 {
		return fmt.Errorf("no target groups found for LB: %s", lbARN)
	}

	// Count registered targets in target groups
	totalTargets := 0
	for tgARN := range targetGroupARNs {
		tgHealth, err := elbClient.DescribeTargetHealth(ctx, &elbv2.DescribeTargetHealthInput{
			TargetGroupArn: aws.String(tgARN),
		})
		if err != nil {
			return fmt.Errorf("failed to describe target health for TG %s: %v", tgARN, err)
		}
		totalTargets += len(tgHealth.TargetHealthDescriptions)
	}

	// Verify count matches number of worker nodes
	if totalTargets != expectedTargets {
		return fmt.Errorf("target count mismatch: expected %d, got %d", expectedTargets, totalTargets)
	}
	return nil
}

// discoverClusterWorkerNode identifies and selects worker nodes in the cluster based on predefined node label selectors.
// It returns a ClusterNodeDiscovery struct with the discovered information.
func discoverClusterWorkerNode(cs clientset.Interface) ClusterNodeDiscovery {
	var workerNodeList []string
	framework.Logf("discovering node label used in the kubernetes distributions")
	for _, selector := range lookupNodeSelectors {
		nodeList, err := cs.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{
			LabelSelector: selector,
		})
		framework.ExpectNoError(err, "failed to list worker nodes")
		if len(nodeList.Items) > 0 {
			for _, node := range nodeList.Items {
				workerNodeList = append(workerNodeList, node.Name)
			}
			// Save the first worker node in the list to be used in cases.
			sort.Strings(workerNodeList)
			return ClusterNodeDiscovery{
				Selector:     selector,
				Count:        len(nodeList.Items),
				SingleWorker: workerNodeList[0],
			}
		}
	}
	framework.ExpectNoError(fmt.Errorf("unable to find node selector for %v", lookupNodeSelectors))
	return ClusterNodeDiscovery{}
}

// inClusterTestReachableHTTP creates a pod within the cluster to test HTTP connectivity to a target IP and port.
// It schedules the pod on the specified node using node affinity to test the hairpin scenario.
// The pod uses a curl-based container to perform the HTTP request and validates the response.
// The function waits for the pod to complete its execution and inspects its exit code to determine success or failure.
//
// Parameters:
// - cs: Kubernetes clientset interface used to interact with the cluster.
// - namespace: The namespace in which the test pod will be created.
// - nodeName: The name of the node where the test pod should be scheduled.
// - target: The IP address or Hostname of the target HTTP server.
// - targetPort: The port number of the target HTTP server.
//
// Returns:
// - error: Returns an error if the pod creation, execution, or cleanup fails, or if the HTTP test fails unexpectedly.
//
// Behavior:
// - The function creates a pod with a curl-based container to perform the HTTP request.
// - It configures the pod to run as a non-root user with security settings.
// - The pod is scheduled on the specified node using node affinity.
// - Logs are periodically collected during the pod's execution for troubleshooting.
// - Events are inspected if the pod remains in a pending state for too long.
// - The function waits for the pod to complete and inspects its exit code to determine success or failure.
// - If the pod fails, an error is returned.
// - The pod is cleaned up after the test completes.
func inClusterTestReachableHTTP(cs clientset.Interface, namespace, nodeName, target string, targetPort int) error {
	podName := "http-test-pod"

	// client http test (curl) pod spec.
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:    "curl",
					Image:   imageutils.GetE2EImage(imageutils.Agnhost),
					Command: []string{"curl"},
					Args: []string{
						"--retry", "15", // Retry up to 15 times in case of transient network issues.
						"--retry-delay", "20", // Wait 20 seconds between retries.
						"--retry-max-time", "480", // Maximum time for retries is 480 seconds.
						"--retry-all-errors",                                                       // Retry on all errors, ensuring robustness against temporary failures.
						"--trace-time",                                                             // Include timestamps in trace output for debugging.
						"-w", "\\\"\\n---> HTTPCode=%{http_code} Time=%{time_total}ms <---\\n\\\"", // Format output to include HTTP code and response time.
						fmt.Sprintf("http://%s:%d/echo?msg=hello", target, targetPort),
					},
				},
			},
			SecurityContext: &v1.PodSecurityContext{
				RunAsNonRoot: aws.Bool(true),  // Ensures the pod runs as a non-root user for enhanced security.
				RunAsUser:    aws.Int64(1000), // Specifies the user ID for the container process.
				RunAsGroup:   aws.Int64(1000), // Specifies the group ID for the container process.
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
										Values:   []string{nodeName}, // Ensures the pod is scheduled on the specified node.
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
	_, err := cs.CoreV1().Pods(namespace).Create(context.TODO(), pod, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create HTTP test pod: %v", err)
	}
	// Clean up the pod
	defer func() {
		err = cs.CoreV1().Pods(namespace).Delete(context.TODO(), podName, metav1.DeleteOptions{})
		if err != nil {
			framework.Logf("Failed to delete pod %s: %v", podName, err)
		}
	}()

	// Pod logs wrapper. Collect recent logs, or all, from a test pod.
	gatherLogs := func(tail int) string {
		opts := &v1.PodLogOptions{}
		if tail == 0 {
			tail = 20
		}
		opts.TailLines = aws.Int64(int64(tail))
		logs, errL := cs.CoreV1().Pods(namespace).GetLogs(podName, opts).DoRaw(context.TODO())
		if errL != nil {
			framework.Logf("Failed to retrieve pod logs: %v", errL)
			return ""
		}
		return string(logs)
	}

	// Wait for the test pod to complete. Limit waiter be higher than curl retries.
	waitCount := 0
	pendingCount := 0
	err = wait.PollImmediate(15*time.Second, 15*time.Minute, func() (bool, error) {
		p, err := cs.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
		if err != nil {
			framework.Logf("Error getting pod %s: %v", podName, err)
			return false, err
		}
		framework.Logf("Pod %s status: Phase=%s", podName, p.Status.Phase)
		podFinished := p.Status.Phase == v1.PodSucceeded || p.Status.Phase == v1.PodFailed

		// Troubleshoot pending pods
		if p.Status.Phase == v1.PodPending {
			pendingCount++
		}
		if pendingCount%10 == 0 && pendingCount > 0 {
			framework.Logf("Pod %s is pending for too long, checking events...", podName)
			events, errE := cs.CoreV1().Events(namespace).List(context.TODO(), metav1.ListOptions{
				FieldSelector: fmt.Sprintf("involvedObject.name=%s", podName),
			})
			if errE != nil {
				framework.Logf("Failed to list events for pod %s: %v", podName, errE)
			} else {
				for _, event := range events.Items {
					framework.Logf("Event: %s - %s", event.Reason, event.Message)
				}
			}
		}
		// frequently collect logs.
		if waitCount > 0 && waitCount%4 == 0 {
			framework.Logf("Tail logs for HTTP test pod:\n%s", gatherLogs(5))
		}
		if podFinished {
			framework.Logf("Tail logs for HTTP test pod:\n%s", gatherLogs(0))
		}
		waitCount++
		return podFinished, nil
	})
	// Check overall error
	if err != nil {
		return fmt.Errorf("error waiting for pod %s to complete: %v", podName, err)
	}

	// Inspect the pod's container status for exit code
	pod, errS := cs.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if errS != nil {
		return fmt.Errorf("failed to get pod %s: %v", podName, errS)
	}
	if len(pod.Status.ContainerStatuses) == 0 {
		return fmt.Errorf("no container statuses found for pod %s", podName)
	}
	containerStatus := pod.Status.ContainerStatuses[0]

	if containerStatus.State.Terminated != nil {
		exitCode := containerStatus.State.Terminated.ExitCode
		if exitCode != 0 {
			errmsg := fmt.Errorf("pod %s exited with code %d", podName, exitCode)
			framework.Logf("WARNING: %s.", errmsg.Error())
			return errmsg
		}
	}

	// Validate HTTP response format
	// Expected format: HTTPCode=200 Time=<time>ms
	response := gatherLogs(0)
	if !strings.Contains(response, "HTTPCode=200") {
		errmsg := fmt.Errorf("HTTP response validation failed: HTTP response format must be HTTPCode=200")
		framework.Logf("WARNING: %s.", errmsg.Error())
		return errmsg
	}

	return nil
}
