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
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/framework"

	admissionapi "k8s.io/pod-security-admission/api"

	"github.com/aws/aws-sdk-go-v2/aws"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	e2eservice "k8s.io/kubernetes/test/e2e/framework/service"
)

const (
	annotationLBType                  = "service.beta.kubernetes.io/aws-load-balancer-type"
	annotationLBInternal              = "service.beta.kubernetes.io/aws-load-balancer-internal"
	annotationLBTargetNodeLabels      = "service.beta.kubernetes.io/aws-load-balancer-target-node-labels"
	annotationLBTargetGroupAttributes = "service.beta.kubernetes.io/aws-load-balancer-target-group-attributes"
)

var (
	// lookupNodeSelectors are valid compute/node/worker selectors commonly used in different kubernetes
	// distributions.
	lookupNodeSelectors = []string{
		"node-role.kubernetes.io/worker", // used in must distributions
		"node-role.kubernetes.io/node",   // used in ccm-aws CI
	}
)

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
		// Overall test case configuration.
		name             string
		resourceSuffix   string
		extraAnnotations map[string]string
		listenerCount    int

		// Hooks
		// HookPostServiceConfig hook runs after the service manifest is created, and before the service is created.
		hookPostServiceConfig func(cfg *E2ETestHelper)
		// HookPostServiceCreate hook runs after the test is run.
		hookPostServiceCreate func(cfg *E2ETestHelper)
		// HookPreTest hook runs before the test is run.
		hookPreTest func(cfg *E2ETestHelper)

		// Flags to override default test behavior.
		overrideTestRunInClusterReachableHTTP bool
		requireAffinity                       bool

		// Test verification
		skipTestFailure bool
	}
	cases := []loadBalancerTestCases{
		{
			name:             "CLB should be reachable with default configurations",
			resourceSuffix:   "",
			extraAnnotations: map[string]string{},
		},
		{
			name:             "NLB should be reachable with default configurations",
			resourceSuffix:   "nlb",
			extraAnnotations: map[string]string{annotationLBType: "nlb"},
		},
		{
			name:             "NLB should be reachable with target-node-labels",
			resourceSuffix:   "sg-nd",
			extraAnnotations: map[string]string{annotationLBType: "nlb"},
			hookPostServiceConfig: func(e2e *E2ETestHelper) {
				framework.Logf("running hook post-service-config patching service annotations to test node label selector")
				e2e.discoverClusterWorkerNode()
				if e2e.svc.Annotations == nil {
					e2e.svc.Annotations = map[string]string{}
				}
				e2e.svc.Annotations[annotationLBTargetNodeLabels] = e2e.nodeSelector
			},
			hookPostServiceCreate: func(cfg *E2ETestHelper) {
				framework.Logf("running hook post-service-create to validate the number of targets in the load balancer selected")
				if len(cfg.svc.Status.LoadBalancer.Ingress) == 0 {
					framework.Failf("No ingress found in LoadBalancer status for service %s/%s", cfg.svc.Namespace, cfg.svc.Name)
				}
				lbDNS := cfg.svc.Status.LoadBalancer.Ingress[0].Hostname
				// TODO expected lbDNS not empty
				// TODO expect awshelper not nil
				framework.ExpectNoError(cfg.GetAWSHelper().GetLBTargetCount(lbDNS, cfg.nodeCount), "AWS LB target count validation failed")
			},
		},
		// Hairpining traffic test for CLB.
		{
			name:           "CLB internal should be reachable with hairpinning traffic",
			resourceSuffix: "hp-clb-int",
			extraAnnotations: map[string]string{
				annotationLBInternal: "true",
			},
			hookPostServiceConfig: func(cfg *E2ETestHelper) {
				cfg.discoverClusterWorkerNode()
				framework.Logf("running hook post-service-config patching service annotations to enforce LB pins/selects target to a single node: kubernetes.io/hostname=%s", cfg.sampleNodeName)
				if cfg.svc.Annotations == nil {
					cfg.svc.Annotations = map[string]string{}
				}
				cfg.svc.Annotations[annotationLBTargetNodeLabels] = fmt.Sprintf("kubernetes.io/hostname=%s", cfg.sampleNodeName)
			},
			overrideTestRunInClusterReachableHTTP: true,
			requireAffinity:                       true,
		},
		// Hairpining traffic test for NLB.
		// The target type instance (default) sets the preserve client IP attribute to true,
		// the NLB target group attributes are set to preserve_client_ip.enabled=false to allow hairpining traffic.
		// The test also validates the target group attributes are set correctly to AWS resource.
		{
			name:           "NLB internal should be reachable with hairpinning traffic",
			resourceSuffix: "hp-nlb-int",
			extraAnnotations: map[string]string{
				annotationLBType:                  "nlb",
				annotationLBInternal:              "true",
				annotationLBTargetGroupAttributes: "preserve_client_ip.enabled=false",
			},
			listenerCount:                         1,
			overrideTestRunInClusterReachableHTTP: true,
			requireAffinity:                       true,
			hookPostServiceConfig: func(cfg *E2ETestHelper) {
				cfg.discoverClusterWorkerNode()
				framework.Logf("running hook post-service-config patching service annotations to enforce LB pins/selects target to a single node: kubernetes.io/hostname=%s", cfg.sampleNodeName)
				if cfg.svc.Annotations == nil {
					cfg.svc.Annotations = map[string]string{}
				}
				cfg.svc.Annotations[annotationLBTargetNodeLabels] = fmt.Sprintf("kubernetes.io/hostname=%s", cfg.sampleNodeName)
			},
			hookPreTest: func(e2e *E2ETestHelper) {
				framework.Logf("running hook pre-test: verify target group attributes are set correctly to AWS resource")

				if e2e.svc.Status.LoadBalancer.Ingress[0].Hostname == "" && e2e.svc.Status.LoadBalancer.Ingress[0].IP == "" {
					framework.Failf("LoadBalancer ingress is empty (no hostname or IP) for service %s/%s", e2e.svc.Namespace, e2e.svc.Name)
				}

				hostAddr := e2eservice.GetIngressPoint(&e2e.svc.Status.LoadBalancer.Ingress[0])
				framework.Logf("Load balancer's ingress address: %s", hostAddr)

				if hostAddr == "" {
					framework.Failf("Unable to get LoadBalancer ingress address for service %s/%s", e2e.svc.Namespace, e2e.svc.Name)
				}

				// DescribeLoadBalancers API doesn't support filtering by DNS name directly
				// Use AWS SDK paginator to search through all load balancers
				foundLB, err := e2e.GetAWSHelper().GetLoadBalancerFromDNSNameWithRetry(hostAddr, 10*time.Minute)
				if err != nil {
					e2e.GatherEventsOnFailure("Target Group Attributes Validation Failure")
					framework.Failf("failed to find load balancer with DNS name %s: %v", hostAddr, err)
				}
				if foundLB == nil {
					framework.Failf("Found load balancer is nil for DNS name %s", hostAddr)
				}

				lbARN := aws.ToString(foundLB.LoadBalancerArn)
				if lbARN == "" {
					framework.Failf("Load balancer ARN is empty for DNS name %s", hostAddr)
				}
				framework.Logf("Found load balancer: %s with ARN: %s", aws.ToString(foundLB.LoadBalancerName), lbARN)

				// lookup target group ARN from load balancer ARN
				targetGroups, err := e2e.GetAWSHelper().GetELBV2Client().DescribeTargetGroups(e2e.ctx, &elbv2.DescribeTargetGroupsInput{
					LoadBalancerArn: aws.String(lbARN),
				})
				framework.ExpectNoError(err, "failed to describe target groups")
				gomega.Expect(len(targetGroups.TargetGroups)).To(gomega.Equal(1))

				targetGroupAttributes, err := e2e.GetAWSHelper().GetELBV2Client().DescribeTargetGroupAttributes(e2e.ctx, &elbv2.DescribeTargetGroupAttributesInput{
					TargetGroupArn: aws.String(aws.ToString(targetGroups.TargetGroups[0].TargetGroupArn)),
				})
				framework.ExpectNoError(err, "failed to describe target group attributes")

				// verify if the target group attributes are set correctly

				annotationToDict := map[string]string{}
				for _, v := range strings.Split(e2e.svc.Annotations[annotationLBTargetGroupAttributes], ",") {
					parts := strings.Split(v, "=")
					annotationToDict[parts[0]] = parts[1]
				}
				framework.Logf("TG attribute Annotation to dict: %v", annotationToDict)

				framework.Logf("=== All Target Group Attributes from AWS ===")
				for _, attr := range targetGroupAttributes.Attributes {
					framework.Logf("  %s=%s", aws.ToString(attr.Key), aws.ToString(attr.Value))
				}

				framework.Logf("=== Expected Target Group Attributes from Annotation ===")
				for key, value := range annotationToDict {
					framework.Logf("  %s=%s", key, value)
				}

				// Check if our expected attributes are present and match
				framework.Logf("=== Verifying Target Group Attributes ===")
				for _, attr := range targetGroupAttributes.Attributes {
					if expectedValue, ok := annotationToDict[aws.ToString(attr.Key)]; ok {
						actualValue := aws.ToString(attr.Value)
						framework.Logf("Checking attribute: %s", aws.ToString(attr.Key))
						framework.Logf("  Expected: %s", expectedValue)
						framework.Logf("  Actual:   %s", actualValue)

						if actualValue != expectedValue {
							framework.Failf("Target group attribute mismatch for %s: expected %s, got %s", aws.ToString(attr.Key), expectedValue, actualValue)
						} else {
							framework.Logf("✓ Target group attribute %s matches expected value %s", aws.ToString(attr.Key), expectedValue)
						}
					}
				}
			},
		},
	}

	serviceNameBase := "lbconfig-test"
	for _, tc := range cases {
		It(tc.name, func(ctx context.Context) {
			By("setting up test environment and discovering worker nodes")
			framework.Logf("[SETUP] Test case: %s", tc.name)

			e2e, err := NewE2ETestHelper(context.TODO(), cs)
			framework.ExpectNoError(err, "failed to create AWS E2E test helper")
			defer e2e.cleanup()

			loadBalancerCreateTimeout := e2eservice.GetServiceLoadBalancerCreationTimeout(ctx, cs)
			framework.Logf("[CONFIG] AWS load balancer timeout: %s", loadBalancerCreateTimeout)

			By("building service configuration with annotations")
			serviceName := serviceNameBase
			if len(tc.resourceSuffix) > 0 {
				serviceName = serviceName + "-" + tc.resourceSuffix
			}
			framework.Logf("[CONFIG] Service name: %s, namespace: %s", serviceName, ns.Name)
			e2e.LBJig = e2eservice.NewTestJig(cs, ns.Name, serviceName)

			// Hook annotations to support dynamic config
			e2e.svc = e2e.buildService(tc.listenerCount, tc.extraAnnotations)
			framework.Logf("[CONFIG] Service ports: %d, extra annotations: %v", len(e2e.svc.Spec.Ports), tc.extraAnnotations)

			if tc.hookPostServiceConfig != nil {
				By("executing hook post-service-config: applying service configuration")
				framework.Logf("[HOOK] Executing post-service-config hook")
				tc.hookPostServiceConfig(e2e)
				framework.Logf("[HOOK] Final service annotations: %v", e2e.svc.Annotations)
			}

			By("creating LoadBalancer service in Kubernetes")
			if _, err := e2e.LBJig.Client.CoreV1().Services(e2e.LBJig.Namespace).Create(context.TODO(), e2e.svc, metav1.CreateOptions{}); err != nil {
				framework.ExpectNoError(fmt.Errorf("failed to create LoadBalancer Service %q: %v", e2e.svc.Name, err))
			}
			framework.Logf("[K8S] LoadBalancer service created successfully")

			By("waiting for AWS load balancer provisioning")
			e2e.svc, err = e2e.LBJig.WaitForLoadBalancer(ctx, loadBalancerCreateTimeout)
			// Collect comprehensive debugging information when LoadBalancer provisioning fails
			if err != nil {
				e2e.GatherEventsOnFailure("LoadBalancer Provisioning Failure")
				framework.ExpectNoError(err, "LoadBalancer provisioning failed - check failure logs")
			}
			framework.Logf("[AWS] Load balancer provisioned successfully")

			By("creating backend server pods")
			_, err = e2e.LBJig.Run(ctx, e2e.buildDeployment(tc.requireAffinity))
			if err != nil {
				e2e.GatherEventsOnFailure("Backend Pod Creation Failure")
				framework.ExpectNoError(err, "Backend pod creation failed - check failure logs")
			}

			framework.Logf("[K8S] Backend pods created, affinity required: %t", tc.requireAffinity)

			if tc.hookPostServiceCreate != nil {
				By("executing hook post-service-create: applying service configuration")
				tc.hookPostServiceCreate(e2e)
			}

			By("collecting service and load balancer information")
			if e2e.svc == nil {
				e2e.GatherEventsOnFailure("Service Validation Failure")
				framework.Failf("Service is nil after LoadBalancer provisioning for service %s", e2e.LBJig.Name)
			}
			if len(e2e.svc.Spec.Ports) == 0 {
				e2e.GatherEventsOnFailure("Service Ports Validation Failure")
				framework.Logf("Service spec: %+v", e2e.svc.Spec)
				framework.Failf("No ports found in service spec for service %s/%s", e2e.svc.Namespace, e2e.svc.Name)
			}
			if len(e2e.svc.Status.LoadBalancer.Ingress) == 0 {
				e2e.GatherEventsOnFailure("LoadBalancer Ingress Validation Failure")
				framework.Logf("Service status: %+v", e2e.svc.Status)
				framework.Failf("No ingress found in LoadBalancer status for service %s/%s", e2e.svc.Namespace, e2e.svc.Name)
			}

			svcPort := int(e2e.svc.Spec.Ports[0].Port)
			ingressAddress := e2eservice.GetIngressPoint(&e2e.svc.Status.LoadBalancer.Ingress[0])
			framework.Logf("[LB-INFO] Ingress address: %s, port: %d", ingressAddress, svcPort)

			if ingressAddress == "" {
				e2e.GatherEventsOnFailure("Empty Ingress Address Validation Failure")
				framework.Logf("LoadBalancer ingress[]: %+v", e2e.svc.Status.LoadBalancer.Ingress)
				framework.Failf("LoadBalancer ingress address is empty for service %s/%s", e2e.svc.Namespace, e2e.svc.Name)
			}

			if tc.hookPreTest != nil {
				By("executing pre-test hook")
				tc.hookPreTest(e2e)
			}

			// overrideTestRunInClusterReachableHTTP changes the default test function to run the client in the cluster.
			if tc.overrideTestRunInClusterReachableHTTP {
				By("testing HTTP connectivity for internal load balancer")
				if len(e2e.sampleNodeName) == 0 {
					e2e.discoverClusterWorkerNode()
				}
				if len(e2e.sampleNodeName) == 0 {
					framework.Failf("Unable to test hairpinning traffic: node is empty for service %s/%s", e2e.svc.Namespace, e2e.svc.Name)
				}

				framework.Logf("[TEST] Running internal connectivity test from node: %s", e2e.sampleNodeName)
				err := e2e.inClusterTestReachableHTTP(ingressAddress, svcPort)
				if err != nil && tc.skipTestFailure {
					Skip(err.Error())
				}
				framework.ExpectNoError(err, "Failed to test HTTP connectivity from internal network")
			} else {
				By("testing HTTP connectivity for external/internet-facing load balancer")
				framework.Logf("[TEST] Running external connectivity test to %s:%d", ingressAddress, svcPort)
				e2eservice.TestReachableHTTP(ctx, ingressAddress, svcPort, e2eservice.LoadBalancerLagTimeoutAWS)
			}
			framework.Logf("[TEST] HTTP connectivity test completed successfully")

			// Update the service to cluster IP
			By("cleaning up: converting service to ClusterIP")
			_, err = e2e.LBJig.UpdateService(ctx, func(s *v1.Service) {
				s.Spec.Type = v1.ServiceTypeClusterIP
			})
			framework.ExpectNoError(err, "Failed to update service to ClusterIP")

			// Wait for the load balancer to be destroyed asynchronously
			By("cleaning up: waiting for load balancer destruction")
			framework.Logf("[CLEANUP] Waiting for load balancer destruction")
			_, err = e2e.LBJig.WaitForLoadBalancerDestroy(ctx, ingressAddress, svcPort, loadBalancerCreateTimeout)
			framework.ExpectNoError(err, "Failed to wait for load balancer destruction")
			framework.Logf("[CLEANUP] Load balancer destroyed successfully")
		})
	}
})
