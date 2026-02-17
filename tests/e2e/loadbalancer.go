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
	"github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
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
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"k8s.io/apimachinery/pkg/api/errors"
)

const (
	annotationLBType                  = "service.beta.kubernetes.io/aws-load-balancer-type"
	annotationLBInternal              = "service.beta.kubernetes.io/aws-load-balancer-internal"
	annotationLBTargetNodeLabels      = "service.beta.kubernetes.io/aws-load-balancer-target-node-labels"
	annotationLBTargetGroupAttributes = "service.beta.kubernetes.io/aws-load-balancer-target-group-attributes"
	annotationLBSecurityGroups        = "service.beta.kubernetes.io/aws-load-balancer-security-groups"
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
		hookPostServiceConfig func(cfg *e2eTestConfig)
		// HookPostServiceCreate hook runs after the test is run.
		hookPostServiceCreate func(cfg *e2eTestConfig)
		// HookPreTest hook runs before the test is run.
		hookPreTest func(cfg *e2eTestConfig)

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
			hookPostServiceConfig: func(cfg *e2eTestConfig) {
				framework.Logf("running hook post-service-config patching service annotations to test node label selector")
				if cfg.svc.Annotations == nil {
					cfg.svc.Annotations = map[string]string{}
				}
				cfg.svc.Annotations[annotationLBTargetNodeLabels] = cfg.nodeSelector
			},
			hookPostServiceCreate: func(cfg *e2eTestConfig) {
				framework.Logf("running hook post-service-create to validate the number of targets in the load balancer selected")
				if len(cfg.svc.Status.LoadBalancer.Ingress) == 0 {
					framework.Failf("No ingress found in LoadBalancer status for service %s/%s", cfg.svc.Namespace, cfg.svc.Name)
				}
				lbDNS := cfg.svc.Status.LoadBalancer.Ingress[0].Hostname
				framework.ExpectNoError(getLBTargetCount(cfg.ctx, lbDNS, cfg.nodeCount), "AWS LB target count validation failed")
			},
		},
		// Hairpining traffic test for CLB.
		{
			name:           "CLB internal should be reachable with hairpinning traffic",
			resourceSuffix: "hp-clb-int",
			extraAnnotations: map[string]string{
				annotationLBInternal: "true",
			},
			hookPostServiceConfig: func(cfg *e2eTestConfig) {
				framework.Logf("running hook post-service-config patching service annotations to enforce LB pins/selects target to a single node: kubernetes.io/hostname=%s", cfg.nodeSingleSample)
				if cfg.svc.Annotations == nil {
					cfg.svc.Annotations = map[string]string{}
				}
				cfg.svc.Annotations[annotationLBTargetNodeLabels] = fmt.Sprintf("kubernetes.io/hostname=%s", cfg.nodeSingleSample)
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
			hookPostServiceConfig: func(cfg *e2eTestConfig) {
				framework.Logf("running hook post-service-config patching service annotations to enforce LB pins/selects target to a single node: kubernetes.io/hostname=%s", cfg.nodeSingleSample)
				if cfg.svc.Annotations == nil {
					cfg.svc.Annotations = map[string]string{}
				}
				cfg.svc.Annotations[annotationLBTargetNodeLabels] = fmt.Sprintf("kubernetes.io/hostname=%s", cfg.nodeSingleSample)
			},
			hookPreTest: func(e2e *e2eTestConfig) {
				framework.Logf("running hook pre-test: verify target group attributes are set correctly to AWS resource")

				if e2e.svc.Status.LoadBalancer.Ingress[0].Hostname == "" && e2e.svc.Status.LoadBalancer.Ingress[0].IP == "" {
					framework.Failf("LoadBalancer ingress is empty (no hostname or IP) for service %s/%s", e2e.svc.Namespace, e2e.svc.Name)
				}

				hostAddr := e2eservice.GetIngressPoint(&e2e.svc.Status.LoadBalancer.Ingress[0])
				framework.Logf("Load balancer's ingress address: %s", hostAddr)

				if hostAddr == "" {
					framework.Failf("Unable to get LoadBalancer ingress address for service %s/%s", e2e.svc.Namespace, e2e.svc.Name)
				}

				elbClient, err := getAWSClientLoadBalancer(e2e.ctx)
				framework.ExpectNoError(err, "failed to create AWS ELB client")

				// DescribeLoadBalancers API doesn't support filtering by DNS name directly
				// Use AWS SDK paginator to search through all load balancers
				foundLB, err := getAWSLoadBalancerFromDNSName(e2e.ctx, elbClient, hostAddr)
				framework.ExpectNoError(err, "failed to find load balancer with DNS name %s", hostAddr)
				if foundLB == nil {
					framework.Failf("Found load balancer is nil for DNS name %s", hostAddr)
				}

				lbARN := aws.ToString(foundLB.LoadBalancerArn)
				if lbARN == "" {
					framework.Failf("Load balancer ARN is empty for DNS name %s", hostAddr)
				}
				framework.Logf("Found load balancer: %s with ARN: %s", aws.ToString(foundLB.LoadBalancerName), lbARN)

				// lookup target group ARN from load balancer ARN
				targetGroups, err := elbClient.DescribeTargetGroups(e2e.ctx, &elbv2.DescribeTargetGroupsInput{
					LoadBalancerArn: aws.String(lbARN),
				})
				framework.ExpectNoError(err, "failed to describe target groups")
				gomega.Expect(len(targetGroups.TargetGroups)).To(gomega.Equal(1))

				targetGroupAttributes, err := elbClient.DescribeTargetGroupAttributes(e2e.ctx, &elbv2.DescribeTargetGroupAttributesInput{
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
		// BYO Security Group tests.
		// The "CLB with managed security group mut update to BYO..." must  validate the features:
		// - existing Service CLB with managed SG have correct tags
		// - existing Service CLB with managed SG is updated to BYO SG (user-provided) through annotation
		// - controller removes the managed SG when BYO SG is applied
		// - load balancer is reachable after the update
		{
			name:           "CLB with managed Security Group must update to BYO Security Group",
			resourceSuffix: "clb-sg",
			listenerCount:  1,
			hookPreTest: func(cfg *e2eTestConfig) {
				framework.Logf("running hook post-service-config patching service annotation with BYO security group")
				isNLB := false
				lbDNS := cfg.svc.Status.LoadBalancer.Ingress[0].Hostname

				managedSecurityGroups, err := cfg.awsHelper.getLoadBalancerSecurityGroups(isNLB, lbDNS)
				framework.ExpectNoError(err, "Failed to get load balancer security groups")
				framework.Logf("Load balancer %s has security groups: %+v", lbDNS, managedSecurityGroups)

				for _, sgID := range managedSecurityGroups {
					managed, err := cfg.awsHelper.isSecurityGroupManaged(sgID)
					framework.ExpectNoError(err, fmt.Sprintf("Failed to check if security group %q is managed", sgID))
					if !managed {
						framework.Failf("Security group %q is not managed by the controller", sgID)
					}
				}

				securityGroupName := cfg.svc.Namespace + "-" + cfg.svc.Name + "-sg-byo"
				cfg.byoSecurityGroupID, err = cfg.awsHelper.createSecurityGroup(securityGroupName, fmt.Sprintf("BYO Security Group for e2e test service %s/%s", cfg.svc.Namespace, cfg.svc.Name))
				framework.ExpectNoError(err, "Failed to create BYO security group")

				// Currently controller does not update rules for BYO SG.
				// TODO: Verify if controller needs to update rules for BYO SG.
				framework.ExpectNoError(cfg.awsHelper.authorizeSecurityGroupToPorts(cfg.byoSecurityGroupID, cfg.svc.Spec.Ports), "Failed to authorize BYO security group to service ports")

				// Verify the rules were actually created
				framework.ExpectNoError(cfg.awsHelper.verifySecurityGroupRules(cfg.byoSecurityGroupID, cfg.svc.Spec.Ports), "Failed to verify BYO security group rules")

				framework.Logf("Patching Service %q with BYO SG %q", cfg.svc.Name, cfg.byoSecurityGroupID)
				cfg.svc.Annotations[annotationLBSecurityGroups] = cfg.byoSecurityGroupID
				newSvc, err := cfg.kubeClient.CoreV1().Services(cfg.LBJig.Namespace).Update(cfg.ctx, cfg.svc, metav1.UpdateOptions{})
				framework.ExpectNoError(err, "Failed to update Kubernetes Service")
				cfg.svc = newSvc

				time.Sleep(10 * time.Second)

				byoSecurityGroups, err := cfg.awsHelper.getLoadBalancerSecurityGroups(isNLB, lbDNS)
				framework.ExpectNoError(err, "Failed to get load balancer security groups")

				framework.Logf("Load balancer %s has security groups: %+v", lbDNS, byoSecurityGroups)
				for _, sgID := range byoSecurityGroups {
					if sgID == cfg.byoSecurityGroupID {
						break
					}
					framework.Failf("Load balancer %s has different security group than expected. Want=%q got=%q", lbDNS, cfg.byoSecurityGroupID, sgID)
				}

				framework.Logf("Checking if managed SGs were removed")
				for _, sgID := range managedSecurityGroups {
					sg, err := cfg.awsHelper.getSecurityGroup(sgID)
					if err != nil && strings.Contains(err.Error(), "InvalidGroup.NotFound") {
						framework.Logf("Managed security group %q removed", sgID)
						break
					}
					if sg != nil {
						framework.Failf("expected managed security group %q removed by controller, got %q", sgID, aws.ToString(sg.GroupId))
					}
					framework.Failf("managed security group %q was not removed by controller: %v", sgID, err)
				}
				framework.Logf("pre-test hook completed")
			},
		},
	}

	serviceNameBase := "lbconfig-test"
	for _, tc := range cases {
		It(tc.name, func(ctx context.Context) {
			By("setting up test environment and discovering worker nodes")
			e2e := newE2eTestConfig(cs)
			e2e.discoverClusterWorkerNode()
			defer e2e.cleanup()

			framework.Logf("[SETUP] Test case: %s", tc.name)
			framework.Logf("[SETUP] Worker nodes discovered: %d nodes, selector: %s, sample node: %s", e2e.nodeCount, e2e.nodeSelector, e2e.nodeSingleSample)

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
			var err error
			e2e.svc, err = e2e.LBJig.WaitForLoadBalancer(ctx, loadBalancerCreateTimeout)
			// Collect comprehensive debugging information when LoadBalancer provisioning fails
			if err != nil {
				serviceName := e2e.LBJig.Name
				if e2e.svc != nil {
					serviceName = e2e.svc.Name
				}
				framework.Logf("ERROR: LoadBalancer provisioning failed for service %q: %v", serviceName, err)
				framework.Logf("ERROR: LoadBalancer provisioning timeout reached after %v", loadBalancerCreateTimeout)

				// Ensure we have detailed debugging information before failing
				framework.Logf("=== LoadBalancer Provisioning Failure Debug Information ===")
				gatherEventosOnFailure(e2e.ctx, e2e.kubeClient, e2e.LBJig.Namespace, e2e.LBJig.Name)
				framework.Logf("=== End of LoadBalancer Provisioning Failure Debug Information ===")

				// Fail the test immediately to prevent further execution
				framework.ExpectNoError(err, "LoadBalancer provisioning failed - check debug information above")
			}
			framework.Logf("[AWS] Load balancer provisioned successfully")

			By("creating backend server pods")
			_, err = e2e.LBJig.Run(ctx, e2e.buildDeployment(tc.requireAffinity))
			if err != nil {
				serviceName := e2e.LBJig.Name
				if e2e.svc != nil {
					serviceName = e2e.svc.Name
				}
				framework.Logf("ERROR: LoadBalancer provisioning failed for service %q: %v", serviceName, err)
				framework.Logf("ERROR: LoadBalancer provisioning timeout reached after %v", loadBalancerCreateTimeout)

				// Ensure we have detailed debugging information before failing
				framework.Logf("=== LoadBalancer Provisioning Failure Debug Information ===")
				gatherEventosOnFailure(e2e.ctx, e2e.kubeClient, e2e.LBJig.Namespace, e2e.LBJig.Name)
				framework.Logf("=== End of LoadBalancer Provisioning Failure Debug Information ===")

				// Fail the test immediately to prevent further execution
				framework.ExpectNoError(err, "LoadBalancer provisioning failed - check debug information above")
			}

			framework.Logf("[K8S] Backend pods created, affinity required: %t", tc.requireAffinity)

			if tc.hookPostServiceCreate != nil {
				By("executing hook post-service-create: applying service configuration")
				tc.hookPostServiceCreate(e2e)
			}

			By("collecting service and load balancer information")
			if e2e.svc == nil {
				framework.Logf("=== Service Validation Error Debug Information ===")
				gatherEventosOnFailure(e2e.ctx, e2e.kubeClient, e2e.LBJig.Namespace, e2e.LBJig.Name)
				framework.Logf("=== End of Service Validation Error Debug Information ===")
				framework.Failf("Service is nil after LoadBalancer provisioning for service %s", e2e.LBJig.Name)
			}
			if len(e2e.svc.Spec.Ports) == 0 {
				framework.Logf("=== Service Ports Error Debug Information ===")
				framework.Logf("Service spec: %+v", e2e.svc.Spec)
				gatherEventosOnFailure(e2e.ctx, e2e.kubeClient, e2e.LBJig.Namespace, e2e.LBJig.Name)
				framework.Logf("=== End of Service Ports Error Debug Information ===")
				framework.Failf("No ports found in service spec for service %s/%s", e2e.svc.Namespace, e2e.svc.Name)
			}
			if len(e2e.svc.Status.LoadBalancer.Ingress) == 0 {
				framework.Logf("=== LoadBalancer Ingress Error Debug Information ===")
				framework.Logf("Service status: %+v", e2e.svc.Status)
				gatherEventosOnFailure(e2e.ctx, e2e.kubeClient, e2e.LBJig.Namespace, e2e.LBJig.Name)
				framework.Logf("=== End of LoadBalancer Ingress Error Debug Information ===")
				framework.Failf("No ingress found in LoadBalancer status for service %s/%s", e2e.svc.Namespace, e2e.svc.Name)
			}

			svcPort := int(e2e.svc.Spec.Ports[0].Port)
			ingressAddress := e2eservice.GetIngressPoint(&e2e.svc.Status.LoadBalancer.Ingress[0])
			framework.Logf("[LB-INFO] Ingress address: %s, port: %d", ingressAddress, svcPort)

			if ingressAddress == "" {
				framework.Logf("=== Empty Ingress Address Debug Information ===")
				framework.Logf("LoadBalancer ingress[0]: %+v", e2e.svc.Status.LoadBalancer.Ingress[0])
				gatherEventosOnFailure(e2e.ctx, e2e.kubeClient, e2e.LBJig.Namespace, e2e.LBJig.Name)
				framework.Logf("=== End of Empty Ingress Address Debug Information ===")
				framework.Failf("LoadBalancer ingress address is empty for service %s/%s", e2e.svc.Namespace, e2e.svc.Name)
			}

			if tc.hookPreTest != nil {
				By("executing pre-test hook")
				tc.hookPreTest(e2e)
			}

			// overrideTestRunInClusterReachableHTTP changes the default test function to run the client in the cluster.
			if tc.overrideTestRunInClusterReachableHTTP {
				By("testing HTTP connectivity for internal load balancer")
				framework.Logf("[TEST] Running internal connectivity test from node: %s", e2e.nodeSingleSample)
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

type e2eTestConfig struct {
	ctx        context.Context
	kubeClient clientset.Interface

	// AWS helper
	awsHelper *awsHelper

	byoSecurityGroupID string

	// service configuration
	cfgPortCount          int
	cfgPodPort            uint16
	cfgPodProtocol        v1.Protocol
	cfgDefaultAnnotations map[string]string
	LBJig                 *e2eservice.TestJig

	// service instance
	svc *v1.Service

	// node discovery
	nodeSelector     string
	nodeCount        int
	nodeSingleSample string
}

func newE2eTestConfig(cs clientset.Interface) *e2eTestConfig {
	// Create a context with a reasonable timeout for e2e tests
	// E2E tests can take several minutes for load balancer provisioning and configuration
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	_ = cancel // We'll let the test framework handle cleanup

	h, err := newAWSHelper(ctx, cs)
	framework.ExpectNoError(err, "Failed to create AWS helper")

	return &e2eTestConfig{
		kubeClient:     cs,
		cfgPortCount:   2,
		ctx:            ctx,
		cfgPodPort:     8080,
		cfgPodProtocol: v1.ProtocolTCP,
		cfgDefaultAnnotations: map[string]string{
			"aws-load-balancer-backend-protocol": "http",
			"aws-load-balancer-ssl-ports":        "https",
		},
		awsHelper: h,
	}
}

// buildService creates a service instance with custom annotations.
func (e2e *e2eTestConfig) buildService(portCount int, extraAnnotations map[string]string) *v1.Service {
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
			TargetPort: intstr.FromInt(int(e2e.cfgPodPort)),
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

// buildDeployment creates a deployment configuration to the network load balancer test framework.
// buildDeployment is based on newDTemplate() from the e2e test framework, which not provide
// customization to bind in non-privileged ports.
func (e2e *e2eTestConfig) buildDeployment(affinity bool) func(deployment *appsv1.Deployment) {
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
										Values:   []string{e2e.nodeSingleSample},
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

// discoverClusterWorkerNode identifies and selects worker nodes in the cluster based on predefined node label selectors.
// It returns a ClusterNodeDiscovery struct with the discovered information.
func (e2e *e2eTestConfig) discoverClusterWorkerNode() {
	var workerNodeList []string
	framework.Logf("discovering node label used in the kubernetes distributions")
	for _, selector := range lookupNodeSelectors {
		nodeList, err := e2e.kubeClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{
			LabelSelector: selector,
		})
		framework.ExpectNoError(err, "failed to list worker nodes")
		if len(nodeList.Items) > 0 {
			for _, node := range nodeList.Items {
				workerNodeList = append(workerNodeList, node.Name)
			}
			// Save the first worker node in the list to be used in cases.
			sort.Strings(workerNodeList)
			e2e.nodeCount = len(nodeList.Items)
			e2e.nodeSingleSample = workerNodeList[0]
			e2e.nodeSelector = selector
			return
		}
	}
	framework.ExpectNoError(fmt.Errorf("unable to find node selector for %v", lookupNodeSelectors))
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
	elbClient, err := getAWSClientLoadBalancer(ctx)
	if err != nil {
		return fmt.Errorf("unable to create AWS client: %v", err)
	}

	// Get Load Balancer ARN from DNS name
	foundLB, err := getAWSLoadBalancerFromDNSName(ctx, elbClient, lbDNSName)
	if err != nil {
		return fmt.Errorf("failed to get load balancer from DNS name: %v", err)
	}
	lbARN := aws.ToString(foundLB.LoadBalancerArn)

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

// AWS helpers
func getAWSClientLoadBalancer(ctx context.Context) (*elbv2.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to load AWS config: %v", err)
	}
	return elbv2.NewFromConfig(cfg), nil
}

func getAWSLoadBalancerFromDNSName(ctx context.Context, elbClient *elbv2.Client, lbDNSName string) (*elbv2types.LoadBalancer, error) {
	var foundLB *elbv2types.LoadBalancer
	framework.Logf("describing load balancers with DNS %s", lbDNSName)

	paginator := elbv2.NewDescribeLoadBalancersPaginator(elbClient, &elbv2.DescribeLoadBalancersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe load balancers: %v", err)
		}

		framework.Logf("found %d load balancers in page", len(page.LoadBalancers))
		// Search for the load balancer with matching DNS name in this page
		for i := range page.LoadBalancers {
			if aws.ToString(page.LoadBalancers[i].DNSName) == lbDNSName {
				foundLB = &page.LoadBalancers[i]
				framework.Logf("found load balancer with DNS %s", aws.ToString(foundLB.DNSName))
				break
			}
		}
		if foundLB != nil {
			break
		}
	}

	if foundLB == nil {
		return nil, fmt.Errorf("no load balancer found with DNS name: %s", lbDNSName)
	}

	return foundLB, nil
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
func (e2e *e2eTestConfig) inClusterTestReachableHTTP(target string, targetPort int) error {
	podName := "http-test-pod"

	// Enhanced curl configuration for better resilience
	// Total timeout calculation: 30 retries * 30s delay + 15min curl max time = ~25 minutes
	// This aligns with the 25-minute polling timeout below
	curlArgs := []string{
		"--retry", "30", // Increase retries for new LBs
		"--retry-delay", "30", // Longer delay for DNS propagation
		"--retry-max-time", "900", // 15 minutes max for curl operations
		"--retry-all-errors",      // Retry on all errors including DNS
		"--retry-connrefused",     // Explicitly retry connection refused
		"--connect-timeout", "30", // 30s connection timeout
		"--max-time", "45", // 45s per individual request
		"--trace-time", // Include timestamps for debugging
		"--verbose",    // More detailed output for troubleshooting
		"-w", "\"\\nCURL_SUMMARY: HTTPCode=%{http_code} Time=%{time_total}s ConnectTime=%{time_connect}s DNSTime=%{time_namelookup}s\\n\"",
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
										Values:   []string{e2e.nodeSingleSample},
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
	_, err := e2e.kubeClient.CoreV1().Pods(e2e.svc.Namespace).Create(e2e.ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create HTTP test pod: %v", err)
	}
	// Clean up the pod
	defer func() {
		err = e2e.kubeClient.CoreV1().Pods(e2e.svc.Namespace).Delete(e2e.ctx, podName, metav1.DeleteOptions{})
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

	err = wait.PollUntilContextTimeout(e2e.ctx, 15*time.Second, podPollingTimeout, true, func(ctx context.Context) (bool, error) {
		p, err := e2e.kubeClient.CoreV1().Pods(e2e.svc.Namespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			consecutiveErrorCount++
			framework.Logf("Error getting pod %s (attempt %d/%d): %v", podName, consecutiveErrorCount, maxConsecutiveErrors, err)

			// Debugging information for CI troubleshooting
			if consecutiveErrorCount == 1 {
				framework.Logf("=== CI Environment Debug Info ===")
				framework.Logf("Namespace: %s, PodName: %s, NodeName: %s", e2e.svc.Namespace, podName, e2e.nodeSingleSample)
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
			framework.Logf("Recent logs from failed pod:\n%s", gatherPodLogs(e2e, podName, 50))
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
			framework.Logf("Tail logs for HTTP test pod:\n%s", gatherPodLogs(e2e, podName, 5))
		}
		if podFinished {
			framework.Logf("Tail logs for HTTP test pod:\n%s", gatherPodLogs(e2e, podName, 0))
		}
		waitCount++
		return podFinished, nil
	})
	if err != nil {
		return fmt.Errorf("error waiting for pod %s to complete: %v", podName, err)
	}

	// Inspect the pod's container status for exit code
	pod, errS := e2e.kubeClient.CoreV1().Pods(e2e.svc.Namespace).Get(e2e.ctx, podName, metav1.GetOptions{})
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

			finalLogs := gatherPodLogs(e2e, podName, 0)
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
	response := gatherPodLogs(e2e, podName, 0)
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
func gatherResourceEvents(ctx context.Context, cs clientset.Interface, namespace, resourceName string) {
	framework.Logf("=== Collecting resource events for debugging ===")
	events, err := cs.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{
		FieldSelector: "involvedObject.name=" + resourceName,
	})
	if err != nil {
		framework.Logf("Error getting events for resource %q: %v", resourceName, err)
	} else {
		framework.Logf("Resource events for %q:", resourceName)
		for _, event := range events.Items {
			framework.Logf("  [%s] %s/%s: %s - %s", event.Type, event.Reason, event.InvolvedObject.Name, event.Message, event.FirstTimestamp)
		}
	}
}

func gatherAllEvents(ctx context.Context, cs clientset.Interface, namespace string) {
	framework.Logf("=== Collecting all namespace events ===")
	allEvents, err := cs.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		framework.Logf("Error getting all namespace events: %v", err)
	} else {
		framework.Logf("All events in namespace %q:", namespace)
		for _, event := range allEvents.Items {
			if strings.Contains(event.Message, "loadbalancer") || strings.Contains(event.Message, "LoadBalancer") ||
				strings.Contains(event.Reason, "LoadBalancer") || strings.Contains(event.Source.Component, "cloud-controller-manager") {
				framework.Logf("  [%s] %s/%s/%s: %s - %s", event.Type, event.Source.Component, event.Reason, event.InvolvedObject.Name, event.Message, event.FirstTimestamp)
			}
		}
	}
}

func gatherControllerLogs(ctx context.Context, cs clientset.Interface) {
	framework.Logf("=== Collecting cloud controller manager logs ===")
	ccmPods, err := cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{
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
			logs, err1 := cs.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, logOpts).DoRaw(ctx)
			if err1 != nil {
				framework.Logf("Error getting logs for CCM pod %s/%s: %v", pod.Namespace, pod.Name, err)
			} else {
				framework.Logf("Recent logs from CCM pod %s/%s:", pod.Namespace, pod.Name)
				framework.Logf("%s", string(logs))
			}
		}
	}
}

func gatherServiceStatus(ctx context.Context, cs clientset.Interface, namespace, resourceName string) {
	framework.Logf("=== Service Status ===")
	currentSvc, err := cs.CoreV1().Services(namespace).Get(ctx, resourceName, metav1.GetOptions{})
	if err != nil {
		framework.Logf("Error getting current service status: %v", err)
	} else {
		framework.Logf("Service %s status:", currentSvc.Name)
		framework.Logf("  Annotations: %+v", currentSvc.Annotations)
		framework.Logf("  LoadBalancer status: %+v", currentSvc.Status.LoadBalancer)
		framework.Logf("  Conditions: %+v", currentSvc.Status.Conditions)
	}
}

func gatherEventosOnFailure(ctx context.Context, cs clientset.Interface, namespace, resourceName string) {
	gatherResourceEvents(ctx, cs, namespace, resourceName)
	gatherAllEvents(ctx, cs, namespace)
	gatherControllerLogs(ctx, cs)
	gatherServiceStatus(ctx, cs, namespace, resourceName)
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
func gatherPodLogs(e2e *e2eTestConfig, podName string, tail int) string {
	opts := &v1.PodLogOptions{}
	if tail == 0 {
		tail = 20
	}
	opts.TailLines = aws.Int64(int64(tail))

	// Try multiple approaches to get logs
	logs, errL := e2e.kubeClient.CoreV1().Pods(e2e.svc.Namespace).GetLogs(podName, opts).DoRaw(e2e.ctx)
	if errL != nil {
		framework.Logf("Failed to retrieve pod logs (attempt 1): %v", errL)

		// Try without tail limit if that was the issue
		opts.TailLines = nil
		logs, errL = e2e.kubeClient.CoreV1().Pods(e2e.svc.Namespace).GetLogs(podName, opts).DoRaw(e2e.ctx)
		if errL != nil {
			framework.Logf("Failed to retrieve pod logs (attempt 2, no tail): %v", errL)

			// Try with different container if multi-container pod
			opts.Container = "curl"
			logs, errL = e2e.kubeClient.CoreV1().Pods(e2e.svc.Namespace).GetLogs(podName, opts).DoRaw(e2e.ctx)
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
