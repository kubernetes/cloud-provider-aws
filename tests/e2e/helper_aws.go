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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/framework"
)

// awsHelper provides AWS API operations for e2e tests
type E2ETestHelperAWS struct {
	ctx context.Context

	ec2Client   *ec2.Client
	elbClient   *elb.Client
	elbv2Client *elbv2.Client
}

// NewAWSHelper creates a new AWS helper with configured clients
func NewAWSHelper(ctx context.Context, cs clientset.Interface) (*E2ETestHelperAWS, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	framework.ExpectNoError(err, "unable to load AWS config")

	// Configure custom retryer to handle transient AWS API errors and credential failures.
	// AWS API limits for ELB are generous (400 TPS for DescribeLoadBalancers),
	// so aggressive retries are safe and necessary for CI stability.
	customRetryer := retry.NewStandard(func(o *retry.StandardOptions) {
		o.MaxAttempts = 10              // Handle IMDS timeouts and transient errors
		o.MaxBackoff = 30 * time.Second // Cap backoff to avoid excessive wait
	})

	// Create AWS clients with custom retryer
	h := &E2ETestHelperAWS{
		ctx:         ctx,
		ec2Client:   ec2.NewFromConfig(cfg, func(o *ec2.Options) { o.Retryer = customRetryer }),
		elbClient:   elb.NewFromConfig(cfg, func(o *elb.Options) { o.Retryer = customRetryer }),
		elbv2Client: elbv2.NewFromConfig(cfg, func(o *elbv2.Options) { o.Retryer = customRetryer }),
	}

	// framework.Logf("Discovering cluster tag")
	// framework.ExpectNoError(h.discoverClusterTag(cs), "unable to find cluster tag")
	// // framework.Logf("Cluster tag discovered: %s", h.clusterTag)

	return h, nil
}

func (h *E2ETestHelperAWS) GetEC2Client() *ec2.Client {
	return h.ec2Client
}

func (h *E2ETestHelperAWS) GetELBV2Client() *elbv2.Client {
	return h.elbv2Client
}

// // discoverClusterTag discovers the cluster tag from a cluster.
// // The discover is done by looking up the EC2 instance tags with tag:Name prefix kubernetes.io/cluster.
// // The EC2 Instance ID is discovered from a cluster node object.
// // The cluster ID, VPC ID and cluster tag are discovered from the EC2 instance tags.
// // If is any error is found, the function returns an error.
// func (h *E2ETestHelperAWS) discoverClusterTag(cs clientset.Interface) error {
// 	nodes, err := cs.CoreV1().Nodes().List(h.ctx, metav1.ListOptions{})
// 	if err != nil {
// 		return fmt.Errorf("failed to list nodes: %v", err)
// 	}

// 	var instanceID string
// 	for _, node := range nodes.Items {
// 		providerID := node.Spec.ProviderID
// 		if providerID == "" {
// 			continue
// 		}
// 		providerID = strings.Replace(providerID, "aws:///", "", 1)
// 		if len(strings.Split(providerID, "/")) < 2 {
// 			continue
// 		}
// 		// h.awsRegion = strings.Split(providerID, "/")[0]
// 		instanceID = strings.Split(providerID, "/")[1]
// 		if !strings.HasPrefix(instanceID, "i-") {
// 			continue
// 		}
// 		break
// 	}

// 	instance, err := h.ec2Client.DescribeInstances(h.ctx, &ec2.DescribeInstancesInput{
// 		InstanceIds: []string{instanceID},
// 	})
// 	if err != nil {
// 		return fmt.Errorf("failed to describe instances: %v", err)
// 	}

// 	clusterTagFound := false
// 	for _, reservation := range instance.Reservations {
// 		for _, tag := range reservation.Instances[0].Tags {
// 			if strings.HasPrefix(aws.ToString(tag.Key), "kubernetes.io/cluster") {
// 				// h.clusterTag = aws.ToString(tag.Key)
// 				// h.clusterTagValue = aws.ToString(tag.Value)
// 				clusterTagFound = true
// 				break
// 			}
// 		}
// 		if clusterTagFound {
// 			break
// 		}
// 	}

// 	if !clusterTagFound {
// 		return fmt.Errorf("cluster tag not found in the instance %s", instanceID)
// 	}

// 	// h.clusterName = strings.Split(h.clusterTag, "/")[2]
// 	// if h.clusterName == "" {
// 	// 	return fmt.Errorf("cluster name not found in the cluster tag %s", h.clusterTag)
// 	// }

// 	// extract VPC ID from the Instance
// 	// for _, networkInterface := range instance.Reservations[0].Instances[0].NetworkInterfaces {
// 	// 	h.vpcID = aws.ToString(networkInterface.VpcId)
// 	// 	break
// 	// }

// 	// if h.vpcID == "" {
// 	// 	return fmt.Errorf("VPC ID not found in the instance %s", instanceID)
// 	// }

// 	return nil
// }

// GetLBTargetCount verifies the number of registered targets for a given LBv2 DNS name matches the expected count.
// The steps includes:
// - Get Load Balancer ARN from DNS name extracted from service Status.LoadBalancer.Ingress[0].Hostname
// - List listeners for the load balancer
// - Get target groups attached to listeners
// - Count registered targets in target groups
// - Verify count matches number of worker nodes
func (h *E2ETestHelperAWS) GetLBTargetCount(lbDNSName string, expectedTargets int) error {
	// Get Load Balancer ARN from DNS name
	foundLB, err := h.GetLoadBalancerFromDNSNameWithRetry(lbDNSName, 10*time.Minute)
	if err != nil {
		return fmt.Errorf("failed to get load balancer from DNS name: %v", err)
	}
	lbARN := aws.ToString(foundLB.LoadBalancerArn)

	// List listeners for the load balancer
	listenersOut, err := h.elbv2Client.DescribeListeners(h.ctx, &elbv2.DescribeListenersInput{
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
		tgHealth, err := h.elbv2Client.DescribeTargetHealth(h.ctx, &elbv2.DescribeTargetHealthInput{
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

// GetLoadBalancerFromDNSName describes a load balancers filtered by DNS name.
func (h *E2ETestHelperAWS) GetLoadBalancerFromDNSName(lbDNSName string) (*elbv2types.LoadBalancer, error) {
	var foundLB *elbv2types.LoadBalancer
	framework.Logf("describing load balancers with DNS %s", lbDNSName)

	paginator := elbv2.NewDescribeLoadBalancersPaginator(h.elbv2Client, &elbv2.DescribeLoadBalancersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(h.ctx)
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

// GetLoadBalancerFromDNSNameWithRetry describes a load balancers filtered by DNS name with retry using
// exponential backoff.
func (h *E2ETestHelperAWS) GetLoadBalancerFromDNSNameWithRetry(lbDNSName string, timeout time.Duration) (*elbv2types.LoadBalancer, error) {
	var foundLB *elbv2types.LoadBalancer

	ctx, cancel := context.WithTimeout(h.ctx, timeout)
	defer cancel()

	backoff := wait.Backoff{
		Duration: 2 * time.Second, // Start slightly slower
		Factor:   2.0,
		Jitter:   0.1,
		Steps:    22, // Covers ~9.5 minutes
		Cap:      30 * time.Second,
	}

	err := wait.ExponentialBackoffWithContext(ctx, backoff, func(ctx context.Context) (bool, error) {
		var err error
		foundLB, err = h.GetLoadBalancerFromDNSName(lbDNSName)
		if err != nil {
			return false, nil
		}
		return true, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to find load balancer %s within timeout: %v", lbDNSName, err)
	}

	return foundLB, nil
}
