/*
Copyright 2026 The Kubernetes Authors.

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
	"k8s.io/kubernetes/test/e2e/framework"
)

const (
	DefaultRetryTimeoutMinutes = 20
)

// E2ETestHelperAWS provides AWS API operations for e2e tests.
type E2ETestHelperAWS struct {
	retryer     *retry.Standard
	ec2Client   *ec2.Client
	elbClient   *elb.Client
	elbv2Client *elbv2.Client
}

// NewAWSHelper creates a new AWS helper with configured clients
func NewAWSHelper(ctx context.Context) (*E2ETestHelperAWS, error) {
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
		retryer:     customRetryer,
		ec2Client:   ec2.NewFromConfig(cfg, func(o *ec2.Options) { o.Retryer = customRetryer }),
		elbClient:   elb.NewFromConfig(cfg, func(o *elb.Options) { o.Retryer = customRetryer }),
		elbv2Client: elbv2.NewFromConfig(cfg, func(o *elbv2.Options) { o.Retryer = customRetryer }),
	}

	return h, nil
}

// GetEC2Client returns the EC2 client.
func (h *E2ETestHelperAWS) GetEC2Client() *ec2.Client {
	return h.ec2Client
}

// GetELBV2Client returns the ELBV2 client.
func (h *E2ETestHelperAWS) GetELBV2Client() *elbv2.Client {
	return h.elbv2Client
}

// GetLBTargets returns the targets for a given LB DNS name, listener port, and target port.
func (h *E2ETestHelperAWS) GetLBTargets(ctx context.Context, lbDNSName string, listenerPort, targetPort int32) ([]string, error) {
	foundLB, err := h.GetLoadBalancerFromDNSNameWithRetry(ctx, lbDNSName)
	if err != nil {
		return nil, fmt.Errorf("failed to get load balancer from DNS name: %v", err)
	}
	lbARN := aws.ToString(foundLB.LoadBalancerArn)

	listenersOut, err := h.elbv2Client.DescribeListeners(ctx, &elbv2.DescribeListenersInput{
		LoadBalancerArn: aws.String(lbARN),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe listeners: %v", err)
	}

	targetGroupARNs := map[string]struct{}{}
	for _, listener := range listenersOut.Listeners {
		if aws.ToInt32(listener.Port) == int32(listenerPort) {
			for _, action := range listener.DefaultActions {
				if action.TargetGroupArn != nil {
					targetGroupARNs[aws.ToString(action.TargetGroupArn)] = struct{}{}
					break
				}
			}
		}
	}
	if len(targetGroupARNs) == 0 {
		return nil, fmt.Errorf("no target groups found for LB: %s", lbARN)
	}

	targets := []string{}
	for tgARN := range targetGroupARNs {
		tgHealth, err := h.elbv2Client.DescribeTargetHealth(ctx, &elbv2.DescribeTargetHealthInput{
			TargetGroupArn: aws.String(tgARN),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe target health for TG %s: %v", tgARN, err)
		}
		for _, target := range tgHealth.TargetHealthDescriptions {
			if aws.ToInt32(target.Target.Port) == int32(targetPort) {
				targets = append(targets, aws.ToString(target.Target.Id))
			}
		}
	}
	return targets, nil
}

// GetLoadBalancerFromDNSName describes a load balancers filtered by DNS name.
func (h *E2ETestHelperAWS) GetLoadBalancerFromDNSName(ctx context.Context, lbDNSName string) (*elbv2types.LoadBalancer, error) {
	framework.Logf("describing load balancers with DNS %s", lbDNSName)

	paginator := elbv2.NewDescribeLoadBalancersPaginator(h.elbv2Client, &elbv2.DescribeLoadBalancersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe load balancers: %w", err)
		}

		framework.Logf("found %d load balancers in page", len(page.LoadBalancers))
		// Search for the load balancer with matching DNS name in this page
		for _, lb := range page.LoadBalancers {
			if aws.ToString(lb.DNSName) == lbDNSName {
				framework.Logf("found load balancer with DNS %s", aws.ToString(lb.DNSName))
				return &lb, nil
			}
		}
	}
	return nil, fmt.Errorf("no load balancer found with DNS name: %s", lbDNSName)
}

// GetLoadBalancerFromDNSNameWithTimeout describes a load balancers filtered by DNS name with retry using
// exponential backoff.
// AWS API
func (h *E2ETestHelperAWS) GetLoadBalancerFromDNSNameWithTimeout(ctx context.Context, lbDNSName string, timeout time.Duration) (*elbv2types.LoadBalancer, error) {
	var foundLB *elbv2types.LoadBalancer

	ctx, cancel := context.WithTimeout(ctx, timeout)
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
		foundLB, err = h.GetLoadBalancerFromDNSName(ctx, lbDNSName)
		if err != nil && h.retryer.IsErrorRetryable(err) {
			framework.Logf("transient error describing load balancers (will retry): %v", err)
			return false, nil
		}
		if err != nil {
			framework.Logf("permanent error describing load balancers: %v", err)
			return true, err
		}
		return true, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to find load balancer %s within timeout: %w", lbDNSName, err)
	}

	return foundLB, nil
}

// GetLoadBalancerFromDNSNameWithRetry describes a load balancers filtered by DNS name with
// default retry values.
// The default timeout is 20 minutes based on the AWS API limits and different regions
// where DNS propagation.
func (h *E2ETestHelperAWS) GetLoadBalancerFromDNSNameWithRetry(ctx context.Context, lbDNSName string) (*elbv2types.LoadBalancer, error) {
	return h.GetLoadBalancerFromDNSNameWithTimeout(ctx, lbDNSName, DefaultRetryTimeoutMinutes*time.Minute)
}
