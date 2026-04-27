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
	"os"
	"strconv"
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
	// DefaultRetryTimeoutMinutes is the default timeout for load balancer DNS resolution with retries.
	// This can be overridden via the E2E_LB_TIMEOUT_MINUTES environment variable.
	DefaultRetryTimeoutMinutes = 20

	// DefaultRetryMaxAttempts is the default maximum number of retry attempts for AWS API calls.
	// This can be overridden via E2ETestHelperAWSOptions.
	DefaultRetryMaxAttempts = 10

	// DefaultRetryMaxBackoff is the default maximum backoff duration between retries.
	// This can be overridden via E2ETestHelperAWSOptions.
	DefaultRetryMaxBackoff = 30 * time.Second

	// DefaultTargetPollInterval is the default polling interval for target health checks.
	// Target registration is eventual consistency, so we use fixed-interval polling.
	DefaultTargetPollInterval = 5 * time.Second

	// DefaultTargetWaitTimeout is the default timeout for waiting for targets to register.
	// AWS target health checks typically complete within 30-90 seconds.
	DefaultTargetWaitTimeout = 3 * time.Minute

	// EnvLBTimeoutMinutes is the environment variable name for configuring LB timeout.
	EnvLBTimeoutMinutes = "E2E_LB_TIMEOUT_MINUTES"
)

// E2ETestHelperAWSOptions configures the behavior of E2ETestHelperAWS.
type E2ETestHelperAWSOptions struct {
	// MaxAttempts configures the maximum number of retry attempts for AWS API calls.
	// Default: DefaultRetryMaxAttempts (10)
	MaxAttempts int

	// MaxBackoff configures the maximum backoff duration between retries.
	// Default: DefaultRetryMaxBackoff (30 seconds)
	MaxBackoff time.Duration
}

// ApplyDefaults fills in default values for unset options.
func (o *E2ETestHelperAWSOptions) ApplyDefaults() {
	if o.MaxAttempts == 0 {
		o.MaxAttempts = DefaultRetryMaxAttempts
	}
	if o.MaxBackoff == 0 {
		o.MaxBackoff = DefaultRetryMaxBackoff
	}
}

// E2ETestHelperAWS provides AWS API operations for e2e tests.
// AWS SDK v2 clients are safe for concurrent use and do not require explicit cleanup.
// Context cancellation will terminate ongoing API calls.
type E2ETestHelperAWS struct {
	retryer     *retry.Standard
	ec2Client   *ec2.Client
	elbClient   *elb.Client
	elbv2Client *elbv2.Client
}

// NewAWSHelper creates a new AWS helper with configured clients using default options.
func NewAWSHelper(ctx context.Context) (*E2ETestHelperAWS, error) {
	return NewAWSHelperWithOptions(ctx, E2ETestHelperAWSOptions{})
}

// NewAWSHelperWithOptions creates a new AWS helper with custom retry configuration.
// Configure custom retryer to handle transient AWS API errors and credential failures.
// AWS API limits for ELB are generous (400 TPS for DescribeLoadBalancers),
// so aggressive retries are safe and necessary for CI stability.
//
// For rate-limited environments or shared test accounts, adjust MaxAttempts and MaxBackoff:
//
//	helper, err := NewAWSHelperWithOptions(ctx, E2ETestHelperAWSOptions{
//	    MaxAttempts: 5,
//	    MaxBackoff: 10 * time.Second,
//	})
func NewAWSHelperWithOptions(ctx context.Context, opts E2ETestHelperAWSOptions) (*E2ETestHelperAWS, error) {
	opts.ApplyDefaults()

	cfg, err := config.LoadDefaultConfig(ctx)
	framework.ExpectNoError(err, "unable to load AWS config")
	if err != nil {
		return nil, fmt.Errorf("unable to load AWS config: %w", err)
	}

	customRetryer := retry.NewStandard(func(o *retry.StandardOptions) {
		o.MaxAttempts = opts.MaxAttempts
		o.MaxBackoff = opts.MaxBackoff
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
// This performs a single check without retry. For waiting until targets are registered,
// use WaitForLBTargets instead.
func (h *E2ETestHelperAWS) GetLBTargets(ctx context.Context, lbDNSName string, listenerPort, targetPort int32) ([]string, error) {
	foundLB, err := h.GetLoadBalancerFromDNSNameDefaultTimeout(ctx, lbDNSName)
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

	framework.Logf("Found %d listeners for load balancer, checking for listener port %d", len(listenersOut.Listeners), int32(listenerPort))
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
	framework.Logf("Found %d target groups for listener", len(targetGroupARNs))
	if len(targetGroupARNs) == 0 {
		return nil, fmt.Errorf("no target groups found for LB: %s", lbARN)
	}

	targets := []string{}
	for tgARN := range targetGroupARNs {
		framework.Logf("Describing target group %s", tgARN)
		tgHealth, err := h.elbv2Client.DescribeTargetHealth(ctx, &elbv2.DescribeTargetHealthInput{
			TargetGroupArn: aws.String(tgARN),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe target health for TG %s: %v", tgARN, err)
		}
		framework.Logf("Found %d targets", len(tgHealth.TargetHealthDescriptions))
		for _, target := range tgHealth.TargetHealthDescriptions {
			targets = append(targets, aws.ToString(target.Target.Id))
		}
	}
	return targets, nil
}

// WaitForLBTargets polls until the specified load balancer has at least the expected number of targets.
// This uses fixed-interval polling (not exponential backoff) because target registration is
// eventual consistency, not an API failure scenario.
//
// AWS target registration typically takes 30-90 seconds for initial health checks.
// Uses 5-second polling interval as a balance between responsiveness and API call volume.
//
// Example:
//
//	// Wait up to 3 minutes for at least 3 targets to be registered
//	targets, err := helper.WaitForLBTargets(ctx, dnsName, 80, 8080, 3, 3*time.Minute)
func (h *E2ETestHelperAWS) WaitForLBTargets(ctx context.Context, lbDNSName string, listenerPort, targetPort int32, minTargets int, timeout time.Duration) ([]string, error) {
	var targets []string
	var lastErr error

	framework.Logf("Waiting for LB %s to have at least %d targets (timeout: %v) on port %d", lbDNSName, minTargets, timeout, listenerPort)

	// Use fixed-interval polling for state convergence (Kubernetes standard pattern)
	// Poll immediately first (true), then every 5 seconds
	err := wait.PollUntilContextTimeout(ctx, DefaultTargetPollInterval, timeout, true, func(ctx context.Context) (bool, error) {
		var err error
		targets, err = h.GetLBTargets(ctx, lbDNSName, listenerPort, targetPort)
		if err != nil {
			// Log but continue polling - target groups might not be ready yet
			framework.Logf("error getting LB targets (will retry): %v", err)
			lastErr = err
			return false, nil
		}

		framework.Logf("LB target status: found %d targets, waiting for at least %d", len(targets), minTargets)

		if len(targets) >= minTargets {
			framework.Logf("Target count satisfied: %d >= %d", len(targets), minTargets)
			return true, nil // Success
		}

		return false, nil // Keep polling
	})

	if err != nil {
		if lastErr != nil {
			return targets, fmt.Errorf("timed out waiting for %d targets (last error: %v): %w", minTargets, lastErr, err)
		}
		return targets, fmt.Errorf("timed out waiting for %d targets (got %d): %w", minTargets, len(targets), err)
	}

	return targets, nil
}

// GetLoadBalancerFromDNSName performs a single attempt to describe load balancers filtered by DNS name.
// For retry logic with exponential backoff, use GetLoadBalancerFromDNSNameWithBackoff.
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

// GetLoadBalancerFromDNSNameWithBackoff describes a load balancer filtered by DNS name with retry using
// exponential backoff and a custom timeout.
// Use this when you need control over the timeout duration for specific test scenarios.
func (h *E2ETestHelperAWS) GetLoadBalancerFromDNSNameWithBackoff(ctx context.Context, lbDNSName string, timeout time.Duration) (*elbv2types.LoadBalancer, error) {
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

// GetLoadBalancerFromDNSNameDefaultTimeout describes a load balancer filtered by DNS name with
// default retry configuration.
// The default timeout is 20 minutes (configurable via E2E_LB_TIMEOUT_MINUTES env var),
// based on AWS API limits and DNS propagation delays across different regions.
//
// Example: Override default timeout via environment variable:
//
//	export E2E_LB_TIMEOUT_MINUTES=30  # Use 30 minutes for slow environments
func (h *E2ETestHelperAWS) GetLoadBalancerFromDNSNameDefaultTimeout(ctx context.Context, lbDNSName string) (*elbv2types.LoadBalancer, error) {
	timeout := getDefaultLBTimeout()
	return h.GetLoadBalancerFromDNSNameWithBackoff(ctx, lbDNSName, timeout)
}

// getDefaultLBTimeout returns the default load balancer timeout.
// Checks E2E_LB_TIMEOUT_MINUTES environment variable first, falls back to DefaultRetryTimeoutMinutes.
func getDefaultLBTimeout() time.Duration {
	if timeoutStr := os.Getenv(EnvLBTimeoutMinutes); timeoutStr != "" {
		if timeoutMinutes, err := strconv.Atoi(timeoutStr); err == nil && timeoutMinutes > 0 {
			return time.Duration(timeoutMinutes) * time.Minute
		}
	}
	return DefaultRetryTimeoutMinutes * time.Minute
}

// Deprecated: GetLoadBalancerFromDNSNameWithRetry is deprecated.
// Use GetLoadBalancerFromDNSNameDefaultTimeout instead for clarity.
// This function will be removed in a future version.
func (h *E2ETestHelperAWS) GetLoadBalancerFromDNSNameWithRetry(ctx context.Context, lbDNSName string) (*elbv2types.LoadBalancer, error) {
	return h.GetLoadBalancerFromDNSNameDefaultTimeout(ctx, lbDNSName)
}
