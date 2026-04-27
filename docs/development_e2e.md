# E2E Test Development Guide

This guide covers advanced E2E test development, including the AWS helper interface, customization options, and testing patterns for different environments.

## Table of Contents

- [Overview](#overview)
- [AWS Helper Usage](#aws-helper-usage)
- [Environment Configuration](#environment-configuration)
- [Customizing Retry Behavior](#customizing-retry-behavior)
- [Testing Patterns](#testing-patterns)
- [Troubleshooting](#troubleshooting)

## Overview

The E2E test framework provides `E2ETestHelperAWS` for AWS operations. This design enables:

- **Environment-specific configuration** without code changes
- **Customization** for different deployment scenarios (CI, local, rate-limited)
- **Proper retry patterns** for API failures vs state convergence

## AWS Helper Usage

The `E2ETestHelperAWS` helper (defined in `tests/e2e/helper_aws.go`) provides AWS operations for E2E tests:

### Basic Usage

```go
// Create helper with defaults
helper, err := NewAWSHelper(ctx)
if err != nil {
    return err
}

// Find load balancer (retries with exponential backoff)
lb, err := helper.GetLoadBalancerFromDNSNameDefaultTimeout(ctx, "my-lb.elb.amazonaws.com")

// Wait for targets to register (fixed-interval polling)
targets, err := helper.WaitForLBTargets(ctx, "my-lb.elb.amazonaws.com", 80, 8080, 3, 3*time.Minute)
```

## Environment Configuration

### Load Balancer Timeout

The default timeout for load balancer operations is 20 minutes. Override via environment variable:

```bash
# For slow environments or cross-region DNS propagation
export E2E_LB_TIMEOUT_MINUTES=30
./e2e.test --ginkgo.focus="loadbalancer.*"

# For fast local testing
export E2E_LB_TIMEOUT_MINUTES=5
./e2e.test --ginkgo.focus="loadbalancer.*"
```

**When to adjust:**
- **Increase (30-45 min)**: Cross-region tests, slow DNS propagation, rate-limited environments
- **Decrease (5-10 min)**: Local development, fast CI environments, LocalStack/moto testing

### Example: CI Pipeline Configuration

```yaml
# .github/workflows/e2e.yml
- name: Run E2E tests
  env:
    E2E_LB_TIMEOUT_MINUTES: 25  # CI-specific timeout
  run: make test-e2e
```

## Customizing Retry Behavior

For environments with different characteristics, customize retry parameters:

### Rate-Limited Environments

```go
// Reduce retry attempts for shared test accounts
helper, err := NewAWSHelperWithOptions(ctx, E2ETestHelperAWSOptions{
    MaxAttempts: 5,           // Fewer attempts
    MaxBackoff:  10 * time.Second,  // Shorter backoff
})
```

### Local Testing (LocalStack/moto)

```go
// Fast retries for local AWS emulation
helper, err := NewAWSHelperWithOptions(ctx, E2ETestHelperAWSOptions{
    MaxAttempts: 3,
    MaxBackoff:  5 * time.Second,
})
```

### Aggressive CI Testing

```go
// Default settings (10 attempts, 30s backoff) work well
helper, err := NewAWSHelper(ctx)
```

## Testing Patterns

### Pattern 1: Load Balancer DNS Resolution

**Use Case**: Waiting for load balancer to be provisioned and DNS to propagate.

**Approach**: Exponential backoff (API retry pattern)

```go
// With custom timeout
lb, err := helper.GetLoadBalancerFromDNSNameWithBackoff(ctx, dnsName, 15*time.Minute)

// With environment-aware timeout
lb, err := helper.GetLoadBalancerFromDNSNameDefaultTimeout(ctx, dnsName)
```

### Pattern 2: Target Registration

**Use Case**: Waiting for EC2 instances to register and become healthy in target groups.

**Approach**: Fixed-interval polling (state convergence pattern)

**Why not exponential backoff?** Target registration is eventual consistency, not an API failure. Fixed intervals are standard for Kubernetes state polling.

```go
// Wait for minimum target count with 3-minute timeout
targets, err := helper.WaitForLBTargets(
    ctx,
    lbDNSName,
    80,    // listener port
    8080,  // target port
    3,     // minimum targets
    3*time.Minute,
)

framework.ExpectNoError(err)
gomega.Expect(len(targets)).To(gomega.BeNumerically(">=", 3))
```

**Polling Details:**
- **Interval**: 5 seconds (configurable via `DefaultTargetPollInterval`)
- **First poll**: Immediate (no initial delay)
- **Timeout**: Customizable (default 3 minutes)
- **Logging**: Progress logged every iteration

### Pattern 3: Immediate Check (No Retry)

**Use Case**: Verifying current state when retries aren't needed.

```go
// Single check, no retry
lb, err := helper.GetLoadBalancerFromDNSName(ctx, dnsName)
targets, err := helper.GetLBTargets(ctx, dnsName, 80, 8080)
```

### Pattern 4: Custom Timeout for Specific Tests

```go
// Short timeout for negative tests
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

lb, err := helper.GetLoadBalancerFromDNSNameWithBackoff(ctx, dnsName, 30*time.Second)
gomega.Expect(err).To(gomega.HaveOccurred()) // Expected to timeout
```

## Troubleshooting

### Tests Failing with Timeout Errors

**Symptom**: `failed to find load balancer within timeout`

**Solutions**:
1. Increase timeout via environment variable:
   ```bash
   export E2E_LB_TIMEOUT_MINUTES=30
   ```

2. Check AWS API rate limits:
   ```bash
   aws service-quotas get-service-quota \
     --service-code elasticloadbalancing \
     --quota-code L-53DA6B97
   ```

3. Verify DNS propagation:
   ```bash
   dig +short <lb-dns-name>
   ```

### Tests Failing with "No Targets Found"

**Symptom**: `expected 3 targets, got 0`

**Solution**: Use `WaitForLBTargets` instead of `GetLBTargets`:

```go
// ❌ WRONG - immediate check, targets may not be registered yet
targets, err := helper.GetLBTargets(ctx, dnsName, 80, 8080)
gomega.Expect(targets).To(gomega.HaveLen(3))

// ✅ CORRECT - wait for state convergence
targets, err := helper.WaitForLBTargets(ctx, dnsName, 80, 8080, 3, 3*time.Minute)
framework.ExpectNoError(err)
```

### Rate Limit Errors in Shared Accounts

**Symptom**: `Throttling: Rate exceeded` errors

**Solution**: Reduce retry aggressiveness:

```go
helper, err := NewAWSHelperWithOptions(ctx, E2ETestHelperAWSOptions{
    MaxAttempts: 5,
    MaxBackoff:  10 * time.Second,
})
```

### LocalStack/Moto Testing Issues

**Problem**: Tests hang with default 20-minute timeout

**Solution**: Set shorter timeout for local testing:

```bash
export E2E_LB_TIMEOUT_MINUTES=2
```

Or use custom options:

```go
helper, err := NewAWSHelperWithOptions(ctx, E2ETestHelperAWSOptions{
    MaxAttempts: 3,
    MaxBackoff:  5 * time.Second,
})
```

## Configuration Reference

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `E2E_LB_TIMEOUT_MINUTES` | 20 | Timeout for load balancer DNS resolution with retries |

### Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `DefaultRetryTimeoutMinutes` | 20 min | Default LB timeout (overridable by env var) |
| `DefaultRetryMaxAttempts` | 10 | Default AWS API retry attempts |
| `DefaultRetryMaxBackoff` | 30s | Default max backoff between retries |
| `DefaultTargetPollInterval` | 5s | Polling interval for target health checks |
| `DefaultTargetWaitTimeout` | 3 min | Default timeout for target registration |

### Helper Options

```go
type E2ETestHelperAWSOptions struct {
    MaxAttempts int           // AWS API retry attempts (default: 10)
    MaxBackoff  time.Duration // Max backoff between retries (default: 30s)
}
```

## Additional Resources

- [Main Development Guide](development.md) - General development setup and workflow
- [Kubernetes E2E Test Framework](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-testing/e2e-tests.md) - Upstream patterns
- [AWS SDK Retry Configuration](https://aws.github.io/aws-sdk-go-v2/docs/configuring-sdk/retries-timeouts/) - AWS SDK documentation
