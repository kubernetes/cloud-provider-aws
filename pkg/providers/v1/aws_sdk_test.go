package aws

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"

	"github.com/stretchr/testify/assert"
	"k8s.io/cloud-provider-aws/pkg/providers/v1/config"
)

// Given an override, a custom endpoint should be used when making API requests
func TestClientsEndpointOverride(t *testing.T) {
	usedCustomEndpoint := false
	// Dummy server that sets usedCustomEndpoint when called
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		usedCustomEndpoint = true
	}))

	// Pass in the test server URL through a CloudConfig, which is used by each client's custom endpoint
	// resolver to override the URL for a request (see EC2Resolver.ResolveEndpoint for an example)
	cfgWithServiceOverride := config.CloudConfig{
		ServiceOverride: map[string]*struct {
			Service       string
			Region        string
			URL           string
			SigningRegion string
			SigningMethod string
			SigningName   string
		}{
			"1": {
				Service:       ec2.ServiceID,
				Region:        "us-west-2",
				URL:           testServer.URL,
				SigningRegion: "signingRegion",
				SigningName:   "signingName",
			},
			"2": {
				Service:       elb.ServiceID,
				Region:        "us-west-2",
				URL:           testServer.URL,
				SigningRegion: "signingRegion",
				SigningName:   "signingName",
			},
			"3": {
				Service:       elbv2.ServiceID,
				Region:        "us-west-2",
				URL:           testServer.URL,
				SigningRegion: "signingRegion",
				SigningName:   "signingName",
			},
		},
	}
	mockProvider := &awsSDKProvider{
		cfg:            &cfgWithServiceOverride,
		regionDelayers: make(map[string]*CrossRequestRetryDelay),
	}

	// EC2 Client
	ec2Client, err := mockProvider.Compute(context.TODO(), "us-west-2", nil)
	if err != nil {
		t.Errorf("error creating client, %v", err)
	}
	_, err = ec2Client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
	assert.True(t, usedCustomEndpoint == true, "custom endpoint was not used for EC2 Client")

	usedCustomEndpoint = false // reset boolean flag for next request
	elbClient, err := mockProvider.LoadBalancing(context.TODO(), "us-west-2", nil)
	if err != nil {
		t.Errorf("error creating client, %v", err)
	}
	_, err = elbClient.DescribeLoadBalancers(context.TODO(), &elb.DescribeLoadBalancersInput{})
	assert.True(t, usedCustomEndpoint == true, "custom endpoint was not used for ELB Client")

	usedCustomEndpoint = false
	elbv2Client, err := mockProvider.LoadBalancingV2(context.TODO(), "us-west-2", nil)
	if err != nil {
		t.Errorf("error creating client, %v", err)
	}
	_, err = elbv2Client.DescribeLoadBalancers(context.TODO(), &elbv2.DescribeLoadBalancersInput{})
	assert.True(t, usedCustomEndpoint == true, "custom endpoint was not used for ELBV2 Client")
}

// Test whether SDK clients refrain from retrying an API request when given a nonRetryableError.
func TestClientsNoRetry(t *testing.T) {
	attemptCount := 0
	// Dummy server that counts attempts and returns a nonRetryableError
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusBadRequest)

		// Insert the nonRetryableError error message
		errorXML := fmt.Sprintf(`
			<Response>
			<Errors>
				<Error>
				<Code>%d</Code>
				<Message>%s</Message>
				</Error>
			</Errors>
			<RequestID>12345678-1234-1234-1234-123456789012</RequestID>
			</Response>`, http.StatusBadRequest, nonRetryableError)

		w.Write([]byte(errorXML))
	}))
	defer testServer.Close()

	// Override service endpoints with dummy server URL
	cfgWithServiceOverride := config.CloudConfig{
		ServiceOverride: map[string]*struct {
			Service       string
			Region        string
			URL           string
			SigningRegion string
			SigningMethod string
			SigningName   string
		}{
			"1": {
				Service:       ec2.ServiceID,
				Region:        "us-west-2",
				URL:           testServer.URL,
				SigningRegion: "signingRegion",
				SigningName:   "signingName",
			},
			"2": {
				Service:       elb.ServiceID,
				Region:        "us-west-2",
				URL:           testServer.URL,
				SigningRegion: "signingRegion",
				SigningName:   "signingName",
			},
			"3": {
				Service:       elbv2.ServiceID,
				Region:        "us-west-2",
				URL:           testServer.URL,
				SigningRegion: "signingRegion",
				SigningName:   "signingName",
			},
		},
	}
	mockProvider := &awsSDKProvider{
		cfg:            &cfgWithServiceOverride,
		regionDelayers: make(map[string]*CrossRequestRetryDelay),
	}

	// EC2 Client
	ec2Client, err := mockProvider.Compute(context.TODO(), "us-west-2", nil)
	if err != nil {
		t.Errorf("error creating client, %v", err)
	}
	_, err = ec2Client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
	// Ensure that only 1 attempt was made, signifying no retries
	assert.True(t, attemptCount == 1, fmt.Sprintf("expected an attempt count of 1 for EC2 client, got %d", attemptCount))

	// ELB Client
	attemptCount = 0 // reset attempt count for next request
	elbClient, err := mockProvider.LoadBalancing(context.TODO(), "us-west-2", nil)
	if err != nil {
		t.Errorf("error creating client, %v", err)
	}
	_, err = elbClient.DescribeLoadBalancers(context.TODO(), &elb.DescribeLoadBalancersInput{})
	assert.True(t, attemptCount == 1, fmt.Sprintf("expected an attempt count of 1 for ELB client, got %d", attemptCount))

	// ELBV2 Client
	attemptCount = 0
	elbv2Client, err := mockProvider.LoadBalancingV2(context.TODO(), "us-west-2", nil)
	if err != nil {
		t.Errorf("error creating client, %v", err)
	}
	_, err = elbv2Client.DescribeLoadBalancers(context.TODO(), &elbv2.DescribeLoadBalancersInput{})
	assert.True(t, attemptCount == 1, fmt.Sprintf("expected an attempt count of 1 for ELBV2 client, got %d", attemptCount))
}

// Test whether SDK clients retry an API request when given a retryable error code.
func TestClientsWithRetry(t *testing.T) {
	attemptCount := 0
	// Dummy server that counts attempts and returns a retryable error
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		// 500 status codes are retried by SDK (see https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/aws/retry)
		http.Error(w, "RequestTimeout", 500)
	}))

	// Override service endpoints with dummy server URL
	cfgWithServiceOverride := config.CloudConfig{
		ServiceOverride: map[string]*struct {
			Service       string
			Region        string
			URL           string
			SigningRegion string
			SigningMethod string
			SigningName   string
		}{
			"1": {
				Service:       ec2.ServiceID,
				Region:        "us-west-2",
				URL:           testServer.URL,
				SigningRegion: "signingRegion",
				SigningName:   "signingName",
			},
			"2": {
				Service:       elb.ServiceID,
				Region:        "us-west-2",
				URL:           testServer.URL,
				SigningRegion: "signingRegion",
				SigningName:   "signingName",
			},
			"3": {
				Service:       elbv2.ServiceID,
				Region:        "us-west-2",
				URL:           testServer.URL,
				SigningRegion: "signingRegion",
				SigningName:   "signingName",
			},
		},
	}
	mockProvider := &awsSDKProvider{
		cfg:            &cfgWithServiceOverride,
		regionDelayers: make(map[string]*CrossRequestRetryDelay),
	}

	// EC2 Client
	ec2Client, err := mockProvider.Compute(context.TODO(), "us-west-2", nil)
	if err != nil {
		t.Errorf("error creating client, %v", err)
	}
	_, err = ec2Client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
	// Ensure that more than 1 attempt was made, signifying retries
	assert.True(t, attemptCount > 1, fmt.Sprintf("expected an attempt count of >1 for EC2 client, got %d", attemptCount))

	// ELB Client
	attemptCount = 0 // Reset the attempt count before the next request
	elbClient, err := mockProvider.LoadBalancing(context.TODO(), "us-west-2", nil)
	if err != nil {
		t.Errorf("error creating client, %v", err)
	}
	_, err = elbClient.DescribeLoadBalancers(context.TODO(), &elb.DescribeLoadBalancersInput{})
	assert.True(t, attemptCount > 1, fmt.Sprintf("expected an attempt count of >1 for ELB client, got %d", attemptCount))

	// ELBV2 Client
	attemptCount = 0
	elbv2Client, err := mockProvider.LoadBalancingV2(context.TODO(), "us-west-2", nil)
	if err != nil {
		t.Errorf("error creating client, %v", err)
	}
	_, err = elbv2Client.DescribeLoadBalancers(context.TODO(), &elbv2.DescribeLoadBalancersInput{})
	assert.True(t, attemptCount > 1, fmt.Sprintf("expected an attempt count of >1 for ELB client, got %d", attemptCount))
}
