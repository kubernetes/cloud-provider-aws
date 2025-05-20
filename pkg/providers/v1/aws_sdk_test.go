package aws

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/stretchr/testify/assert"
	"k8s.io/cloud-provider-aws/pkg/providers/v1/config"
)

// Given an override, a custom endpoint should be used when making API requests
func TestComputeEndpointOverride(t *testing.T) {
	usedCustomEndpoint := false
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		usedCustomEndpoint = true
	}))

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
				Service:       "EC2",
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

	ec2Client, err := mockProvider.Compute(context.TODO(), "us-west-2")
	if err != nil {
		t.Errorf("error creating client, %v", err)
	}
	_, err = ec2Client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
	assert.True(t, usedCustomEndpoint == true, "custom endpoint was not used for EC2 Client")
}

// When a nonRetryableError is thrown, an API request should not be retried
func TestComputeNoRetry(t *testing.T) {
	attemptCount := 0
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("hit custom endpoint")
		attemptCount += 1
		// http code is a placeholder, error message is what's used by the retryer
		http.Error(w, nonRetryableError, http.StatusForbidden)
	}))

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
				Service:       "EC2",
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

	ec2Client, err := mockProvider.Compute(context.TODO(), "us-west-2")
	if err != nil {
		t.Errorf("error creating client, %v", err)
	}
	_, err = ec2Client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
	assert.True(t, attemptCount == 1, fmt.Sprintf("expected an attempt count of 1, got %d", attemptCount))
}

// When a retryable error is thrown, an API request should be retried
func TestComputeWithRetry(t *testing.T) {
	attemptCount := 0
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("hit custom endpoint")
		attemptCount += 1
		// Request timeouts are generally retried (https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/aws/retry)
		http.Error(w, "RequestTimeout", 500)
	}))

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
				Service:       "EC2",
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

	ec2Client, err := mockProvider.Compute(context.TODO(), "us-west-2")
	if err != nil {
		t.Errorf("error creating client, %v", err)
	}
	_, err = ec2Client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
	assert.True(t, attemptCount > 1, fmt.Sprintf("expected an attempt count >1, got %d", attemptCount))
}
