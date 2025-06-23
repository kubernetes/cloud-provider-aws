package aws

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/stretchr/testify/assert"
	"k8s.io/cloud-provider-aws/pkg/providers/v1/config"
)

type requestInfo struct {
	usedCustomEndpoint bool
	credential         string
}

// Given an override, a custom endpoint should be used when making API requests
func TestClientsEndpointOverride(t *testing.T) {
	reqInfo := requestInfo{} // stores information about requests, should be reset between API calls
	// Dummy server that sets usedCustomEndpoint when called, and collects information about the request
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqInfo.usedCustomEndpoint = true
		// Extract credential from auth header
		auth := r.Header.Get("Authorization")
		credRe := regexp.MustCompile(`Credential=([^,]+)`)
		credMatch := credRe.FindStringSubmatch(auth)
		if len(credMatch) == 2 { // true when it's able to find exactly one match for the Credential header
			reqInfo.credential = credMatch[1]
		}
	}))
	defer testServer.Close()

	// Clients should be able to have their default signing region and name overridden
	t.Run("With overridden URL, signing region, and signing name", func(t *testing.T) {
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
					SigningRegion: "custom-region",
					SigningName:   "custom-service",
				},
				"2": {
					Service:       elb.ServiceID,
					Region:        "us-west-2",
					URL:           testServer.URL,
					SigningRegion: "custom-region",
					SigningName:   "custom-service",
				},
				"3": {
					Service:       elbv2.ServiceID,
					Region:        "us-west-2",
					URL:           testServer.URL,
					SigningRegion: "custom-region",
					SigningName:   "custom-service",
				},
				"4": {
					Service:       kms.ServiceID,
					Region:        "us-west-2",
					URL:           testServer.URL,
					SigningRegion: "custom-region",
					SigningName:   "custom-service",
				},
			},
		}
		mockProvider := &awsSDKProvider{
			cfg:            &cfgWithServiceOverride,
			regionDelayers: make(map[string]*CrossRequestRetryDelay),
		}

		// Test EC2 client
		ec2Client, err := mockProvider.Compute(context.TODO(), "us-west-2", nil)
		if err != nil {
			t.Errorf("error creating EC2 client, %v", err)
		}
		_, err = ec2Client.DescribeVpcs(context.TODO(), &ec2.DescribeVpcsInput{})
		assert.True(t, reqInfo.usedCustomEndpoint, "EC2: custom endpoint was not used")
		assert.True(t, strings.Contains(reqInfo.credential, "custom-service"), "EC2: signing name was not properly overridden")
		assert.True(t, strings.Contains(reqInfo.credential, "custom-region"), "EC2: signing region was not properly overridden")

		// Test ELB client
		reqInfo = requestInfo{}
		elbClient, err := mockProvider.LoadBalancing(context.TODO(), "us-west-2", nil)
		if err != nil {
			t.Errorf("error creating ELB client, %v", err)
		}
		_, err = elbClient.DescribeLoadBalancers(context.TODO(), &elb.DescribeLoadBalancersInput{})
		assert.True(t, reqInfo.usedCustomEndpoint, "ELB: custom endpoint was not used")
		assert.True(t, strings.Contains(reqInfo.credential, "custom-service"), "ELB: signing name was not properly overridden")
		assert.True(t, strings.Contains(reqInfo.credential, "custom-region"), "ELB: signing region was not properly overridden")

		// Test ELBV2 client
		reqInfo = requestInfo{}
		elbv2Client, err := mockProvider.LoadBalancingV2(context.TODO(), "us-west-2", nil)
		if err != nil {
			t.Errorf("error creating ELBV2 client, %v", err)
		}
		_, err = elbv2Client.DescribeLoadBalancers(context.TODO(), &elbv2.DescribeLoadBalancersInput{})
		assert.True(t, reqInfo.usedCustomEndpoint, "ELBV2: custom endpoint was not used")
		assert.True(t, strings.Contains(reqInfo.credential, "custom-service"), "ELBV2: signing name was not properly overridden")
		assert.True(t, strings.Contains(reqInfo.credential, "custom-region"), "ELBV2: signing region was not properly overridden")

		// Test KMS client
		reqInfo = requestInfo{}
		kmsClient, err := mockProvider.KeyManagement(context.TODO(), "us-west-2", nil)
		if err != nil {
			t.Errorf("error creating KMS client, %v", err)
		}
		_, err = kmsClient.DescribeKey(context.TODO(), &kms.DescribeKeyInput{KeyId: aws.String("dummy")})
		assert.True(t, reqInfo.usedCustomEndpoint, "KMS: custom endpoint was not used")
		assert.True(t, strings.Contains(reqInfo.credential, "custom-service"), "KMS: signing name was not properly overridden")
		assert.True(t, strings.Contains(reqInfo.credential, "custom-region"), "KMS: signing region was not properly overridden")
	})

	// When the signing name is overridden but not the signing region, the signing name should be
	// whatever is configured in the override, and the signing region should fall back to the request region.
	t.Run("With overridden signing name and default region", func(t *testing.T) {
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
					SigningRegion: "",
					SigningName:   "custom-service",
				},
				"2": {
					Service:       elb.ServiceID,
					Region:        "us-west-2",
					URL:           testServer.URL,
					SigningRegion: "",
					SigningName:   "custom-service",
				},
				"3": {
					Service:       elbv2.ServiceID,
					Region:        "us-west-2",
					URL:           testServer.URL,
					SigningRegion: "",
					SigningName:   "custom-service",
				},
				"4": {
					Service:       kms.ServiceID,
					Region:        "us-west-2",
					URL:           testServer.URL,
					SigningRegion: "",
					SigningName:   "custom-service",
				},
			},
		}
		mockProvider := &awsSDKProvider{
			cfg:            &cfgWithServiceOverride,
			regionDelayers: make(map[string]*CrossRequestRetryDelay),
		}

		// Test EC2 client
		ec2Client, err := mockProvider.Compute(context.TODO(), "us-west-2", nil)
		if err != nil {
			t.Errorf("error creating EC2 client, %v", err)
		}
		_, err = ec2Client.DescribeVpcs(context.TODO(), &ec2.DescribeVpcsInput{})
		assert.True(t, reqInfo.usedCustomEndpoint, "EC2: custom endpoint was not used")
		assert.True(t, strings.Contains(reqInfo.credential, "us-west-2"), "EC2: blank signing region should fall back to request region")
		assert.True(t, strings.Contains(reqInfo.credential, "custom-service"), "EC2: signing name was not properly overridden")

		// Test ELB client
		reqInfo = requestInfo{}
		elbClient, err := mockProvider.LoadBalancing(context.TODO(), "us-west-2", nil)
		if err != nil {
			t.Errorf("error creating ELB client, %v", err)
		}
		_, err = elbClient.DescribeLoadBalancers(context.TODO(), &elb.DescribeLoadBalancersInput{})
		assert.True(t, reqInfo.usedCustomEndpoint, "ELB: custom endpoint was not used")
		assert.True(t, strings.Contains(reqInfo.credential, "us-west-2"), "ELB: blank signing region should fall back to request region")
		assert.True(t, strings.Contains(reqInfo.credential, "custom-service"), "ELB: signing name was not properly overridden")

		// Test ELBV2 client
		reqInfo = requestInfo{}
		elbv2Client, err := mockProvider.LoadBalancingV2(context.TODO(), "us-west-2", nil)
		if err != nil {
			t.Errorf("error creating ELBV2 client, %v", err)
		}
		_, err = elbv2Client.DescribeLoadBalancers(context.TODO(), &elbv2.DescribeLoadBalancersInput{})
		assert.True(t, reqInfo.usedCustomEndpoint, "ELBV2: custom endpoint was not used")
		assert.True(t, strings.Contains(reqInfo.credential, "us-west-2"), "ELBV2: blank signing region should fall back to request region")
		assert.True(t, strings.Contains(reqInfo.credential, "custom-service"), "ELBV2: signing name was not properly overridden")

		// Test KMS client
		reqInfo = requestInfo{}
		kmsClient, err := mockProvider.KeyManagement(context.TODO(), "us-west-2", nil)
		if err != nil {
			t.Errorf("error creating KMS client, %v", err)
		}
		_, err = kmsClient.DescribeKey(context.TODO(), &kms.DescribeKeyInput{KeyId: aws.String("dummy")})
		assert.True(t, reqInfo.usedCustomEndpoint, "KMS: custom endpoint was not used")
		assert.True(t, strings.Contains(reqInfo.credential, "us-west-2"), "KMS: blank signing region should fall back to request region")
		assert.True(t, strings.Contains(reqInfo.credential, "custom-service"), "KMS: signing name was not properly overridden")
	})

	// When the signing region is overridden but not the signing name, the signing region should be
	// whatever is configured in the override, and the signing name should fall back to the client's service name.
	t.Run("With overriden signing region and default name", func(t *testing.T) {
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
					SigningRegion: "custom-region",
					SigningName:   "",
				},
				"2": {
					Service:       elb.ServiceID,
					Region:        "us-west-2",
					URL:           testServer.URL,
					SigningRegion: "custom-region",
					SigningName:   "",
				},
				"3": {
					Service:       elbv2.ServiceID,
					Region:        "us-west-2",
					URL:           testServer.URL,
					SigningRegion: "custom-region",
					SigningName:   "",
				},
				"4": {
					Service:       kms.ServiceID,
					Region:        "us-west-2",
					URL:           testServer.URL,
					SigningRegion: "custom-region",
					SigningName:   "",
				},
			},
		}
		mockProvider := &awsSDKProvider{
			cfg:            &cfgWithServiceOverride,
			regionDelayers: make(map[string]*CrossRequestRetryDelay),
		}

		// Test EC2 client
		ec2Client, err := mockProvider.Compute(context.TODO(), "us-west-2", nil)
		if err != nil {
			t.Errorf("error creating EC2 client, %v", err)
		}
		_, err = ec2Client.DescribeVpcs(context.TODO(), &ec2.DescribeVpcsInput{})
		assert.True(t, reqInfo.usedCustomEndpoint, "EC2: custom endpoint was not used")
		assert.True(t, strings.Contains(reqInfo.credential, strings.ToLower(ec2.ServiceID)), "EC2: blank signing name should fall back to request service")
		assert.True(t, strings.Contains(reqInfo.credential, "custom-region"), "EC2: signing region was not properly overridden")

		// Test ELB client
		reqInfo = requestInfo{}
		elbClient, err := mockProvider.LoadBalancing(context.TODO(), "us-west-2", nil)
		if err != nil {
			t.Errorf("error creating ELB client, %v", err)
		}
		_, err = elbClient.DescribeLoadBalancers(context.TODO(), &elb.DescribeLoadBalancersInput{})
		assert.True(t, reqInfo.usedCustomEndpoint, "ELB: custom endpoint was not used")
		// remove whitespace due to multi-word service name
		assert.True(t, strings.Contains(reqInfo.credential, strings.ReplaceAll(strings.ToLower(elb.ServiceID), " ", "")), "ELB: blank signing name should fall back to request service")
		assert.True(t, strings.Contains(reqInfo.credential, "custom-region"), "ELB: signing region was not properly overridden")

		// Test ELBV2 client
		reqInfo = requestInfo{}
		elbv2Client, err := mockProvider.LoadBalancingV2(context.TODO(), "us-west-2", nil)
		if err != nil {
			t.Errorf("error creating ELBV2 client, %v", err)
		}
		_, err = elbv2Client.DescribeLoadBalancers(context.TODO(), &elbv2.DescribeLoadBalancersInput{})
		assert.True(t, reqInfo.usedCustomEndpoint, "ELBV2: custom endpoint was not used")
		// ELB and ELBV2 use the same default signing name (https://docs.aws.amazon.com/general/latest/gr/elb.html)
		assert.True(t, strings.Contains(reqInfo.credential, strings.ReplaceAll(strings.ToLower(elb.ServiceID), " ", "")), "ELBV2: blank signing name should fall back to request service")
		assert.True(t, strings.Contains(reqInfo.credential, "custom-region"), "ELBV2: signing region was not properly overridden")

		// Test KMS client
		reqInfo = requestInfo{}
		kmsClient, err := mockProvider.KeyManagement(context.TODO(), "us-west-2", nil)
		if err != nil {
			t.Errorf("error creating KMS client, %v", err)
		}
		_, err = kmsClient.DescribeKey(context.TODO(), &kms.DescribeKeyInput{KeyId: aws.String("dummy")})
		assert.True(t, reqInfo.usedCustomEndpoint, "KMS: custom endpoint was not used")
		assert.True(t, strings.Contains(reqInfo.credential, strings.ToLower(kms.ServiceID)), "KMS: blank signing name should fall back to request service")
		assert.True(t, strings.Contains(reqInfo.credential, "custom-region"), "KMS: signing region was not properly overridden")
	})

	// When only the URL is overridden, and not the signing region or name, the URL should be whatever is configured in
	// the override, the region should fall back to the request region, and the name should fall back to the client's
	// service name.
	t.Run("Only URL override", func(t *testing.T) {
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
					SigningRegion: "",
					SigningName:   "",
				},
				"2": {
					Service:       elb.ServiceID,
					Region:        "us-west-2",
					URL:           testServer.URL,
					SigningRegion: "",
					SigningName:   "",
				},
				"3": {
					Service:       elbv2.ServiceID,
					Region:        "us-west-2",
					URL:           testServer.URL,
					SigningRegion: "",
					SigningName:   "",
				},
				"4": {
					Service:       kms.ServiceID,
					Region:        "us-west-2",
					URL:           testServer.URL,
					SigningRegion: "",
					SigningName:   "",
				},
				"5": {
					Service:       imds.ServiceID,
					Region:        "us-west-2",
					URL:           testServer.URL,
					SigningRegion: "",
					SigningName:   "",
				},
			},
		}
		mockProvider := &awsSDKProvider{
			cfg:            &cfgWithServiceOverride,
			regionDelayers: make(map[string]*CrossRequestRetryDelay),
		}

		// Test EC2 client
		ec2Client, err := mockProvider.Compute(context.TODO(), "us-west-2", nil)
		if err != nil {
			t.Errorf("error creating EC2 client, %v", err)
		}
		_, err = ec2Client.DescribeVpcs(context.TODO(), &ec2.DescribeVpcsInput{})
		assert.True(t, reqInfo.usedCustomEndpoint, "EC2: custom endpoint was not used")
		assert.True(t, strings.Contains(reqInfo.credential, strings.ToLower(ec2.ServiceID)), "EC2: blank signing name should fall back to request service")
		assert.True(t, strings.Contains(reqInfo.credential, "us-west-2"), "EC2: blank signing region should fall back to request region")

		// Test ELB client
		reqInfo = requestInfo{}
		elbClient, err := mockProvider.LoadBalancing(context.TODO(), "us-west-2", nil)
		if err != nil {
			t.Errorf("error creating ELB client, %v", err)
		}
		_, err = elbClient.DescribeLoadBalancers(context.TODO(), &elb.DescribeLoadBalancersInput{})
		assert.True(t, reqInfo.usedCustomEndpoint, "ELB: custom endpoint was not used")
		assert.True(t, strings.Contains(reqInfo.credential, strings.ReplaceAll(strings.ToLower(elb.ServiceID), " ", "")), "ELB: blank signing name should fall back to request service")
		assert.True(t, strings.Contains(reqInfo.credential, "us-west-2"), "ELB: blank signing region should fall back to request region")

		// Test ELBV2 client
		reqInfo = requestInfo{}
		elbv2Client, err := mockProvider.LoadBalancingV2(context.TODO(), "us-west-2", nil)
		if err != nil {
			t.Errorf("error creating ELBV2 client, %v", err)
		}
		_, err = elbv2Client.DescribeLoadBalancers(context.TODO(), &elbv2.DescribeLoadBalancersInput{})
		assert.True(t, reqInfo.usedCustomEndpoint, "ELBV2: custom endpoint was not used")
		// ELB and ELBV2 use the same default signing name (https://docs.aws.amazon.com/general/latest/gr/elb.html)
		assert.True(t, strings.Contains(reqInfo.credential, strings.ReplaceAll(strings.ToLower(elb.ServiceID), " ", "")), "ELBV2: blank signing name should fall back to request service")
		assert.True(t, strings.Contains(reqInfo.credential, "us-west-2"), "ELBV2: blank signing region should fall back to request region")

		// Test KMS client
		reqInfo = requestInfo{}
		kmsClient, err := mockProvider.KeyManagement(context.TODO(), "us-west-2", nil)
		if err != nil {
			t.Errorf("error creating KMS client, %v", err)
		}
		_, err = kmsClient.DescribeKey(context.TODO(), &kms.DescribeKeyInput{KeyId: aws.String("dummy")})
		assert.True(t, reqInfo.usedCustomEndpoint, "KMS: custom endpoint was not used")
		assert.True(t, strings.Contains(reqInfo.credential, strings.ToLower(kms.ServiceID)), "KMS: blank signing name should fall back to request service")
		assert.True(t, strings.Contains(reqInfo.credential, "us-west-2"), "KMS: blank signing region should fall back to request region")

		val := os.Getenv("AWS_EC2_METADATA_DISABLED")
		// Test Metadata client. This client only supports overriding the URL, not the signing name and region.
		reqInfo = requestInfo{}
		// This client can only successfully make requests when AWS_EC2_METADATA_DISABLED = false.
		// https://docs.aws.amazon.com/sdkref/latest/guide/feature-imds-credentials.html
		os.Setenv("AWS_EC2_METADATA_DISABLED", "false")
		// Call Metadata(), which both creates the client and uses it to make a request.
		mockProvider.Metadata(context.TODO())
		assert.True(t, reqInfo.usedCustomEndpoint, "IMDS: custom endpoint was not used")

		// Create the client with AWS_EC2_METADATA_DISABLED = true to make sure that requests are not made.
		os.Setenv("AWS_EC2_METADATA_DISABLED", "true")
		reqInfo = requestInfo{}
		mockProvider.Metadata(context.TODO())
		assert.False(t, reqInfo.usedCustomEndpoint, "IMDS: request was completed despite setting AWS_EC2_METADATA_DISABLED=true")

		// reset AWS_EC2_METADATA_DISABLED
		os.Setenv("AWS_EC2_METADATA_DISABLED", val)
	})
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
			"4": {
				Service:       kms.ServiceID,
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

	// KMS Client
	attemptCount = 0
	kmsClient, err := mockProvider.KeyManagement(context.TODO(), "us-west-2", nil)
	if err != nil {
		t.Errorf("error creating client, %v", err)
	}
	_, err = kmsClient.DescribeKey(context.TODO(), &kms.DescribeKeyInput{KeyId: aws.String("dummy")})
	assert.True(t, attemptCount == 1, fmt.Sprintf("expected an attempt count of 1 for KMS client, got %d", attemptCount))
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
			"4": {
				Service:       kms.ServiceID,
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

	// KMS Client
	attemptCount = 0
	kmsClient, err := mockProvider.KeyManagement(context.TODO(), "us-west-2", nil)
	if err != nil {
		t.Errorf("error creating client, %v", err)
	}
	_, err = kmsClient.DescribeKey(context.TODO(), &kms.DescribeKeyInput{KeyId: aws.String("dummy")})
	assert.True(t, attemptCount > 1, fmt.Sprintf("expected an attempt count of >1 for KMS client, got %d", attemptCount))
}
