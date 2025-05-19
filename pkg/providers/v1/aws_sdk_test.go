package aws

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/stretchr/testify/assert"

	"k8s.io/cloud-provider-aws/pkg/providers/v1/config"
	"k8s.io/cloud-provider-aws/pkg/providers/v1/iface"
)

type MockAWSSDKProvider struct {
	p *awsSDKProvider
}

// Mocks endpoint resolution and custom retries in the EC2 Client.
func (m *MockAWSSDKProvider) Compute(ctx context.Context, regionName string, mockRT *MockRoundTripper) (iface.EC2, error) {
	cfg, err := awsConfig.LoadDefaultConfig(ctx,
		awsConfig.WithRegion(regionName),
		awsConfig.WithHTTPClient(&http.Client{Transport: mockRT}),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize AWS config: %v", err)
	}

	var opts []func(*ec2.Options) = m.p.cfg.GetEC2EndpointOpts(regionName)
	opts = append(opts, func(o *ec2.Options) {
		o.Retryer = &customRetryer{
			retry.NewStandard(),
		}
	})
	opts = append(opts, func(o *ec2.Options) {
		o.EndpointResolverV2 = m.p.cfg.GetCustomEC2Resolver()
	})

	ec2Client := ec2.NewFromConfig(cfg, opts...)

	ec2 := &awsSdkEC2{
		ec2: ec2Client,
	}
	return ec2, nil
}

// Verifies that an EC2 client configured with customRetryer does not retry nonRetryableErrors
func TestComputeRetryer(t *testing.T) {
	mockProvider := &MockAWSSDKProvider{
		p: &awsSDKProvider{
			cfg: &config.CloudConfig{},
		},
	}

	// Verify that when a non-retryable error is thrown, only one attempt is made
	var attemptCount = 0
	mockRT := &MockRoundTripper{
		attemptCount:      &attemptCount,
		throwNonRetryable: true,
	}
	ec2Client, err := mockProvider.Compute(context.TODO(), "us-west-2", mockRT)
	if err != nil {
		t.Errorf("error creating client, %v", err)
	}
	_, err = ec2Client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
	assert.True(t, attemptCount == 1)

	// Verify that when any other error is thrown, the error is retried
	attemptCount = 0
	mockRT = &MockRoundTripper{
		attemptCount:      &attemptCount,
		throwNonRetryable: false,
	}
	ec2Client, err = mockProvider.Compute(context.TODO(), "us-west-2", mockRT)
	if err != nil {
		t.Errorf("error creating client, %v", err)
	}
	_, err = ec2Client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
	assert.True(t, attemptCount > 1)
}

// Tests whether the EC2 endpoint resolver correctly overrides the URL
func TestComputeEndpoint(t *testing.T) {
	overrideURL := "ec2.foo.bar"
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
				URL:           "https://" + overrideURL,
				SigningRegion: "signingRegion",
				SigningName:   "signingName",
			},
		},
	}
	mockProvider := &MockAWSSDKProvider{
		p: &awsSDKProvider{
			cfg: &cfgWithServiceOverride,
		},
	}

	// Verify that the endpoint is correctly overriden when a ServiceOverride is configured
	var host = ""
	mockRT := &MockRoundTripper{
		host:              &host,
		throwNonRetryable: true, // not necessary, just to prevent retries and make the test run faster
	}
	ec2Client, err := mockProvider.Compute(context.TODO(), "us-west-2", mockRT)
	if err != nil {
		t.Errorf("error creating client, %v", err)
	}
	_, err = ec2Client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
	assert.True(t, host == overrideURL)

	// Verify that the endpoint is not overriden when no ServiceOverride is configured
	cfgNoOverride := config.CloudConfig{}
	mockProvider = &MockAWSSDKProvider{
		p: &awsSDKProvider{
			cfg: &cfgNoOverride,
		},
	}
	host = ""
	mockRT = &MockRoundTripper{
		host:              &host,
		throwNonRetryable: true, // not necessary, just to prevent retries and make the test run faster
	}
	ec2Client, err = mockProvider.Compute(context.TODO(), "us-west-2", mockRT)
	if err != nil {
		t.Errorf("error creating client, %v", err)
	}
	_, err = ec2Client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
	assert.True(t, host != overrideURL)
}

type MockRoundTripper struct {
	attemptCount      *int
	throwNonRetryable bool
	host              *string // stores the host url used in a request
}

func (m *MockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.host != nil {
		*m.host = req.URL.Host
	}
	if m.attemptCount != nil {
		*m.attemptCount += 1
	}
	if m.throwNonRetryable {
		return nil, errors.New(nonRetryableError)
	}
	return nil, nil
}
