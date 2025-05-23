/*
Copyright 2016 The Kubernetes Authors.

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

package aws

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"

	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"k8s.io/cloud-provider-aws/pkg/providers/v1/config"
)

// There follows a group of tests for the backoff logic.  There's nothing
// particularly special about the values chosen: if we tweak the values in the
// backoff logic then we might well have to update the tests.  However the key
// behavioural elements should remain (e.g. no errors => no backoff), and these
// are each tested by one of the tests below.

// Test that we don't apply any delays when there are no errors
func TestBackoffNoErrors(t *testing.T) {
	b := &Backoff{}
	b.init(decayIntervalSeconds, decayFraction, maxDelay)

	now := time.Now()
	for i := 0; i < 100; i++ {
		d := b.ComputeDelayForRequest(now)
		if d.Nanoseconds() != 0 {
			t.Fatalf("unexpected delay during no-error case")
		}
		now = now.Add(time.Second)
	}
}

// Test that we always apply a delay when there are errors, and also that we
// don't "flap" - that our own delay doesn't cause us to oscillate between
// delay and no-delay.
func TestBackoffAllErrors(t *testing.T) {
	b := &Backoff{}
	b.init(decayIntervalSeconds, decayFraction, maxDelay)

	now := time.Now()
	// Warm up
	for i := 0; i < 10; i++ {
		_ = b.ComputeDelayForRequest(now)
		b.ReportError()
		now = now.Add(time.Second)
	}

	for i := 0; i < 100; i++ {
		d := b.ComputeDelayForRequest(now)
		b.ReportError()
		if d.Seconds() < 5 {
			t.Fatalf("unexpected short-delay during all-error case: %v", d)
		}
		t.Logf("delay @%d %v", i, d)
		now = now.Add(d)
	}
}

// Test that we do come close to our max delay, when we see all errors at 1
// second intervals (this simulates multiple concurrent requests, because we
// don't wait for delay in between requests)
func TestBackoffHitsMax(t *testing.T) {
	b := &Backoff{}
	b.init(decayIntervalSeconds, decayFraction, maxDelay)

	now := time.Now()
	for i := 0; i < 100; i++ {
		_ = b.ComputeDelayForRequest(now)
		b.ReportError()
		now = now.Add(time.Second)
	}

	for i := 0; i < 10; i++ {
		d := b.ComputeDelayForRequest(now)
		b.ReportError()
		if float32(d.Nanoseconds()) < (float32(maxDelay.Nanoseconds()) * 0.95) {
			t.Fatalf("expected delay to be >= 95 percent of max delay, was %v", d)
		}
		t.Logf("delay @%d %v", i, d)
		now = now.Add(time.Second)
	}
}

// Test that after a phase of errors, we eventually stop applying a delay once there are
// no more errors.
func TestBackoffRecovers(t *testing.T) {
	b := &Backoff{}
	b.init(decayIntervalSeconds, decayFraction, maxDelay)

	now := time.Now()

	// Phase of all-errors
	for i := 0; i < 100; i++ {
		_ = b.ComputeDelayForRequest(now)
		b.ReportError()
		now = now.Add(time.Second)
	}

	for i := 0; i < 10; i++ {
		d := b.ComputeDelayForRequest(now)
		b.ReportError()
		if d.Seconds() < 5 {
			t.Fatalf("unexpected short-delay during all-error phase: %v", d)
		}
		t.Logf("error phase delay @%d %v", i, d)
		now = now.Add(time.Second)
	}

	// Phase of no errors
	for i := 0; i < 100; i++ {
		_ = b.ComputeDelayForRequest(now)
		now = now.Add(3 * time.Second)
	}

	for i := 0; i < 10; i++ {
		d := b.ComputeDelayForRequest(now)
		if d.Seconds() != 0 {
			t.Fatalf("unexpected delay during error recovery phase: %v", d)
		}
		t.Logf("no-error phase delay @%d %v", i, d)
		now = now.Add(time.Second)
	}
}

// Make sure that nonRetryableErrors, which are thrown by AWS SDK Go V2 clients
// when the request context is canceled, are not retried with customRetryer is used.
func TestNonRetryableError(t *testing.T) {
	mockedEC2API := newMockedEC2API()
	mockedEC2API.On("DescribeInstances", mock.Anything).Return(&ec2.DescribeInstancesOutput{}, errors.New(nonRetryableError))

	ec2Client := &awsSdkEC2{
		ec2: mockedEC2API,
	}
	_, err := ec2Client.ec2.DescribeInstances(context.Background(), &ec2.DescribeInstancesInput{})

	// Verify that the custom retryer can recognize when a nonRetryableError is thrown
	retryer := &customRetryer{
		retry.NewStandard(),
	}
	if retryer.IsErrorRetryable(err) {
		t.Errorf("Expected nonRetryableError error to be non-retryable")
	}
}

// Tests delayPresign to ensure that it delays the request
func TestDelayPresign(t *testing.T) {
	// This test forces certain results from ComputeDelayForRequest() and sleepWithContext()
	// to trigger a delay from delayPresign().
	// Dummy server to make sure the client request doesn't actually hit the API.
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

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
	// Create a dummy delayer that sets a delay of 5 seconds for ComputeDelayForRequest()
	delayer := NewCrossRequestRetryDelay()
	delayer.backoff.countRequests = 1
	delayer.backoff.countErrorsRequestLimit = 100000
	delayer.backoff.maxDelay = 100000
	regionDelayersMap := make(map[string]*CrossRequestRetryDelay)
	regionDelayersMap["us-west-2"] = delayer
	mockProvider := &awsSDKProvider{
		cfg:            &cfgWithServiceOverride,
		regionDelayers: regionDelayersMap,
	}

	ec2Client, err := mockProvider.Compute(context.Background(), "us-west-2", nil)
	if err != nil {
		t.Errorf("error creating client, %v", err)
	}
	startTime := time.Now()
	_, _ = ec2Client.DescribeInstances(context.Background(), &ec2.DescribeInstancesInput{})
	endTime := time.Now()
	diff := endTime.Sub(startTime)
	assert.True(t, diff > 5, fmt.Sprintf("expected a delay of at least 5 seconds, got %d", diff))
}

// Tests that delayAfterRetry() recognizes RequestLimitExceeded errors and counts them towards the backoff
func TestAfterRetry(t *testing.T) {
	// Dummy handler that delayAfterRetry() will trigger in its next.HandleFinalize() call.
	// Throws a RequestLimitExceeded error, which delayAfterRetry() should recognize.
	nextHandlerCalled := false
	nextHandler := middleware.FinalizeHandlerFunc(
		func(ctx context.Context, in middleware.FinalizeInput) (
			out middleware.FinalizeOutput, metadata middleware.Metadata, err error,
		) {
			nextHandlerCalled = true
			return middleware.FinalizeOutput{}, middleware.Metadata{}, &smithy.GenericAPIError{
				Code:    "RequestLimitExceeded",
				Message: "You have exceeded the request limit.",
			}
		},
	)

	delayer := NewCrossRequestRetryDelay()
	preDelayErrorCount := delayer.backoff.countErrorsRequestLimit
	_, _, err := delayAfterRetry(delayer).HandleFinalize(
		context.Background(),
		middleware.FinalizeInput{},
		nextHandler,
	)
	postDelayErrorCount := delayer.backoff.countErrorsRequestLimit

	// Verify that a RequestLimitExceeded error was thrown
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "RequestLimitExceeded")
	assert.True(t, nextHandlerCalled, "Next handler should have been called")

	// Verify that the delayer's backoff was updated
	diff := (int)(postDelayErrorCount - preDelayErrorCount)
	assert.True(t, diff == 1, fmt.Sprintf("expected an update to the backoff count of %d, got %d", 1, diff))
}
