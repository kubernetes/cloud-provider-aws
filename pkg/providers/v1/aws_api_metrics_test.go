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

package aws

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/assert"
	"k8s.io/component-base/metrics/testutil"
)

// respErr builds an *awshttp.ResponseError carrying the given HTTP status and
// optional API error code, as the SDK does for a terminal HTTP error.
func respErr(statusCode int, errorCode string) error {
	var err error = fmt.Errorf("api error")
	if errorCode != "" {
		err = &smithy.GenericAPIError{Code: errorCode, Message: "api error"}
	}

	return &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: statusCode}},
			Err:      err,
		},
	}
}

// statusCounterValue returns the recorded count for a status and error type
// (empty service/operation, as produced by the test middleware chain).
func statusCounterValue(t *testing.T, statusCode, errorType string) float64 {
	t.Helper()
	v, err := testutil.GetCounterMetricValue(awsAPIResponseStatusTotal.With(map[string]string{
		"service":     "",
		"operation":   "",
		"status_code": statusCode,
		"error_type":  errorType,
	}))
	assert.NoError(t, err)
	return v
}

func TestAWSAPIMetricsMiddleware(t *testing.T) {
	registerMetrics()

	tests := []struct {
		name             string
		err              error
		expectStatusCode string // "" means expect nothing recorded
		expectErrorType  string
	}{
		{
			name:             "terminal 4xx records status code",
			err:              respErr(403, ""),
			expectStatusCode: "403",
			expectErrorType:  awsAPIErrorTypeOther,
		},
		{
			name:             "terminal 5xx records status code",
			err:              respErr(500, ""),
			expectStatusCode: "500",
			expectErrorType:  awsAPIErrorTypeOther,
		},
		{
			name:             "terminal RequestLimitExceeded 503 records throttle error type",
			err:              respErr(503, "RequestLimitExceeded"),
			expectStatusCode: "503",
			expectErrorType:  awsAPIErrorTypeThrottle,
		},
		{
			name:             "terminal 503 without API error records other error type",
			err:              respErr(503, ""),
			expectStatusCode: "503",
			expectErrorType:  awsAPIErrorTypeOther,
		},
		{
			name:             "terminal ThrottlingException 400 records throttle error type",
			err:              respErr(400, "ThrottlingException"),
			expectStatusCode: "400",
			expectErrorType:  awsAPIErrorTypeThrottle,
		},
		{
			name:             "terminal 429 without API error records throttle error type",
			err:              respErr(429, ""),
			expectStatusCode: "429",
			expectErrorType:  awsAPIErrorTypeThrottle,
		},
		{
			name:             "terminal non-throttle API error records other error type",
			err:              respErr(400, "ValidationException"),
			expectStatusCode: "400",
			expectErrorType:  awsAPIErrorTypeOther,
		},
		{
			name: "success records nothing",
			err:  nil,
		},
		{
			name: "terminal error without HTTP response records nothing",
			err:  fmt.Errorf("connection reset"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			awsAPIResponseStatusTotal.Reset()

			mw := awsAPIMetricsMiddleware()
			handler := middleware.FinalizeHandlerFunc(
				func(ctx context.Context, in middleware.FinalizeInput) (
					middleware.FinalizeOutput, middleware.Metadata, error,
				) {
					return middleware.FinalizeOutput{}, middleware.Metadata{}, tc.err
				},
			)

			_, _, _ = mw.HandleFinalize(context.Background(), middleware.FinalizeInput{}, handler)

			if tc.expectStatusCode != "" {
				assert.Equal(t, float64(1), statusCounterValue(t, tc.expectStatusCode, tc.expectErrorType))
			}
		})
	}
}

// TestAWSAPIMetricsMiddlewareWithRetries asserts that transient failures the
// retryer recovers from are NOT counted (the point of counting at Finalize,
// before Retry, rather than at Deserialize), while a failure that exhausts
// retries is counted exactly once.
func TestAWSAPIMetricsMiddlewareWithRetries(t *testing.T) {
	registerMetrics()

	// Standard retryer: 3 attempts, zero backoff so the test is fast.
	retryer := retry.NewStandard(func(o *retry.StandardOptions) {
		o.MaxAttempts = 3
		o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
	})
	attempt := retry.NewAttemptMiddleware(retryer, func(i interface{}) interface{} { return i })
	metricsMW := awsAPIMetricsMiddleware()

	run := func(inner middleware.FinalizeHandler) error {
		// Adapt the attempt middleware into a FinalizeHandler that drives the retry loop
		// over inner, so metricsMW (inserted before Retry) sees only the terminal result.
		retryHandler := middleware.FinalizeHandlerFunc(func(ctx context.Context, in middleware.FinalizeInput) (
			middleware.FinalizeOutput, middleware.Metadata, error) {
			return attempt.HandleFinalize(ctx, in, inner)
		})
		_, _, err := metricsMW.HandleFinalize(context.Background(), middleware.FinalizeInput{}, retryHandler)
		return err
	}

	t.Run("transient 503 then success is not counted", func(t *testing.T) {
		awsAPIResponseStatusTotal.Reset()
		calls := 0
		err := run(middleware.FinalizeHandlerFunc(func(ctx context.Context, in middleware.FinalizeInput) (
			middleware.FinalizeOutput, middleware.Metadata, error) {
			calls++
			if calls == 1 {
				return middleware.FinalizeOutput{}, middleware.Metadata{}, respErr(503, "RequestLimitExceeded")
			}
			return middleware.FinalizeOutput{}, middleware.Metadata{}, nil // recovered
		}))
		assert.NoError(t, err, "expected success after retry")
		assert.Equal(t, 2, calls, "expected 2 attempts (1 fail + 1 success)")
		assert.Equal(t, float64(0), statusCounterValue(t, "503", awsAPIErrorTypeThrottle), "retried-away 503 should not be counted")
	})

	t.Run("retry-exhausted RequestLimitExceeded 503 is counted once as throttle", func(t *testing.T) {
		awsAPIResponseStatusTotal.Reset()
		calls := 0
		err := run(middleware.FinalizeHandlerFunc(func(ctx context.Context, in middleware.FinalizeInput) (
			middleware.FinalizeOutput, middleware.Metadata, error) {
			calls++
			return middleware.FinalizeOutput{}, middleware.Metadata{}, respErr(503, "RequestLimitExceeded")
		}))
		assert.Error(t, err, "expected terminal error after exhausting retries")
		assert.Equal(t, 3, calls, "expected 3 attempts (max)")
		assert.Equal(t, float64(1), statusCounterValue(t, "503", awsAPIErrorTypeThrottle), "retry-exhausted 503 should be counted exactly once")
	})

	t.Run("non-retryable 400 is counted once on first attempt", func(t *testing.T) {
		awsAPIResponseStatusTotal.Reset()
		calls := 0
		err := run(middleware.FinalizeHandlerFunc(func(ctx context.Context, in middleware.FinalizeInput) (
			middleware.FinalizeOutput, middleware.Metadata, error) {
			calls++
			return middleware.FinalizeOutput{}, middleware.Metadata{}, respErr(400, "")
		}))
		assert.Error(t, err, "expected terminal error for 400")
		assert.Equal(t, float64(1), statusCounterValue(t, "400", awsAPIErrorTypeOther), "terminal 400 should be counted exactly once")
	})
}
