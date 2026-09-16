/*
Copyright 2017 The Kubernetes Authors.

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
	"net/http"
	"strconv"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go/middleware"
	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
)

const (
	awsAPIErrorTypeOther    = "other"
	awsAPIErrorTypeThrottle = "throttle"
)

var (
	awsAPIMetric = metrics.NewHistogramVec(
		&metrics.HistogramOpts{
			Name:           "cloudprovider_aws_api_request_duration_seconds",
			Help:           "Latency of AWS API calls",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"request"})

	awsAPIErrorMetric = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Name:           "cloudprovider_aws_api_request_errors",
			Help:           "AWS API errors",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"request"})

	awsAPIThrottlesMetric = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Name:           "cloudprovider_aws_api_throttled_requests_total",
			Help:           "AWS API throttled requests",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"operation_name"})

	// awsAPIResponseStatusTotal counts AWS API responses with an error status code
	// (>= 400). It is recorded by a Finalize middleware inserted before the SDK's
	// "Retry" middleware, so it counts the terminal status of each logical call
	// once (after retries are exhausted) rather than once per attempt — a response
	// that is retried and then succeeds is not counted.
	awsAPIResponseStatusTotal = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Name:           "cloudprovider_aws_api_response_status_total",
			Help:           "AWS API error response counts by status code and bounded error type (throttle or other; terminal, after retries are exhausted)",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"service", "operation", "status_code", "error_type"})
)

func recordAWSMetric(actionName string, timeTaken float64, err error) {
	if err != nil {
		awsAPIErrorMetric.With(metrics.Labels{"request": actionName}).Inc()
	} else {
		awsAPIMetric.With(metrics.Labels{"request": actionName}).Observe(timeTaken)
	}
}

func recordAWSThrottlesMetric(operation string) {
	awsAPIThrottlesMetric.With(metrics.Labels{"operation_name": operation}).Inc()
}

var registerOnce sync.Once

func registerMetrics() {
	registerOnce.Do(func() {
		legacyregistry.MustRegister(awsAPIMetric)
		legacyregistry.MustRegister(awsAPIErrorMetric)
		legacyregistry.MustRegister(awsAPIThrottlesMetric)
		legacyregistry.MustRegister(awsAPIResponseStatusTotal)
	})
}

// awsAPIMetricsMiddleware returns a Finalize middleware that records the HTTP
// status code of AWS API calls that fail terminally. It is inserted before the
// SDK's "Retry" middleware so it wraps the entire retry loop and runs once per
// logical call, recording only the terminal error status (not per attempt), so
// a response that is retried and then succeeds is not counted.
func awsAPIMetricsMiddleware() middleware.FinalizeMiddleware {
	return middleware.FinalizeMiddlewareFunc(
		"k8s/aws-api-metrics",
		func(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (
			out middleware.FinalizeOutput, metadata middleware.Metadata, err error,
		) {
			out, metadata, err = next.HandleFinalize(ctx, in)
			if err == nil {
				return out, metadata, err
			}

			// The SDK surfaces every non-2xx terminal response as an error carrying
			// an *awshttp.ResponseError; a nil error means a 2xx, which we do not count.
			var respErr *awshttp.ResponseError
			if errors.As(err, &respErr) && respErr.HTTPStatusCode() >= 400 {
				errorType := awsAPIErrorTypeOther
				throttleErrorCode := retry.ThrottleErrorCode{Codes: retry.DefaultThrottleErrorCodes}
				if respErr.HTTPStatusCode() == http.StatusTooManyRequests ||
					throttleErrorCode.IsErrorThrottle(err).Bool() {
					errorType = awsAPIErrorTypeThrottle
				}

				awsAPIResponseStatusTotal.With(metrics.Labels{
					"service":     middleware.GetServiceID(ctx),
					"operation":   middleware.GetOperationName(ctx),
					"status_code": strconv.Itoa(respErr.HTTPStatusCode()),
					"error_type":  errorType,
				}).Inc()
			}

			return out, metadata, err
		},
	)
}

// addAWSAPIMetricsMiddleware inserts the metrics middleware into the Finalize
// step before the SDK's "Retry" middleware, so it observes only terminal outcomes.
func addAWSAPIMetricsMiddleware(stack *middleware.Stack) error {
	return stack.Finalize.Insert(awsAPIMetricsMiddleware(), "Retry", middleware.Before)
}
