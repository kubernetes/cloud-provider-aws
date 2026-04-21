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
	"strconv"
	"sync"

	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
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

	// awsAPIResponseStatusTotal counts AWS API responses by status code.
	awsAPIResponseStatusTotal = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Name:           "cloudprovider_aws_api_response_status_total",
			Help:           "AWS API response status code counts",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"service", "operation", "status_code"})
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

// awsAPIMetricsMiddleware returns a Deserialize middleware that records
// AWS API response status codes as metrics.
func awsAPIMetricsMiddleware() middleware.DeserializeMiddleware {
	return middleware.DeserializeMiddlewareFunc(
		"k8s/aws-api-metrics",
		func(ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler) (
			out middleware.DeserializeOutput, metadata middleware.Metadata, err error,
		) {
			out, metadata, err = next.HandleDeserialize(ctx, in)

			service := middleware.GetServiceID(ctx)
			operation := middleware.GetOperationName(ctx)

			if response, ok := out.RawResponse.(*smithyhttp.Response); ok && response.StatusCode >= 400 {
				awsAPIResponseStatusTotal.With(metrics.Labels{
					"service":     service,
					"operation":   operation,
					"status_code": strconv.Itoa(response.StatusCode),
				}).Inc()
			}

			return out, metadata, err
		},
	)
}
