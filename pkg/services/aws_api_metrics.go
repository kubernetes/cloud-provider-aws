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

package services

import (
	"context"
	"strconv"
	"sync"

	"github.com/aws/smithy-go/middleware"
	"github.com/aws/smithy-go/transport/http"
	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
)

// AWSAPIResponseStatusTotal counts AWS API responses by status code.
var AWSAPIResponseStatusTotal = metrics.NewCounterVec(
	&metrics.CounterOpts{
		Name:           "cloudprovider_aws_api_response_status_total",
		Help:           "AWS API response status code counts",
		StabilityLevel: metrics.ALPHA,
	},
	[]string{"service", "operation", "status_code"})

var registerAPIMetricsOnce sync.Once

// RegisterAWSAPIMetrics registers the AWS API metrics with the legacy registry.
func RegisterAWSAPIMetrics() {
	registerAPIMetricsOnce.Do(func() {
		legacyregistry.MustRegister(AWSAPIResponseStatusTotal)
	})
}

// AWSAPIMetricsMiddleware returns a Deserialize middleware that records
// AWS API response status codes as metrics.
func AWSAPIMetricsMiddleware() middleware.DeserializeMiddleware {
	return middleware.DeserializeMiddlewareFunc(
		"k8s/aws-api-metrics",
		func(ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler) (
			out middleware.DeserializeOutput, metadata middleware.Metadata, err error,
		) {
			out, metadata, err = next.HandleDeserialize(ctx, in)

			service := middleware.GetServiceID(ctx)
			operation := middleware.GetOperationName(ctx)

			if response, ok := out.RawResponse.(*http.Response); ok && response.StatusCode >= 400 {
				AWSAPIResponseStatusTotal.With(metrics.Labels{
					"service":     service,
					"operation":   operation,
					"status_code": strconv.Itoa(response.StatusCode),
				}).Inc()
			}

			return out, metadata, err
		},
	)
}
