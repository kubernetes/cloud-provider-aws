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

	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/assert"
	"k8s.io/component-base/metrics/testutil"
)

func TestAWSAPIMetricsMiddleware(t *testing.T) {
	registerMetrics()

	tests := []struct {
		name             string
		statusCode       int
		err              error
		expectStatusCode string
	}{
		{
			name:             "4xx response records status code",
			statusCode:       403,
			expectStatusCode: "403",
		},
		{
			name:             "5xx response records status code",
			statusCode:       500,
			expectStatusCode: "500",
		},
		{
			name:       "2xx response does not record",
			statusCode: 200,
		},
		{
			name:             "4xx with API error records status code",
			statusCode:       400,
			err:              &smithy.GenericAPIError{Code: "ThrottlingException", Message: "rate exceeded"},
			expectStatusCode: "400",
		},
		{
			name:             "5xx with non-API error records status code",
			statusCode:       500,
			err:              fmt.Errorf("connection reset"),
			expectStatusCode: "500",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			awsAPIResponseStatusTotal.Reset()

			mw := awsAPIMetricsMiddleware()
			handler := middleware.DeserializeHandlerFunc(
				func(ctx context.Context, in middleware.DeserializeInput) (
					middleware.DeserializeOutput, middleware.Metadata, error,
				) {
					return middleware.DeserializeOutput{
						RawResponse: &smithyhttp.Response{
							Response: &http.Response{StatusCode: tc.statusCode},
						},
					}, middleware.Metadata{}, tc.err
				},
			)

			_, _, _ = mw.HandleDeserialize(context.Background(), middleware.DeserializeInput{}, handler)

			if tc.expectStatusCode != "" {
				val, err := testutil.GetCounterMetricValue(awsAPIResponseStatusTotal.With(map[string]string{
					"service":     "",
					"operation":   "",
					"status_code": tc.expectStatusCode,
				}))
				assert.NoError(t, err)
				assert.Equal(t, float64(1), val)
			}
		})
	}
}
