/*
Copyright 2015 The Kubernetes Authors.

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

	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	"github.com/aws/smithy-go/transport/http"
	"k8s.io/klog/v2"
)

// Handler for aws-sdk-go that logs all requests
func awsHandlerLogger(req *request.Request) {
	service, name := awsServiceAndName(req)
	klog.V(4).Infof("AWS request: %s %s", service, name)
}

func awsSendHandlerLogger(req *request.Request) {
	service, name := awsServiceAndName(req)
	klog.V(4).Infof("AWS API Send: %s %s %v %v", service, name, req.Operation, req.Params)
}

func awsValidateResponseHandlerLogger(req *request.Request) {
	service, name := awsServiceAndName(req)
	klog.V(4).Infof("AWS API ValidateResponse: %s %s %v %v %s", service, name, req.Operation, req.Params, req.HTTPResponse.Status)
}

func awsServiceAndName(req *request.Request) (string, string) {
	service := req.ClientInfo.ServiceName

	name := "?"
	if req.Operation != nil {
		name = req.Operation.Name
	}
	return service, name
}

// Middleware for AWS SDK Go V2 clients
// AWS SDK Go V2 version of awsHandlerLogger()
func awsHandlerLoggerMiddleware() middleware.FinalizeMiddleware {
	return middleware.FinalizeMiddlewareFunc(
		"k8s/logger",
		func(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (
			out middleware.FinalizeOutput, metadata middleware.Metadata, err error,
		) {
			service, name := awsServiceAndNameV2(ctx)

			klog.V(4).Infof("AWS request: %s %s", service, name)
			return next.HandleFinalize(ctx, in)
		},
	)
}

// AWS SDK Go V2 version of awsValidateResponseHandlerLogger()
func awsValidateResponseHandlerLoggerMiddleware() middleware.DeserializeMiddleware {
	return middleware.DeserializeMiddlewareFunc(
		"k8s/api-validate-response",
		func(ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler) (
			out middleware.DeserializeOutput, metadata middleware.Metadata, err error,
		) {
			out, metadata, err = next.HandleDeserialize(ctx, in)
			response, ok := out.RawResponse.(*http.Response)
			if !ok {
				return out, metadata, &smithy.DeserializationError{Err: fmt.Errorf("unknown transport type %T", out.RawResponse)}
			}
			service, name := awsServiceAndNameV2(ctx)
			klog.V(4).Infof("AWS API ValidateResponse: %s %s %d", service, name, response.StatusCode)
			return out, metadata, err
		},
	)
}

// AWS SDK Go V2 version of awsSendHandlerLogger(), sans logging req.Operation, which is logged
// during the Finalize phase in delayPreSign().
func awsSendHandlerLoggerMiddleware() middleware.SerializeMiddleware {
	return middleware.SerializeMiddlewareFunc(
		"k8s/api-request",
		func(ctx context.Context, in middleware.SerializeInput, next middleware.SerializeHandler) (
			out middleware.SerializeOutput, metadata middleware.Metadata, err error,
		) {
			service, name := awsServiceAndNameV2(ctx)
			klog.V(4).Infof("AWS API Send: %s %s %v", service, name, in.Parameters)
			return next.HandleSerialize(ctx, in)
		},
	)
}

// Gets the service and operation name from AWS SDK Go V2 client requests.
// For AWS SDK Go V1 clients, func awsServiceAndName(req *request.Request) is used.
func awsServiceAndNameV2(ctx context.Context) (string, string) {
	service := middleware.GetServiceID(ctx)

	name := "?"
	if opName := middleware.GetOperationName(ctx); opName != "" {
		name = opName
	}
	return service, name
}
