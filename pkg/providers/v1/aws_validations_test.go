/*
Copyright 2025 The Kubernetes Authors.

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
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestValidateServiceAnnotationTargetGroupAttributes(t *testing.T) {
	tests := []struct {
		name          string
		annotations   map[string]string
		servicePorts  []v1.ServicePort
		expectedError string
	}{
		{
			name:        "no target group attributes annotation",
			annotations: map[string]string{},
			servicePorts: []v1.ServicePort{
				{Port: 80, Protocol: v1.ProtocolTCP},
			},
			expectedError: "",
		},
		{
			name: "empty target group attributes annotation",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "",
			},
			servicePorts: []v1.ServicePort{
				{Port: 80, Protocol: v1.ProtocolTCP},
			},
			expectedError: "",
		},
		{
			name: "valid preserve_client_ip.enabled=true",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=true",
			},
			servicePorts: []v1.ServicePort{
				{Port: 80, Protocol: v1.ProtocolTCP},
			},
			expectedError: "",
		},
		{
			name: "valid preserve_client_ip.enabled=false",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=false",
			},
			servicePorts: []v1.ServicePort{
				{Port: 80, Protocol: v1.ProtocolTCP},
			},
			expectedError: "",
		},
		{
			name: "valid proxy_protocol_v2.enabled=true",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "proxy_protocol_v2.enabled=true",
			},
			servicePorts: []v1.ServicePort{
				{Port: 80, Protocol: v1.ProtocolTCP},
			},
			expectedError: "",
		},
		{
			name: "valid proxy_protocol_v2.enabled=false",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "proxy_protocol_v2.enabled=false",
			},
			servicePorts: []v1.ServicePort{
				{Port: 80, Protocol: v1.ProtocolTCP},
			},
			expectedError: "",
		},
		{
			name: "valid multiple attributes",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=true,proxy_protocol_v2.enabled=false",
			},
			servicePorts: []v1.ServicePort{
				{Port: 80, Protocol: v1.ProtocolTCP},
			},
			expectedError: "",
		},
		{
			name: "duplicate attribute in annotation (last one wins - no error expected)",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=true,preserve_client_ip.enabled=false",
			},
			servicePorts: []v1.ServicePort{
				{Port: 80, Protocol: v1.ProtocolTCP},
			},
			expectedError: "", // getKeyValuePropertiesFromAnnotation overwrites, so no duplicate detection
		},
		{
			name: "empty attribute value",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=",
			},
			servicePorts: []v1.ServicePort{
				{Port: 80, Protocol: v1.ProtocolTCP},
			},
			expectedError: "attribute value is empty for \"preserve_client_ip.enabled\"",
		},
		{
			name: "invalid preserve_client_ip.enabled value",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=invalid",
			},
			servicePorts: []v1.ServicePort{
				{Port: 80, Protocol: v1.ProtocolTCP},
			},
			expectedError: "invalid attribute value for \"preserve_client_ip.enabled\": invalid",
		},
		{
			name: "invalid proxy_protocol_v2.enabled value",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "proxy_protocol_v2.enabled=yes",
			},
			servicePorts: []v1.ServicePort{
				{Port: 80, Protocol: v1.ProtocolTCP},
			},
			expectedError: "invalid attribute value for \"proxy_protocol_v2.enabled\": yes",
		},
		{
			name: "unsupported attribute",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "unsupported_attribute=value",
			},
			servicePorts: []v1.ServicePort{
				{Port: 80, Protocol: v1.ProtocolTCP},
			},
			expectedError: "the attribute \"unsupported_attribute\" is not supported by the controller or is invalid",
		},
		{
			name: "preserve_client_ip.enabled=false with UDP port should fail",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=false",
			},
			servicePorts: []v1.ServicePort{
				{Port: 53, Protocol: v1.ProtocolUDP},
			},
			expectedError: "client IP preservation can't be disabled for UDP ports",
		},
		{
			name: "preserve_client_ip.enabled=false with TCP_UDP port should fail",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=false",
			},
			servicePorts: []v1.ServicePort{
				{Port: 53, Protocol: "TCP_UDP"},
			},
			expectedError: "client IP preservation can't be disabled for UDP ports",
		},
		{
			name: "preserve_client_ip.enabled=true with UDP port should succeed",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=true",
			},
			servicePorts: []v1.ServicePort{
				{Port: 53, Protocol: v1.ProtocolUDP},
			},
			expectedError: "",
		},
		{
			name: "preserve_client_ip.enabled=false with mixed TCP and UDP ports should fail",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=false",
			},
			servicePorts: []v1.ServicePort{
				{Port: 80, Protocol: v1.ProtocolTCP},
				{Port: 53, Protocol: v1.ProtocolUDP},
			},
			expectedError: "client IP preservation can't be disabled for UDP ports",
		},
		{
			name: "multiple attributes with preserve_client_ip.enabled=false and UDP port should fail",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=false,proxy_protocol_v2.enabled=true",
			},
			servicePorts: []v1.ServicePort{
				{Port: 53, Protocol: v1.ProtocolUDP},
			},
			expectedError: "client IP preservation can't be disabled for UDP ports",
		},
		{
			name: "case sensitivity - preserve_client_ip.enabled with True should fail",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=True",
			},
			servicePorts: []v1.ServicePort{
				{Port: 80, Protocol: v1.ProtocolTCP},
			},
			expectedError: "invalid attribute value for \"preserve_client_ip.enabled\": True",
		},
		{
			name: "case sensitivity - proxy_protocol_v2.enabled with FALSE should fail",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "proxy_protocol_v2.enabled=FALSE",
			},
			servicePorts: []v1.ServicePort{
				{Port: 80, Protocol: v1.ProtocolTCP},
			},
			expectedError: "invalid attribute value for \"proxy_protocol_v2.enabled\": FALSE",
		},
		{
			name: "whitespace in attribute values should fail",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled= true ",
			},
			servicePorts: []v1.ServicePort{
				{Port: 80, Protocol: v1.ProtocolTCP},
			},
			expectedError: "invalid attribute value for \"preserve_client_ip.enabled\":",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test service with the specified ports
			service := &v1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-service",
					Namespace:   "test-namespace",
					Annotations: tt.annotations,
				},
				Spec: v1.ServiceSpec{
					Type:  v1.ServiceTypeLoadBalancer,
					Ports: tt.servicePorts,
				},
			}

			// Create validation input
			input := &awsValidationInput{
				apiService:  service,
				annotations: tt.annotations,
			}

			// Execute the validation
			err := validateServiceAnnotationTargetGroupAttributes(input)

			// Verify the result
			if tt.expectedError == "" {
				assert.NoError(t, err, "Expected no error for test case: %s", tt.name)
			} else {
				assert.Error(t, err, "Expected error for test case: %s", tt.name)
				assert.Contains(t, err.Error(), tt.expectedError, "Error message should contain expected text for test case: %s", tt.name)
			}
		})
	}
}

func TestValidateServiceAnnotations(t *testing.T) {
	const byoSecurityGroupID = "sg-123456789"
	const classicLBHostname = "my-classic-lb-1234567890.us-east-1.elb.amazonaws.com"
	const nlbHostname = "my-nlb-1234567890.elb.us-east-1.amazonaws.com"

	tests := []struct {
		name          string
		annotations   map[string]string
		servicePorts  []v1.ServicePort
		ingressStatus []v1.LoadBalancerIngress
		expectedError string
	}{
		// Valid cases - CLB (Classic Load Balancer) should allow BYO security groups
		{
			name: "CLB with BYO SG annotation - success",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerSecurityGroups: byoSecurityGroupID,
			},
			expectedError: "",
		},
		{
			name: "CLB with BYO extra SG annotation - success",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerExtraSecurityGroups: byoSecurityGroupID,
			},
			expectedError: "",
		},
		{
			name: "CLB with both BYO SG annotations - success",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerSecurityGroups:      byoSecurityGroupID,
				ServiceAnnotationLoadBalancerExtraSecurityGroups: "sg-extra123",
			},
			expectedError: "",
		},

		// Success cases - NLB with valid BYO security group annotation
		{
			name: "NLB with single valid BYO SG - success",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerType:           "nlb",
				ServiceAnnotationLoadBalancerSecurityGroups: "sg-123456789",
			},
			expectedError: "",
		},
		{
			name: "NLB with single BYO SG (different format) - success",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerType:           "nlb",
				ServiceAnnotationLoadBalancerSecurityGroups: byoSecurityGroupID,
			},
			expectedError: "",
		},
		{
			name: "NLB with BYO SG with whitespace (trimmed) - success",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerType:           "nlb",
				ServiceAnnotationLoadBalancerSecurityGroups: " sg-123456 ",
			},
			expectedError: "",
		},
		{
			name: "NLB with BYO SG with empty value - success (empty annotation, will use other config)",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerType:           "nlb",
				ServiceAnnotationLoadBalancerSecurityGroups: "",
			},
			expectedError: "",
		},
		{
			name: "NLB mixed annotations - BYO SG and other annotations - success",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerSecurityGroups: "sg-123456",
				ServiceAnnotationLoadBalancerType:           "nlb",
				ServiceAnnotationLoadBalancerInternal:       "true",
			},
			expectedError: "",
		},

		// Error cases - NLB BYO SG validation failures
		{
			name: "NLB with multiple BYO SGs - error (NLB supports only one)",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerType:           "nlb",
				ServiceAnnotationLoadBalancerSecurityGroups: "sg-123,sg-456",
			},
			expectedError: "NLB supports only one security group, got 2 security groups [sg-123 sg-456]",
		},
		{
			name: "NLB with multiple BYO SGs (3 groups) - error",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerType:           "nlb",
				ServiceAnnotationLoadBalancerSecurityGroups: "sg-123456789,sg-987654321,sg-abcdef123",
			},
			expectedError: "NLB supports only one security group, got 3 security groups",
		},
		{
			name: "NLB with invalid BYO SG format (missing sg- prefix) - error",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerType:           "nlb",
				ServiceAnnotationLoadBalancerSecurityGroups: "invalid-sg-format",
			},
			expectedError: "invalid security group ID \"invalid-sg-format\" in annotation \"service.beta.kubernetes.io/aws-load-balancer-security-groups\": security group ID must start with 'sg-'",
		},
		{
			name: "NLB with invalid BYO SG format (wrong case) - error",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerType:           "nlb",
				ServiceAnnotationLoadBalancerSecurityGroups: "SG-123ABC",
			},
			expectedError: "invalid security group ID \"SG-123ABC\" in annotation \"service.beta.kubernetes.io/aws-load-balancer-security-groups\": security group ID must start with 'sg-'",
		},
		{
			name: "NLB with invalid BYO SG format (just numbers) - error",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerType:           "nlb",
				ServiceAnnotationLoadBalancerSecurityGroups: "123456789",
			},
			expectedError: "invalid security group ID \"123456789\" in annotation \"service.beta.kubernetes.io/aws-load-balancer-security-groups\": security group ID must start with 'sg-'",
		},

		// Error cases - NLB extra SG annotation (not supported)
		{
			name: "NLB with BYO extra SG annotation - error (not supported)",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerType:                "nlb",
				ServiceAnnotationLoadBalancerExtraSecurityGroups: byoSecurityGroupID,
			},
			expectedError: "extra security group annotation \"service.beta.kubernetes.io/aws-load-balancer-extra-security-groups\" is not supported by NLB (NLB supports only one security group)",
		},
		{
			name: "NLB with both BYO SG and extra SG annotations - error (extra not supported)",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerType:                "nlb",
				ServiceAnnotationLoadBalancerSecurityGroups:      "sg-123456",
				ServiceAnnotationLoadBalancerExtraSecurityGroups: "sg-extra123",
			},
			expectedError: "extra security group annotation \"service.beta.kubernetes.io/aws-load-balancer-extra-security-groups\" is not supported by NLB (NLB supports only one security group)",
		},

		// Target group attributes validation for NLB (should succeed)
		{
			name: "NLB with target group attributes - success",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerType:                  "nlb",
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=true",
			},
			servicePorts: []v1.ServicePort{
				{Port: 80, Protocol: v1.ProtocolTCP},
			},
			expectedError: "",
		},

		// Target group attributes validation for CLB (should fail)
		{
			name: "CLB with target group attributes - error (only supported for NLB)",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=true",
			},
			expectedError: "target group attributes annotation is only supported for NLB",
		},

		// No annotations (should succeed)
		{
			name:          "no annotations - success",
			annotations:   map[string]string{},
			expectedError: "",
		},

		// No existing ingress - any type should be allowed
		{
			name:          "NLB in new service with no ingress should be allowed",
			annotations:   map[string]string{ServiceAnnotationLoadBalancerType: "nlb"},
			ingressStatus: nil,
			expectedError: "",
		},
		{
			name:          "CLB in new service with no ingress should be allowed",
			annotations:   map[string]string{},
			ingressStatus: nil,
			expectedError: "",
		},
		{
			name:          "NLB in new service with empty ingress list should be allowed",
			annotations:   map[string]string{ServiceAnnotationLoadBalancerType: "nlb"},
			ingressStatus: []v1.LoadBalancerIngress{},
			expectedError: "",
		},

		// Existing Classic LB - same type should succeed
		{
			name:        "CLB in existing service with no type annotation should be allowed",
			annotations: map[string]string{},
			ingressStatus: []v1.LoadBalancerIngress{
				{Hostname: classicLBHostname},
			},
			expectedError: "",
		},
		{
			name:        "CLB in existing service with type annotation should be allowed",
			annotations: map[string]string{ServiceAnnotationLoadBalancerType: "clb"},
			ingressStatus: []v1.LoadBalancerIngress{
				{Hostname: classicLBHostname},
			},
			expectedError: "",
		},

		// Existing NLB - same type should succeed
		{
			name:        "NLB in existing service with type annotation should be allowed",
			annotations: map[string]string{ServiceAnnotationLoadBalancerType: "nlb"},
			ingressStatus: []v1.LoadBalancerIngress{
				{Hostname: nlbHostname},
			},
			expectedError: "",
		},

		// Type change from CLB to NLB - should fail
		{
			name:        "CLB in existing service with type annotation should not be allowed to change to NLB",
			annotations: map[string]string{ServiceAnnotationLoadBalancerType: "nlb"},
			ingressStatus: []v1.LoadBalancerIngress{
				{Hostname: classicLBHostname},
			},
			expectedError: "cannot update Load Balancer Type annotation",
		},

		// Type change from NLB to CLB - should fail
		{
			name:        "NLB in existing service with type annotation should not be allowed to change to CLB",
			annotations: map[string]string{},
			ingressStatus: []v1.LoadBalancerIngress{
				{Hostname: nlbHostname},
			},
			expectedError: "cannot update Load Balancer Type annotation",
		},
		{
			name:        "NLB in existing service with type annotation should not be allowed to change to CLB",
			annotations: map[string]string{ServiceAnnotationLoadBalancerType: "clb"},
			ingressStatus: []v1.LoadBalancerIngress{
				{Hostname: nlbHostname},
			},
			expectedError: "cannot update Load Balancer Type annotation",
		},

		// Edge cases with hostname patterns
		{
			name:        "CLB in existing service with regional hostname should be allowed",
			annotations: map[string]string{},
			ingressStatus: []v1.LoadBalancerIngress{
				{Hostname: "internal-my-lb-123.eu-west-1.elb.amazonaws.com"},
			},
			expectedError: "",
		},
		{
			name:        "NLB in existing service with different region hostname should be allowed",
			annotations: map[string]string{ServiceAnnotationLoadBalancerType: "nlb"},
			ingressStatus: []v1.LoadBalancerIngress{
				{Hostname: "my-nlb-abc123.elb.ap-southeast-1.amazonaws.com"},
			},
			expectedError: "",
		},
		{
			name:        "NLB in existing service with regional hostname should not be allowed to change to CLB",
			annotations: map[string]string{},
			ingressStatus: []v1.LoadBalancerIngress{
				{Hostname: "my-nlb-abc123.elb.eu-central-1.amazonaws.com"},
			},
			expectedError: "cannot update Load Balancer Type annotation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test service with the specified ports and annotations
			service := &v1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-service",
					Namespace:   "test-namespace",
					Annotations: tt.annotations,
				},
				Spec: v1.ServiceSpec{
					Type:  v1.ServiceTypeLoadBalancer,
					Ports: tt.servicePorts,
				},
			}
			if tt.ingressStatus != nil {
				service.Status.LoadBalancer.Ingress = tt.ingressStatus
			}

			// Create validation input
			input := &awsValidationInput{
				apiService:  service,
				annotations: tt.annotations,
			}

			// Execute the validation
			err := validateServiceAnnotations(input)

			// Verify the result
			if tt.expectedError == "" {
				assert.NoError(t, err, "Expected no error for test case: %s", tt.name)
			} else {
				assert.Error(t, err, "Expected error for test case: %s", tt.name)
				assert.Contains(t, err.Error(), tt.expectedError, "Error message should contain expected text for test case: %s", tt.name)
			}
		})
	}
}
