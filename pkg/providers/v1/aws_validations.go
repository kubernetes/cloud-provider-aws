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
	"fmt"
	"strings"

	v1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
)

// validationInput is the input parameters for validations.
// TODO: ensure validations receive copy of values preventing mutation.
type awsValidationInput struct {
	apiService  *v1.Service
	annotations map[string]string
}

// ensureLoadBalancerValidation validates the Service configuration early on EnsureLoadBalancer.
// It validates the Service annotations and other constraints provided by the user are valid and supported by the controller.
// It does not validate the AWS constraints.
//
// input:
// v: awsValidationInput containing the required configuration to validate the Service object.
//
// returns:
// - error: validation errors.
func ensureLoadBalancerValidation(v *awsValidationInput) error {
	// Validate Service annotations.
	if err := validateServiceAnnotations(v); err != nil {
		return err
	}

	// TODO: migrate other validations from EnsureLoadBalancer to this function.
	return nil
}

// validateServiceAnnotations validates the service annotations constraints provided by the user
// are valid and supported by the controller.
func validateServiceAnnotations(v *awsValidationInput) error {
	isNLB := isNLB(v.annotations)

	// ServiceAnnotationLoadBalancerType
	// Load Balancer Type annotation must not be updated after creation.
	// Classic Load Balancer: hostname ends with ".elb.amazonaws.com"
	// NLB: hostname ends with ".elb.<region>.amazonaws.com"
	{
		hostIsCreated := len(v.apiService.Status.LoadBalancer.Ingress) > 0
		if hostIsCreated {
			hostIsClassic := strings.HasSuffix(v.apiService.Status.LoadBalancer.Ingress[0].Hostname, ".elb.amazonaws.com")
			// If annotation is set to NLB and hostname has classic pattern, return an error.
			if isNLB && hostIsClassic {
				return fmt.Errorf("cannot update Load Balancer Type annotation %q after creation for NLB", ServiceAnnotationLoadBalancerType)
			}
			// If annotation is set to CLB and hostname has NLB pattern, return an error.
			if !isNLB && !hostIsClassic {
				return fmt.Errorf("cannot update Load Balancer Type annotation %q after creation for Classic Load Balancer", ServiceAnnotationLoadBalancerType)
			}
		}
	}

	// ServiceAnnotationLoadBalancerSecurityGroups
	// NLB only: ensure the BYO annotations are not supported and return an error.
	// FIXME: the BYO SG for NLB implementation is blocked by https://github.com/kubernetes/cloud-provider-aws/pull/1209
	if _, hasBYOAnnotation := v.annotations[ServiceAnnotationLoadBalancerSecurityGroups]; hasBYOAnnotation {
		if isNLB {
			return fmt.Errorf("BYO security group annotation %q is not supported by NLB", ServiceAnnotationLoadBalancerSecurityGroups)
		}
	}

	// ServiceAnnotationLoadBalancerExtraSecurityGroups
	if _, hasExtraBYOAnnotation := v.annotations[ServiceAnnotationLoadBalancerExtraSecurityGroups]; hasExtraBYOAnnotation {
		if isNLB {
			return fmt.Errorf("BYO extra security group annotation %q is not supported by NLB", ServiceAnnotationLoadBalancerExtraSecurityGroups)
		}
	}

	// ServiceAnnotationLoadBalancerTargetGroupAttributes
	if _, present := v.annotations[ServiceAnnotationLoadBalancerTargetGroupAttributes]; present {
		if !isNLB {
			return fmt.Errorf("target group attributes annotation is only supported for NLB")
		}
		if err := validateServiceAnnotationTargetGroupAttributes(v); err != nil {
			return err
		}
	}
	return nil
}

// validateServiceAnnotationTargetGroupAttributes validates the target group attributes set through annotation:
// Annotation: service.beta.kubernetes.io/aws-load-balancer-target-group-attributes
//
// input:
// v: awsValidationInput containing the required configuration to validate the Service object.
//
// returns:
// - error: validation errors.
func validateServiceAnnotationTargetGroupAttributes(v *awsValidationInput) error {
	errPrefix := "error validating target group attributes"

	// Attributes are in format key=value separated by comma.
	annotationGroupAttributes := getKeyValuePropertiesFromAnnotation(v.annotations, ServiceAnnotationLoadBalancerTargetGroupAttributes)
	targetGroupAttributes := make(map[string]string, len(annotationGroupAttributes))

	for attrKey, attrValue := range annotationGroupAttributes {
		if _, ok := targetGroupAttributes[attrKey]; ok {
			return fmt.Errorf("%s: %q is set twice in the annotation", errPrefix, attrKey)
		}
		if len(attrValue) == 0 {
			return fmt.Errorf("%s: attribute value is empty for %q", errPrefix, attrKey)
		}

		switch attrKey {
		case targetGroupAttributePreserveClientIPEnabled:
			if attrValue != "true" && attrValue != "false" {
				return fmt.Errorf("%s: invalid attribute value for %q: %s", errPrefix, attrKey, attrValue)
			}
			// AWS restriction: Client IP preservation can't be disabled for UDP and TCP_UDP target groups.
			for _, port := range v.apiService.Spec.Ports {
				if (port.Protocol == v1.ProtocolUDP || port.Protocol == "TCP_UDP") && attrValue == "false" {
					return fmt.Errorf("%s: client IP preservation can't be disabled for UDP ports", errPrefix)
				}
			}
			targetGroupAttributes[attrKey] = attrValue

		case targetGroupAttributeProxyProtocolV2Enabled:
			if attrValue != "true" && attrValue != "false" {
				return fmt.Errorf("%s: invalid attribute value for %q: %s", errPrefix, attrKey, attrValue)
			}
			targetGroupAttributes[attrKey] = attrValue

		default:
			return fmt.Errorf("%s: the attribute %q is not supported by the controller or is invalid", errPrefix, attrKey)
		}
	}

	return nil
}

// canFallbackToIPv4 reports whether a Service can be provisioned as an IPv4-only Classic Load
// Balancer even when IPv6 appears in spec.ipFamilies. It returns true when the service's IP
// family policy allows an IPv4-only load balancer:
//   - nil policy or SingleStack with only IPv4 (no IPv6 requested)
//   - PreferDualStack (IPv4-only is an acceptable fallback)
//
// It returns false when the policy demands IPv6 participation:
//   - SingleStack with IPv6 in ipFamilies
//   - RequireDualStack (CLB cannot satisfy a dual-stack requirement)
func canFallbackToIPv4(service *v1.Service) bool {
	if service == nil {
		return true
	}

	policy := service.Spec.IPFamilyPolicy
	if policy == nil {
		// Implicit SingleStack: acceptable only if no IPv6 family is present.
		return !serviceRequestsIPv6(service)
	}

	switch *policy {
	case v1.IPFamilyPolicySingleStack:
		return !serviceRequestsIPv6(service)
	case v1.IPFamilyPolicyPreferDualStack:
		return true
	case v1.IPFamilyPolicyRequireDualStack:
		return false
	}

	return true
}

// validateIPFamilyInfo validates that a Service's IP Families and IP Family Policies are supported.
// Special cases:
// - Cannot have an IPv6, single stack service (AWS limitation)
// - RequireDualStack policy *must* have 2 entries in IP Family Policies
//
// input:
// service: the target v1.Service
//
// returns:
// - error: validation errors.
func validateIPFamilyInfo(service *v1.Service, ipv6Requested bool) error {
	// Sanity checks in case they're missed earlier up the call stack.
	if service == nil {
		return fmt.Errorf("service required")
	}

	// Make sure we have a usable zero value for IPFamilies
	if service.Spec.IPFamilies == nil {
		service.Spec.IPFamilies = make([]v1.IPFamily, 0)
	}

	// If we somehow got an unset IP familiy policy, (most likely in tests) set it explicitly for our use.
	ipFamilyPolicy := service.Spec.IPFamilyPolicy
	if ipFamilyPolicy == nil {
		ipFamilyPolicy = ptr.To(v1.IPFamilyPolicySingleStack)
	}

	// Kube server will ensure that Spec.IPFamilyPolicy and Spec.IPFamilies are populated
	// See kubernetes/pkg/registry/core/service/storage/{alloc,storage}.go
	ipFamilies := service.Spec.IPFamilies
	if len(ipFamilies) >= 3 {
		return fmt.Errorf("ipFamilies requires 1 or 2 entries. got %d", len(ipFamilies))
	}

	// Single stack IPv6 not supported by AWS
	if *ipFamilyPolicy == v1.IPFamilyPolicySingleStack && ipv6Requested {
		return fmt.Errorf("single stack IPv6 is not supported for network load balancers")
	}

	// RequireDualStack must have 2 entries
	if *ipFamilyPolicy == v1.IPFamilyPolicyRequireDualStack && len(ipFamilies) != 2 {
		return fmt.Errorf("policy %s requires 2 entries in the ipFamilies field. got %d", v1.IPFamilyPolicyRequireDualStack, len(ipFamilies))
	}

	// PreferDualStack supports 1 or 2 entries.
	if *ipFamilyPolicy == v1.IPFamilyPolicyPreferDualStack && (len(ipFamilies) >= 3) {
		return fmt.Errorf("policy %s requires 1 or 2 entries. got %d", v1.IPFamilyPolicyPreferDualStack, len(ipFamilies))
	}

	return nil
}
