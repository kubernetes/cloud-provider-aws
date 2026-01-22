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

	// Validate ipFamilyPolicy and ipFamilies
	if err := validateIPFamilyPolicy(v); err != nil {
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

	if _, present := v.annotations[ServiceAnnotationLoadBalancerIPAddressType]; present {
		if !isNLB {
			return fmt.Errorf("ip address type annotation is only supported for NLB")
		}
	}

	if _, present := v.annotations[ServiceAnnotationLoadBalancerTargetGroupIPAddressType]; present {
		if !isNLB {
			return fmt.Errorf("target group ip address type annotation is only supported for NLB")
		}
	}
	return nil
}

// validateIPFamilyPolicy validates the ipFamilyPolicy and ipFamilies fields in the Service spec.
func validateIPFamilyPolicy(v *awsValidationInput) error {
	isNLB := isNLB(v.annotations)

	// Validate ipFamilyPolicy and ipFamilies
	if v.apiService.Spec.IPFamilyPolicy != nil {
		switch *v.apiService.Spec.IPFamilyPolicy {
		case v1.IPFamilyPolicyRequireDualStack:
			// RequireDualStack is only supported for NLB
			if !isNLB {
				return fmt.Errorf("ipFamilyPolicy RequireDualStack is only supported for NLB (set annotation service.beta.kubernetes.io/aws-load-balancer-type: nlb)")
			}

			// Ensure both IPv4 and IPv6 are specified
			hasIPv4, hasIPv6 := false, false
			for _, family := range v.apiService.Spec.IPFamilies {
				switch family {
				case v1.IPv4Protocol:
					hasIPv4 = true
				case v1.IPv6Protocol:
					hasIPv6 = true
				}
				// If we somehow get more than 2 entries, we don't need to iterate over them.
				if hasIPv4 && hasIPv6 {
					break
				}
			}
			if !hasIPv4 || !hasIPv6 {
				return fmt.Errorf("ipFamilyPolicy RequireDualStack requires both IPv4 and IPv6 in spec.ipFamilies")
			}

		case v1.IPFamilyPolicySingleStack:
			// SingleStack with IPv6-only is not supported (AWS limitation)
			if len(v.apiService.Spec.IPFamilies) == 1 && v.apiService.Spec.IPFamilies[0] == v1.IPv6Protocol {
				return fmt.Errorf("IPv6-only load balancers are not supported by AWS (use ipFamilyPolicy: PreferDualStack with ipFamilies: [IPv6, IPv4] instead)")
			}

		case v1.IPFamilyPolicyPreferDualStack:
			// PreferDualStack is supported for both CLB (will only use IPv4) and NLB
			// No additional validation needed
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
