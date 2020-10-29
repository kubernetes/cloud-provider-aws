/*
Copyright 2020 The Kubernetes Authors.

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

// Package v2 is an out-of-tree only implementation of the AWS cloud provider.
// It is not compatible with v1 and should only be used on new clusters.
package v2

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/elb"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
)

func isEqualIntPointer(l, r *int64) bool {
	if l == nil {
		return r == nil
	}
	if r == nil {
		return l == nil
	}
	return *l == *r
}

func isEqualStringPointer(l, r *string) bool {
	if l == nil {
		return r == nil
	}
	if r == nil {
		return l == nil
	}
	return *l == *r
}

func isSubnetPublic(rt []*ec2.RouteTable, subnetID string) (bool, error) {
	var subnetTable *ec2.RouteTable
	for _, table := range rt {
		for _, assoc := range table.Associations {
			if aws.StringValue(assoc.SubnetId) == subnetID {
				subnetTable = table
				break
			}
		}
	}

	if subnetTable == nil {
		// If there is no explicit association, the subnet will be implicitly
		// associated with the VPC's main routing table.
		for _, table := range rt {
			for _, assoc := range table.Associations {
				if aws.BoolValue(assoc.Main) == true {
					klog.V(4).Infof("Assuming implicit use of main routing table %s for %s",
						aws.StringValue(table.RouteTableId), subnetID)
					subnetTable = table
					break
				}
			}
		}
	}

	if subnetTable == nil {
		return false, fmt.Errorf("could not locate routing table for subnet %s", subnetID)
	}

	for _, route := range subnetTable.Routes {
		// There is no direct way in the AWS API to determine if a subnet is public or private.
		// A public subnet is one which has an internet gateway route
		// we look for the gatewayId and make sure it has the prefix of igw to differentiate
		// from the default in-subnet route which is called "local"
		// or other virtual gateway (starting with vgv)
		// or vpc peering connections (starting with pcx).
		if strings.HasPrefix(aws.StringValue(route.GatewayId), "igw") {
			return true, nil
		}
	}

	return false, nil
}

func stringSetToPointers(in sets.String) []*string {
	if in == nil {
		return nil
	}
	out := make([]*string, 0, len(in))
	for k := range in {
		out = append(out, aws.String(k))
	}
	return out
}

func stringSetFromPointers(in []*string) sets.String {
	if in == nil {
		return nil
	}
	out := sets.NewString()
	for i := range in {
		out.Insert(aws.StringValue(in[i]))
	}
	return out
}

func elbListenersAreEqual(actual, expected *elb.Listener) bool {
	if !elbProtocolsAreEqual(actual.Protocol, expected.Protocol) {
		return false
	}
	if !elbProtocolsAreEqual(actual.InstanceProtocol, expected.InstanceProtocol) {
		return false
	}
	if aws.Int64Value(actual.InstancePort) != aws.Int64Value(expected.InstancePort) {
		return false
	}
	if aws.Int64Value(actual.LoadBalancerPort) != aws.Int64Value(expected.LoadBalancerPort) {
		return false
	}
	if !awsArnEquals(actual.SSLCertificateId, expected.SSLCertificateId) {
		return false
	}
	return true
}

func elbProtocolsAreEqual(l, r *string) bool {
	if l == nil || r == nil {
		return l == r
	}
	return strings.EqualFold(aws.StringValue(l), aws.StringValue(r))
}

// awsArnEquals checks if two ARN strings are considered the same
// Comparison is case insensitive
func awsArnEquals(l, r *string) bool {
	if l == nil || r == nil {
		return l == r
	}
	return strings.EqualFold(aws.StringValue(l), aws.StringValue(r))
}

func proxyProtocolEnabled(backend *elb.BackendServerDescription) bool {
	for _, policy := range backend.PolicyNames {
		if aws.StringValue(policy) == ProxyProtocolPolicyName {
			return true
		}
	}

	return false
}