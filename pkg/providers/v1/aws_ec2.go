/*
Copyright 2024 The Kubernetes Authors.

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

	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
)

// awsSdkEC2 is an implementation of the EC2 interface, backed by aws-sdk-go
type awsSdkEC2 struct {
	ec2 ec2iface.EC2API
}

func (s *awsSdkEC2) DescribeInstanceTopology(request *ec2.DescribeInstanceTopologyInput) ([]*ec2.InstanceTopology, error) {
	var topologies []*ec2.InstanceTopology

	err := s.ec2.DescribeInstanceTopologyPages(request,
		func(page *ec2.DescribeInstanceTopologyOutput, lastPage bool) bool {
			topologies = append(topologies, page.Instances...)
			// Don't short-circuit. Just go through all of the pages
			return false
		})

	return topologies, err
}
