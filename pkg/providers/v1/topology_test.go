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
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/mock"
	"k8s.io/cloud-provider-aws/pkg/providers/v1/config"
	"k8s.io/cloud-provider-aws/pkg/services"
)

func TestDoesInstanceTypeRequireResponse(t *testing.T) {
	instanceTypesRequireResponse := []string{
		"hpc6a.48xlarge", "hpc6id.32xlarge", "hpc7a.12xlarge", "hpc7a.24xlarge", "hpc7a.48xlarge", "hpc7a.96xlarge", "hpc7g.4xlarge", "hpc7g.8xlarge", "hpc7g.16xlarge",
		"p3dn.24xlarge", "p4d.24xlarge", "p4de.24xlarge", "p5.48xlarge", "p5e.48xlarge", "p5en.48xlarge",
		"trn1.2xlarge", "trn1.32xlarge", "trn1n.32xlarge", "trn2.48xlarge", "trn2u.48xlarge", "inf2.48xlarge",
	}
	t.Run("Should return true for instance types that require response", func(t *testing.T) {
		topologyManager := NewInstanceTopologyManager(nil, &config.CloudConfig{})
		for _, instanceType := range instanceTypesRequireResponse {
			if !topologyManager.DoesInstanceTypeRequireResponse(instanceType) {
				t.Errorf("Expected instance type %s to require response", instanceType)
			}
		}
	})

	instanceTypesNoRequireResponse := []string{
		"m6g.large", "t3.large", "c3.large", "m5.large",
	}
	t.Run("Should return false for instance types that don't require response", func(t *testing.T) {
		topologyManager := NewInstanceTopologyManager(nil, &config.CloudConfig{})
		for _, instanceType := range instanceTypesNoRequireResponse {
			if topologyManager.DoesInstanceTypeRequireResponse(instanceType) {
				t.Errorf("Expected instance type %s to not require response", instanceType)
			}
		}
	})

	t.Run("Should allow overriding the instance type requires response regex", func(t *testing.T) {
		var cfg = config.CloudConfig{}
		cfg.Global.SupportedTopologyInstanceTypePattern = "t3.large"

		topologyManager := NewInstanceTopologyManager(nil, &cfg)
		if !topologyManager.DoesInstanceTypeRequireResponse("t3.large") {
			t.Errorf("Expected instance type t3.large to require response")
		}
		if topologyManager.DoesInstanceTypeRequireResponse("trn2.48xlarge") {
			t.Errorf("Expected instance type trn2.48xlarge to require response")
		}
	})
}

func TestGetNodeTopology(t *testing.T) {
	t.Run("Should skip nodes that don't have instance type set", func(t *testing.T) {
		mockedEC2 := MockedFakeEC2{}
		topologyManager := NewInstanceTopologyManager(&mockedEC2, &config.CloudConfig{})
		// Loop multiple times to check cache use
		topology, err := topologyManager.GetNodeTopology(context.TODO(), "" /* empty instance type */, "some-region", "some-id")
		if err != nil {
			t.Errorf("Should not error getting node topology: %s", err)
		}
		if topology != nil {
			t.Errorf("Should not be returning a topology: %v", topology)
		}

		mockedEC2.AssertNumberOfCalls(t, "DescribeInstanceTopology", 0)
	})

	t.Run("Should handle unsupported regions and utilize cache", func(t *testing.T) {
		mockedEC2 := MockedFakeEC2{}
		topologyManager := NewInstanceTopologyManager(&mockedEC2, &config.CloudConfig{})

		mockedEC2.On("DescribeInstanceTopology", mock.Anything, mock.Anything).Return(nil,
			services.NewMockAPIError("UnsupportedOperation", "Not supported in region"))

		// Loop multiple times to check cache use
		for i := 0; i < 2; i++ {
			topology, err := topologyManager.GetNodeTopology(context.TODO(), "some-type", "some-region", "some-id")
			if err != nil {
				t.Errorf("Should not error getting node topology: %s", err)
			}
			if topology != nil {
				t.Errorf("Should not be returning a topology: %v", topology)
			}
		}

		mockedEC2.AssertNumberOfCalls(t, "DescribeInstanceTopology", 1)
	})

	t.Run("Should handle unsupported instance types and utilize cache", func(t *testing.T) {
		mockedEC2 := MockedFakeEC2{}
		topologyManager := NewInstanceTopologyManager(&mockedEC2, &config.CloudConfig{})

		mockedEC2.On("DescribeInstanceTopology", mock.Anything, mock.Anything).Return([]types.InstanceTopology{}, nil)

		// Loop multiple times to check cache use
		for i := 0; i < 2; i++ {
			topology, err := topologyManager.GetNodeTopology(context.TODO(), "some-type", "some-region", "some-id")
			if err != nil {
				t.Errorf("Should not error getting node topology: %s", err)
			}
			if topology != nil {
				t.Errorf("Should not be returning a topology: %v", topology)
			}
		}

		mockedEC2.AssertNumberOfCalls(t, "DescribeInstanceTopology", 1)
	})

	t.Run("Should handle unsupported instance IDs and utilize cache", func(t *testing.T) {
		mockedEC2 := MockedFakeEC2{}
		topologyManager := NewInstanceTopologyManager(&mockedEC2, &config.CloudConfig{})

		mockedEC2.On("DescribeInstanceTopology", mock.Anything, mock.Anything).Return([]types.InstanceTopology{}, nil)

		// Loop multiple times to check cache use
		for i := 0; i < 2; i++ {
			// Use instance type that expects a response.
			topology, err := topologyManager.GetNodeTopology(context.TODO(), "trn2.48xlarge", "some-region", "some-id")
			if err != nil {
				t.Errorf("Should not error getting node topology: %s", err)
			}
			if topology != nil {
				t.Errorf("Should not be returning a topology: %v", topology)
			}
		}

		mockedEC2.AssertNumberOfCalls(t, "DescribeInstanceTopology", 1)
	})

	t.Run("Should handle missing permissions to call DescribeInstanceTopology", func(t *testing.T) {
		mockedEC2 := MockedFakeEC2{}
		topologyManager := NewInstanceTopologyManager(&mockedEC2, &config.CloudConfig{})

		mockedEC2.On("DescribeInstanceTopology", mock.Anything, mock.Anything).Return(nil,
			services.NewMockAPIError("UnauthorizedOperation", "Update your perms"))

		// Loop multiple times to check cache use
		for i := 0; i < 2; i++ {
			topology, err := topologyManager.GetNodeTopology(context.TODO(), "some-type", "some-region", "some-id")
			if err != nil {
				t.Errorf("Should not error getting node topology: %s", err)
			}
			if topology != nil {
				t.Errorf("Should not be returning a topology: %v", topology)
			}
		}

		mockedEC2.AssertNumberOfCalls(t, "DescribeInstanceTopology", 1)
	})

	t.Run("Should return error when exceeding request limits for DescribeInstanceTopology", func(t *testing.T) {
		mockedEC2 := MockedFakeEC2{}
		topologyManager := NewInstanceTopologyManager(&mockedEC2, &config.CloudConfig{})

		mockedEC2.On("DescribeInstanceTopology", mock.Anything, mock.Anything).Return(nil,
			services.NewMockAPIError("RequestLimitExceeded", "Slow down!"))

		// Loop multiple times to check cache use
		for i := 0; i < 2; i++ {
			_, err := topologyManager.GetNodeTopology(context.TODO(), "some-type", "some-region", "some-id")
			if err == nil {
				t.Errorf("Should return error getting node topology: %s", err)
			}
		}

		mockedEC2.AssertNumberOfCalls(t, "DescribeInstanceTopology", 2)
	})

	t.Run("Should return unhandled errors", func(t *testing.T) {
		mockedEC2 := MockedFakeEC2{}
		topologyManager := NewInstanceTopologyManager(&mockedEC2, &config.CloudConfig{})

		mockedEC2.On("DescribeInstanceTopology", mock.Anything, mock.Anything).Return(nil,
			services.NewMockAPIError("NOPE", "Nice try."))

		_, err := topologyManager.GetNodeTopology(context.TODO(), "some-type", "some-region", "some-id")
		if err == nil {
			t.Errorf("Should have gotten an error")
		}

		mockedEC2.AssertNumberOfCalls(t, "DescribeInstanceTopology", 1)
	})
}
