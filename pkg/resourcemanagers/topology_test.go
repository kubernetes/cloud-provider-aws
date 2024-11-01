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

package resourcemanagers

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/mock"
	"k8s.io/cloud-provider-aws/pkg/services"
)

func TestGetNodeTopology(t *testing.T) {
	t.Run("Should handle unsupported regions and utilize cache", func(t *testing.T) {
		mockedEc2SdkV2 := services.MockedEc2SdkV2{}
		topologyManager := NewInstanceTopologyManager(&mockedEc2SdkV2)

		mockedEc2SdkV2.On("DescribeInstanceTopology", mock.Anything, mock.Anything).Return(nil,
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

		mockedEc2SdkV2.AssertNumberOfCalls(t, "DescribeInstanceTopology", 1)
	})

	t.Run("Should handle unsupported instance types and utilize cache", func(t *testing.T) {
		mockedEc2SdkV2 := services.MockedEc2SdkV2{}
		topologyManager := NewInstanceTopologyManager(&mockedEc2SdkV2)

		mockedEc2SdkV2.On("DescribeInstanceTopology", mock.Anything, mock.Anything).Return([]types.InstanceTopology{}, nil)

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

		mockedEc2SdkV2.AssertNumberOfCalls(t, "DescribeInstanceTopology", 1)
	})

	t.Run("Should handle missing permissions to call DescribeInstanceTopology", func(t *testing.T) {
		mockedEc2SdkV2 := services.MockedEc2SdkV2{}
		topologyManager := NewInstanceTopologyManager(&mockedEc2SdkV2)

		mockedEc2SdkV2.On("DescribeInstanceTopology", mock.Anything, mock.Anything).Return(nil,
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

		mockedEc2SdkV2.AssertNumberOfCalls(t, "DescribeInstanceTopology", 2)
	})

	t.Run("Should handle exceeding request limits for DescribeInstanceTopology", func(t *testing.T) {
		mockedEc2SdkV2 := services.MockedEc2SdkV2{}
		topologyManager := NewInstanceTopologyManager(&mockedEc2SdkV2)

		mockedEc2SdkV2.On("DescribeInstanceTopology", mock.Anything, mock.Anything).Return(nil,
			services.NewMockAPIError("RequestLimitExceeded", "Slow down!"))

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

		mockedEc2SdkV2.AssertNumberOfCalls(t, "DescribeInstanceTopology", 2)
	})

	t.Run("Should return unhandled errors", func(t *testing.T) {
		mockedEc2SdkV2 := services.MockedEc2SdkV2{}
		topologyManager := NewInstanceTopologyManager(&mockedEc2SdkV2)

		mockedEc2SdkV2.On("DescribeInstanceTopology", mock.Anything, mock.Anything).Return(nil,
			services.NewMockAPIError("NOPE", "Nice try."))

		_, err := topologyManager.GetNodeTopology(context.TODO(), "some-type", "some-region", "some-id")
		if err == nil {
			t.Errorf("Should have gotten an error")
		}

		mockedEc2SdkV2.AssertNumberOfCalls(t, "DescribeInstanceTopology", 1)
	})
}
