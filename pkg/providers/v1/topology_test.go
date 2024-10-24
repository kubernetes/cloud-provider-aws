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
	"testing"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/stretchr/testify/mock"
)

func TestGetNodeTopology(t *testing.T) {
	t.Run("Should handle unsupported regions and utilize cache", func(t *testing.T) {
		mockedEC2API := newMockedEC2API()
		topologyManager := newInstanceTopologyManager(&awsSdkEC2{ec2: mockedEC2API})

		mockedEC2API.On("DescribeInstanceTopologyPages", mock.Anything).Return(nil,
			awserr.New("UnsupportedOperation", "Not supported in region", nil))

		// Loop multiple times to check cache use
		for i := 0; i < 2; i++ {
			topology, err := topologyManager.getNodeTopology("some-type", "some-region", "some-id")
			if err != nil {
				t.Errorf("Should not error getting node topology: %s", err)
			}
			if topology != nil {
				t.Errorf("Should not be returning a topology: %v", topology)
			}
		}

		mockedEC2API.AssertNumberOfCalls(t, "DescribeInstanceTopologyPages", 1)
	})

	t.Run("Should handle unsupported instance types and utilize cache", func(t *testing.T) {
		mockedEC2API := newMockedEC2API()
		topologyManager := newInstanceTopologyManager(&awsSdkEC2{ec2: mockedEC2API})

		mockedEC2API.On("DescribeInstanceTopologyPages", mock.Anything).Return(&ec2.DescribeInstanceTopologyOutput{}, nil)

		// Loop multiple times to check cache use
		for i := 0; i < 2; i++ {
			topology, err := topologyManager.getNodeTopology("some-type", "some-region", "some-id")
			if err != nil {
				t.Errorf("Should not error getting node topology: %s", err)
			}
			if topology != nil {
				t.Errorf("Should not be returning a topology: %v", topology)
			}
		}

		mockedEC2API.AssertNumberOfCalls(t, "DescribeInstanceTopologyPages", 1)
	})

	t.Run("Should handle missing permissions to call DescribeInstanceTopology", func(t *testing.T) {
		mockedEC2API := newMockedEC2API()
		topologyManager := newInstanceTopologyManager(&awsSdkEC2{ec2: mockedEC2API})

		mockedEC2API.On("DescribeInstanceTopologyPages", mock.Anything).Return(nil,
			awserr.New("UnauthorizedOperation", "Update your perms", nil))

		// Loop multiple times to check cache use
		for i := 0; i < 2; i++ {
			topology, err := topologyManager.getNodeTopology("some-type", "some-region", "some-id")
			if err != nil {
				t.Errorf("Should not error getting node topology: %s", err)
			}
			if topology != nil {
				t.Errorf("Should not be returning a topology: %v", topology)
			}
		}

		mockedEC2API.AssertNumberOfCalls(t, "DescribeInstanceTopologyPages", 2)
	})

	t.Run("Should handle exceeding request limits for DescribeInstanceTopology", func(t *testing.T) {
		mockedEC2API := newMockedEC2API()
		topologyManager := newInstanceTopologyManager(&awsSdkEC2{ec2: mockedEC2API})

		mockedEC2API.On("DescribeInstanceTopologyPages", mock.Anything).Return(nil,
			awserr.New("RequestLimitExceeded", "Slow down!", nil))

		// Loop multiple times to check cache use
		for i := 0; i < 2; i++ {
			topology, err := topologyManager.getNodeTopology("some-type", "some-region", "some-id")
			if err != nil {
				t.Errorf("Should not error getting node topology: %s", err)
			}
			if topology != nil {
				t.Errorf("Should not be returning a topology: %v", topology)
			}
		}

		mockedEC2API.AssertNumberOfCalls(t, "DescribeInstanceTopologyPages", 2)
	})

	t.Run("Should return unhandled errors", func(t *testing.T) {
		mockedEC2API := newMockedEC2API()
		topologyManager := newInstanceTopologyManager(&awsSdkEC2{ec2: mockedEC2API})

		mockedEC2API.On("DescribeInstanceTopologyPages", mock.Anything).Return(nil,
			awserr.New("NOPE", "Nice try.", nil))

		_, err := topologyManager.getNodeTopology("some-type", "some-region", "some-id")
		if err == nil {
			t.Errorf("Should have gotten an error")
		}

		mockedEC2API.AssertNumberOfCalls(t, "DescribeInstanceTopologyPages", 1)
	})
}
