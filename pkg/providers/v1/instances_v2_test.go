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
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	v1 "k8s.io/api/core/v1"
	"k8s.io/cloud-provider-aws/pkg/services"
)

func TestGetProviderId(t *testing.T) {
	for _, tc := range []struct {
		name               string
		instanceID         string
		node               v1.Node
		expectedProviderID string
	}{
		{
			name:       "ProviderID already set should be returned",
			instanceID: "i-00000000000000000",
			node: v1.Node{
				Spec: v1.NodeSpec{
					ProviderID: "obviously-custom-id",
				},
			},
			expectedProviderID: "obviously-custom-id",
		},
		{
			name:       "Should get ProviderID if not already set",
			instanceID: "i-00000000000000001",
			node: v1.Node{
				Spec: v1.NodeSpec{},
			},
			expectedProviderID: "aws:///us-west-2a/i-00000000000000001",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			instance := makeMinimalInstance(tc.instanceID)
			c, _ := mockInstancesResp(&instance, []*ec2types.Instance{&instance})

			result, err := c.getProviderID(context.TODO(), &tc.node)
			if err != nil {
				t.Errorf("Should not error getting ProviderID: %s", err)
			}

			if result != tc.expectedProviderID {
				t.Errorf("Expected ProviderID to be %s. Got %s", tc.expectedProviderID, result)
			}
		})
	}
}

func TestInstanceExists(t *testing.T) {
	for _, tc := range []struct {
		name           string
		instanceExists bool
		instanceState  ec2types.InstanceStateName
		expectedExists bool
	}{
		{
			name:           "Should return false when instance is not found",
			instanceExists: false,
			instanceState:  "",
			expectedExists: false,
		},
		{
			name:           "Should return true when instance is found and running",
			instanceExists: true,
			instanceState:  ec2types.InstanceStateNameRunning,
			expectedExists: true,
		},
		{
			name:           "Should return false when instance is found but terminated",
			instanceExists: true,
			instanceState:  ec2types.InstanceStateNameTerminated,
			expectedExists: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := getCloudWithMockedDescribeInstances(tc.instanceExists, tc.instanceState, "i-abc")

			result, err := c.InstanceExists(context.TODO(), &v1.Node{
				Spec: v1.NodeSpec{
					ProviderID: "aws:///us-west-2c/1abc-2def/i-abc",
				},
			})

			assert.Nil(t, err)
			if tc.expectedExists {
				assert.True(t, result)
			} else {
				assert.False(t, result)
			}
		})
	}
}

func TestInstanceShutdown(t *testing.T) {
	for _, tc := range []struct {
		name             string
		instanceExists   bool
		instanceState    ec2types.InstanceStateName
		expectedShutdown bool
	}{
		{
			name:             "Should return false when instance is found and running",
			instanceExists:   true,
			instanceState:    ec2types.InstanceStateNameRunning,
			expectedShutdown: false,
		},
		{
			name:             "Should return false when instance is found and terminated",
			instanceExists:   true,
			instanceState:    ec2types.InstanceStateNameTerminated,
			expectedShutdown: false,
		},
		{
			name:             "Should return true when instance is found and stopped",
			instanceExists:   true,
			instanceState:    ec2types.InstanceStateNameStopped,
			expectedShutdown: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := getCloudWithMockedDescribeInstances(tc.instanceExists, tc.instanceState, "i-abc")

			result, err := c.InstanceShutdown(context.TODO(), &v1.Node{
				Spec: v1.NodeSpec{
					ProviderID: "aws:///us-west-2c/1abc-2def/i-abc",
				},
			})

			assert.Nil(t, err)
			if tc.expectedShutdown {
				assert.True(t, result)
			} else {
				assert.False(t, result)
			}
		})
	}
}

func TestInstanceMetadata(t *testing.T) {
	t.Run("Should return populated InstanceMetadata", func(t *testing.T) {
		instance := makeInstance("i-00000000000000000", "192.168.0.1", "1.2.3.4", "instance-same.ec2.internal", "instance-same.ec2.external", nil, true)
		c, _ := mockInstancesResp(&instance, []*ec2types.Instance{&instance})
		var mockedTopologyManager MockedInstanceTopologyManager
		c.instanceTopologyManager = &mockedTopologyManager
		mockedTopologyManager.On("GetNodeTopology", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&ec2types.InstanceTopology{
			AvailabilityZone: aws.String("us-west-2b"),
			GroupName:        new(string),
			InstanceId:       aws.String("i-123456789"),
			InstanceType:     new(string),
			NetworkNodes:     []string{"nn-123456789", "nn-234567890", "nn-345678901"},
			ZoneId:           aws.String("az2"),
		}, nil)
		node := &v1.Node{
			Spec: v1.NodeSpec{
				ProviderID: fmt.Sprintf("aws:///us-west-2c/1abc-2def/%s", *instance.InstanceId),
			},
		}

		result, err := c.InstanceMetadata(context.TODO(), node)
		if err != nil {
			t.Errorf("Should not error getting InstanceMetadata: %s", err)
		}

		mockedTopologyManager.AssertNumberOfCalls(t, "GetNodeTopology", 1)
		assert.Equal(t, "aws:///us-west-2c/1abc-2def/i-00000000000000000", result.ProviderID)
		assert.Equal(t, "c3.large", result.InstanceType)
		assert.Equal(t, []v1.NodeAddress{
			{Type: "InternalIP", Address: "192.168.0.1"},
			{Type: "ExternalIP", Address: "1.2.3.4"},
			{Type: "InternalDNS", Address: "instance-same.ec2.internal"},
			{Type: "Hostname", Address: "instance-same.ec2.internal"},
			{Type: "ExternalDNS", Address: "instance-same.ec2.external"},
		}, result.NodeAddresses)
		assert.Equal(t, "us-west-2a", result.Zone)
		assert.Equal(t, "us-west-2", result.Region)
		assert.Equal(t, map[string]string{
			LabelZoneID:                  "az1",
			LabelNetworkNodePrefix + "1": "nn-123456789",
			LabelNetworkNodePrefix + "2": "nn-234567890",
			LabelNetworkNodePrefix + "3": "nn-345678901",
		}, result.AdditionalLabels)
	})

	t.Run("Should skip additional labels if already set", func(t *testing.T) {
		instance := makeInstance("i-00000000000000000", "192.168.0.1", "1.2.3.4", "instance-same.ec2.internal", "instance-same.ec2.external", nil, true)
		c, _ := mockInstancesResp(&instance, []*ec2types.Instance{&instance})
		var mockedTopologyManager MockedInstanceTopologyManager
		c.instanceTopologyManager = &mockedTopologyManager
		node := &v1.Node{
			Spec: v1.NodeSpec{
				ProviderID: fmt.Sprintf("aws:///us-west-2c/1abc-2def/%s", *instance.InstanceId),
			},
		}
		// Set labels to skip attempts to update them
		node.Labels = map[string]string{
			LabelZoneID:                  "az1",
			LabelNetworkNodePrefix + "1": "nn-123456789",
			LabelNetworkNodePrefix + "2": "nn-234567890",
			LabelNetworkNodePrefix + "3": "nn-345678901",
		}

		result, err := c.InstanceMetadata(context.TODO(), node)
		if err != nil {
			t.Errorf("Should not error getting InstanceMetadata: %s", err)
		}

		mockedTopologyManager.AssertNumberOfCalls(t, "GetNodeTopology", 0)
		// Validate that labels are unchanged.
		assert.Equal(t, map[string]string{}, result.AdditionalLabels)
	})

	t.Run("Should swallow errors if getting node topology fails if instance type not expected to be supported", func(t *testing.T) {
		instance := makeInstance("i-00000000000000000", "192.168.0.1", "1.2.3.4", "instance-same.ec2.internal", "instance-same.ec2.external", nil, true)
		c, _ := mockInstancesResp(&instance, []*ec2types.Instance{&instance})
		var mockedTopologyManager MockedInstanceTopologyManager
		c.instanceTopologyManager = &mockedTopologyManager
		mockedTopologyManager.On("GetNodeTopology", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil,
			services.NewMockAPIError("InvalidParameterValue", "Nope."))
		mockedTopologyManager.On("DoesInstanceTypeRequireResponse", mock.Anything).Return(false)
		node := &v1.Node{
			Spec: v1.NodeSpec{
				ProviderID: fmt.Sprintf("aws:///us-west-2c/1abc-2def/%s", *instance.InstanceId),
			},
		}

		result, err := c.InstanceMetadata(context.TODO(), node)
		if err != nil {
			t.Errorf("Should not error getting InstanceMetadata: %s", err)
		}

		mockedTopologyManager.AssertNumberOfCalls(t, "GetNodeTopology", 1)
		assert.Equal(t, map[string]string{
			LabelZoneID: "az1",
		}, result.AdditionalLabels)
	})

	t.Run("Should not swallow errors if getting node topology fails if instance type is expected to be supported", func(t *testing.T) {
		instance := makeInstance("i-00000000000000000", "192.168.0.1", "1.2.3.4", "instance-same.ec2.internal", "instance-same.ec2.external", nil, true)
		c, _ := mockInstancesResp(&instance, []*ec2types.Instance{&instance})
		var mockedTopologyManager MockedInstanceTopologyManager
		c.instanceTopologyManager = &mockedTopologyManager
		mockedTopologyManager.On("GetNodeTopology", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil,
			services.NewMockAPIError("InvalidParameterValue", "Nope."))
		mockedTopologyManager.On("DoesInstanceTypeRequireResponse", mock.Anything).Return(true)
		node := &v1.Node{
			Spec: v1.NodeSpec{
				ProviderID: fmt.Sprintf("aws:///us-west-2c/1abc-2def/%s", *instance.InstanceId),
			},
		}

		_, err := c.InstanceMetadata(context.TODO(), node)
		if err == nil {
			t.Error("Should error getting InstanceMetadata but succeeded.")
		}

		mockedTopologyManager.AssertNumberOfCalls(t, "GetNodeTopology", 1)
	})

	t.Run("Should limit ec2:DescribeInstances calls to a single request per instance", func(t *testing.T) {
		instance := makeInstance("i-00000000000001234", "192.168.0.1", "1.2.3.4", "instance-same.ec2.internal", "instance-same.ec2.external", nil, true)
		c, awsServices := mockInstancesResp(&instance, []*ec2types.Instance{&instance})

		// Add mock for DescribeInstanceTopology on the EC2 mock
		awsServices.ec2.(*MockedFakeEC2).On("DescribeInstanceTopology", mock.Anything, mock.Anything).Return([]ec2types.InstanceTopology{
			{
				AvailabilityZone: aws.String("us-west-2b"),
				GroupName:        new(string),
				InstanceId:       aws.String("i-00000000000001234"),
				InstanceType:     new(string),
				NetworkNodes:     []string{"nn-123456789", "nn-234567890", "nn-345678901"},
				ZoneId:           aws.String("az2"),
			},
		}, nil)

		node := &v1.Node{
			Spec: v1.NodeSpec{
				ProviderID: fmt.Sprintf("aws:///us-west-2c/%s", *instance.InstanceId),
			},
		}
		instanceMetadataDescribeInstances := fmt.Sprintf("%s:%s:%s", "ec2", "DescribeInstances", *instance.InstanceId)
		delete(awsServices.callCounts, instanceMetadataDescribeInstances)
		_, err := c.InstanceMetadata(context.TODO(), node)
		if err != nil {
			t.Errorf("Should not error getting InstanceMetadata: %s", err)
		}
		assert.Equal(t, awsServices.callCounts[instanceMetadataDescribeInstances], 1)
	})
}

func TestDescribeInstanceBatching(t *testing.T) {
	mockedEC2API := newMockedEC2API()
	batcher := newdescribeInstanceBatcher(context.Background(), &awsSdkEC2{ec2: mockedEC2API})

	mockedEC2API.On("DescribeInstances", mock.Anything).Return(&ec2.DescribeInstancesOutput{
		Reservations: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{
						InstanceId: aws.String("Test-1"),
					},
					{
						InstanceId: aws.String("Test-2"),
					},
					{
						InstanceId: aws.String("Test-3"),
					},
				},
			},
		},
	}, nil)

	type result struct {
		input  string
		output []*ec2types.Instance
		err    error
	}

	// Add extra space to channel so that we can ensure there were only 3 responses
	resCh := make(chan result, 5)
	helper := func(wg *sync.WaitGroup, input string) {
		defer wg.Done()
		res, err := batcher.DescribeInstances(context.Background(), &ec2.DescribeInstancesInput{InstanceIds: []string{input}})
		resCh <- result{input: input, output: res, err: err}
	}

	wg := sync.WaitGroup{}
	wg.Add(3)
	go helper(&wg, "Test-1")
	go helper(&wg, "Test-2")
	go helper(&wg, "Test-3")
	wg.Wait()
	close(resCh)

	assert.Len(t, resCh, 3)
	for res := range resCh {
		assert.NoError(t, res.err)
		assert.Len(t, res.output, 1)
		assert.Equal(t, res.input, *res.output[0].InstanceId)
	}

	mockedEC2API.AssertNumberOfCalls(t, "DescribeInstances", 1)
}

func getCloudWithMockedDescribeInstances(instanceExists bool, instanceState ec2types.InstanceStateName, instanceID string) *Cloud {
	mockedEC2API := newMockedEC2API()
	c := &Cloud{ec2: &awsSdkEC2{ec2: mockedEC2API}, describeInstanceBatcher: newdescribeInstanceBatcher(context.Background(), &awsSdkEC2{ec2: mockedEC2API})}

	if !instanceExists {
		mockedEC2API.On("DescribeInstances", mock.Anything).Return(&ec2.DescribeInstancesOutput{}, errors.New("InvalidInstanceID.NotFound: Instance not found"))
	} else {
		mockedEC2API.On("DescribeInstances", mock.Anything).Return(&ec2.DescribeInstancesOutput{
			Reservations: []ec2types.Reservation{
				{
					Instances: []ec2types.Instance{
						{
							InstanceId: aws.String(instanceID),
							State: &ec2types.InstanceState{
								Name: instanceState,
							},
						},
					},
				},
			},
		}, nil)
	}

	return c
}
