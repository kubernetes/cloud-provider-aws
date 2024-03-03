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
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	v1 "k8s.io/api/core/v1"
	"testing"
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
			c, _ := mockInstancesResp(&instance, []*ec2.Instance{&instance})

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
		instanceState  string
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
			instanceState:  ec2.InstanceStateNameRunning,
			expectedExists: true,
		},
		{
			name:           "Should return false when instance is found but terminated",
			instanceExists: true,
			instanceState:  ec2.InstanceStateNameTerminated,
			expectedExists: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := getCloudWithMockedDescribeInstances(tc.instanceExists, tc.instanceState)

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
		instanceState    string
		expectedShutdown bool
	}{
		{
			name:             "Should return false when instance is found and running",
			instanceExists:   true,
			instanceState:    ec2.InstanceStateNameRunning,
			expectedShutdown: false,
		},
		{
			name:             "Should return false when instance is found and terminated",
			instanceExists:   true,
			instanceState:    ec2.InstanceStateNameTerminated,
			expectedShutdown: false,
		},
		{
			name:             "Should return true when instance is found and stopped",
			instanceExists:   true,
			instanceState:    ec2.InstanceStateNameStopped,
			expectedShutdown: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := getCloudWithMockedDescribeInstances(tc.instanceExists, tc.instanceState)

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
		c, _ := mockInstancesResp(&instance, []*ec2.Instance{&instance})
		node := &v1.Node{
			Spec: v1.NodeSpec{
				ProviderID: fmt.Sprintf("aws:///us-west-2c/1abc-2def/%s", *instance.InstanceId),
			},
		}

		result, err := c.InstanceMetadata(context.TODO(), node)
		if err != nil {
			t.Errorf("Should not error getting InstanceMetadata: %s", err)
		}

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
			LabelZoneID: "az1",
		}, result.AdditionalLabels)
	})
}

func getCloudWithMockedDescribeInstances(instanceExists bool, instanceState string) *Cloud {
	mockedEC2API := newMockedEC2API()
	c := &Cloud{ec2: &awsSdkEC2{ec2: mockedEC2API}}

	if !instanceExists {
		mockedEC2API.On("DescribeInstances", mock.Anything).Return(&ec2.DescribeInstancesOutput{}, awserr.New("InvalidInstanceID.NotFound", "Instance not found", nil))
	} else {
		mockedEC2API.On("DescribeInstances", mock.Anything).Return(&ec2.DescribeInstancesOutput{
			Reservations: []*ec2.Reservation{
				{
					Instances: []*ec2.Instance{
						{
							State: &ec2.InstanceState{
								Name: aws.String(instanceState),
							},
						},
					},
				},
			},
		}, nil)
	}

	return c
}
