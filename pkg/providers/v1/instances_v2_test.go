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
	"strconv"
	"testing"
	"strconv"
)

func TestGetAdditionalLabels(t *testing.T) {
	for _, tc := range []struct {
		name           string
		instanceID     string
		instanceType   string
		region         string
		zone           zoneDetails
		expectedLabels map[string]string
	}{
		{
			name:         "test in topology supported region and instance type",
			instanceID:   "i-00000000000000000",
			instanceType: "trn1.2xlarge",
			region:       "us-west-2",
			zone: zoneDetails{
				name:     "us-west-2a",
				id:       "az1",
				zoneType: "zonetype",
			},
			expectedLabels: map[string]string{
				LabelZoneID:                        "az1",
				LabelNetworkNode + strconv.Itoa(0): "nn1",
				LabelNetworkNode + strconv.Itoa(1): "nn2",
				LabelNetworkNode + strconv.Itoa(2): "nn3",
			},
		},
		{
			name:         "test in topology unsupported region",
			instanceID:   "i-00000000000000000",
			instanceType: "trn1.2xlarge",
			region:       "ap-south-1",
			zone: zoneDetails{
				name:     "ap-south-1a",
				id:       "az1",
				zoneType: "zonetype",
			},
			expectedLabels: map[string]string{
				LabelZoneID: "az1",
			},
		},
		{
			name:         "test with topology unsupported instance type",
			instanceID:   "i-00000000000000000",
			instanceType: "t3.xlarge",
			region:       "us-west-2",
			zone: zoneDetails{
				name:     "us-west-2a",
				id:       "az1",
				zoneType: "zonetype",
			},
			expectedLabels: map[string]string{
				LabelZoneID: "az1",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			az := ec2.AvailabilityZone{
				ZoneName: aws.String(tc.zone.name),
				ZoneId:   aws.String(tc.zone.id),
				ZoneType: aws.String(tc.zone.zoneType),
			}
			testNetworkNode0 := "nn1"
			testNetworkNode1 := "nn2"
			testNetworkNode2 := "nn3"
			topology := ec2.InstanceTopology{NetworkNodes: []*string{&testNetworkNode0, &testNetworkNode1, &testNetworkNode2}}

			mockedEC2API := newMockedEC2API()
			c := &Cloud{ec2: &awsSdkEC2{ec2: mockedEC2API}}
			c.zoneCache.zoneNameToDetails = map[string]zoneDetails{
				tc.zone.name: tc.zone,
			}
			mockedEC2API.On("DescribeAvailabilityZones", mock.Anything).Return(&ec2.DescribeAvailabilityZonesOutput{
				AvailabilityZones: []*ec2.AvailabilityZone{&az},
			}, nil)
			mockedEC2API.On("DescribeInstanceTopology", mock.Anything).Return(&ec2.DescribeInstanceTopologyOutput{
				Instances: []*ec2.InstanceTopology{&topology},
			}, nil)

			res, err := c.getAdditionalLabels(tc.zone.name, tc.instanceID, tc.instanceType, tc.region)
			if err != nil {
				t.Errorf("Should not error getting Additional Labels: %s", err)
			}
			assert.Equal(t, tc.expectedLabels, res)
		})
	}
}

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
			LabelNetworkNode+strconv.Itoa(1): "nn-123456789",
			LabelNetworkNode+strconv.Itoa(2): "nn-234567890",
			LabelNetworkNode+strconv.Itoa(3): "nn-345678901",
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
