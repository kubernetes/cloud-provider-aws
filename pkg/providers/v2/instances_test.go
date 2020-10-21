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
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	cloudprovider "k8s.io/cloud-provider"
	"k8s.io/cloud-provider-aws/pkg/providers/v2/mocks"
)

const TestClusterID = "clusterid.test"

func makeInstance(num int, privateIP, publicIP, privateDNSName, publicDNSName string, stateName string) *ec2.Instance {
	instance := ec2.Instance{
		InstanceId:       aws.String(fmt.Sprintf("i-%d", num)),
		PrivateDnsName:   aws.String(privateDNSName),
		PrivateIpAddress: aws.String(privateIP),
		PublicDnsName:    aws.String(publicDNSName),
		PublicIpAddress:  aws.String(publicIP),
		InstanceType:     aws.String("c3.large"),
		Placement:        &ec2.Placement{AvailabilityZone: aws.String("us-west-1a")},
		State: &ec2.InstanceState{
			Name: aws.String(stateName),
		},
		NetworkInterfaces: []*ec2.InstanceNetworkInterface{
			{
				Status: aws.String(ec2.NetworkInterfaceStatusInUse),
				PrivateIpAddresses: []*ec2.InstancePrivateIpAddress{
					{
						PrivateIpAddress: aws.String(privateIP),
					},
				},
			},
		},
	}

	return &instance
}

func makeNode(nodeName string) *v1.Node {
	providerID := "aws://us-west-1a/i-1234"
	return &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
		},
		Spec: v1.NodeSpec{
			ProviderID: providerID,
		},
	}
}

func makeNodeWithoutProviderID(nodeName string) *v1.Node {
	return &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
		},
	}
}

func TestGetInstanceProviderID(t *testing.T) {
	testCases := []struct {
		name       string
		instance   *ec2.Instance
		providerID string
	}{
		{
			name:       "get instance (regular) provider ID",
			instance:   makeInstance(0, "192.168.0.1", "1.2.3.4", "instance-same.ec2.internal", "instance-same.ec2.external", "running"),
			providerID: "aws:///us-west-1a/i-0",
		},
		{
			name:       "get instance (without public IP/DNS) provider ID",
			instance:   makeInstance(1, "192.168.0.2", "", "instance-same.ec2.internal", "", "running"),
			providerID: "aws:///us-west-1a/i-1",
		},
		{
			name:       "get instance (without private IP/DNS) provider ID",
			instance:   makeInstance(2, "", "1.2.3.4", "", "instance-same.ec2.external", "running"),
			providerID: "aws:///us-west-1a/i-2",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			providerID, err := getInstanceProviderID(testCase.instance)
			assert.NoError(t, err)
			assert.Equal(t, testCase.providerID, providerID)
		})
	}
}

func TestInstanceExists(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockEC2 := mocks.NewMockEC2(mockCtrl)

	fakeInstances := &instances{
		ec2: mockEC2,
	}

	nodeName := "ip-192-168-0-1.ec2.internal"

	tests := []struct {
		name            string
		node            *v1.Node
		mockedEC2Output *ec2.DescribeInstancesOutput
		expectedResult  bool
	}{
		{
			name: "test InstanceExists with running instance",
			node: makeNode(nodeName),
			mockedEC2Output: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{
							makeInstance(0, "192.168.0.1", "1.2.3.4", "instance-same.ec2.internal", "instance-same.ec2.external", "running"),
						},
					},
				},
			},
			expectedResult: true,
		},
		{
			name: "test InstanceExists with stopping instance",
			node: makeNode(nodeName),
			mockedEC2Output: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{
							makeInstance(1, "192.168.0.1", "1.2.3.4", "instance-same.ec2.internal", "instance-same.ec2.external", "stopping"),
						},
					},
				},
			},
			expectedResult: true,
		},
		{
			name: "test InstanceExists with terminated instance (node without providerID)",
			node: makeNodeWithoutProviderID(nodeName),
			mockedEC2Output: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{},
					},
				},
			},
			expectedResult: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockEC2.EXPECT().DescribeInstances(gomock.Any()).Return(test.mockedEC2Output, nil)

			exists, err := fakeInstances.InstanceExists(context.TODO(), test.node)

			if err != nil {
				t.Errorf("InstanceExists failed with node %v: %v", nodeName, err)
			}

			if exists != test.expectedResult {
				t.Errorf("unexpected result, InstanceExists should return %v", test.expectedResult)
			}
		})
	}
}

func TestInstanceShutdown(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockEC2 := mocks.NewMockEC2(mockCtrl)

	fakeInstances := &instances{
		ec2: mockEC2,
	}

	nodeName := "ip-192-168-0-1.ec2.internal"

	tests := []struct {
		name            string
		node            *v1.Node
		mockedEC2Output *ec2.DescribeInstancesOutput
		expectedResult  bool
	}{
		{
			name: "test InstanceShutdown with running instance",
			node: makeNode(nodeName),
			mockedEC2Output: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{
							makeInstance(0, "192.168.0.1", "1.2.3.6", "instance-same.ec2.internal", "instance-same.ec2.external", "running"),
						},
					},
				},
			},
			expectedResult: false,
		},
		{
			name: "test InstanceShutdown with running instance (node without providerID)",
			node: makeNodeWithoutProviderID(nodeName),
			mockedEC2Output: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{
							makeInstance(0, "192.168.0.1", "1.2.3.6", "instance-same.ec2.internal", "instance-same.ec2.external", "running"),
						},
					},
				},
			},
			expectedResult: false,
		},
		{
			name: "test InstanceShutdown with stopping instance",
			node: makeNode(nodeName),
			mockedEC2Output: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{
							makeInstance(0, "192.168.0.1", "1.2.3.6", "instance-same.ec2.internal", "instance-same.ec2.external", "stopping"),
						},
					},
				},
			},
			expectedResult: false,
		},
		{
			name: "test InstanceShutdown with stopped instance (node without providerID)",
			node: makeNodeWithoutProviderID(nodeName),
			mockedEC2Output: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{
							makeInstance(0, "192.168.0.1", "1.2.3.6", "instance-same.ec2.internal", "instance-same.ec2.external", "stopped"),
						},
					},
				},
			},
			expectedResult: true,
		},
		{
			name: "test InstanceShutdown with terminated instance",
			node: makeNode(nodeName),
			mockedEC2Output: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{
							makeInstance(0, "192.168.0.1", "1.2.3.6", "instance-same.ec2.internal", "instance-same.ec2.external", "terminated"),
						},
					},
				},
			},
			expectedResult: false,
		},
		{
			name: "test InstanceShutdown with terminated instance (node without provierID)",
			node: makeNodeWithoutProviderID(nodeName),
			mockedEC2Output: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{
							makeInstance(0, "192.168.0.1", "1.2.3.6", "instance-same.ec2.internal", "instance-same.ec2.external", "terminated"),
						},
					},
				},
			},
			expectedResult: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockEC2.EXPECT().DescribeInstances(gomock.Any()).Return(test.mockedEC2Output, nil)

			shutdown, err := fakeInstances.InstanceShutdown(context.TODO(), test.node)

			if err != nil {
				t.Logf("InstanceShutdown failed with node %v: %v", nodeName, err)
			}

			if shutdown != test.expectedResult {
				t.Errorf("unexpected result, InstanceShutdown should return %v", test.expectedResult)
			}
		})
	}
}

func TestInstanceMetadata(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockEC2 := mocks.NewMockEC2(mockCtrl)

	fakeInstances := &instances{
		ec2: mockEC2,
	}

	nodeName := "ip-192-168-0-1.ec2.internal"

	tests := []struct {
		name            string
		node            *v1.Node
		expectedResult  *cloudprovider.InstanceMetadata
		mockedEC2Output *ec2.DescribeInstancesOutput
	}{
		{
			name: "test InstanceMetadata with running instance",
			node: makeNode(nodeName),
			mockedEC2Output: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{
							makeInstance(0, "192.168.0.1", "1.2.3.6", "instance-same.ec2.internal", "instance-same.ec2.external", "running"),
						},
					},
				},
			},
			expectedResult: &cloudprovider.InstanceMetadata{
				ProviderID:   "aws:///us-west-1a/i-0",
				InstanceType: "c3.large",
				NodeAddresses: []v1.NodeAddress{
					{
						Type:    "InternalIP",
						Address: "192.168.0.1",
					},
				},
			},
		},
		{
			name: "test InstanceMetadata with running instance (node without providerID)",
			node: makeNodeWithoutProviderID(nodeName),
			mockedEC2Output: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{
							makeInstance(0, "192.168.0.1", "1.2.3.6", "instance-same.ec2.internal", "instance-same.ec2.external", "running"),
						},
					},
				},
			},
			expectedResult: &cloudprovider.InstanceMetadata{
				ProviderID:   "aws:///us-west-1a/i-0",
				InstanceType: "c3.large",
				NodeAddresses: []v1.NodeAddress{
					{
						Type:    "InternalIP",
						Address: "192.168.0.1",
					},
				},
			},
		},
		{
			name: "test InstanceMetadata with stopping instance",
			node: makeNode(nodeName),
			mockedEC2Output: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{
							makeInstance(1, "192.168.0.1", "1.2.3.6", "instance-same.ec2.internal", "instance-same.ec2.external", "stopping"),
						},
					},
				},
			},
			expectedResult: &cloudprovider.InstanceMetadata{
				ProviderID:   "aws:///us-west-1a/i-1",
				InstanceType: "c3.large",
				NodeAddresses: []v1.NodeAddress{
					{
						Type:    "InternalIP",
						Address: "192.168.0.1",
					},
				},
			},
		},
		{
			name: "test InstanceMetadata with terminated instance",
			node: makeNode(nodeName),
			mockedEC2Output: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{},
					},
				},
			},
			expectedResult: nil,
		},
		{
			name: "test InstanceMetadata with terminated instance (node without providerID)",
			node: makeNodeWithoutProviderID(nodeName),
			mockedEC2Output: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{},
					},
				},
			},
			expectedResult: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockEC2.EXPECT().DescribeInstances(gomock.Any()).Return(test.mockedEC2Output, nil)

			nodeName := "ip-172-21-32-3.ec2.internal"
			node := &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeName,
				},
			}
			metadata, err := fakeInstances.InstanceMetadata(context.TODO(), node)

			if err != nil {
				t.Logf("InstanceMetadata failed with node %v: %v", nodeName, err)
			}

			if !cmp.Equal(metadata, test.expectedResult) {
				t.Errorf("unexpected metadata %v, InstanceMetadata should return %v", metadata, test.expectedResult)
			}
		})
	}
}

func TestParseInstanceIDFromProviderID(t *testing.T) {
	testCases := []struct {
		providerID string
		instanceID string
	}{
		{"aws://eu-central-1a/i-1238asjd8asdm123", "i-1238asjd8asdm123"},
		{"aws://us-west-2a/i-112as321asjd8asdm23", "i-112as321asjd8asdm23"},
		{"aws://us-iso-east-1a/i-123", "i-123"},
		{"aws://us-isob-east-1a/i-abcdef", "i-abcdef"},
		{"aws:///us-isob-east-1a/i-abCDef", "i-abCDef"},
		{"aws://us-east-1a/8asdm23", "8asdm23"},
		{"aws:///us-west-2a/i-0226b64168e09815e", "i-0226b64168e09815e"},
		{"i-0226b64168e09815e", "i-0226b64168e09815e"},
	}

	for _, testCase := range testCases {
		ret, err := parseInstanceIDFromProviderID(testCase.providerID)
		assert.NoError(t, err)
		assert.Equal(t, testCase.instanceID, ret)
	}
}
