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
	"testing"

	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/golang/mock/gomock"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/cloud-provider-aws/pkg/providers/v2/mocks"
)

func TestGetZone(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockEC2 := mocks.NewMockEC2(mockCtrl)

	testCases := []struct {
		name                  string
		region                string
		az                    string
		expectedRegion        string
		expectedFailureDomain string
	}{
		{
			name:                  "regular zones",
			region:                "us-west-2",
			az:                    "us-west-2a",
			expectedRegion:        "us-west-2",
			expectedFailureDomain: "us-west-2a",
		},
		{
			name:                  "availability zone not set",
			region:                "us-west-2",
			az:                    "",
			expectedRegion:        "us-west-2",
			expectedFailureDomain: "",
		},
		{
			name:                  "region not set",
			region:                "",
			az:                    "us-west-2a",
			expectedRegion:        "",
			expectedFailureDomain: "us-west-2a",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fakeZones := &zones{
				availabilityZone: testCase.az,
				ec2:              mockEC2,
				region:           testCase.region,
			}

			zone, err := fakeZones.GetZone(context.TODO())
			if err != nil {
				t.Fatalf("GetZone failed: %v", err)
			}
			if zone.Region != testCase.expectedRegion {
				t.Errorf("Unexpected region: %s", zone.Region)
			}
			if zone.FailureDomain != testCase.expectedFailureDomain {
				t.Errorf("Unexpected FailureDomain: %s", zone.FailureDomain)
			}
		})
	}
}

func TestGetZoneByProviderID(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockEC2 := mocks.NewMockEC2(mockCtrl)

	testCases := []struct {
		name                  string
		providerID            string
		expectedEc2Output     *ec2.DescribeInstancesOutput
		expectedRegion        string
		expectedFailureDomain string
	}{
		{
			name:       "GetZoneByProviderID with running instances",
			providerID: "aws:///us-west-1a/i-0",
			expectedEc2Output: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{
							makeInstance(0, "192.168.0.1", "1.2.3.4", "instance-same.ec2.internal", "instance-same.ec2.external", "running"),
						},
					},
				},
			},
			expectedRegion:        "us-west-1",
			expectedFailureDomain: "us-west-1a",
		},
		{
			name:       "GetZoneByProviderID with terminated instances",
			providerID: "aws://us-west-1a/i-0",
			expectedEc2Output: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{},
					},
				},
			},
			expectedRegion:        "",
			expectedFailureDomain: "",
		},
		{
			name:       "GetZoneByProviderID with invalid providerID",
			providerID: "aws:////us-where-1a/i-0",
			expectedEc2Output: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{},
					},
				},
			},
			expectedRegion:        "",
			expectedFailureDomain: "",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mockEC2.EXPECT().DescribeInstances(gomock.Any()).Return(testCase.expectedEc2Output, nil)

			fakeZones := &zones{
				ec2: mockEC2,
			}

			zone, err := fakeZones.GetZoneByProviderID(context.TODO(), testCase.providerID)
			if err != nil {
				t.Logf("GetZoneByProviderID failed with providerID %v: %v", testCase.providerID, err)
			}
			if zone.Region != testCase.expectedRegion {
				t.Errorf("Unexpected region: %s", zone.Region)
			}
			if zone.FailureDomain != testCase.expectedFailureDomain {
				t.Errorf("Unexpected FailureDomain: %s", zone.FailureDomain)
			}
		})
	}
}

func TestGetZoneByNodeName(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockEC2 := mocks.NewMockEC2(mockCtrl)

	testCases := []struct {
		name                  string
		nodeName              types.NodeName
		expectedEc2Output     *ec2.DescribeInstancesOutput
		expectedRegion        string
		expectedFailureDomain string
	}{
		{
			name:     "GetZoneByNodeName with running instances",
			nodeName: "instance-same.ec2.external",
			expectedEc2Output: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{
							makeInstance(0, "192.168.0.1", "1.2.3.4", "instance-same.ec2.internal", "instance-same.ec2.external", "running"),
						},
					},
				},
			},
			expectedRegion:        "us-west-1",
			expectedFailureDomain: "us-west-1a",
		},
		{
			name:     "GetZoneByNodeName with terminated instances",
			nodeName: "instance-same.ec2.external",
			expectedEc2Output: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{},
					},
				},
			},
			expectedRegion:        "",
			expectedFailureDomain: "",
		},
		{
			name:     "GetZoneByNodeName with empty nodeName",
			nodeName: "",
			expectedEc2Output: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{},
					},
				},
			},
			expectedRegion:        "",
			expectedFailureDomain: "",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mockEC2.EXPECT().DescribeInstances(gomock.Any()).Return(testCase.expectedEc2Output, nil)

			fakeZones := &zones{
				ec2: mockEC2,
			}

			zone, err := fakeZones.GetZoneByNodeName(context.TODO(), testCase.nodeName)
			if err != nil {
				t.Logf("GetZoneByNodeName failed with nodeName %v: %v", testCase.nodeName, err)
			}
			if zone.Region != testCase.expectedRegion {
				t.Errorf("Unexpected region: %s", zone.Region)
			}
			if zone.FailureDomain != testCase.expectedFailureDomain {
				t.Errorf("Unexpected FailureDomain: %s", zone.FailureDomain)
			}
		})
	}
}
