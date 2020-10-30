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
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cloud-provider-aws/pkg/providers/v2/mocks"
)

const TestClusterName = "testCluster"

func makeNodeWithInvalidProviderID(nodeName string) *v1.Node {
	providerID := "aws:////us-where-1a//i-1234"
	return &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
		},
		Spec: v1.NodeSpec{
			ProviderID: providerID,
		},
	}
}

func TestEnsureLoadBalancerDeleted(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockEC2 := mocks.NewMockEC2(mockCtrl)
	mockELB := mocks.NewMockELB(mockCtrl)
	mockELB.EXPECT().DescribeLoadBalancers(gomock.Any()).Return(&elb.DescribeLoadBalancersOutput{
		LoadBalancerDescriptions: []*elb.LoadBalancerDescription{{}},
	}, nil)

	fakeLoadbalancers := &loadbalancer{
		ec2: mockEC2,
		elb: mockELB,
	}

	fakeLoadbalancers.EnsureLoadBalancerDeleted(context.TODO(), TestClusterName, &v1.Service{ObjectMeta: metav1.ObjectMeta{Name: "myservice", UID: "id"}})
}

func TestUpdateLoadBalancer(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockEC2 := mocks.NewMockEC2(mockCtrl)
	mockELB := mocks.NewMockELB(mockCtrl)
	mockELB.EXPECT().DescribeLoadBalancers(gomock.Any()).Return(&elb.DescribeLoadBalancersOutput{
		LoadBalancerDescriptions: []*elb.LoadBalancerDescription{{}},
	}, nil)

	fakeLoadbalancers := &loadbalancer{
		ec2: mockEC2,
		elb: mockELB,
	}

	fakeLoadbalancers.UpdateLoadBalancer(context.TODO(), TestClusterName, &v1.Service{ObjectMeta: metav1.ObjectMeta{Name: "myservice", UID: "id"}}, []*v1.Node{})
}

func TestGetLoadBalancer(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockEC2 := mocks.NewMockEC2(mockCtrl)
	mockELB := mocks.NewMockELB(mockCtrl)
	mockELB.EXPECT().DescribeLoadBalancers(gomock.Any()).Return(&elb.DescribeLoadBalancersOutput{
		LoadBalancerDescriptions: []*elb.LoadBalancerDescription{{}},
	}, nil)

	fakeLoadbalancers := &loadbalancer{
		ec2: mockEC2,
		elb: mockELB,
	}

	fakeLoadbalancers.GetLoadBalancer(context.TODO(), TestClusterName, &v1.Service{ObjectMeta: metav1.ObjectMeta{Name: "myservice", UID: "id"}})
}

func TestGetLoadBalancerName(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockEC2 := mocks.NewMockEC2(mockCtrl)
	mockELB := mocks.NewMockELB(mockCtrl)

	fakeLoadbalancers := &loadbalancer{
		ec2: mockEC2,
		elb: mockELB,
	}

	lbName := fakeLoadbalancers.GetLoadBalancerName(context.TODO(), TestClusterName, &v1.Service{ObjectMeta: metav1.ObjectMeta{Name: "testservice", Namespace: "testnamespace"}})
	assert.True(t, strings.HasPrefix(lbName, "k8stestnametestserv"))
}

func TestGetInstanceIDsFromNodes(t *testing.T) {
	nodeName := "ip-192-168-0-1.ec2.internal"

	testCases := []struct {
		name                string
		nodes               []*v1.Node
		expectedInstanceIDs []*string
	}{
		{
			name: "get instance IDs from nodes",
			nodes: []*v1.Node{
				makeNode(nodeName),
			},
			expectedInstanceIDs: []*string{
				aws.String("i-1234"),
			},
		},
		{
			name:                "get instance IDs from an empty list of nodes",
			nodes:               []*v1.Node{},
			expectedInstanceIDs: []*string(nil),
		},
		{
			name: "get instance IDs from nodes with invalid providerID",
			nodes: []*v1.Node{
				makeNodeWithInvalidProviderID(nodeName),
			},
			expectedInstanceIDs: []*string{aws.String("")},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			instanceIDs, err := getInstanceIDsFromNodes(testCase.nodes)
			assert.NoError(t, err)
			assert.Equal(t, testCase.expectedInstanceIDs, instanceIDs)
		})
	}
}

func TestFilterTargetNodes(t *testing.T) {
	tests := []struct {
		name                    string
		nodeLabels, annotations map[string]string
		nodeTargeted            bool
	}{
		{
			name:         "when no filter is provided, node should be targeted",
			nodeLabels:   map[string]string{"k1": "v1"},
			nodeTargeted: true,
		},
		{
			name:         "when all key-value filters match, node should be targeted",
			nodeLabels:   map[string]string{"k1": "v1", "k2": "v2"},
			annotations:  map[string]string{ServiceAnnotationLoadBalancerTargetNodeLabels: "k1=v1,k2=v2"},
			nodeTargeted: true,
		},
		{
			name:         "when all just-key filter match, node should be targeted",
			nodeLabels:   map[string]string{"k1": "v1", "k2": "v2"},
			annotations:  map[string]string{ServiceAnnotationLoadBalancerTargetNodeLabels: "k1,k2"},
			nodeTargeted: true,
		},
		{
			name:         "when some filters do not match, node should not be targeted",
			nodeLabels:   map[string]string{"k1": "v1"},
			annotations:  map[string]string{ServiceAnnotationLoadBalancerTargetNodeLabels: "k1=v1,k2"},
			nodeTargeted: false,
		},
		{
			name:         "when no filter matches, node should not be targeted",
			nodeLabels:   map[string]string{"k1": "v1", "k2": "v2"},
			annotations:  map[string]string{ServiceAnnotationLoadBalancerTargetNodeLabels: "k3=v3"},
			nodeTargeted: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			node := &v1.Node{}
			node.Labels = test.nodeLabels

			nodes := []*v1.Node{node}
			targetNodes := filterTargetNodes(nodes, test.annotations)

			if test.nodeTargeted {
				assert.Equal(t, nodes, targetNodes)
			} else {
				assert.Empty(t, targetNodes)
			}
		})
	}
}

func TestGetKeyValuePairsFromAnnotation(t *testing.T) {
	tagTests := []struct {
		Annotations map[string]string
		Tags        map[string]string
	}{
		{
			Annotations: map[string]string{
				ServiceAnnotationLoadBalancerAdditionalTags: "Key=Val",
			},
			Tags: map[string]string{
				"Key": "Val",
			},
		},
		{
			Annotations: map[string]string{
				ServiceAnnotationLoadBalancerAdditionalTags: "Key1=Val1, Key2=Val2",
			},
			Tags: map[string]string{
				"Key1": "Val1",
				"Key2": "Val2",
			},
		},
		{
			Annotations: map[string]string{
				ServiceAnnotationLoadBalancerAdditionalTags: "Key1=, Key2=Val2",
				"anotherKey": "anotherValue",
			},
			Tags: map[string]string{
				"Key1": "",
				"Key2": "Val2",
			},
		},
		{
			Annotations: map[string]string{
				"Nothing": "Key1=, Key2=Val2, Key3",
			},
			Tags: map[string]string{},
		},
		{
			Annotations: map[string]string{
				ServiceAnnotationLoadBalancerAdditionalTags: "K=V K1=V2,Key1========, =====, ======Val, =Val, , 234,",
			},
			Tags: map[string]string{
				"K":    "V K1",
				"Key1": "",
				"234":  "",
			},
		},
	}

	for _, tagTest := range tagTests {
		result := getKeyValuePairsFromAnnotation(tagTest.Annotations, ServiceAnnotationLoadBalancerAdditionalTags)
		for k, v := range result {
			if len(result) != len(tagTest.Tags) {
				t.Errorf("incorrect expected length: %v != %v", result, tagTest.Tags)
				continue
			}
			if tagTest.Tags[k] != v {
				t.Errorf("%s != %s", tagTest.Tags[k], v)
				continue
			}
		}
	}
}
