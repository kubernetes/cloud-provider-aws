/*
Copyright 2017 The Kubernetes Authors.

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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestMapToAWSInstanceIDs(t *testing.T) {
	tests := []struct {
		Kubernetes  KubernetesInstanceID
		Aws         InstanceID
		ExpectError bool
	}{
		{
			Kubernetes: "aws:///us-east-1a/i-12345678",
			Aws:        "i-12345678",
		},
		{
			Kubernetes: "aws:////i-12345678",
			Aws:        "i-12345678",
		},
		{
			Kubernetes: "i-12345678",
			Aws:        "i-12345678",
		},
		{
			Kubernetes: "aws:///us-east-1a/i-12345678abcdef01",
			Aws:        "i-12345678abcdef01",
		},
		{
			Kubernetes: "aws:////i-12345678abcdef01",
			Aws:        "i-12345678abcdef01",
		},
		{
			Kubernetes: "i-12345678abcdef01",
			Aws:        "i-12345678abcdef01",
		},
		{
			Kubernetes:  "vol-123456789",
			ExpectError: true,
		},
		{
			Kubernetes:  "aws:///us-east-1a/vol-12345678abcdef01",
			ExpectError: true,
		},
		{
			Kubernetes:  "aws://accountid/us-east-1a/vol-12345678abcdef01",
			ExpectError: true,
		},
		{
			Kubernetes:  "aws:///us-east-1a/vol-12345678abcdef01/suffix",
			ExpectError: true,
		},
		{
			Kubernetes:  "",
			ExpectError: true,
		},
		{
			Kubernetes: "aws:///us-west-2c/1abc-2def/fargate-ip-192-168-164-88.internal",
			Aws:        "fargate-ip-192-168-164-88.internal",
		},
		{
			Kubernetes: "aws:///us-west-2c/1abc-2def/fargate-192.168.164.88",
			Aws:        "fargate-192.168.164.88",
		},
	}

	for _, test := range tests {
		awsID, err := test.Kubernetes.MapToAWSInstanceID()
		if err != nil {
			if !test.ExpectError {
				t.Errorf("unexpected error parsing %s: %v", test.Kubernetes, err)
			}
		} else {
			if test.ExpectError {
				t.Errorf("expected error parsing %s", test.Kubernetes)
			} else if test.Aws != awsID {
				t.Errorf("unexpected value parsing %s, got %s", test.Kubernetes, awsID)
			}
		}
	}

	for _, test := range tests {
		node := &v1.Node{}
		node.Spec.ProviderID = string(test.Kubernetes)

		awsInstanceIds, err := mapToAWSInstanceIDs([]*v1.Node{node})
		if err != nil {
			if !test.ExpectError {
				t.Errorf("unexpected error parsing %s: %v", test.Kubernetes, err)
			}
		} else {
			if test.ExpectError {
				t.Errorf("expected error parsing %s", test.Kubernetes)
			} else if len(awsInstanceIds) != 1 {
				t.Errorf("unexpected value parsing %s, got %s", test.Kubernetes, awsInstanceIds)
			} else if awsInstanceIds[0] != test.Aws {
				t.Errorf("unexpected value parsing %s, got %s", test.Kubernetes, awsInstanceIds)
			}
		}

		awsInstanceIds = mapToAWSInstanceIDsTolerant([]*v1.Node{node})
		if test.ExpectError {
			if len(awsInstanceIds) != 0 {
				t.Errorf("unexpected results parsing %s: %s", test.Kubernetes, awsInstanceIds)
			}
		} else {
			if len(awsInstanceIds) != 1 {
				t.Errorf("unexpected value parsing %s, got %s", test.Kubernetes, awsInstanceIds)
			} else if awsInstanceIds[0] != test.Aws {
				t.Errorf("unexpected value parsing %s, got %s", test.Kubernetes, awsInstanceIds)
			}
		}
	}
}

func TestSnapshotMeetsCriteria(t *testing.T) {
	snapshot := &allInstancesSnapshot{timestamp: time.Now().Add(-3601 * time.Second)}

	if !snapshot.MeetsCriteria(cacheCriteria{}) {
		t.Errorf("Snapshot should always meet empty criteria")
	}

	if snapshot.MeetsCriteria(cacheCriteria{MaxAge: time.Hour}) {
		t.Errorf("Snapshot did not honor MaxAge")
	}

	if snapshot.MeetsCriteria(cacheCriteria{HasInstances: []InstanceID{InstanceID("i-12345678")}}) {
		t.Errorf("Snapshot did not honor HasInstances with missing instances")
	}

	snapshot.instances = make(map[InstanceID]*ec2.Instance)
	snapshot.instances[InstanceID("i-12345678")] = &ec2.Instance{}

	if !snapshot.MeetsCriteria(cacheCriteria{HasInstances: []InstanceID{InstanceID("i-12345678")}}) {
		t.Errorf("Snapshot did not honor HasInstances with matching instances")
	}

	if snapshot.MeetsCriteria(cacheCriteria{HasInstances: []InstanceID{InstanceID("i-12345678"), InstanceID("i-00000000")}}) {
		t.Errorf("Snapshot did not honor HasInstances with partially matching instances")
	}
}

func TestOlderThan(t *testing.T) {
	t1 := time.Now()
	t2 := t1.Add(time.Second)

	s1 := &allInstancesSnapshot{timestamp: t1}
	s2 := &allInstancesSnapshot{timestamp: t2}

	assert.True(t, s1.olderThan(s2), "s1 should be olderThan s2")
	assert.False(t, s2.olderThan(s1), "s2 not should be olderThan s1")
	assert.False(t, s1.olderThan(s1), "s1 not should be olderThan itself")
}

func TestSnapshotFindInstances(t *testing.T) {
	snapshot := &allInstancesSnapshot{}

	snapshot.instances = make(map[InstanceID]*ec2.Instance)
	{
		id := InstanceID("i-12345678")
		snapshot.instances[id] = &ec2.Instance{InstanceId: id.awsString()}
	}
	{
		id := InstanceID("i-23456789")
		snapshot.instances[id] = &ec2.Instance{InstanceId: id.awsString()}
	}

	instances := snapshot.FindInstances([]InstanceID{InstanceID("i-12345678"), InstanceID("i-23456789"), InstanceID("i-00000000")})
	if len(instances) != 2 {
		t.Errorf("findInstances returned %d results, expected 2", len(instances))
	}

	for _, id := range []InstanceID{InstanceID("i-12345678"), InstanceID("i-23456789")} {
		i := instances[id]
		if i == nil {
			t.Errorf("findInstances did not return %s", id)
			continue
		}
		if aws.StringValue(i.InstanceId) != string(id) {
			t.Errorf("findInstances did not return expected instanceId for %s", id)
		}
		if i != snapshot.instances[id] {
			t.Errorf("findInstances did not return expected instance (reference equality) for %s", id)
		}
	}
}

func TestNodeAddresses(t *testing.T) {
	for _, tc := range []struct {
		Name            string
		InstanceID      string
		PrivateIP       string
		PublicIP        string
		PrivateDNSName  string
		PublicDNSName   string
		Ipv6s           []string
		SetNetInterface bool
		NodeName        string
		Ipv6Only        bool

		ExpectedNumAddresses int
	}{
		{
			Name:                 "ipv4 w/public IP",
			InstanceID:           "i-00000000000000000",
			PrivateIP:            "192.168.0.1",
			PublicIP:             "1.2.3.4",
			PrivateDNSName:       "instance-same.ec2.internal",
			PublicDNSName:        "instance-same.ec2.external",
			SetNetInterface:      true,
			NodeName:             "foo",
			ExpectedNumAddresses: 5,
		},
		{
			Name:                 "ipv4 w/private IP only",
			InstanceID:           "i-00000000000000002",
			PrivateIP:            "192.168.0.1",
			PublicIP:             "1.2.3.4",
			PrivateDNSName:       "instance-other.ec2.internal",
			ExpectedNumAddresses: 3,
		},
		{
			Name:                 "ipv6 only",
			InstanceID:           "i-00000000000000003",
			PrivateIP:            "192.168.0.3",
			PrivateDNSName:       "instance-ipv6.ec2.internal",
			PublicDNSName:        "instance-same.ec2.external",
			Ipv6s:                []string{"2a05:d014:aa7:911:fc7e:1600:fc4d:ab2", "2a05:d014:aa7:911:9f44:e737:1aa0:6489"},
			SetNetInterface:      true,
			Ipv6Only:             true,
			NodeName:             "foo",
			ExpectedNumAddresses: 1,
		},
		{
			Name:                 "resource based naming using FQDN",
			InstanceID:           "i-00000000000000004",
			PrivateIP:            "192.168.0.4",
			PublicIP:             "1.2.3.4",
			PrivateDNSName:       "i-00000000000000004.ec2.internal",
			SetNetInterface:      true,
			ExpectedNumAddresses: 4,
		},
		{
			Name:                 "resource based naming using hostname only",
			InstanceID:           "i-00000000000000005",
			PrivateIP:            "192.168.0.5",
			PublicIP:             "1.2.3.4",
			PrivateDNSName:       "i-00000000000000005",
			SetNetInterface:      true,
			ExpectedNumAddresses: 4,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			instance := makeInstance(tc.InstanceID, tc.PrivateIP, tc.PublicIP, tc.PrivateDNSName, tc.PublicDNSName, tc.Ipv6s, tc.SetNetInterface)
			aws1, _ := mockInstancesResp(&instance, []*ec2.Instance{&instance})
			_, err := aws1.NodeAddresses(context.TODO(), "instance-mismatch.ec2.internal")
			if err == nil {
				t.Errorf("Should error when no instance found")
			}
			if tc.Ipv6Only {
				aws1.cfg.Global.NodeIPFamilies = []string{"ipv6"}
			}
			if tc.NodeName != "" {
				aws1.selfAWSInstance.nodeName = types.NodeName(tc.NodeName)
			}
			addrs, err := aws1.NodeAddresses(context.TODO(), types.NodeName(tc.PrivateDNSName))
			if err != nil {
				t.Errorf("Should not error when instance found, %s", err)
			}
			if len(addrs) != tc.ExpectedNumAddresses {
				t.Errorf("Should return exactly %d NodeAddresses, got %d (%v)", tc.ExpectedNumAddresses, len(addrs), addrs)
			}

			if tc.SetNetInterface && !tc.Ipv6Only {
				testHasNodeAddress(t, addrs, v1.NodeInternalIP, tc.PrivateIP)
			}
			if tc.PublicIP != "" && !tc.Ipv6Only {
				testHasNodeAddress(t, addrs, v1.NodeExternalIP, tc.PublicIP)
			}
			if tc.PublicDNSName != "" && !tc.Ipv6Only {
				testHasNodeAddress(t, addrs, v1.NodeExternalDNS, tc.PublicDNSName)
			}
			if tc.PrivateDNSName != "" && !tc.Ipv6Only {
				testHasNodeAddress(t, addrs, v1.NodeInternalDNS, tc.PrivateDNSName)
				testHasNodeAddress(t, addrs, v1.NodeHostName, tc.PrivateDNSName)
			}
			if tc.Ipv6Only {
				testHasNodeAddress(t, addrs, v1.NodeInternalIP, tc.Ipv6s[0])
			}
		})
	}
}

func TestNodeAddressesForFargate(t *testing.T) {
	awsServices := newMockedFakeAWSServices(TestClusterID)
	c, _ := newAWSCloud(CloudConfig{}, awsServices)

	nodeAddresses, _ := c.NodeAddressesByProviderID(context.TODO(), "aws:///us-west-2c/1abc-2def/fargate-ip-return-private-dns-name.us-west-2.compute.internal")
	verifyNodeAddressesForFargate(t, "IPV4", true, nodeAddresses)
}

func TestNodeAddressesForFargateIPV6Family(t *testing.T) {
	awsServices := newMockedFakeAWSServices(TestClusterID)
	c, _ := newAWSCloud(CloudConfig{}, awsServices)
	c.cfg.Global.NodeIPFamilies = []string{"ipv6"}

	nodeAddresses, _ := c.NodeAddressesByProviderID(context.TODO(), "aws:///us-west-2c/1abc-2def/fargate-ip-return-private-dns-name-ipv6.us-west-2.compute.internal")
	verifyNodeAddressesForFargate(t, "IPV6", true, nodeAddresses)
}

func TestNodeAddressesForFargatePrivateIP(t *testing.T) {
	awsServices := newMockedFakeAWSServices(TestClusterID)
	c, _ := newAWSCloud(CloudConfig{}, awsServices)

	nodeAddresses, _ := c.NodeAddressesByProviderID(context.TODO(), "aws:///us-west-2c/1abc-2def/fargate-192.168.164.88")
	verifyNodeAddressesForFargate(t, "IPV4", false, nodeAddresses)
}

func verifyNodeAddressesForFargate(t *testing.T, ipFamily string, verifyPublicIP bool, nodeAddresses []v1.NodeAddress) {
	if verifyPublicIP {
		assert.Equal(t, 2, len(nodeAddresses))
		assert.Equal(t, "ip-1-2-3-4.compute.amazon.com", nodeAddresses[1].Address)
		assert.Equal(t, v1.NodeInternalDNS, nodeAddresses[1].Type)
	} else {
		assert.Equal(t, 1, len(nodeAddresses))
	}

	if ipFamily == "IPV4" {
		assert.Equal(t, "1.2.3.4", nodeAddresses[0].Address)
	} else {
		assert.Equal(t, "2001:db8:3333:4444:5555:6666:7777:8888", nodeAddresses[0].Address)
	}
	assert.Equal(t, v1.NodeInternalIP, nodeAddresses[0].Type)
}

func TestNodeAddressesByProviderID(t *testing.T) {
	for _, tc := range []struct {
		Name            string
		InstanceID      string
		PrivateIP       string
		PublicIP        string
		PrivateDNSName  string
		PublicDNSName   string
		Ipv6s           []string
		SetNetInterface bool
		NodeName        string
		Ipv6Only        bool

		ExpectedNumAddresses int
	}{
		{
			Name:                 "ipv4 w/public IP",
			InstanceID:           "i-00000000000000000",
			PrivateIP:            "192.168.0.1",
			PublicIP:             "1.2.3.4",
			PrivateDNSName:       "instance-same.ec2.internal",
			PublicDNSName:        "instance-same.ec2.external",
			SetNetInterface:      true,
			ExpectedNumAddresses: 5,
		},
		{
			Name:                 "ipv4 w/private IP only",
			InstanceID:           "i-00000000000000001",
			PrivateIP:            "192.168.0.2",
			PrivateDNSName:       "instance-same.ec2.internal",
			ExpectedNumAddresses: 2,
		},
		{
			Name:                 "ipv4 w/public IP and no public DNS",
			InstanceID:           "i-00000000000000002",
			PrivateIP:            "192.168.0.1",
			PublicIP:             "1.2.3.4",
			PrivateDNSName:       "instance-other.ec2.internal",
			ExpectedNumAddresses: 3,
		},
		{
			Name:                 "ipv6 only",
			InstanceID:           "i-00000000000000003",
			PrivateIP:            "192.168.0.3",
			PrivateDNSName:       "instance-ipv6.ec2.internal",
			Ipv6s:                []string{"2a05:d014:aa7:911:fc7e:1600:fc4d:ab2", "2a05:d014:aa7:911:9f44:e737:1aa0:6489"},
			SetNetInterface:      true,
			ExpectedNumAddresses: 1,
			NodeName:             "foo",
			Ipv6Only:             true,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			instance := makeInstance(tc.InstanceID, tc.PrivateIP, tc.PublicIP, tc.PrivateDNSName, tc.PublicDNSName, tc.Ipv6s, tc.SetNetInterface)
			aws1, _ := mockInstancesResp(&instance, []*ec2.Instance{&instance})
			_, err := aws1.NodeAddressesByProviderID(context.TODO(), "i-xxx")
			if err == nil {
				t.Errorf("Should error when no instance found")
			}
			if tc.Ipv6Only {
				aws1.cfg.Global.NodeIPFamilies = []string{"ipv6"}
			}
			if tc.NodeName != "" {
				aws1.selfAWSInstance.nodeName = types.NodeName(tc.NodeName)
			}
			addrs, err := aws1.NodeAddressesByProviderID(context.TODO(), tc.InstanceID)
			if err != nil {
				t.Errorf("Should not error when instance found, %s", err)
			}
			if len(addrs) != tc.ExpectedNumAddresses {
				t.Errorf("Should return exactly %d NodeAddresses, got %d (%v)", tc.ExpectedNumAddresses, len(addrs), addrs)
			}

			if tc.SetNetInterface && !tc.Ipv6Only {
				testHasNodeAddress(t, addrs, v1.NodeInternalIP, tc.PrivateIP)
			}
			if tc.PublicIP != "" {
				testHasNodeAddress(t, addrs, v1.NodeExternalIP, tc.PublicIP)
			}
			if tc.PublicDNSName != "" {
				testHasNodeAddress(t, addrs, v1.NodeExternalDNS, tc.PublicDNSName)
			}
			if tc.PrivateDNSName != "" && !tc.Ipv6Only {
				testHasNodeAddress(t, addrs, v1.NodeInternalDNS, tc.PrivateDNSName)
				testHasNodeAddress(t, addrs, v1.NodeHostName, tc.PrivateDNSName)
			}
			if tc.Ipv6Only {
				testHasNodeAddress(t, addrs, v1.NodeInternalIP, tc.Ipv6s[0])
			}
		})
	}
}

func TestInstanceTypeByProviderIDForFargate(t *testing.T) {
	awsServices := newMockedFakeAWSServices(TestClusterID)
	c, _ := newAWSCloud(CloudConfig{}, awsServices)

	instanceType, err := c.InstanceTypeByProviderID(context.TODO(), "aws:///us-west-2c/1abc-2def/fargate-not-found")
	assert.Nil(t, err)
	assert.Equal(t, "", instanceType)
}

func TestInstanceExistsByProviderIDForFargate(t *testing.T) {
	awsServices := newMockedFakeAWSServices(TestClusterID)
	c, _ := newAWSCloud(CloudConfig{}, awsServices)

	instanceExist, err := c.InstanceExistsByProviderID(context.TODO(), "aws:///us-west-2c/1abc-2def/fargate-192.168.164.88")
	assert.Nil(t, err)
	assert.True(t, instanceExist)
}

func TestInstanceExistsByProviderIDWithNodeNameForFargate(t *testing.T) {
	awsServices := newMockedFakeAWSServices(TestClusterID)
	c, _ := newAWSCloud(CloudConfig{}, awsServices)

	instanceExist, err := c.InstanceExistsByProviderID(context.TODO(), "aws:///us-west-2c/1abc-2def/fargate-ip-192-168-164-88.us-west-2.compute.internal")
	assert.Nil(t, err)
	assert.True(t, instanceExist)
}

func TestInstanceExistsByProviderIDForInstanceNotFound(t *testing.T) {
	mockedEC2API := newMockedEC2API()
	c := &Cloud{ec2: &awsSdkEC2{ec2: mockedEC2API}}

	mockedEC2API.On("DescribeInstances", mock.Anything).Return(&ec2.DescribeInstancesOutput{}, awserr.New("InvalidInstanceID.NotFound", "Instance not found", nil))

	instanceExists, err := c.InstanceExistsByProviderID(context.TODO(), "aws:///us-west-2c/1abc-2def/i-not-found")
	assert.Nil(t, err)
	assert.False(t, instanceExists)
}

func TestInstanceNotExistsByProviderIDForFargate(t *testing.T) {
	awsServices := newMockedFakeAWSServices(TestClusterID)
	c, _ := newAWSCloud(CloudConfig{}, awsServices)

	instanceExist, err := c.InstanceExistsByProviderID(context.TODO(), "aws:///us-west-2c/1abc-2def/fargate-not-found")
	assert.Nil(t, err)
	assert.False(t, instanceExist)
}

func TestInstanceShutdownByProviderIDForFargate(t *testing.T) {
	awsServices := newMockedFakeAWSServices(TestClusterID)
	c, _ := newAWSCloud(CloudConfig{}, awsServices)

	instanceExist, err := c.InstanceShutdownByProviderID(context.TODO(), "aws:///us-west-2c/1abc-2def/fargate-192.168.164.88")
	assert.Nil(t, err)
	assert.True(t, instanceExist)
}

func TestInstanceShutdownNotExistsByProviderIDForFargate(t *testing.T) {
	awsServices := newMockedFakeAWSServices(TestClusterID)
	c, _ := newAWSCloud(CloudConfig{}, awsServices)

	instanceExist, err := c.InstanceShutdownByProviderID(context.TODO(), "aws:///us-west-2c/1abc-2def/fargate-not-found")
	assert.Nil(t, err)
	assert.False(t, instanceExist)
}
