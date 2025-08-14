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
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"k8s.io/cloud-provider-aws/pkg/providers/v1/config"
)

func TestElbProtocolsAreEqual(t *testing.T) {
	grid := []struct {
		L        *string
		R        *string
		Expected bool
	}{
		{
			L:        aws.String("http"),
			R:        aws.String("http"),
			Expected: true,
		},
		{
			L:        aws.String("HTTP"),
			R:        aws.String("http"),
			Expected: true,
		},
		{
			L:        aws.String("HTTP"),
			R:        aws.String("TCP"),
			Expected: false,
		},
		{
			L:        aws.String(""),
			R:        aws.String("TCP"),
			Expected: false,
		},
		{
			L:        aws.String(""),
			R:        aws.String(""),
			Expected: true,
		},
		{
			L:        nil,
			R:        aws.String(""),
			Expected: false,
		},
		{
			L:        aws.String(""),
			R:        nil,
			Expected: false,
		},
		{
			L:        nil,
			R:        nil,
			Expected: true,
		},
	}
	for _, g := range grid {
		actual := elbProtocolsAreEqual(g.L, g.R)
		if actual != g.Expected {
			t.Errorf("unexpected result from protocolsEquals(%v, %v)", g.L, g.R)
		}
	}
}

func TestAWSARNEquals(t *testing.T) {
	grid := []struct {
		L        *string
		R        *string
		Expected bool
	}{
		{
			L:        aws.String("arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"),
			R:        aws.String("arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"),
			Expected: true,
		},
		{
			L:        aws.String("ARN:AWS:ACM:US-EAST-1:123456789012:CERTIFICATE/12345678-1234-1234-1234-123456789012"),
			R:        aws.String("arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"),
			Expected: true,
		},
		{
			L:        aws.String("arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"),
			R:        aws.String(""),
			Expected: false,
		},
		{
			L:        aws.String(""),
			R:        aws.String(""),
			Expected: true,
		},
		{
			L:        nil,
			R:        aws.String(""),
			Expected: false,
		},
		{
			L:        aws.String(""),
			R:        nil,
			Expected: false,
		},
		{
			L:        nil,
			R:        nil,
			Expected: true,
		},
	}
	for _, g := range grid {
		actual := awsArnEquals(g.L, g.R)
		if actual != g.Expected {
			t.Errorf("unexpected result from awsArnEquals(%v, %v)", g.L, g.R)
		}
	}
}

func TestIsNLB(t *testing.T) {
	tests := []struct {
		name string

		annotations map[string]string
		want        bool
	}{
		{
			"NLB annotation provided",
			map[string]string{"service.beta.kubernetes.io/aws-load-balancer-type": "nlb"},
			true,
		},
		{
			"NLB annotation has invalid value",
			map[string]string{"service.beta.kubernetes.io/aws-load-balancer-type": "elb"},
			false,
		},
		{
			"NLB annotation absent",
			map[string]string{},
			false,
		},
	}

	for _, test := range tests {
		t.Logf("Running test case %s", test.name)
		got := isNLB(test.annotations)

		if got != test.want {
			t.Errorf("Incorrect value for isNLB() case %s. Got %t, expected %t.", test.name, got, test.want)
		}
	}
}

func TestIsLBExternal(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		want        bool
	}{
		{
			name:        "No annotation",
			annotations: map[string]string{},
			want:        false,
		},
		{
			name:        "Type NLB",
			annotations: map[string]string{"service.beta.kubernetes.io/aws-load-balancer-type": "nlb"},
			want:        false,
		},
		{
			name:        "Type NLB-IP",
			annotations: map[string]string{"service.beta.kubernetes.io/aws-load-balancer-type": "nlb-ip"},
			want:        true,
		},
		{
			name:        "Type External",
			annotations: map[string]string{"service.beta.kubernetes.io/aws-load-balancer-type": "external"},
			want:        true,
		},
	}
	for _, test := range tests {
		t.Logf("Running test case %s", test.name)
		got := isLBExternal(test.annotations)

		if got != test.want {
			t.Errorf("Incorrect value for isLBExternal() case %s. Got %t, expected %t.", test.name, got, test.want)
		}
	}
}

func TestSyncElbListeners(t *testing.T) {
	tests := []struct {
		name                 string
		loadBalancerName     string
		listeners            []elbtypes.Listener
		listenerDescriptions []elbtypes.ListenerDescription
		toCreate             []elbtypes.Listener
		toDelete             []int32
	}{
		{
			name:             "no edge cases",
			loadBalancerName: "lb_one",
			listeners: []elbtypes.Listener{
				{InstancePort: aws.Int32(443), InstanceProtocol: aws.String("HTTP"), LoadBalancerPort: 443, Protocol: aws.String("HTTP"), SSLCertificateId: aws.String("abc-123")},
				{InstancePort: aws.Int32(80), InstanceProtocol: aws.String("TCP"), LoadBalancerPort: 80, Protocol: aws.String("TCP"), SSLCertificateId: aws.String("def-456")},
				{InstancePort: aws.Int32(8443), InstanceProtocol: aws.String("TCP"), LoadBalancerPort: 8443, Protocol: aws.String("TCP"), SSLCertificateId: aws.String("def-456")},
			},
			listenerDescriptions: []elbtypes.ListenerDescription{
				{Listener: &elbtypes.Listener{InstancePort: aws.Int32(80), InstanceProtocol: aws.String("TCP"), LoadBalancerPort: 80, Protocol: aws.String("TCP")}},
				{Listener: &elbtypes.Listener{InstancePort: aws.Int32(8443), InstanceProtocol: aws.String("TCP"), LoadBalancerPort: 8443, Protocol: aws.String("TCP"), SSLCertificateId: aws.String("def-456")}},
			},
			toDelete: []int32{80},
			toCreate: []elbtypes.Listener{
				{InstancePort: aws.Int32(443), InstanceProtocol: aws.String("HTTP"), LoadBalancerPort: 443, Protocol: aws.String("HTTP"), SSLCertificateId: aws.String("abc-123")},
				{InstancePort: aws.Int32(80), InstanceProtocol: aws.String("TCP"), LoadBalancerPort: 80, Protocol: aws.String("TCP"), SSLCertificateId: aws.String("def-456")},
			},
		},
		{
			name:             "no listeners to delete",
			loadBalancerName: "lb_two",
			listeners: []elbtypes.Listener{
				{InstancePort: aws.Int32(443), InstanceProtocol: aws.String("HTTP"), LoadBalancerPort: 443, Protocol: aws.String("HTTP"), SSLCertificateId: aws.String("abc-123")},
				{InstancePort: aws.Int32(80), InstanceProtocol: aws.String("TCP"), LoadBalancerPort: 80, Protocol: aws.String("TCP"), SSLCertificateId: aws.String("def-456")},
			},
			listenerDescriptions: []elbtypes.ListenerDescription{
				{Listener: &elbtypes.Listener{InstancePort: aws.Int32(443), InstanceProtocol: aws.String("HTTP"), LoadBalancerPort: 443, Protocol: aws.String("HTTP"), SSLCertificateId: aws.String("abc-123")}},
			},
			toCreate: []elbtypes.Listener{
				{InstancePort: aws.Int32(80), InstanceProtocol: aws.String("TCP"), LoadBalancerPort: 80, Protocol: aws.String("TCP"), SSLCertificateId: aws.String("def-456")},
			},
			toDelete: []int32{},
		},
		{
			name:             "no listeners to create",
			loadBalancerName: "lb_three",
			listeners: []elbtypes.Listener{
				{InstancePort: aws.Int32(443), InstanceProtocol: aws.String("HTTP"), LoadBalancerPort: 443, Protocol: aws.String("HTTP"), SSLCertificateId: aws.String("abc-123")},
			},
			listenerDescriptions: []elbtypes.ListenerDescription{
				{Listener: &elbtypes.Listener{InstancePort: aws.Int32(80), InstanceProtocol: aws.String("TCP"), LoadBalancerPort: 80, Protocol: aws.String("TCP")}},
				{Listener: &elbtypes.Listener{InstancePort: aws.Int32(443), InstanceProtocol: aws.String("HTTP"), LoadBalancerPort: 443, Protocol: aws.String("HTTP"), SSLCertificateId: aws.String("abc-123")}},
			},
			toDelete: []int32{80},
			toCreate: []elbtypes.Listener{},
		},
		{
			name:             "nil actual listener",
			loadBalancerName: "lb_four",
			listeners: []elbtypes.Listener{
				{InstancePort: aws.Int32(443), InstanceProtocol: aws.String("HTTP"), LoadBalancerPort: 443, Protocol: aws.String("HTTP")},
			},
			listenerDescriptions: []elbtypes.ListenerDescription{
				{Listener: &elbtypes.Listener{InstancePort: aws.Int32(443), InstanceProtocol: aws.String("HTTP"), LoadBalancerPort: 443, Protocol: aws.String("HTTP"), SSLCertificateId: aws.String("abc-123")}},
				{Listener: nil},
			},
			toDelete: []int32{443},
			toCreate: []elbtypes.Listener{
				{InstancePort: aws.Int32(443), InstanceProtocol: aws.String("HTTP"), LoadBalancerPort: 443, Protocol: aws.String("HTTP")},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			additions, removals := syncElbListeners(test.loadBalancerName, test.listeners, test.listenerDescriptions)
			assert.Equal(t, additions, test.toCreate)
			assert.Equal(t, removals, test.toDelete)
		})
	}
}

func TestElbListenersAreEqual(t *testing.T) {
	tests := []struct {
		name             string
		expected, actual elbtypes.Listener
		equal            bool
	}{
		{
			name:     "should be equal",
			expected: elbtypes.Listener{InstancePort: aws.Int32(80), InstanceProtocol: aws.String("TCP"), LoadBalancerPort: 80, Protocol: aws.String("TCP")},
			actual:   elbtypes.Listener{InstancePort: aws.Int32(80), InstanceProtocol: aws.String("TCP"), LoadBalancerPort: 80, Protocol: aws.String("TCP")},
			equal:    true,
		},
		{
			name:     "instance port should be different",
			expected: elbtypes.Listener{InstancePort: aws.Int32(443), InstanceProtocol: aws.String("TCP"), LoadBalancerPort: 80, Protocol: aws.String("TCP")},
			actual:   elbtypes.Listener{InstancePort: aws.Int32(80), InstanceProtocol: aws.String("TCP"), LoadBalancerPort: 80, Protocol: aws.String("TCP")},
			equal:    false,
		},
		{
			name:     "instance protocol should be different",
			expected: elbtypes.Listener{InstancePort: aws.Int32(80), InstanceProtocol: aws.String("HTTP"), LoadBalancerPort: 80, Protocol: aws.String("TCP")},
			actual:   elbtypes.Listener{InstancePort: aws.Int32(80), InstanceProtocol: aws.String("TCP"), LoadBalancerPort: 80, Protocol: aws.String("TCP")},
			equal:    false,
		},
		{
			name:     "load balancer port should be different",
			expected: elbtypes.Listener{InstancePort: aws.Int32(443), InstanceProtocol: aws.String("TCP"), LoadBalancerPort: 443, Protocol: aws.String("TCP")},
			actual:   elbtypes.Listener{InstancePort: aws.Int32(443), InstanceProtocol: aws.String("TCP"), LoadBalancerPort: 80, Protocol: aws.String("TCP")},
			equal:    false,
		},
		{
			name:     "protocol should be different",
			expected: elbtypes.Listener{InstancePort: aws.Int32(443), InstanceProtocol: aws.String("TCP"), LoadBalancerPort: 80, Protocol: aws.String("TCP")},
			actual:   elbtypes.Listener{InstancePort: aws.Int32(443), InstanceProtocol: aws.String("TCP"), LoadBalancerPort: 80, Protocol: aws.String("HTTP")},
			equal:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.equal, elbListenersAreEqual(test.expected, test.actual))
		})
	}
}

func TestBuildTargetGroupName(t *testing.T) {
	type args struct {
		serviceName    types.NamespacedName
		servicePort    int32
		nodePort       int32
		targetProtocol elbv2types.ProtocolEnum
		targetType     elbv2types.TargetTypeEnum
		nlbConfig      nlbPortMapping
	}
	tests := []struct {
		name      string
		clusterID string
		args      args
		want      string
	}{
		{
			name:      "base case",
			clusterID: "cluster-a",
			args: args{
				serviceName:    types.NamespacedName{Namespace: "default", Name: "service-a"},
				servicePort:    80,
				nodePort:       8080,
				targetProtocol: elbv2types.ProtocolEnumTcp,
				targetType:     elbv2types.TargetTypeEnumInstance,
				nlbConfig:      nlbPortMapping{},
			},
			want: "k8s-default-servicea-7fa2e07508",
		},
		{
			name:      "base case & clusterID changed",
			clusterID: "cluster-b",
			args: args{
				serviceName:    types.NamespacedName{Namespace: "default", Name: "service-a"},
				servicePort:    80,
				nodePort:       8080,
				targetProtocol: elbv2types.ProtocolEnumTcp,
				targetType:     elbv2types.TargetTypeEnumInstance,
				nlbConfig:      nlbPortMapping{},
			},
			want: "k8s-default-servicea-719ee635da",
		},
		{
			name:      "base case & serviceNamespace changed",
			clusterID: "cluster-a",
			args: args{
				serviceName:    types.NamespacedName{Namespace: "another", Name: "service-a"},
				servicePort:    80,
				nodePort:       8080,
				targetProtocol: elbv2types.ProtocolEnumTcp,
				targetType:     elbv2types.TargetTypeEnumInstance,
				nlbConfig:      nlbPortMapping{},
			},
			want: "k8s-another-servicea-f66e09847d",
		},
		{
			name:      "base case & serviceName changed",
			clusterID: "cluster-a",
			args: args{
				serviceName:    types.NamespacedName{Namespace: "default", Name: "service-b"},
				servicePort:    80,
				nodePort:       8080,
				targetProtocol: elbv2types.ProtocolEnumTcp,
				targetType:     elbv2types.TargetTypeEnumInstance,
				nlbConfig:      nlbPortMapping{},
			},
			want: "k8s-default-serviceb-196c19c881",
		},
		{
			name:      "base case & servicePort changed",
			clusterID: "cluster-a",
			args: args{
				serviceName:    types.NamespacedName{Namespace: "default", Name: "service-a"},
				servicePort:    9090,
				nodePort:       8080,
				targetProtocol: elbv2types.ProtocolEnumTcp,
				targetType:     elbv2types.TargetTypeEnumInstance,
				nlbConfig:      nlbPortMapping{},
			},
			want: "k8s-default-servicea-06876706cb",
		},
		{
			name:      "base case & nodePort changed",
			clusterID: "cluster-a",
			args: args{
				serviceName:    types.NamespacedName{Namespace: "default", Name: "service-a"},
				servicePort:    80,
				nodePort:       9090,
				targetProtocol: elbv2types.ProtocolEnumTcp,
				targetType:     elbv2types.TargetTypeEnumInstance,
				nlbConfig:      nlbPortMapping{},
			},
			want: "k8s-default-servicea-119f844ec0",
		},
		{
			name:      "base case & targetProtocol changed",
			clusterID: "cluster-a",
			args: args{
				serviceName:    types.NamespacedName{Namespace: "default", Name: "service-a"},
				servicePort:    80,
				nodePort:       8080,
				targetProtocol: elbv2types.ProtocolEnumUdp,
				targetType:     elbv2types.TargetTypeEnumInstance,
				nlbConfig:      nlbPortMapping{},
			},
			want: "k8s-default-servicea-3868761686",
		},
		{
			name:      "base case & targetType changed",
			clusterID: "cluster-a",
			args: args{
				serviceName:    types.NamespacedName{Namespace: "default", Name: "service-a"},
				servicePort:    80,
				nodePort:       8080,
				targetProtocol: elbv2types.ProtocolEnumTcp,
				targetType:     elbv2types.TargetTypeEnumIp,
				nlbConfig:      nlbPortMapping{},
			},
			want: "k8s-default-servicea-0fa31f4b0f",
		},
		{
			name:      "custom healthcheck config",
			clusterID: "cluster-a",
			args: args{
				serviceName:    types.NamespacedName{Namespace: "default", Name: "service-a"},
				servicePort:    80,
				nodePort:       8080,
				targetProtocol: elbv2types.ProtocolEnumTcp,
				targetType:     elbv2types.TargetTypeEnumIp,
				nlbConfig: nlbPortMapping{
					HealthCheckConfig: healthCheckConfig{
						Protocol: "HTTP",
						Interval: 10,
					},
				},
			},
			want: "k8s-default-servicea-4028e49618",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Cloud{
				tagging: awsTagging{ClusterID: tt.clusterID},
			}
			if got := c.buildTargetGroupName(tt.args.serviceName, tt.args.servicePort, tt.args.nodePort, tt.args.targetProtocol, tt.args.targetType, tt.args.nlbConfig); got != tt.want {
				assert.Equal(t, tt.want, got)
			}
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

func makeNodeInstancePair(offset int) (*v1.Node, *ec2types.Instance) {
	instanceID := fmt.Sprintf("i-%x", int64(0x03bcc3496da09f78e)+int64(offset))
	instance := &ec2types.Instance{
		InstanceId: aws.String(instanceID),
		Placement: &ec2types.Placement{
			AvailabilityZone: aws.String("us-east-1b"),
		},
		PrivateDnsName:   aws.String(fmt.Sprintf("ip-192-168-32-%d.ec2.internal", 101+offset)),
		PrivateIpAddress: aws.String(fmt.Sprintf("192.168.32.%d", 101+offset)),
		PublicIpAddress:  aws.String(fmt.Sprintf("1.2.3.%d", 1+offset)),
	}

	var tag ec2types.Tag
	tag.Key = aws.String(fmt.Sprintf("%s%s", TagNameKubernetesClusterPrefix, TestClusterID))
	tag.Value = aws.String("owned")
	instance.Tags = []ec2types.Tag{tag}

	node := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("ip-192-168-0-%d.ec2.internal", 101+offset),
		},
		Spec: v1.NodeSpec{
			ProviderID: fmt.Sprintf("aws:///us-east-1b/%s", instanceID),
		},
	}
	return node, instance
}

func TestCloud_findInstancesForELB(t *testing.T) {
	defaultNode := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ip-172-20-0-100.ec2.internal",
		},
		Spec: v1.NodeSpec{
			ProviderID: "aws:///us-east-1a/i-self",
		},
	}
	newNode, newInstance := makeNodeInstancePair(1)
	awsServices := NewFakeAWSServices(TestClusterID)
	c, err := newAWSCloud(config.CloudConfig{}, awsServices)
	if err != nil {
		t.Errorf("Error building aws cloud: %v", err)
		return
	}

	want := map[InstanceID]*ec2types.Instance{
		"i-self": awsServices.selfInstance,
	}
	got, err := c.findInstancesForELB(context.TODO(), []*v1.Node{defaultNode}, nil)
	assert.NoError(t, err)
	assert.True(t, reflect.DeepEqual(want, got))

	// Add a new EC2 instance
	awsServices.instances = append(awsServices.instances, newInstance)
	want = map[InstanceID]*ec2types.Instance{
		"i-self": awsServices.selfInstance,
		InstanceID(aws.ToString(newInstance.InstanceId)): newInstance,
	}
	got, err = c.findInstancesForELB(context.TODO(), []*v1.Node{defaultNode, newNode}, nil)
	assert.NoError(t, err)
	assert.True(t, reflect.DeepEqual(want, got))

	// Verify existing instance cache gets used
	cacheExpiryOld := c.instanceCache.snapshot.timestamp
	got, err = c.findInstancesForELB(context.TODO(), []*v1.Node{defaultNode, newNode}, nil)
	assert.NoError(t, err)
	assert.True(t, reflect.DeepEqual(want, got))
	cacheExpiryNew := c.instanceCache.snapshot.timestamp
	assert.Equal(t, cacheExpiryOld, cacheExpiryNew)

	// Force cache expiry and verify cache gets updated with new timestamp
	cacheExpiryOld = c.instanceCache.snapshot.timestamp
	c.instanceCache.snapshot.timestamp = c.instanceCache.snapshot.timestamp.Add(-(defaultEC2InstanceCacheMaxAge + 1*time.Second))
	got, err = c.findInstancesForELB(context.TODO(), []*v1.Node{defaultNode, newNode}, nil)
	assert.NoError(t, err)
	assert.True(t, reflect.DeepEqual(want, got))
	cacheExpiryNew = c.instanceCache.snapshot.timestamp
	assert.True(t, cacheExpiryNew.After(cacheExpiryOld))
}

func TestCloud_chunkTargetDescriptions(t *testing.T) {
	type args struct {
		targets   []elbv2types.TargetDescription
		chunkSize int
	}
	tests := []struct {
		name string
		args args
		want [][]elbv2types.TargetDescription
	}{
		{
			name: "can be evenly chunked",
			args: args{
				targets: []elbv2types.TargetDescription{
					{
						Id:   aws.String("i-abcdefg1"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdefg2"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdefg3"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdefg4"),
						Port: aws.Int32(8080),
					},
				},
				chunkSize: 2,
			},
			want: [][]elbv2types.TargetDescription{
				{
					{
						Id:   aws.String("i-abcdefg1"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdefg2"),
						Port: aws.Int32(8080),
					},
				},
				{
					{
						Id:   aws.String("i-abcdefg3"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdefg4"),
						Port: aws.Int32(8080),
					},
				},
			},
		},
		{
			name: "cannot be evenly chunked",
			args: args{
				targets: []elbv2types.TargetDescription{
					{
						Id:   aws.String("i-abcdefg1"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdefg2"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdefg3"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdefg4"),
						Port: aws.Int32(8080),
					},
				},
				chunkSize: 3,
			},
			want: [][]elbv2types.TargetDescription{
				{
					{
						Id:   aws.String("i-abcdefg1"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdefg2"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdefg3"),
						Port: aws.Int32(8080),
					},
				},
				{

					{
						Id:   aws.String("i-abcdefg4"),
						Port: aws.Int32(8080),
					},
				},
			},
		},
		{
			name: "chunkSize equal to total count",
			args: args{
				targets: []elbv2types.TargetDescription{
					{
						Id:   aws.String("i-abcdefg1"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdefg2"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdefg3"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdefg4"),
						Port: aws.Int32(8080),
					},
				},
				chunkSize: 4,
			},
			want: [][]elbv2types.TargetDescription{
				{
					{
						Id:   aws.String("i-abcdefg1"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdefg2"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdefg3"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdefg4"),
						Port: aws.Int32(8080),
					},
				},
			},
		},
		{
			name: "chunkSize greater than total count",
			args: args{
				targets: []elbv2types.TargetDescription{
					{
						Id:   aws.String("i-abcdefg1"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdefg2"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdefg3"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdefg4"),
						Port: aws.Int32(8080),
					},
				},
				chunkSize: 10,
			},
			want: [][]elbv2types.TargetDescription{
				{
					{
						Id:   aws.String("i-abcdefg1"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdefg2"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdefg3"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdefg4"),
						Port: aws.Int32(8080),
					},
				},
			},
		},
		{
			name: "chunk nil slice",
			args: args{
				targets:   nil,
				chunkSize: 2,
			},
			want: nil,
		},
		{
			name: "chunk empty slice",
			args: args{
				targets:   []elbv2types.TargetDescription{},
				chunkSize: 2,
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Cloud{}
			got := c.chunkTargetDescriptions(tt.args.targets, tt.args.chunkSize)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCloud_diffTargetGroupTargets(t *testing.T) {
	type args struct {
		expectedTargets []*elbv2types.TargetDescription
		actualTargets   []*elbv2types.TargetDescription
	}
	tests := []struct {
		name                    string
		args                    args
		wantTargetsToRegister   []elbv2types.TargetDescription
		wantTargetsToDeregister []elbv2types.TargetDescription
	}{
		{
			name: "all targets to register",
			args: args{
				expectedTargets: []*elbv2types.TargetDescription{
					{
						Id:   aws.String("i-abcdef1"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdef2"),
						Port: aws.Int32(8080),
					},
				},
				actualTargets: nil,
			},
			wantTargetsToRegister: []elbv2types.TargetDescription{
				{
					Id:   aws.String("i-abcdef1"),
					Port: aws.Int32(8080),
				},
				{
					Id:   aws.String("i-abcdef2"),
					Port: aws.Int32(8080),
				},
			},
			wantTargetsToDeregister: nil,
		},
		{
			name: "all targets to deregister",
			args: args{
				expectedTargets: nil,
				actualTargets: []*elbv2types.TargetDescription{
					{
						Id:   aws.String("i-abcdef1"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdef2"),
						Port: aws.Int32(8080),
					},
				},
			},
			wantTargetsToRegister: nil,
			wantTargetsToDeregister: []elbv2types.TargetDescription{
				{
					Id:   aws.String("i-abcdef1"),
					Port: aws.Int32(8080),
				},
				{
					Id:   aws.String("i-abcdef2"),
					Port: aws.Int32(8080),
				},
			},
		},
		{
			name: "some targets to register and deregister",
			args: args{
				expectedTargets: []*elbv2types.TargetDescription{
					{
						Id:   aws.String("i-abcdef1"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdef4"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdef5"),
						Port: aws.Int32(8080),
					},
				},
				actualTargets: []*elbv2types.TargetDescription{
					{
						Id:   aws.String("i-abcdef1"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdef2"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdef3"),
						Port: aws.Int32(8080),
					},
				},
			},
			wantTargetsToRegister: []elbv2types.TargetDescription{
				{
					Id:   aws.String("i-abcdef4"),
					Port: aws.Int32(8080),
				},
				{
					Id:   aws.String("i-abcdef5"),
					Port: aws.Int32(8080),
				},
			},
			wantTargetsToDeregister: []elbv2types.TargetDescription{
				{
					Id:   aws.String("i-abcdef2"),
					Port: aws.Int32(8080),
				},
				{
					Id:   aws.String("i-abcdef3"),
					Port: aws.Int32(8080),
				},
			},
		},
		{
			name: "both expected and actual targets are empty",
			args: args{
				expectedTargets: nil,
				actualTargets:   nil,
			},
			wantTargetsToRegister:   nil,
			wantTargetsToDeregister: nil,
		},
		{
			name: "expected and actual targets equals",
			args: args{
				expectedTargets: []*elbv2types.TargetDescription{
					{
						Id:   aws.String("i-abcdef1"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdef2"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdef3"),
						Port: aws.Int32(8080),
					},
				},
				actualTargets: []*elbv2types.TargetDescription{
					{
						Id:   aws.String("i-abcdef1"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdef2"),
						Port: aws.Int32(8080),
					},
					{
						Id:   aws.String("i-abcdef3"),
						Port: aws.Int32(8080),
					},
				},
			},
			wantTargetsToRegister:   nil,
			wantTargetsToDeregister: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Cloud{}
			gotTargetsToRegister, gotTargetsToDeregister := c.diffTargetGroupTargets(tt.args.expectedTargets, tt.args.actualTargets)
			assert.Equal(t, tt.wantTargetsToRegister, gotTargetsToRegister)
			assert.Equal(t, tt.wantTargetsToDeregister, gotTargetsToDeregister)
		})
	}
}

func TestCloud_computeTargetGroupExpectedTargets(t *testing.T) {
	type args struct {
		instanceIDs []string
		port        int32
	}
	tests := []struct {
		name string
		args args
		want []*elbv2types.TargetDescription
	}{
		{
			name: "no instance",
			args: args{
				instanceIDs: nil,
				port:        8080,
			},
			want: []*elbv2types.TargetDescription{},
		},
		{
			name: "one instance",
			args: args{
				instanceIDs: []string{"i-abcdef1"},
				port:        8080,
			},
			want: []*elbv2types.TargetDescription{
				{
					Id:   aws.String("i-abcdef1"),
					Port: aws.Int32(8080),
				},
			},
		},
		{
			name: "multiple instances",
			args: args{
				instanceIDs: []string{"i-abcdef1", "i-abcdef2", "i-abcdef3"},
				port:        8080,
			},
			want: []*elbv2types.TargetDescription{
				{
					Id:   aws.String("i-abcdef1"),
					Port: aws.Int32(8080),
				},
				{
					Id:   aws.String("i-abcdef2"),
					Port: aws.Int32(8080),
				},
				{
					Id:   aws.String("i-abcdef3"),
					Port: aws.Int32(8080),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Cloud{}
			got := c.computeTargetGroupExpectedTargets(tt.args.instanceIDs, tt.args.port)
			assert.Equal(t, tt.want, got)
		})
	}
}

// Unit test generated by Cursor AI, reviewed by human.
func TestCloud_isOwnedSecurityGroup(t *testing.T) {
	type testArgs struct {
		securityGroupID string
		clusterID       string
	}

	tests := []struct {
		name            string
		securityGroupID string
		clusterID       string
		setupMocks      func(*MockedFakeEC2, testArgs)
		expectOwned     bool
		expectError     bool
	}{
		{
			name:            "security group is owned",
			securityGroupID: "sg-owned",
			clusterID:       "test-cluster",
			setupMocks: func(m *MockedFakeEC2, args testArgs) {
				m.On("DescribeSecurityGroups", &ec2.DescribeSecurityGroupsInput{
					GroupIds: []string{args.securityGroupID},
				}).Return([]ec2types.SecurityGroup{
					{
						GroupId: aws.String(args.securityGroupID),
						Tags: []ec2types.Tag{
							{
								Key:   aws.String("kubernetes.io/cluster/" + args.clusterID),
								Value: aws.String("owned"),
							},
						},
					},
				}, nil)
			},
			expectOwned: true,
			expectError: false,
		},
		{
			name:            "security group is not owned",
			securityGroupID: "sg-not-owned",
			clusterID:       "test-cluster",
			setupMocks: func(m *MockedFakeEC2, args testArgs) {
				m.On("DescribeSecurityGroups", &ec2.DescribeSecurityGroupsInput{
					GroupIds: []string{args.securityGroupID},
				}).Return([]ec2types.SecurityGroup{
					{
						GroupId: aws.String(args.securityGroupID),
						Tags: []ec2types.Tag{
							{
								Key:   aws.String("kubernetes.io/cluster/" + args.clusterID),
								Value: aws.String("shared"),
							},
						},
					},
				}, nil)
			},
			expectOwned: false,
			expectError: false,
		},
		{
			name:            "security group with legacy tag is owned",
			securityGroupID: "sg-legacy-owned",
			clusterID:       "test-cluster",
			setupMocks: func(m *MockedFakeEC2, args testArgs) {
				m.On("DescribeSecurityGroups", &ec2.DescribeSecurityGroupsInput{
					GroupIds: []string{args.securityGroupID},
				}).Return([]ec2types.SecurityGroup{
					{
						GroupId: aws.String(args.securityGroupID),
						Tags: []ec2types.Tag{
							{
								Key:   aws.String("KubernetesCluster"),
								Value: aws.String(args.clusterID),
							},
						},
					},
				}, nil)
			},
			expectOwned: true,
			expectError: false,
		},
		{
			name:            "error retrieving security group",
			securityGroupID: "sg-error",
			clusterID:       "test-cluster",
			setupMocks: func(m *MockedFakeEC2, args testArgs) {
				m.On("DescribeSecurityGroups", &ec2.DescribeSecurityGroupsInput{
					GroupIds: []string{args.securityGroupID},
				}).Return([]ec2types.SecurityGroup{}, errors.New("AWS error"))
			},
			expectOwned: false,
			expectError: true,
		},
		{
			name:            "security group not found",
			securityGroupID: "sg-not-found",
			clusterID:       "test-cluster",
			setupMocks: func(m *MockedFakeEC2, args testArgs) {
				m.On("DescribeSecurityGroups", &ec2.DescribeSecurityGroupsInput{
					GroupIds: []string{args.securityGroupID},
				}).Return([]ec2types.SecurityGroup{}, nil)
			},
			expectOwned: false,
			expectError: true,
		},
		{
			name:            "multiple security groups found",
			securityGroupID: "sg-multiple",
			clusterID:       "test-cluster",
			setupMocks: func(m *MockedFakeEC2, args testArgs) {
				m.On("DescribeSecurityGroups", &ec2.DescribeSecurityGroupsInput{
					GroupIds: []string{args.securityGroupID},
				}).Return([]ec2types.SecurityGroup{
					{
						VpcId:   aws.String("vpc-123"),
						GroupId: aws.String(args.securityGroupID),
						Tags: []ec2types.Tag{
							{
								Key:   aws.String("kubernetes.io/cluster/" + args.clusterID),
								Value: aws.String("owned"),
							},
						},
					},
					{
						VpcId:   aws.String("vpc-456"),
						GroupId: aws.String(args.securityGroupID),
						Tags: []ec2types.Tag{
							{
								Key:   aws.String("kubernetes.io/cluster/" + args.clusterID),
								Value: aws.String("owned"),
							},
						},
					},
				}, nil)
			},
			expectOwned: false,
			expectError: true,
		},
		{
			name:            "multiple security groups owned and not owned",
			securityGroupID: "sg-multiple-mixed",
			clusterID:       "test-cluster",
			setupMocks: func(m *MockedFakeEC2, args testArgs) {
				m.On("DescribeSecurityGroups", &ec2.DescribeSecurityGroupsInput{
					GroupIds: []string{args.securityGroupID},
				}).Return([]ec2types.SecurityGroup{
					{
						GroupId: aws.String(args.securityGroupID),
						Tags: []ec2types.Tag{
							{
								Key:   aws.String("kubernetes.io/cluster/" + args.clusterID),
								Value: aws.String("owned"),
							},
						},
					},
					{
						GroupId: aws.String(args.securityGroupID),
						Tags:    []ec2types.Tag{},
					},
				}, nil)
			},
			expectOwned: false,
			expectError: true,
		},
		{
			name:            "empty cluster ID means not owned",
			securityGroupID: "sg-empty-cluster",
			clusterID:       "", // Empty cluster ID
			setupMocks: func(m *MockedFakeEC2, args testArgs) {
				m.On("DescribeSecurityGroups", &ec2.DescribeSecurityGroupsInput{
					GroupIds: []string{args.securityGroupID},
				}).Return([]ec2types.SecurityGroup{
					{
						GroupId: aws.String(args.securityGroupID),
						Tags:    []ec2types.Tag{},
					},
				}, nil)
			},
			expectOwned: false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockedEC2 := &MockedFakeEC2{}

			tt.setupMocks(mockedEC2, testArgs{
				securityGroupID: tt.securityGroupID,
				clusterID:       tt.clusterID,
			})

			cloud := &Cloud{
				ec2: mockedEC2,
				tagging: awsTagging{
					ClusterID: tt.clusterID,
				},
			}

			ctx := context.Background()
			owned, err := cloud.isOwnedSecurityGroup(ctx, tt.securityGroupID)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectOwned, owned)
			}

			mockedEC2.AssertExpectations(t)
		})
	}
}

func TestCloud_removeOwnedSecurityGroups(t *testing.T) {
	tests := []struct {
		name                   string
		securityGroups         []string
		setupMocks             func(*MockedFakeEC2)
		setupSecurityGroupTags func() map[string][]ec2types.Tag
		expectError            bool
		expectRevokeCallCount  int
		expectDeleteCallCount  int
	}{
		{
			name:           "successfully remove owned security groups",
			securityGroups: []string{"sg-owned1", "sg-owned2"},
			setupMocks: func(mockedEC2 *MockedFakeEC2) {
				// Mock DescribeSecurityGroups for ownership check
				mockedEC2.On("DescribeSecurityGroups", mock.MatchedBy(func(input *ec2.DescribeSecurityGroupsInput) bool {
					return len(input.GroupIds) == 1 && (input.GroupIds[0] == "sg-owned1" || input.GroupIds[0] == "sg-owned2")
				})).Return([]ec2types.SecurityGroup{
					{
						GroupId: aws.String("sg-owned1"),
						Tags: []ec2types.Tag{
							{
								Key:   aws.String("kubernetes.io/cluster/test-cluster"),
								Value: aws.String("owned"),
							},
						},
					},
				}, nil)

				// Mock DescribeSecurityGroups for rule references
				mockedEC2.On("DescribeSecurityGroups", mock.MatchedBy(func(input *ec2.DescribeSecurityGroupsInput) bool {
					return len(input.Filters) > 0
				})).Return([]ec2types.SecurityGroup{
					{
						GroupId: aws.String("sg-ref1"),
						Tags: []ec2types.Tag{
							{
								Key:   aws.String("kubernetes.io/cluster/test-cluster"),
								Value: aws.String("owned"),
							},
						},
						IpPermissions: []ec2types.IpPermission{
							{
								IpProtocol: aws.String("tcp"),
								FromPort:   aws.Int32(80),
								ToPort:     aws.Int32(80),
								UserIdGroupPairs: []ec2types.UserIdGroupPair{
									{
										GroupId: aws.String("sg-owned1"),
									},
								},
							},
						},
					},
				}, nil)

				// Mock RevokeSecurityGroupIngress
				mockedEC2.On("RevokeSecurityGroupIngress", mock.MatchedBy(func(input *ec2.RevokeSecurityGroupIngressInput) bool {
					return aws.ToString(input.GroupId) == "sg-ref1"
				})).Return(&ec2.RevokeSecurityGroupIngressOutput{}, nil)

				// Mock DeleteSecurityGroup
				mockedEC2.On("DeleteSecurityGroup", mock.MatchedBy(func(input *ec2.DeleteSecurityGroupInput) bool {
					return aws.ToString(input.GroupId) == "sg-owned1" || aws.ToString(input.GroupId) == "sg-owned2"
				})).Return(&ec2.DeleteSecurityGroupOutput{}, nil)
			},
			expectError:           false,
			expectRevokeCallCount: 2,
			expectDeleteCallCount: 2,
		},
		{
			name:           "skip non-owned security groups",
			securityGroups: []string{"sg-not-owned1", "sg-not-owned2"},
			setupMocks: func(mockedEC2 *MockedFakeEC2) {
				// Mock DescribeSecurityGroups for ownership check - return non-owned
				mockedEC2.On("DescribeSecurityGroups", mock.MatchedBy(func(input *ec2.DescribeSecurityGroupsInput) bool {
					return len(input.GroupIds) == 1 && input.GroupIds[0] == "sg-not-owned1"
				})).Return([]ec2types.SecurityGroup{
					{
						GroupId: aws.String("sg-not-owned1"),
						Tags: []ec2types.Tag{
							{
								Key:   aws.String("some-other-tag"),
								Value: aws.String("some-value"),
							},
						},
					},
				}, nil)

				mockedEC2.On("DescribeSecurityGroups", mock.MatchedBy(func(input *ec2.DescribeSecurityGroupsInput) bool {
					return len(input.GroupIds) == 1 && input.GroupIds[0] == "sg-not-owned2"
				})).Return([]ec2types.SecurityGroup{
					{
						GroupId: aws.String("sg-not-owned2"),
						Tags: []ec2types.Tag{
							{
								Key:   aws.String("another-tag"),
								Value: aws.String("another-value"),
							},
						},
					},
				}, nil)

				// Mock DescribeSecurityGroups for rule references for sg-not-owned1
				mockedEC2.On("DescribeSecurityGroups", mock.MatchedBy(func(input *ec2.DescribeSecurityGroupsInput) bool {
					return len(input.Filters) > 0 && len(input.Filters[0].Values) > 0 && input.Filters[0].Values[0] == "sg-not-owned1"
				})).Return([]ec2types.SecurityGroup{
					{
						GroupId: aws.String("sg-ref1"),
						Tags: []ec2types.Tag{
							{
								Key:   aws.String("kubernetes.io/cluster/test-cluster"),
								Value: aws.String("owned"),
							},
						},
						IpPermissions: []ec2types.IpPermission{
							{
								IpProtocol: aws.String("tcp"),
								FromPort:   aws.Int32(80),
								ToPort:     aws.Int32(80),
								UserIdGroupPairs: []ec2types.UserIdGroupPair{
									{
										GroupId: aws.String("sg-not-owned1"),
									},
								},
							},
						},
					},
				}, nil)

				// Mock DescribeSecurityGroups for rule references for sg-not-owned2
				mockedEC2.On("DescribeSecurityGroups", mock.MatchedBy(func(input *ec2.DescribeSecurityGroupsInput) bool {
					return len(input.Filters) > 0 && len(input.Filters[0].Values) > 0 && input.Filters[0].Values[0] == "sg-not-owned2"
				})).Return([]ec2types.SecurityGroup{
					{
						GroupId: aws.String("sg-ref2"),
						Tags: []ec2types.Tag{
							{
								Key:   aws.String("kubernetes.io/cluster/test-cluster"),
								Value: aws.String("owned"),
							},
						},
						IpPermissions: []ec2types.IpPermission{
							{
								IpProtocol: aws.String("tcp"),
								FromPort:   aws.Int32(443),
								ToPort:     aws.Int32(443),
								UserIdGroupPairs: []ec2types.UserIdGroupPair{
									{
										GroupId: aws.String("sg-not-owned2"),
									},
								},
							},
						},
					},
				}, nil)

				// Mock RevokeSecurityGroupIngress for sg-ref1
				mockedEC2.On("RevokeSecurityGroupIngress", mock.MatchedBy(func(input *ec2.RevokeSecurityGroupIngressInput) bool {
					return aws.ToString(input.GroupId) == "sg-ref1"
				})).Return(&ec2.RevokeSecurityGroupIngressOutput{}, nil)

				// Mock RevokeSecurityGroupIngress for sg-ref2
				mockedEC2.On("RevokeSecurityGroupIngress", mock.MatchedBy(func(input *ec2.RevokeSecurityGroupIngressInput) bool {
					return aws.ToString(input.GroupId) == "sg-ref2"
				})).Return(&ec2.RevokeSecurityGroupIngressOutput{}, nil)

				// DeleteSecurityGroup should NOT be called for non-owned groups
			},
			expectError:           false,
			expectRevokeCallCount: 2,
			expectDeleteCallCount: 0,
		},
		{
			name:           "error checking ownership",
			securityGroups: []string{"sg-error"},
			setupMocks: func(mockedEC2 *MockedFakeEC2) {
				// Mock DescribeSecurityGroups to return error
				mockedEC2.On("DescribeSecurityGroups", mock.MatchedBy(func(input *ec2.DescribeSecurityGroupsInput) bool {
					return len(input.GroupIds) == 1 && input.GroupIds[0] == "sg-error"
				})).Return([]ec2types.SecurityGroup(nil), errors.New("AWS error"))
			},
			expectError:           true, // Function should return error when ownership check fails
			expectRevokeCallCount: 0,
			expectDeleteCallCount: 0,
		},
		{
			name:           "empty security groups list",
			securityGroups: []string{},
			setupMocks: func(mockedEC2 *MockedFakeEC2) {
				// No mocks needed for empty list
			},
			expectError:           false,
			expectRevokeCallCount: 0,
			expectDeleteCallCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockedEC2 := &MockedFakeEC2{}

			// Setup mocks
			tt.setupMocks(mockedEC2)

			cloud := &Cloud{
				ec2: mockedEC2,
				tagging: awsTagging{
					ClusterID: "test-cluster",
				},
			}

			ctx := context.Background()
			errs := cloud.removeOwnedSecurityGroups(ctx, "test-lb", tt.securityGroups)

			if tt.expectError {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}

			mockedEC2.AssertExpectations(t)
		})
	}
}

func TestCloud_buildSecurityGroupRuleReferences(t *testing.T) {
	tests := []struct {
		name                                 string
		targetGroupID                        string
		setupMocks                           func(*MockedFakeEC2)
		expectError                          bool
		expectedErrorContains                string
		expectedGroupsWithTagsCount          int
		expectedGroupsLinkedPermissionsCount int
		additionalAssertions                 func(t *testing.T, groupsWithTags map[*ec2types.SecurityGroup]bool, groupsLinkedPermissions map[*ec2types.SecurityGroup]IPPermissionSet)
	}{
		{
			name:          "success with cluster tagged security group and linked permissions",
			targetGroupID: "sg-target",
			setupMocks: func(mockedEC2 *MockedFakeEC2) {
				mockedEC2.On("DescribeSecurityGroups", &ec2.DescribeSecurityGroupsInput{
					Filters: []ec2types.Filter{
						{
							Name:   aws.String("ip-permission.group-id"),
							Values: []string{"sg-target"},
						},
					},
				}).Return([]ec2types.SecurityGroup{
					{
						GroupId: aws.String("sg-owned"),
						Tags: []ec2types.Tag{
							{
								Key:   aws.String("kubernetes.io/cluster/test-cluster"),
								Value: aws.String("owned"),
							},
						},
						IpPermissions: []ec2types.IpPermission{
							{
								IpProtocol: aws.String("tcp"),
								FromPort:   aws.Int32(80),
								ToPort:     aws.Int32(80),
								UserIdGroupPairs: []ec2types.UserIdGroupPair{
									{
										GroupId: aws.String("sg-target"),
									},
								},
							},
						},
					},
				}, nil)
			},
			expectError:                          false,
			expectedGroupsWithTagsCount:          1,
			expectedGroupsLinkedPermissionsCount: 1,
			additionalAssertions: func(t *testing.T, groupsWithTags map[*ec2types.SecurityGroup]bool, groupsLinkedPermissions map[*ec2types.SecurityGroup]IPPermissionSet) {
				// Find the security group in the results
				var foundSG *ec2types.SecurityGroup
				for sg := range groupsWithTags {
					if aws.ToString(sg.GroupId) == "sg-owned" {
						foundSG = sg
						break
					}
				}
				require.NotNil(t, foundSG)

				// Check that the security group has cluster tags
				assert.True(t, groupsWithTags[foundSG])

				// Check that the security group has linked permissions
				assert.Equal(t, 1, groupsLinkedPermissions[foundSG].Len())
			},
		},
		{
			name:          "success with non-cluster tagged security group",
			targetGroupID: "sg-target",
			setupMocks: func(mockedEC2 *MockedFakeEC2) {
				mockedEC2.On("DescribeSecurityGroups", &ec2.DescribeSecurityGroupsInput{
					Filters: []ec2types.Filter{
						{
							Name:   aws.String("ip-permission.group-id"),
							Values: []string{"sg-target"},
						},
					},
				}).Return([]ec2types.SecurityGroup{
					{
						GroupId: aws.String("sg-unowned"),
						Tags: []ec2types.Tag{
							{
								Key:   aws.String("some-other-tag"),
								Value: aws.String("some-value"),
							},
						},
						IpPermissions: []ec2types.IpPermission{
							{
								IpProtocol: aws.String("tcp"),
								FromPort:   aws.Int32(80),
								ToPort:     aws.Int32(80),
								UserIdGroupPairs: []ec2types.UserIdGroupPair{
									{
										GroupId: aws.String("sg-target"),
									},
								},
							},
						},
					},
				}, nil)
			},
			expectError:                          false,
			expectedGroupsWithTagsCount:          1,
			expectedGroupsLinkedPermissionsCount: 1,
			additionalAssertions: func(t *testing.T, groupsWithTags map[*ec2types.SecurityGroup]bool, groupsLinkedPermissions map[*ec2types.SecurityGroup]IPPermissionSet) {
				// Find the security group in the linkedPermissions results
				var foundSG *ec2types.SecurityGroup
				for sg := range groupsLinkedPermissions {
					if aws.ToString(sg.GroupId) == "sg-unowned" {
						foundSG = sg
						break
					}
				}
				require.NotNil(t, foundSG)

				// Check that the security group is in groupsWithTags but not cluster tagged
				_, exists := groupsWithTags[foundSG]
				assert.True(t, exists)

				// Check that the security group is not cluster tagged
				assert.False(t, groupsWithTags[foundSG])
			},
		},
		{
			name:          "error when DescribeSecurityGroups fails",
			targetGroupID: "sg-target",
			setupMocks: func(mockedEC2 *MockedFakeEC2) {
				mockedEC2.On("DescribeSecurityGroups", &ec2.DescribeSecurityGroupsInput{
					Filters: []ec2types.Filter{
						{
							Name:   aws.String("ip-permission.group-id"),
							Values: []string{"sg-target"},
						},
					},
				}).Return([]ec2types.SecurityGroup{}, errors.New("AWS API error"))
			},
			expectError:                          true,
			expectedErrorContains:                "error querying security groups for ELB",
			expectedGroupsWithTagsCount:          0,
			expectedGroupsLinkedPermissionsCount: 0,
		},
		{
			name:          "success with no security groups found",
			targetGroupID: "sg-target",
			setupMocks: func(mockedEC2 *MockedFakeEC2) {
				mockedEC2.On("DescribeSecurityGroups", &ec2.DescribeSecurityGroupsInput{
					Filters: []ec2types.Filter{
						{
							Name:   aws.String("ip-permission.group-id"),
							Values: []string{"sg-target"},
						},
					},
				}).Return([]ec2types.SecurityGroup{}, nil)
			},
			expectError:                          false,
			expectedGroupsWithTagsCount:          0,
			expectedGroupsLinkedPermissionsCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockedEC2 := &MockedFakeEC2{}
			tt.setupMocks(mockedEC2)

			c := &Cloud{
				ec2:    mockedEC2,
				region: "us-west-2",
				tagging: awsTagging{
					ClusterID: "test-cluster",
				},
			}

			ctx := context.TODO()
			groupsWithTags, groupsLinkedPermissions, err := c.buildSecurityGroupRuleReferences(ctx, tt.targetGroupID)

			if tt.expectError {
				require.Error(t, err)
				if tt.expectedErrorContains != "" {
					assert.Contains(t, err.Error(), tt.expectedErrorContains)
				}
			} else {
				require.NoError(t, err)
			}

			assert.Len(t, groupsWithTags, tt.expectedGroupsWithTagsCount)
			assert.Len(t, groupsLinkedPermissions, tt.expectedGroupsLinkedPermissionsCount)

			if tt.additionalAssertions != nil {
				tt.additionalAssertions(t, groupsWithTags, groupsLinkedPermissions)
			}

			mockedEC2.AssertExpectations(t)
		})
	}
}
