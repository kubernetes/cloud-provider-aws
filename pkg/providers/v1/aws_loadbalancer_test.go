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
	"fmt"
	"reflect"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/stretchr/testify/assert"

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
		instances     map[InstanceID]*ec2types.Instance
		port          int32
		ipAddressType elbv2types.TargetGroupIpAddressTypeEnum
	}
	tests := []struct {
		name string
		args args
		want []*elbv2types.TargetDescription
	}{
		{
			name: "no instance",
			args: args{
				instances:     nil,
				port:          8080,
				ipAddressType: elbv2types.TargetGroupIpAddressTypeEnumIpv4,
			},
			want: []*elbv2types.TargetDescription{},
		},
		{
			name: "one instance - IPv4",
			args: args{
				instances: map[InstanceID]*ec2types.Instance{
					"i-abcdef1": {},
				},
				port:          8080,
				ipAddressType: elbv2types.TargetGroupIpAddressTypeEnumIpv4,
			},
			want: []*elbv2types.TargetDescription{
				{
					Id:   aws.String("i-abcdef1"),
					Port: aws.Int32(8080),
				},
			},
		},
		{
			name: "multiple instances - IPv4",
			args: args{
				instances: map[InstanceID]*ec2types.Instance{
					"i-abcdef1": {},
					"i-abcdef2": {},
					"i-abcdef3": {},
				},
				port:          8080,
				ipAddressType: elbv2types.TargetGroupIpAddressTypeEnumIpv4,
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
		{
			name: "one instance - IPv6",
			args: args{
				instances: map[InstanceID]*ec2types.Instance{
					"i-abcdef1": {
						NetworkInterfaces: []ec2types.InstanceNetworkInterface{
							{
								Status: ec2types.NetworkInterfaceStatusInUse,
								Ipv6Addresses: []ec2types.InstanceIpv6Address{
									{
										Ipv6Address: aws.String("2001:db8::1"),
									},
								},
							},
						},
					},
				},
				port:          8080,
				ipAddressType: elbv2types.TargetGroupIpAddressTypeEnumIpv6,
			},
			want: []*elbv2types.TargetDescription{
				{
					Id:   aws.String("2001:db8::1"),
					Port: aws.Int32(8080),
				},
			},
		},
		{
			name: "multiple instances - IPv6",
			args: args{
				instances: map[InstanceID]*ec2types.Instance{
					"i-abcdef1": {
						NetworkInterfaces: []ec2types.InstanceNetworkInterface{
							{
								Status: ec2types.NetworkInterfaceStatusInUse,
								Ipv6Addresses: []ec2types.InstanceIpv6Address{
									{
										Ipv6Address: aws.String("2001:db8::1"),
									},
								},
							},
						},
					},
					"i-abcdef2": {
						NetworkInterfaces: []ec2types.InstanceNetworkInterface{
							{
								Status: ec2types.NetworkInterfaceStatusInUse,
								Ipv6Addresses: []ec2types.InstanceIpv6Address{
									{
										Ipv6Address: aws.String("2001:db8::2"),
									},
								},
							},
						},
					},
					"i-abcdef3": {
						NetworkInterfaces: []ec2types.InstanceNetworkInterface{
							{
								Status: ec2types.NetworkInterfaceStatusInUse,
								Ipv6Addresses: []ec2types.InstanceIpv6Address{
									{
										Ipv6Address: aws.String("2001:db8::3"),
									},
								},
							},
						},
					},
				},
				port:          8080,
				ipAddressType: elbv2types.TargetGroupIpAddressTypeEnumIpv6,
			},
			want: []*elbv2types.TargetDescription{
				{
					Id:   aws.String("2001:db8::1"),
					Port: aws.Int32(8080),
				},
				{
					Id:   aws.String("2001:db8::2"),
					Port: aws.Int32(8080),
				},
				{
					Id:   aws.String("2001:db8::3"),
					Port: aws.Int32(8080),
				},
			},
		},
		{
			name: "instance without IPv6 - IPv6 target group",
			args: args{
				instances: map[InstanceID]*ec2types.Instance{
					"i-abcdef1": {
						NetworkInterfaces: []ec2types.InstanceNetworkInterface{
							{
								Status: ec2types.NetworkInterfaceStatusInUse,
							},
						},
					},
				},
				port:          8080,
				ipAddressType: elbv2types.TargetGroupIpAddressTypeEnumIpv6,
			},
			want: []*elbv2types.TargetDescription{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Cloud{}
			got := c.computeTargetGroupExpectedTargets(tt.args.instances, tt.args.port, tt.args.ipAddressType)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

// Make sure that errors returned by DescribeLoadBalancerPolicies are
// handled gracefully, and don't progress further into the function
func TestEnsureSSLNegotiationPolicyErrorHandling(t *testing.T) {
	awsServices := NewFakeAWSServices(TestClusterID)
	c, err := newAWSCloud(config.CloudConfig{}, awsServices)
	if err != nil {
		t.Errorf("Error building aws cloud: %v", err)
		return
	}

	tests := []struct {
		name         string
		loadBalancer *elbtypes.LoadBalancerDescription
		policyName   string
		expectError  bool
	}{
		{
			name: "Expect LoadBalancerAttributeNotFoundException, error",
			loadBalancer: &elbtypes.LoadBalancerDescription{
				LoadBalancerName: aws.String(""),
			},
			policyName:  "",
			expectError: true,
		},
		{
			name: "Expect PolicyNotFoundException, nil error",
			loadBalancer: &elbtypes.LoadBalancerDescription{
				LoadBalancerName: aws.String("test-lb"),
			},
			policyName:  "",
			expectError: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := c.ensureSSLNegotiationPolicy(context.TODO(), test.loadBalancer, test.policyName)
			if test.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !test.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

// Unit test generated by Cursor AI, reviewed by Human
func TestCloud_buildTargetGroupAttributes(t *testing.T) {
	tests := []struct {
		name               string
		targetGroup        *elbv2types.TargetGroup
		existingAttributes []elbv2types.TargetGroupAttribute
		annotations        map[string]string
		expectedAttributes []elbv2types.TargetGroupAttribute
		expectedError      string
	}{
		// Invalid AWS constraints are validated by pre-flight (validateServiceAnnotationTargetGroupAttributes).
		// Examples:
		// - preserve_client_ip.enabled=false for UDP target
		// - preserve_client_ip.enabled=false for TCP_UDP target
		// Unsupported attributes by controller are validated by pre-flight.
		// Examples:
		// - unsupported_attribute=value
		// - different attribute names than supported by controller:
		//   - preserve_client_ip.enabled
		//   - proxy_protocol_v2.enabled
		// Malformed annotations are validated by pre-flight.
		// Duplicate attributes are validated by pre-flight.
		{
			name:        "nil target group should return error",
			targetGroup: nil,
			existingAttributes: []elbv2types.TargetGroupAttribute{
				{Key: aws.String("preserve_client_ip.enabled"), Value: aws.String("true")},
			},
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=false",
			},
			expectedError: "error building target group attributes: target group is nil",
		},
		{
			name: "nil existing attributes should return error",
			targetGroup: &elbv2types.TargetGroup{
				TargetGroupArn: aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-tg/1234567890123456"),
				Protocol:       elbv2types.ProtocolEnumTcp,
				TargetType:     elbv2types.TargetTypeEnumInstance,
			},
			existingAttributes: nil,
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=false",
			},
			expectedError: "error building target group attributes: target group attributes are nil",
		},
		{
			name: "no target group attributes annotation",
			targetGroup: &elbv2types.TargetGroup{
				TargetGroupArn: aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-tg/1234567890123456"),
				Protocol:       elbv2types.ProtocolEnumTcp,
				TargetType:     elbv2types.TargetTypeEnumInstance,
			},
			existingAttributes: []elbv2types.TargetGroupAttribute{
				{Key: aws.String("some_key"), Value: aws.String("some_value")},
			},
			annotations:        map[string]string{},
			expectedAttributes: []elbv2types.TargetGroupAttribute{},
		},
		{
			name: "annotation parsing - empty annotation should return empty diff",
			targetGroup: &elbv2types.TargetGroup{
				TargetGroupArn: aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-tg/1234567890123456"),
				Protocol:       elbv2types.ProtocolEnumHttp,
				TargetType:     elbv2types.TargetTypeEnumInstance,
			},
			existingAttributes: []elbv2types.TargetGroupAttribute{
				{Key: aws.String("preserve_client_ip.enabled"), Value: aws.String("true")},
			},
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "",
			},
			expectedAttributes: []elbv2types.TargetGroupAttribute{},
		},
		{
			name: "valid preserve_client_ip.enabled=true for instance target",
			targetGroup: &elbv2types.TargetGroup{
				TargetGroupArn: aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-tg/1234567890123456"),
				Protocol:       elbv2types.ProtocolEnumTcp,
				TargetType:     elbv2types.TargetTypeEnumInstance,
			},
			existingAttributes: []elbv2types.TargetGroupAttribute{
				{Key: aws.String("preserve_client_ip.enabled"), Value: aws.String("false")},
			},
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=true",
			},
			expectedAttributes: []elbv2types.TargetGroupAttribute{
				{Key: aws.String("preserve_client_ip.enabled"), Value: aws.String("true")},
			},
		},
		{
			name: "valid preserve_client_ip.enabled=false for IP target with TCP",
			targetGroup: &elbv2types.TargetGroup{
				TargetGroupArn: aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-tg/1234567890123456"),
				Protocol:       elbv2types.ProtocolEnumTcp,
				TargetType:     elbv2types.TargetTypeEnumIp,
			},
			existingAttributes: []elbv2types.TargetGroupAttribute{
				{Key: aws.String("preserve_client_ip.enabled"), Value: aws.String("true")},
			},
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=false",
			},
			expectedAttributes: []elbv2types.TargetGroupAttribute{
				{Key: aws.String("preserve_client_ip.enabled"), Value: aws.String("false")},
			},
		},
		{
			name: "valid proxy_protocol_v2.enabled=true",
			targetGroup: &elbv2types.TargetGroup{
				TargetGroupArn: aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-tg/1234567890123456"),
				Protocol:       elbv2types.ProtocolEnumTcp,
				TargetType:     elbv2types.TargetTypeEnumInstance,
			},
			existingAttributes: []elbv2types.TargetGroupAttribute{
				{Key: aws.String("proxy_protocol_v2.enabled"), Value: aws.String("false")},
			},
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "proxy_protocol_v2.enabled=true",
			},
			expectedAttributes: []elbv2types.TargetGroupAttribute{
				{Key: aws.String("proxy_protocol_v2.enabled"), Value: aws.String("true")},
			},
		},
		{
			name: "multiple attributes",
			targetGroup: &elbv2types.TargetGroup{
				TargetGroupArn: aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-tg/1234567890123456"),
				Protocol:       elbv2types.ProtocolEnumTcp,
				TargetType:     elbv2types.TargetTypeEnumInstance,
			},
			existingAttributes: []elbv2types.TargetGroupAttribute{
				{Key: aws.String("preserve_client_ip.enabled"), Value: aws.String("false")},
				{Key: aws.String("proxy_protocol_v2.enabled"), Value: aws.String("false")},
			},
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=true,proxy_protocol_v2.enabled=true",
			},
			expectedAttributes: []elbv2types.TargetGroupAttribute{
				{Key: aws.String("preserve_client_ip.enabled"), Value: aws.String("true")},
				{Key: aws.String("proxy_protocol_v2.enabled"), Value: aws.String("true")},
			},
		},
		{
			name: "no changes needed - attributes match defaults",
			targetGroup: &elbv2types.TargetGroup{
				TargetGroupArn: aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-tg/1234567890123456"),
				Protocol:       elbv2types.ProtocolEnumHttp,
				TargetType:     elbv2types.TargetTypeEnumInstance,
			},
			existingAttributes: []elbv2types.TargetGroupAttribute{
				{Key: aws.String("preserve_client_ip.enabled"), Value: aws.String("true")},
				{Key: aws.String("proxy_protocol_v2.enabled"), Value: aws.String("false")},
			},
			annotations:        map[string]string{},
			expectedAttributes: []elbv2types.TargetGroupAttribute{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Cloud{}
			result, err := c.buildTargetGroupAttributes(tt.targetGroup, tt.existingAttributes, tt.annotations)

			if len(tt.expectedError) > 0 {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, len(tt.expectedAttributes), len(result))

				// Convert to maps for easier comparison since order might vary
				expectedMap := make(map[string]string)
				for _, attr := range tt.expectedAttributes {
					expectedMap[aws.ToString(attr.Key)] = aws.ToString(attr.Value)
				}

				resultMap := make(map[string]string)
				for _, attr := range result {
					resultMap[aws.ToString(attr.Key)] = aws.ToString(attr.Value)
				}

				assert.Equal(t, expectedMap, resultMap)
			}
		})
	}
}

func TestCreateSubnetMappings(t *testing.T) {
	tests := []struct {
		name                   string
		subnetIDs              []string
		allocationIDs          []string
		privateIPv4Addresses   []string
		expectedSubnetMappings []elbv2types.SubnetMapping
	}{
		{
			name:                 "Add allocation ids",
			subnetIDs:            []string{"subnet-1234", "subnet-3456"},
			allocationIDs:        []string{"eipalloc-2345", "eipalloc-4567"},
			privateIPv4Addresses: []string{},
			expectedSubnetMappings: []elbv2types.SubnetMapping{
				{
					SubnetId:     aws.String("subnet-1234"),
					AllocationId: aws.String("eipalloc-2345"),
				},
				{
					SubnetId:     aws.String("subnet-3456"),
					AllocationId: aws.String("eipalloc-4567"),
				},
			},
		},
		{
			name:                 "Add Private ip address",
			subnetIDs:            []string{"subnet-1234", "subnet-3456"},
			allocationIDs:        []string{},
			privateIPv4Addresses: []string{"10.1.2.3", "10.2.3.4"},
			expectedSubnetMappings: []elbv2types.SubnetMapping{
				{
					SubnetId:           aws.String("subnet-1234"),
					PrivateIPv4Address: aws.String("10.1.2.3"),
				},
				{
					SubnetId:           aws.String("subnet-3456"),
					PrivateIPv4Address: aws.String("10.2.3.4"),
				},
			},
		},
		{
			name:                 "No private ips and allocation ids",
			subnetIDs:            []string{"subnet-1234", "subnet-3456"},
			allocationIDs:        []string{},
			privateIPv4Addresses: []string{},
			expectedSubnetMappings: []elbv2types.SubnetMapping{
				{
					SubnetId: aws.String("subnet-1234"),
				},
				{
					SubnetId: aws.String("subnet-3456"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualSubnetMappings := createSubnetMappings(tt.subnetIDs, tt.allocationIDs, tt.privateIPv4Addresses)
			assert.Equal(t, tt.expectedSubnetMappings, actualSubnetMappings)
		})
	}
}

// Unit test generated by Cursor AI
func TestGetKeyValuePropertiesFromAnnotation_TargetGroupAttributes(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		annotation  string
		expected    map[string]string
	}{
		{
			name: "valid target group attributes",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=true,proxy_protocol_v2.enabled=false",
			},
			annotation: ServiceAnnotationLoadBalancerTargetGroupAttributes,
			expected: map[string]string{
				"preserve_client_ip.enabled": "true",
				"proxy_protocol_v2.enabled":  "false",
			},
		},
		{
			name: "single attribute",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=true",
			},
			annotation: ServiceAnnotationLoadBalancerTargetGroupAttributes,
			expected: map[string]string{
				"preserve_client_ip.enabled": "true",
			},
		},
		{
			name: "empty annotation",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: "",
			},
			annotation: ServiceAnnotationLoadBalancerTargetGroupAttributes,
			expected:   map[string]string{},
		},
		{
			name: "annotation with spaces",
			annotations: map[string]string{
				ServiceAnnotationLoadBalancerTargetGroupAttributes: " preserve_client_ip.enabled=true , proxy_protocol_v2.enabled=false ",
			},
			annotation: ServiceAnnotationLoadBalancerTargetGroupAttributes,
			expected: map[string]string{
				"preserve_client_ip.enabled": "true",
				"proxy_protocol_v2.enabled":  "false",
			},
		},
		{
			name: "annotation not present",
			annotations: map[string]string{
				"other.annotation": "value",
			},
			annotation: ServiceAnnotationLoadBalancerTargetGroupAttributes,
			expected:   map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getKeyValuePropertiesFromAnnotation(tt.annotations, tt.annotation)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test-specific mock for ELB v2 client that embeds MockedFakeELBV2
type mockELBV2ClientForTargetGroupAttributes struct {
	*MockedFakeELBV2
	describeTargetGroupsFunc          func(ctx context.Context, input *elbv2.DescribeTargetGroupsInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupsOutput, error)
	describeTargetGroupAttributesFunc func(ctx context.Context, input *elbv2.DescribeTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupAttributesOutput, error)
	modifyTargetGroupAttributesFunc   func(ctx context.Context, input *elbv2.ModifyTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.ModifyTargetGroupAttributesOutput, error)
}

func (m *mockELBV2ClientForTargetGroupAttributes) DescribeTargetGroups(ctx context.Context, input *elbv2.DescribeTargetGroupsInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupsOutput, error) {
	if m.describeTargetGroupsFunc != nil {
		return m.describeTargetGroupsFunc(ctx, input, optFns...)
	}
	// Fall back to the embedded MockedFakeELBV2 implementation
	return m.MockedFakeELBV2.DescribeTargetGroups(ctx, input, optFns...)
}

func (m *mockELBV2ClientForTargetGroupAttributes) DescribeTargetGroupAttributes(ctx context.Context, input *elbv2.DescribeTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupAttributesOutput, error) {
	if m.describeTargetGroupAttributesFunc != nil {
		return m.describeTargetGroupAttributesFunc(ctx, input, optFns...)
	}
	return nil, fmt.Errorf("DescribeTargetGroupAttributes not mocked")
}

func (m *mockELBV2ClientForTargetGroupAttributes) ModifyTargetGroupAttributes(ctx context.Context, input *elbv2.ModifyTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.ModifyTargetGroupAttributesOutput, error) {
	if m.modifyTargetGroupAttributesFunc != nil {
		return m.modifyTargetGroupAttributesFunc(ctx, input, optFns...)
	}
	return nil, fmt.Errorf("ModifyTargetGroupAttributes not mocked")
}

// Unit test generated by Cursor AI
func TestCloud_ensureTargetGroupAttributes(t *testing.T) {
	testTargetGroup := &elbv2types.TargetGroup{
		TargetGroupArn: aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-tg/1234567890123456"),
		Protocol:       elbv2types.ProtocolEnumHttp,
		TargetType:     elbv2types.TargetTypeEnumInstance,
	}

	tests := []struct {
		name                           string
		targetGroup                    *elbv2types.TargetGroup
		annotations                    map[string]string
		mockDescribeTargetGroupAttribs func(ctx context.Context, input *elbv2.DescribeTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupAttributesOutput, error)
		mockModifyTargetGroupAttribs   func(ctx context.Context, input *elbv2.ModifyTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.ModifyTargetGroupAttributesOutput, error)
		expectedError                  string
		description                    string
	}{
		{
			name:          "nil target group should return error",
			targetGroup:   nil,
			annotations:   map[string]string{ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=true"},
			expectedError: "unable to reconcile target group attributes: target group is required",
			description:   "Function should validate target group is not nil before proceeding",
		},
		// DescribeTargetGroupAttributes failure
		{
			name:        "DescribeTargetGroupAttributes fails",
			targetGroup: testTargetGroup,
			annotations: map[string]string{ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=false"},
			mockDescribeTargetGroupAttribs: func(ctx context.Context, input *elbv2.DescribeTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupAttributesOutput, error) {
				return nil, fmt.Errorf("AWS API error: target group not found")
			},
			expectedError: "unable to retrieve target group attributes during attribute sync",
			description:   "Function should handle DescribeTargetGroupAttributes API failures",
		},
		// No changes needed - attributes match (successful case with no updates)
		{
			name:        "no changes needed - attributes already match desired state",
			targetGroup: testTargetGroup,
			annotations: map[string]string{ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=true,proxy_protocol_v2.enabled=false"},
			mockDescribeTargetGroupAttribs: func(ctx context.Context, input *elbv2.DescribeTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupAttributesOutput, error) {
				return &elbv2.DescribeTargetGroupAttributesOutput{
					Attributes: []elbv2types.TargetGroupAttribute{
						{Key: aws.String("preserve_client_ip.enabled"), Value: aws.String("true")}, // matches annotation
						{Key: aws.String("proxy_protocol_v2.enabled"), Value: aws.String("false")}, // matches annotation
					},
				}, nil
			},
			description: "Function should succeed when attributes already match desired state",
		},
		// No changes needed - no annotations (restore defaults, but they already match)
		{
			name:        "no changes needed - no annotations and attributes match defaults",
			targetGroup: testTargetGroup,
			annotations: map[string]string{}, // No target group attributes annotation
			mockDescribeTargetGroupAttribs: func(ctx context.Context, input *elbv2.DescribeTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupAttributesOutput, error) {
				return &elbv2.DescribeTargetGroupAttributesOutput{
					Attributes: []elbv2types.TargetGroupAttribute{
						{Key: aws.String("preserve_client_ip.enabled"), Value: aws.String("true")}, // matches default for instance target
						{Key: aws.String("proxy_protocol_v2.enabled"), Value: aws.String("false")}, // matches default
					},
				}, nil
			},
			description: "Function should succeed when no annotation provided and attributes match defaults",
		},
		{
			name:        "ModifyTargetGroupAttributes fails",
			targetGroup: testTargetGroup,
			annotations: map[string]string{ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=false"},
			mockDescribeTargetGroupAttribs: func(ctx context.Context, input *elbv2.DescribeTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupAttributesOutput, error) {
				return &elbv2.DescribeTargetGroupAttributesOutput{
					Attributes: []elbv2types.TargetGroupAttribute{
						{Key: aws.String("preserve_client_ip.enabled"), Value: aws.String("true")}, // different from annotation (false)
						{Key: aws.String("proxy_protocol_v2.enabled"), Value: aws.String("false")}, // matches default
					},
				}, nil
			},
			mockModifyTargetGroupAttribs: func(ctx context.Context, input *elbv2.ModifyTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.ModifyTargetGroupAttributesOutput, error) {
				return nil, fmt.Errorf("AWS API error: access denied")
			},
			expectedError: "unable to modify target group attributes during attribute sync",
			description:   "Function should handle ModifyTargetGroupAttributes API failures",
		},
		// Successful case - changes needed and applied
		{
			name:        "successful case - attributes updated",
			targetGroup: testTargetGroup,
			annotations: map[string]string{ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=false,proxy_protocol_v2.enabled=true"},
			mockDescribeTargetGroupAttribs: func(ctx context.Context, input *elbv2.DescribeTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupAttributesOutput, error) {
				return &elbv2.DescribeTargetGroupAttributesOutput{
					Attributes: []elbv2types.TargetGroupAttribute{
						{Key: aws.String("preserve_client_ip.enabled"), Value: aws.String("true")}, // different from annotation (false)
						{Key: aws.String("proxy_protocol_v2.enabled"), Value: aws.String("false")}, // different from annotation (true)
					},
				}, nil
			},
			mockModifyTargetGroupAttribs: func(ctx context.Context, input *elbv2.ModifyTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.ModifyTargetGroupAttributesOutput, error) {
				expectedAttributes := map[string]string{
					"preserve_client_ip.enabled": "false",
					"proxy_protocol_v2.enabled":  "true",
				}

				for _, attr := range input.Attributes {
					key := aws.ToString(attr.Key)
					value := aws.ToString(attr.Value)
					if expectedValue, exists := expectedAttributes[key]; exists {
						if value != expectedValue {
							return nil, fmt.Errorf("unexpected attribute value for %s: got %s, expected %s", key, value, expectedValue)
						}
					}
				}

				return &elbv2.ModifyTargetGroupAttributesOutput{}, nil
			},
			description: "Function should successfully update target group attributes",
		},
		// Successful case - restore defaults
		{
			name: "successful case - restore defaults for IP+TCP target group",
			targetGroup: &elbv2types.TargetGroup{
				TargetGroupArn: aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-ip-tg/1234567890123456"),
				Protocol:       elbv2types.ProtocolEnumTcp,
				TargetType:     elbv2types.TargetTypeEnumIp,
			},
			annotations: map[string]string{}, // No annotation - should restore defaults
			mockDescribeTargetGroupAttribs: func(ctx context.Context, input *elbv2.DescribeTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupAttributesOutput, error) {
				return &elbv2.DescribeTargetGroupAttributesOutput{
					Attributes: []elbv2types.TargetGroupAttribute{
						{Key: aws.String("preserve_client_ip.enabled"), Value: aws.String("true")}, // wrong, should be false for IP+TCP
						{Key: aws.String("proxy_protocol_v2.enabled"), Value: aws.String("false")}, // correct default
					},
				}, nil
			},
			mockModifyTargetGroupAttribs: func(ctx context.Context, input *elbv2.ModifyTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.ModifyTargetGroupAttributesOutput, error) {
				// Should restore preserve_client_ip.enabled to false for IP+TCP combination
				for _, attr := range input.Attributes {
					if aws.ToString(attr.Key) == "preserve_client_ip.enabled" && aws.ToString(attr.Value) == "false" {
						return &elbv2.ModifyTargetGroupAttributesOutput{}, nil
					}
				}
				return nil, fmt.Errorf("expected preserve_client_ip.enabled=false to be set")
			},
			description: "Function should successfully restore default values for IP+TCP target group combination",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockELBV2ClientForTargetGroupAttributes{
				MockedFakeELBV2: &MockedFakeELBV2{
					LoadBalancers:          []*elbv2types.LoadBalancer{},
					TargetGroups:           []*elbv2types.TargetGroup{},
					Listeners:              []*elbv2types.Listener{},
					LoadBalancerAttributes: make(map[string]map[string]string),
					Tags:                   make(map[string][]elbv2types.Tag),
					RegisteredInstances:    make(map[string][]string),
				},
				describeTargetGroupAttributesFunc: tt.mockDescribeTargetGroupAttribs,
				modifyTargetGroupAttributesFunc:   tt.mockModifyTargetGroupAttribs,
			}
			c := &Cloud{
				elbv2: mockClient,
			}

			err := c.ensureTargetGroupAttributes(context.TODO(), tt.targetGroup, tt.annotations)

			if len(tt.expectedError) > 0 {
				assert.Error(t, err, "Expected error for test case: %s", tt.description)
				assert.Contains(t, err.Error(), tt.expectedError, "Error message should contain expected text for test case: %s", tt.description)
			} else {
				assert.NoError(t, err, "Expected no error for test case: %s", tt.description)
			}
		})
	}
}

func TestCloud_reconcileTargetGroupsAttributes(t *testing.T) {
	testLBARN := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/test-lb/1234567890123456"
	testTG1ARN := "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-tg-1/1234567890123456"
	testTG2ARN := "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-tg-2/1234567890123456"

	tests := []struct {
		name                              string
		lbARN                             string
		annotations                       map[string]string
		targetGroups                      []*elbv2types.TargetGroup
		describeTargetGroupsError         error
		describeTargetGroupAttributesFunc func(ctx context.Context, input *elbv2.DescribeTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupAttributesOutput, error)
		modifyTargetGroupAttributesFunc   func(ctx context.Context, input *elbv2.ModifyTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.ModifyTargetGroupAttributesOutput, error)
		expectedError                     string
	}{
		{
			name:          "empty load balancer ARN should return error",
			lbARN:         "",
			annotations:   map[string]string{},
			expectedError: "error updating target groups attributes: load balancer ARN is empty",
		},
		{
			name:                      "DescribeTargetGroups API failure",
			lbARN:                     testLBARN,
			annotations:               map[string]string{},
			describeTargetGroupsError: fmt.Errorf("AWS API error: access denied"),
			expectedError:             "error updating target groups attributes from load balancer \"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/test-lb/1234567890123456\": AWS API error: access denied",
		},
		{
			name:         "no target groups found - success",
			lbARN:        testLBARN,
			annotations:  map[string]string{},
			targetGroups: []*elbv2types.TargetGroup{},
		},
		{
			name:        "single target group - success",
			lbARN:       testLBARN,
			annotations: map[string]string{ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=true"},
			targetGroups: []*elbv2types.TargetGroup{
				{
					TargetGroupArn:   aws.String(testTG1ARN),
					LoadBalancerArns: []string{testLBARN},
					Protocol:         elbv2types.ProtocolEnumHttp,
					TargetType:       elbv2types.TargetTypeEnumInstance,
				},
			},
			describeTargetGroupAttributesFunc: func(ctx context.Context, input *elbv2.DescribeTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupAttributesOutput, error) {
				return &elbv2.DescribeTargetGroupAttributesOutput{
					Attributes: []elbv2types.TargetGroupAttribute{
						{Key: aws.String("preserve_client_ip.enabled"), Value: aws.String("false")},
						{Key: aws.String("proxy_protocol_v2.enabled"), Value: aws.String("false")},
					},
				}, nil
			},
			modifyTargetGroupAttributesFunc: func(ctx context.Context, input *elbv2.ModifyTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.ModifyTargetGroupAttributesOutput, error) {
				return &elbv2.ModifyTargetGroupAttributesOutput{}, nil
			},
		},
		{
			name:        "multiple target groups - success",
			lbARN:       testLBARN,
			annotations: map[string]string{ServiceAnnotationLoadBalancerTargetGroupAttributes: "proxy_protocol_v2.enabled=true"},
			targetGroups: []*elbv2types.TargetGroup{
				{
					TargetGroupArn:   aws.String(testTG1ARN),
					LoadBalancerArns: []string{testLBARN},
					Protocol:         elbv2types.ProtocolEnumHttp,
					TargetType:       elbv2types.TargetTypeEnumInstance,
				},
				{
					TargetGroupArn:   aws.String(testTG2ARN),
					LoadBalancerArns: []string{testLBARN},
					Protocol:         elbv2types.ProtocolEnumTcp,
					TargetType:       elbv2types.TargetTypeEnumInstance,
				},
			},
			describeTargetGroupAttributesFunc: func(ctx context.Context, input *elbv2.DescribeTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupAttributesOutput, error) {
				return &elbv2.DescribeTargetGroupAttributesOutput{
					Attributes: []elbv2types.TargetGroupAttribute{
						{Key: aws.String("preserve_client_ip.enabled"), Value: aws.String("true")},
						{Key: aws.String("proxy_protocol_v2.enabled"), Value: aws.String("false")},
					},
				}, nil
			},
			modifyTargetGroupAttributesFunc: func(ctx context.Context, input *elbv2.ModifyTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.ModifyTargetGroupAttributesOutput, error) {
				return &elbv2.ModifyTargetGroupAttributesOutput{}, nil
			},
		},
		{
			name:        "partial failure - some target groups fail",
			lbARN:       testLBARN,
			annotations: map[string]string{ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=true"},
			targetGroups: []*elbv2types.TargetGroup{
				{
					TargetGroupArn:   aws.String(testTG1ARN),
					LoadBalancerArns: []string{testLBARN},
					Protocol:         elbv2types.ProtocolEnumHttp,
					TargetType:       elbv2types.TargetTypeEnumInstance,
				},
				{
					TargetGroupArn:   aws.String(testTG2ARN),
					LoadBalancerArns: []string{testLBARN},
					Protocol:         elbv2types.ProtocolEnumTcp,
					TargetType:       elbv2types.TargetTypeEnumInstance,
				},
			},
			describeTargetGroupAttributesFunc: func(ctx context.Context, input *elbv2.DescribeTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupAttributesOutput, error) {
				if aws.ToString(input.TargetGroupArn) == testTG1ARN {
					return &elbv2.DescribeTargetGroupAttributesOutput{
						Attributes: []elbv2types.TargetGroupAttribute{
							{Key: aws.String("preserve_client_ip.enabled"), Value: aws.String("false")},
							{Key: aws.String("proxy_protocol_v2.enabled"), Value: aws.String("false")},
						},
					}, nil
				}
				return nil, fmt.Errorf("target group not found")
			},
			modifyTargetGroupAttributesFunc: func(ctx context.Context, input *elbv2.ModifyTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.ModifyTargetGroupAttributesOutput, error) {
				return &elbv2.ModifyTargetGroupAttributesOutput{}, nil
			},
			expectedError: "one or more errors occurred while updating target group attributes: [error updating target group attributes for target group \"arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-tg-2/1234567890123456\": unable to retrieve target group attributes during attribute sync: target group not found]",
		},
		{
			name:        "all target groups fail",
			lbARN:       testLBARN,
			annotations: map[string]string{ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=true"},
			targetGroups: []*elbv2types.TargetGroup{
				{
					TargetGroupArn:   aws.String(testTG1ARN),
					LoadBalancerArns: []string{testLBARN},
					Protocol:         elbv2types.ProtocolEnumHttp,
					TargetType:       elbv2types.TargetTypeEnumInstance,
				},
				{
					TargetGroupArn:   aws.String(testTG2ARN),
					LoadBalancerArns: []string{testLBARN},
					Protocol:         elbv2types.ProtocolEnumTcp,
					TargetType:       elbv2types.TargetTypeEnumInstance,
				},
			},
			describeTargetGroupAttributesFunc: func(ctx context.Context, input *elbv2.DescribeTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupAttributesOutput, error) {
				return nil, fmt.Errorf("target group not found")
			},
			expectedError: "one or more errors occurred while updating target group attributes: [error updating target group attributes for target group \"arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-tg-1/1234567890123456\": unable to retrieve target group attributes during attribute sync: target group not found error updating target group attributes for target group \"arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-tg-2/1234567890123456\": unable to retrieve target group attributes during attribute sync: target group not found]",
		},
		{
			name:        "ModifyTargetGroupAttributes fails for some target groups",
			lbARN:       testLBARN,
			annotations: map[string]string{ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=true"},
			targetGroups: []*elbv2types.TargetGroup{
				{
					TargetGroupArn:   aws.String(testTG1ARN),
					LoadBalancerArns: []string{testLBARN},
					Protocol:         elbv2types.ProtocolEnumHttp,
					TargetType:       elbv2types.TargetTypeEnumInstance,
				},
				{
					TargetGroupArn:   aws.String(testTG2ARN),
					LoadBalancerArns: []string{testLBARN},
					Protocol:         elbv2types.ProtocolEnumTcp,
					TargetType:       elbv2types.TargetTypeEnumInstance,
				},
			},
			describeTargetGroupAttributesFunc: func(ctx context.Context, input *elbv2.DescribeTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupAttributesOutput, error) {
				return &elbv2.DescribeTargetGroupAttributesOutput{
					Attributes: []elbv2types.TargetGroupAttribute{
						{Key: aws.String("preserve_client_ip.enabled"), Value: aws.String("false")},
						{Key: aws.String("proxy_protocol_v2.enabled"), Value: aws.String("false")},
					},
				}, nil
			},
			modifyTargetGroupAttributesFunc: func(ctx context.Context, input *elbv2.ModifyTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.ModifyTargetGroupAttributesOutput, error) {
				if aws.ToString(input.TargetGroupArn) == testTG1ARN {
					return &elbv2.ModifyTargetGroupAttributesOutput{}, nil
				}
				return nil, fmt.Errorf("permission denied")
			},
			expectedError: "one or more errors occurred while updating target group attributes: [error updating target group attributes for target group \"arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-tg-2/1234567890123456\": unable to modify target group attributes during attribute sync: permission denied]",
		},
		{
			name:        "buildTargetGroupAttributes fails due to nil existing attributes",
			lbARN:       testLBARN,
			annotations: map[string]string{ServiceAnnotationLoadBalancerTargetGroupAttributes: "preserve_client_ip.enabled=true"},
			targetGroups: []*elbv2types.TargetGroup{
				{
					TargetGroupArn:   aws.String(testTG1ARN),
					LoadBalancerArns: []string{testLBARN},
					Protocol:         elbv2types.ProtocolEnumHttp,
					TargetType:       elbv2types.TargetTypeEnumInstance,
				},
			},
			describeTargetGroupAttributesFunc: func(ctx context.Context, input *elbv2.DescribeTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupAttributesOutput, error) {
				return &elbv2.DescribeTargetGroupAttributesOutput{
					Attributes: nil, // This will cause buildTargetGroupAttributes to fail
				}, nil
			},
			expectedError: "one or more errors occurred while updating target group attributes: [error updating target group attributes for target group \"arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-tg-1/1234567890123456\": unable to build target group attributes: error building target group attributes: target group attributes are nil]",
		},
		{
			name:        "no annotations - success",
			lbARN:       testLBARN,
			annotations: map[string]string{}, // No target group attributes annotation
			targetGroups: []*elbv2types.TargetGroup{
				{
					TargetGroupArn:   aws.String(testTG1ARN),
					LoadBalancerArns: []string{testLBARN},
					Protocol:         elbv2types.ProtocolEnumHttp,
					TargetType:       elbv2types.TargetTypeEnumInstance,
				},
			},
			describeTargetGroupAttributesFunc: func(ctx context.Context, input *elbv2.DescribeTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupAttributesOutput, error) {
				return &elbv2.DescribeTargetGroupAttributesOutput{
					Attributes: []elbv2types.TargetGroupAttribute{
						{Key: aws.String("preserve_client_ip.enabled"), Value: aws.String("true")}, // Already at default
						{Key: aws.String("proxy_protocol_v2.enabled"), Value: aws.String("false")}, // Already at default
					},
				}, nil
			},
			// No ModifyTargetGroupAttributes function since no changes needed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mockClient *mockELBV2ClientForTargetGroupAttributes

			// For empty ARN test, we don't need to set up mocks
			if tt.lbARN != "" {
				mockELBV2 := &MockedFakeELBV2{
					TargetGroups: tt.targetGroups,
				}

				// Override DescribeTargetGroups if we need to simulate error
				if tt.describeTargetGroupsError != nil {
					// Create a custom mock that returns error for DescribeTargetGroups
					mockClient = &mockELBV2ClientForTargetGroupAttributes{
						MockedFakeELBV2: &MockedFakeELBV2{},
						describeTargetGroupsFunc: func(ctx context.Context, input *elbv2.DescribeTargetGroupsInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupsOutput, error) {
							return nil, tt.describeTargetGroupsError
						},
					}
				} else {
					mockClient = &mockELBV2ClientForTargetGroupAttributes{
						MockedFakeELBV2: mockELBV2,
					}
				}

				// Set up target group attribute functions
				if tt.describeTargetGroupAttributesFunc != nil {
					mockClient.describeTargetGroupAttributesFunc = tt.describeTargetGroupAttributesFunc
				}
				if tt.modifyTargetGroupAttributesFunc != nil {
					mockClient.modifyTargetGroupAttributesFunc = tt.modifyTargetGroupAttributesFunc
				}
			}

			c := &Cloud{
				elbv2: mockClient,
			}

			err := c.reconcileTargetGroupsAttributes(context.TODO(), tt.lbARN, tt.annotations)
			if err != nil {
				if len(tt.expectedError) == 0 {
					t.Fatalf("Expected no error for test case: %s, but got: %v", tt.name, err)
				}
				assert.Error(t, err, "Expected error for test case: %s", tt.name)
				assert.Equal(t, tt.expectedError, err.Error(), "Error message should contain expected text for test case: %s", tt.name)
			} else {
				assert.NoError(t, err, "Expected no error for test case: %s", tt.name)
			}
		})
	}
}

func TestIsIPv6CIDR(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		expected bool
	}{
		{
			name:     "IPv4 CIDR - single IP",
			cidr:     "192.168.1.1/32",
			expected: false,
		},
		{
			name:     "IPv4 CIDR - network",
			cidr:     "10.0.0.0/8",
			expected: false,
		},
		{
			name:     "IPv4 CIDR - default route",
			cidr:     "0.0.0.0/0",
			expected: false,
		},
		{
			name:     "IPv6 CIDR - single IP",
			cidr:     "2001:db8::1/128",
			expected: true,
		},
		{
			name:     "IPv6 CIDR - network",
			cidr:     "2001:db8::/32",
			expected: true,
		},
		{
			name:     "IPv6 CIDR - default route",
			cidr:     "::/0",
			expected: true,
		},
		{
			name:     "IPv6 CIDR - link local",
			cidr:     "fe80::/10",
			expected: true,
		},
		{
			name:     "IPv6 CIDR - unique local",
			cidr:     "fc00::/7",
			expected: true,
		},
		{
			name:     "IPv6 CIDR - full address",
			cidr:     "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128",
			expected: true,
		},
		{
			name:     "IPv6 CIDR - compressed",
			cidr:     "2001:db8::8a2e:370:7334/64",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isIPv6CIDR(tt.cidr)
			assert.Equal(t, tt.expected, result)
		})
	}
}
