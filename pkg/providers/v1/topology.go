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
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"k8s.io/client-go/tools/cache"
	"k8s.io/cloud-provider-aws/pkg/providers/v1/iface"
	"k8s.io/klog/v2"
)

const instanceTopologyManagerCacheTimeout = 24 * time.Hour

// stringKeyFunc is a string as cache key function
func topStringKeyFunc(obj interface{}) (string, error) {
	// Type should already be a string, so just return as is.
	s, ok := obj.(string)
	if !ok {
		return "", fmt.Errorf("failed to cast to string: %+v", obj)
	}

	return s, nil
}

type instanceTopologyManager struct {
	ec2                 iface.EC2
	unsupportedKeyStore cache.Store
}

func newInstanceTopologyManager(ec2 iface.EC2) *instanceTopologyManager {
	return &instanceTopologyManager{
		ec2: ec2,
		// These should change very infrequently, if ever, so checking once a day sounds fair.
		unsupportedKeyStore: cache.NewTTLStore(topStringKeyFunc, instanceTopologyManagerCacheTimeout),
	}
}

func (t *instanceTopologyManager) getNodeTopology(instanceType string, region string, instanceID string) (*ec2.InstanceTopology, error) {
	if t.mightSupportTopology(instanceType, region) {
		request := &ec2.DescribeInstanceTopologyInput{InstanceIds: []*string{&instanceID}}
		topologies, err := t.ec2.DescribeInstanceTopology(request)
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case "UnsupportedOperation":
					klog.Infof("ec2:DescribeInstanceTopology is not available in %s: %q", region, err)
					// If region is unsupported, track it to avoid making the call in the future.
					t.addUnsupported(region)
					return nil, nil
				case "UnauthorizedOperation":
					// Gracefully handle the DecribeInstanceTopology access missing error
					klog.Warningf("Not authorized to perform: ec2:DescribeInstanceTopology, permission missing: %q", err)
					return nil, nil
				case "RequestLimitExceeded":
					// Gracefully handle request throttling
					klog.Warningf("Exceeded ec2:DescribeInstanceTopology request limits. Try again later: %q", err)
					return nil, nil
				}
			}

			// Unhandled error
			klog.Errorf("Error describing instance topology: %q", err)
			return nil, err
		} else if len(topologies) == 0 {
			// If no topology is returned, track the instance type as unsupported
			klog.Infof("Instance type %s unsupported for getting instance topology", instanceType)
			t.addUnsupported(instanceType)
			return nil, nil
		}

		return topologies[0], nil
	}
	return nil, nil
}

func (t *instanceTopologyManager) addUnsupported(key string) {
	err := t.unsupportedKeyStore.Add(key)
	if err != nil {
		klog.Errorf("Failed to cache unsupported key %s: %q", key, err)
	}
}

func (t *instanceTopologyManager) mightSupportTopology(instanceType string, region string) bool {
	if _, exists, err := t.unsupportedKeyStore.GetByKey(region); exists {
		return false
	} else if err != nil {
		klog.Errorf("Failed to get cached unsupported region: %q:", err)
	}

	if _, exists, err := t.unsupportedKeyStore.GetByKey(instanceType); exists {
		return false
	} else if err != nil {
		klog.Errorf("Failed to get cached unsupported instance type: %q:", err)
	}

	return true
}
