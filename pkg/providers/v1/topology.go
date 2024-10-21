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
	"slices"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go/service/ec2"
	"k8s.io/klog/v2"
)

type topologyCache struct {
	cloud               *Cloud
	mutex               sync.RWMutex
	unsupportedInstance []string
	unsupportedRegion   []string
}

func (t *topologyCache) getNodeTopology(instanceType string, region string, instanceID string) (*ec2.InstanceTopology, error) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	if t.mightSupportTopology(instanceType, region) {
		topologyRequest := &ec2.DescribeInstanceTopologyInput{InstanceIds: []*string{&instanceID}}
		topology, err := t.cloud.ec2.DescribeInstanceTopology(topologyRequest)
		if err != nil {
			klog.Errorf("Error describing instance topology: %q", err)
			if strings.Contains(err.Error(), "The functionality you requested is not available in this region") {
				t.unsupportedRegion = append(t.unsupportedRegion, region)
				return nil, nil
			}
			return nil, err
		} else if len(topology) == 0 {
			// instanceType is not support topology info and the result is empty
			t.unsupportedInstance = append(t.unsupportedInstance, instanceType)
		}
		return topology[0], nil
	}
	return nil, nil
}

func (t *topologyCache) mightSupportTopology(instanceType string, region string) bool {
	// Initialize the map if it's unset
	if t.unsupportedInstance == nil {
		t.unsupportedInstance = []string{}
	}
	if t.unsupportedRegion == nil {
		t.unsupportedRegion = []string{}
	}
	// if both instanceType and region are not in unsupported cache, the instance type and region might be supported
	// or we haven't check the supportness and cache it yet. If they are unsupported and not cached, we will run
	// describeTopology api once for them
	// Initialize the map if it's unset
	return !slices.Contains(t.unsupportedInstance, instanceType) && !slices.Contains(t.unsupportedRegion, region)
}
