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
	"sync"
	"time"

	"github.com/mitchellh/hashstructure/v2"
	"github.com/samber/lo"
	"k8s.io/cloud-provider-aws/pkg/providers/v1/batcher"
	"k8s.io/cloud-provider-aws/pkg/providers/v1/iface"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/aws/aws-sdk-go/service/ec2"
)

// descibeInstanceBatcher contains the batcher details
type descibeInstanceBatcher struct {
	batcher *batcher.Batcher[ec2.DescribeInstancesInput, ec2.Instance]
}

// newDescibeInstanceBatcher creates a createDescibeInstanceBatcher object
func newDescibeInstanceBatcher(ctx context.Context, ec2api iface.EC2) *descibeInstanceBatcher {
	options := batcher.Options[ec2.DescribeInstancesInput, ec2.Instance]{
		Name:          "create_tags",
		IdleTimeout:   100 * time.Millisecond,
		MaxTimeout:    1 * time.Second,
		MaxItems:      50,
		RequestHasher: describeInstanceHasher,
		BatchExecutor: execDescribeInstanceBatch(ec2api),
	}
	return &descibeInstanceBatcher{batcher: batcher.NewBatcher(ctx, options)}
}

// CreateTags adds create tag input to batcher
func (b *descibeInstanceBatcher) DescribeInstances(ctx context.Context, input *ec2.DescribeInstancesInput) ([]*ec2.Instance, error) {
	if len(input.InstanceIds) != 1 {
		return nil, fmt.Errorf("expected to receive a single instance only, found %d", len(input.InstanceIds))
	}
	result := b.batcher.Add(ctx, input)
	return []*ec2.Instance{result.Output}, result.Err
}

// DescribeInstanceHasher generates hash for different create tag inputs
// Same inputs have same hash, so they get executed together
func describeInstanceHasher(ctx context.Context, input *ec2.DescribeInstancesInput) uint64 {
	hash, err := hashstructure.Hash(input.Filters, hashstructure.FormatV2, &hashstructure.HashOptions{SlicesAsSets: true})
	if err != nil {
		log.FromContext(ctx).Error(err, "failed hashing input filters")
	}
	return hash
}

func execDescribeInstanceBatch(ec2api iface.EC2) batcher.BatchExecutor[ec2.DescribeInstancesInput, ec2.Instance] {
	return func(ctx context.Context, inputs []*ec2.DescribeInstancesInput) []batcher.Result[ec2.Instance] {
		results := make([]batcher.Result[ec2.Instance], len(inputs))
		firstInput := inputs[0]
		// aggregate instanceIDs into 1 input
		for _, input := range inputs[1:] {
			firstInput.InstanceIds = append(firstInput.InstanceIds, input.InstanceIds...)
		}
		batchedInput := &ec2.DescribeInstancesInput{
			InstanceIds: firstInput.InstanceIds,
		}
		klog.Infof("Batched describe instances %v", batchedInput)
		output, err := ec2api.DescribeInstances(batchedInput)
		if err != nil {
			klog.Errorf("Error occurred trying to batch describe instance, trying individually, %v", err)
			var wg sync.WaitGroup
			for idx, input := range inputs {
				wg.Add(1)
				go func(input *ec2.DescribeInstancesInput) {
					defer wg.Done()
					out, err := ec2api.DescribeInstances(input)
					if err != nil {
						results[idx] = batcher.Result[ec2.Instance]{Output: nil, Err: err}
						return
					}
					results[idx] = batcher.Result[ec2.Instance]{Output: out[0], Err: err}
				}(input)
			}
			wg.Wait()
		} else {
			instanceIDToOutputMap := map[string]*ec2.Instance{}
			lo.ForEach(output, func(o *ec2.Instance, _ int) { instanceIDToOutputMap[lo.FromPtr(o.InstanceId)] = o })
			for idx, input := range inputs {
				results[idx] = batcher.Result[ec2.Instance]{Output: instanceIDToOutputMap[lo.FromPtr(input.InstanceIds[0])]}
			}
		}
		return results
	}
}
