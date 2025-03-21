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

package batcher

import (
	"context"
	"fmt"
	"github.com/mitchellh/hashstructure/v2"
	"k8s.io/cloud-provider-aws/pkg/providers/v1/iface"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/service/ec2"
)

type CreateTagsBatcher struct {
	batcher *Batcher[ec2.CreateTagsInput, ec2.CreateTagsOutput]
}

func NewCreateTagsBatcher(ctx context.Context, ec2api iface.EC2) *CreateTagsBatcher {
	options := Options[ec2.CreateTagsInput, ec2.CreateTagsOutput]{
		Name:          "create_tags",
		IdleTimeout:   100 * time.Millisecond,
		MaxTimeout:    1 * time.Second,
		MaxItems:      500,
		RequestHasher: CreateTagsHasher,
		BatchExecutor: execCreateTagsBatch(ec2api),
	}
	return &CreateTagsBatcher{batcher: NewBatcher(ctx, options)}
}

func (b *CreateTagsBatcher) CreateTags(ctx context.Context, CreateTagsInput *ec2.CreateTagsInput) (*ec2.CreateTagsOutput, error) {
	if len(CreateTagsInput.Resources) != 1 {
		return nil, fmt.Errorf("expected to receive a single instance only, found %d", len(CreateTagsInput.Resources))
	}
	result := b.batcher.Add(ctx, CreateTagsInput)
	return result.Output, result.Err
}

func CreateTagsHasher(ctx context.Context, input *ec2.CreateTagsInput) uint64 {
	// Same set of tags will have same hash, will be executed together
	hash, err := hashstructure.Hash(input.Tags, hashstructure.FormatV2, &hashstructure.HashOptions{SlicesAsSets: true})
	if err != nil {
		log.FromContext(ctx).Error(err, "failed hashing input tags")
	}
	return hash
}

func execCreateTagsBatch(ec2api iface.EC2) BatchExecutor[ec2.CreateTagsInput, ec2.CreateTagsOutput] {
	return func(ctx context.Context, inputs []*ec2.CreateTagsInput) []Result[ec2.CreateTagsOutput] {
		results := make([]Result[ec2.CreateTagsOutput], len(inputs))
		firstInput := inputs[0]
		// aggregate instanceIDs into 1 input
		for _, input := range inputs[1:] {
			firstInput.Resources = append(firstInput.Resources, input.Resources...)
		}
		batchedInput := &ec2.CreateTagsInput{
			Resources: firstInput.Resources,
			Tags:      firstInput.Tags,
		}
		klog.Infof("Batched create tags %v", batchedInput)
		output, err := ec2api.CreateTags(batchedInput)

		if err != nil {
			klog.Errorf("Error occurred trying to batch tag resources, trying individually, %v", err)
			var wg sync.WaitGroup
			for idx, input := range inputs {
				wg.Add(1)
				go func(input *ec2.CreateTagsInput) {
					defer wg.Done()
					out, err := ec2api.CreateTags(input)
					results[idx] = Result[ec2.CreateTagsOutput]{Output: out, Err: err}

				}(input)
			}
			wg.Wait()
		} else {
			for idx := range inputs {
				results[idx] = Result[ec2.CreateTagsOutput]{Output: output}
			}
		}
		return results
	}
}
