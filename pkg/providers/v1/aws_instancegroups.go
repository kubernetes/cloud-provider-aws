/*
Copyright 2014 The Kubernetes Authors.

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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	autoscalingtypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	"k8s.io/klog/v2"
)

// AWSCloud implements InstanceGroups
var _ InstanceGroups = &Cloud{}

// ResizeInstanceGroup sets the size of the specificed instancegroup Exported
// so it can be used by the e2e tests, which don't want to instantiate a full
// cloudprovider.
func ResizeInstanceGroup(ctx context.Context, asg ASG, instanceGroupName string, size int) error {
	request := &autoscaling.UpdateAutoScalingGroupInput{
		AutoScalingGroupName: aws.String(instanceGroupName),
		DesiredCapacity:      aws.Int32(int32(size)),
	}
	if _, err := asg.UpdateAutoScalingGroup(ctx, request); err != nil {
		return fmt.Errorf("error resizing AWS autoscaling group: %q", err)
	}
	return nil
}

// ResizeInstanceGroup implements InstanceGroups.ResizeInstanceGroup
// Set the size to the fixed size
func (c *Cloud) ResizeInstanceGroup(ctx context.Context, instanceGroupName string, size int) error {
	return ResizeInstanceGroup(ctx, c.asg, instanceGroupName, size)
}

// DescribeInstanceGroup gets info about the specified instancegroup
// Exported so it can be used by the e2e tests,
// which don't want to instantiate a full cloudprovider.
func DescribeInstanceGroup(ctx context.Context, asg ASG, instanceGroupName string) (InstanceGroupInfo, error) {
	request := &autoscaling.DescribeAutoScalingGroupsInput{
		AutoScalingGroupNames: []string{instanceGroupName},
	}
	response, err := asg.DescribeAutoScalingGroups(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("error listing AWS autoscaling group (%s): %q", instanceGroupName, err)
	}

	if len(response.AutoScalingGroups) == 0 {
		return nil, nil
	}
	if len(response.AutoScalingGroups) > 1 {
		klog.Warning("AWS returned multiple autoscaling groups with name ", instanceGroupName)
	}
	group := &response.AutoScalingGroups[0]
	return &awsInstanceGroup{group: group}, nil
}

// DescribeInstanceGroup implements InstanceGroups.DescribeInstanceGroup
// Queries the cloud provider for information about the specified instance group
func (c *Cloud) DescribeInstanceGroup(ctx context.Context, instanceGroupName string) (InstanceGroupInfo, error) {
	return DescribeInstanceGroup(ctx, c.asg, instanceGroupName)
}

// awsInstanceGroup implements InstanceGroupInfo
var _ InstanceGroupInfo = &awsInstanceGroup{}

type awsInstanceGroup struct {
	group *autoscalingtypes.AutoScalingGroup
}

// Implement InstanceGroupInfo.CurrentSize
// The number of instances currently running under control of this group
func (g *awsInstanceGroup) CurrentSize() (int, error) {
	return len(g.group.Instances), nil
}
