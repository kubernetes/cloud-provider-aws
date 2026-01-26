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

package e2e

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/framework"
)

// awsHelper provides AWS-specific operations for E2E tests
type awsHelper struct {
	ec2Client   *ec2.Client
	elbClient   *elasticloadbalancingv2.Client
	ctx         context.Context
	clusterName string
	vpcID       string
	awsRegion   string
}

// newAWSHelper creates a new AWS helper with automatic cluster discovery
func newAWSHelper(ctx context.Context, cs clientset.Interface) (*awsHelper, error) {
	helper := &awsHelper{
		ctx: ctx,
	}

	// Discover cluster configuration from nodes
	if err := helper.discoverClusterTag(cs); err != nil {
		return nil, fmt.Errorf("failed to discover cluster configuration: %w", err)
	}

	// Load AWS SDK configuration
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(helper.awsRegion))
	if err != nil {
		return nil, fmt.Errorf("unable to load AWS config: %w", err)
	}

	helper.ec2Client = ec2.NewFromConfig(cfg)
	helper.elbClient = elasticloadbalancingv2.NewFromConfig(cfg)

	return helper, nil
}

// discoverClusterTag discovers cluster configuration from node metadata
func (h *awsHelper) discoverClusterTag(cs clientset.Interface) error {
	// List nodes to get provider ID
	nodes, err := cs.CoreV1().Nodes().List(h.ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list nodes: %w", err)
	}

	if len(nodes.Items) == 0 {
		return fmt.Errorf("no nodes found in cluster")
	}

	// Extract region and instance ID from provider ID
	// Format: aws:///zone/instance-id
	providerID := nodes.Items[0].Spec.ProviderID
	parts := strings.Split(providerID, "/")
	if len(parts) < 2 {
		return fmt.Errorf("invalid provider ID format: %s", providerID)
	}
	instanceID := parts[len(parts)-1]

	// Extract region from zone in provider ID
	// Format: aws:///us-east-1a/i-xxxxx
	if len(parts) >= 4 {
		zone := parts[len(parts)-2]
		// Remove last character (availability zone letter) to get region
		if len(zone) > 0 {
			h.awsRegion = zone[:len(zone)-1]
		}
	}

	// Create temporary EC2 client to discover VPC
	cfg, err := config.LoadDefaultConfig(h.ctx, config.WithRegion(h.awsRegion))
	if err != nil {
		return fmt.Errorf("unable to load AWS config for region %s: %w", h.awsRegion, err)
	}

	tmpEC2Client := ec2.NewFromConfig(cfg)

	// Describe instance to get VPC ID and cluster tag
	instancesOutput, err := tmpEC2Client.DescribeInstances(h.ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return fmt.Errorf("failed to describe instance %s: %w", instanceID, err)
	}

	if len(instancesOutput.Reservations) == 0 || len(instancesOutput.Reservations[0].Instances) == 0 {
		return fmt.Errorf("instance %s not found", instanceID)
	}

	instance := instancesOutput.Reservations[0].Instances[0]
	h.vpcID = aws.ToString(instance.VpcId)

	// Extract cluster name from instance tags
	for _, tag := range instance.Tags {
		if strings.HasPrefix(aws.ToString(tag.Key), "kubernetes.io/cluster/") {
			h.clusterName = strings.TrimPrefix(aws.ToString(tag.Key), "kubernetes.io/cluster/")
			break
		}
	}

	if h.clusterName == "" {
		return fmt.Errorf("cluster tag not found on instance %s", instanceID)
	}

	framework.Logf("Discovered cluster configuration: region=%s, vpcID=%s, clusterName=%s",
		h.awsRegion, h.vpcID, h.clusterName)

	return nil
}

// createSecurityGroup creates a new security group with proper tagging for BYO SG tests
func (h *awsHelper) createSecurityGroup(name, description string) (string, error) {
	result, err := h.ec2Client.CreateSecurityGroup(h.ctx, &ec2.CreateSecurityGroupInput{
		GroupName:   aws.String(name),
		Description: aws.String(description),
		TagSpecifications: []ec2types.TagSpecification{
			{
				ResourceType: ec2types.ResourceTypeSecurityGroup,
				Tags: []ec2types.Tag{
					{
						Key:   aws.String("Name"),
						Value: aws.String(name),
					},
					{
						Key:   aws.String(fmt.Sprintf("kubernetes.io/cluster/%s", h.clusterName)),
						Value: aws.String("shared"), // "shared" tag = user-managed, controller must not delete
					},
				},
			},
		},
		VpcId: aws.String(h.vpcID),
	})
	if err != nil {
		return "", fmt.Errorf("failed to create security group: %w", err)
	}

	sgID := aws.ToString(result.GroupId)
	framework.Logf("Created security group %s (ID: %s) with 'shared' tag", name, sgID)

	return sgID, nil
}

// getSecurityGroup retrieves a security group by ID
func (h *awsHelper) getSecurityGroup(sgID string) (*ec2types.SecurityGroup, error) {
	result, err := h.ec2Client.DescribeSecurityGroups(h.ctx, &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{sgID},
	})
	if err != nil {
		return nil, err
	}

	if len(result.SecurityGroups) == 0 {
		return nil, fmt.Errorf("security group %s not found", sgID)
	}

	return &result.SecurityGroups[0], nil
}

// deleteSecurityGroup deletes a security group
func (h *awsHelper) deleteSecurityGroup(sgID string) error {
	_, err := h.ec2Client.DeleteSecurityGroup(h.ctx, &ec2.DeleteSecurityGroupInput{
		GroupId: aws.String(sgID),
	})
	return err
}

// waitForSecurityGroupDeletion waits for a security group to be deleted, handling dependencies
func (h *awsHelper) waitForSecurityGroupDeletion(sgID string, timeout time.Duration) error {
	framework.Logf("Waiting for security group %s deletion (timeout: %v)", sgID, timeout)

	return wait.PollImmediate(1*time.Second, timeout, func() (bool, error) {
		// Try to get the security group
		_, err := h.getSecurityGroup(sgID)
		if err != nil {
			// Security group not found = successfully deleted
			if strings.Contains(err.Error(), "InvalidGroup.NotFound") ||
				strings.Contains(err.Error(), "does not exist") {
				framework.Logf("Security group %s successfully deleted", sgID)
				return true, nil
			}
			// Other errors are unexpected
			return false, fmt.Errorf("error checking security group %s: %w", sgID, err)
		}

		// Security group still exists, try to delete it
		err = h.deleteSecurityGroup(sgID)
		if err != nil {
			// Handle dependency violations - keep waiting
			if strings.Contains(err.Error(), "DependencyViolation") ||
				strings.Contains(err.Error(), "InvalidGroup.InUse") {
				framework.Logf("Security group %s still in use, retrying...", sgID)
				return false, nil
			}

			// Already deleted (race condition)
			if strings.Contains(err.Error(), "InvalidGroup.NotFound") {
				framework.Logf("Security group %s successfully deleted", sgID)
				return true, nil
			}

			// Other errors are failures
			return false, fmt.Errorf("error deleting security group %s: %w", sgID, err)
		}

		// Deletion succeeded
		framework.Logf("Security group %s successfully deleted", sgID)
		return true, nil
	})
}
