/*
Copyright 2025 The Kubernetes Authors.

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
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/framework"
)

// awsHelper provides AWS API operations for e2e tests
type awsHelper struct {
	ctx         context.Context
	ec2Client   *ec2.Client
	elbClient   *elb.Client
	elbv2Client *elbv2.Client

	// Cluster information
	clusterName     string
	clusterTag      string
	clusterTagValue string
	vpcID           string
	awsRegion       string
}

// newAWSHelper creates a new AWS helper with configured clients
func newAWSHelper(ctx context.Context, cs clientset.Interface) (*awsHelper, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	framework.ExpectNoError(err, "unable to load AWS config")

	h := &awsHelper{
		ctx:         ctx,
		ec2Client:   ec2.NewFromConfig(cfg),
		elbClient:   elb.NewFromConfig(cfg),
		elbv2Client: elbv2.NewFromConfig(cfg),
	}

	framework.Logf("Discovering cluster tag")
	framework.ExpectNoError(h.discoverClusterTag(cs), "unable to find cluster tag")
	framework.Logf("Cluster tag discovered: %s", h.clusterTag)

	return h, nil
}

// discoverClusterTag discovers the cluster tag from a cluster.
// The discover is done by looking up the EC2 instance tags with tag:Name prefix kubernetes.io/cluster.
// The EC2 Instance ID is discovered from a cluster node object.
// The cluster ID, VPC ID and cluster tag are discovered from the EC2 instance tags.
// If is any error is found, the function returns an error.
func (h *awsHelper) discoverClusterTag(cs clientset.Interface) error {
	nodes, err := cs.CoreV1().Nodes().List(h.ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list nodes: %v", err)
	}

	var instanceID string
	for _, node := range nodes.Items {
		providerID := node.Spec.ProviderID
		if providerID == "" {
			continue
		}
		providerID = strings.Replace(providerID, "aws:///", "", 1)
		if len(strings.Split(providerID, "/")) < 2 {
			continue
		}
		h.awsRegion = strings.Split(providerID, "/")[0]
		instanceID = strings.Split(providerID, "/")[1]
		if !strings.HasPrefix(instanceID, "i-") {
			continue
		}
		break
	}

	instance, err := h.ec2Client.DescribeInstances(h.ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return fmt.Errorf("failed to describe instances: %v", err)
	}

	clusterTagFound := false
	for _, reservation := range instance.Reservations {
		for _, tag := range reservation.Instances[0].Tags {
			if strings.HasPrefix(aws.ToString(tag.Key), "kubernetes.io/cluster") {
				h.clusterTag = aws.ToString(tag.Key)
				h.clusterTagValue = aws.ToString(tag.Value)
				clusterTagFound = true
				break
			}
		}
		if clusterTagFound {
			break
		}
	}

	if !clusterTagFound {
		return fmt.Errorf("cluster tag not found in the instance %s", instanceID)
	}

	h.clusterName = strings.Split(h.clusterTag, "/")[2]
	if h.clusterName == "" {
		return fmt.Errorf("cluster name not found in the cluster tag %s", h.clusterTag)
	}

	// extract VPC ID from the Instance
	for _, networkInterface := range instance.Reservations[0].Instances[0].NetworkInterfaces {
		h.vpcID = aws.ToString(networkInterface.VpcId)
		break
	}

	if h.vpcID == "" {
		return fmt.Errorf("VPC ID not found in the instance %s", instanceID)
	}

	return nil
}

// getLoadBalancerSecurityGroups gets security groups attached to a load balancer
func (h *awsHelper) getLoadBalancerSecurityGroups(isNLB bool, lbDNSName string) ([]string, error) {
	if isNLB {
		if h.elbv2Client == nil {
			return nil, fmt.Errorf("elbv2Client is not initialized")
		}
		describeNLBs, err := h.elbv2Client.DescribeLoadBalancers(h.ctx, &elbv2.DescribeLoadBalancersInput{})
		framework.ExpectNoError(err, "failed to describe load balancers to retrieve security groups")

		for _, lb := range describeNLBs.LoadBalancers {
			if strings.EqualFold(aws.ToString(lb.DNSName), lbDNSName) {
				return lb.SecurityGroups, nil
			}
		}
		return nil, fmt.Errorf("load balancer with DNS %s not found", lbDNSName)
	}

	// Get CLB ARN from DNS name
	if h.elbClient == nil {
		return nil, fmt.Errorf("elbClient is not initialized")
	}
	describeCLBs, err := h.elbClient.DescribeLoadBalancers(h.ctx, &elb.DescribeLoadBalancersInput{})
	framework.ExpectNoError(err, "failed to describe load balancers to retrieve security groups")

	for _, lb := range describeCLBs.LoadBalancerDescriptions {
		if strings.EqualFold(aws.ToString(lb.DNSName), lbDNSName) {
			return lb.SecurityGroups, nil
		}
	}
	return nil, fmt.Errorf("load balancer with DNS %s not found", lbDNSName)
}

// isSecurityGroupManaged checks if a security group is managed by the controller
// It checks for the cluster ownership tag to determine if the controller owns this security group
func (h *awsHelper) isSecurityGroupManaged(sgID string) (bool, error) {
	sg, err := h.getSecurityGroup(sgID)
	if err != nil {
		return false, err
	}

	// Check for cluster ownership tag - security groups owned by the controller
	// have the cluster tag with "owned" value
	clusterTagKey := fmt.Sprintf("kubernetes.io/cluster/%s", h.clusterName)
	for _, tag := range sg.Tags {
		if aws.ToString(tag.Key) == clusterTagKey &&
			aws.ToString(tag.Value) == "owned" {
			return true, nil
		}
	}
	return false, nil
}

// getSecurityGroup gets a security group by ID
func (h *awsHelper) getSecurityGroup(sgID string) (*ec2types.SecurityGroup, error) {
	if h.ec2Client == nil {
		return nil, fmt.Errorf("ec2Client is not initialized")
	}
	result, err := h.ec2Client.DescribeSecurityGroups(h.ctx, &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{sgID},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to describe security group %q: %v", sgID, err)
	}
	if len(result.SecurityGroups) == 0 {
		return nil, fmt.Errorf("security group %s not found", sgID)
	}
	return &result.SecurityGroups[0], nil
}

// createSecurityGroup creates a new security group for testing purposes
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
						Value: aws.String("shared"),
					},
				},
			},
		},
		VpcId: aws.String(h.vpcID),
	})
	if err != nil {
		return "", fmt.Errorf("failed to create security group: %v", err)
	}

	return aws.ToString(result.GroupId), nil
}

// cleanup cleans up the e2e resources.
func (e *e2eTestConfig) cleanup() {
	framework.Logf("Cleaning up e2e resources")

	// Cleanup security group
	if e.awsHelper != nil && e.byoSecurityGroupID != "" {
		err := e.awsHelper.waitForSecurityGroupDeletion(e.byoSecurityGroupID, 5*time.Minute)
		if err != nil {
			framework.Logf("Failed to delete security group %s during cleanup: %v", e.byoSecurityGroupID, err)
		}
	}
}

// authorizeSecurityGroupToPorts authorizes a security group to allow traffic to the service ports
func (h *awsHelper) authorizeSecurityGroupToPorts(sgID string, ports []v1.ServicePort) error {
	if h.ec2Client == nil {
		return fmt.Errorf("ec2Client is not initialized")
	}

	if len(ports) == 0 {
		return nil
	}

	ingressRules := make([]ec2types.IpPermission, 0, len(ports))
	for _, port := range ports {
		protocol := strings.ToLower(string(port.Protocol))
		rule := ec2types.IpPermission{
			FromPort:   aws.Int32(int32(port.Port)),
			ToPort:     aws.Int32(int32(port.Port)),
			IpProtocol: aws.String(protocol),
			IpRanges: []ec2types.IpRange{
				{
					CidrIp:      aws.String("0.0.0.0/0"),
					Description: aws.String(fmt.Sprintf("E2E test access for port %d", port.Port)),
				},
			},
		}
		ingressRules = append(ingressRules, rule)
	}
	_, err := h.ec2Client.AuthorizeSecurityGroupIngress(h.ctx, &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId:       aws.String(sgID),
		IpPermissions: ingressRules,
	})
	if err != nil {
		// Check if error is due to duplicate rules (which is actually okay)
		if strings.Contains(err.Error(), "InvalidPermission.Duplicate") {
			framework.Logf("Some rules already exist in security group %s (this is okay): %v", sgID, err)
			return nil
		}
		return fmt.Errorf("failed to authorize security group %s to ports %v: %v", sgID, ports, err)
	}

	return nil
}

// verifySecurityGroupRules verifies that the expected rules exist in the security group
// This is helpful for debugging when rules don't appear to be created
func (h *awsHelper) verifySecurityGroupRules(sgID string, expectedPorts []v1.ServicePort) error {
	if h.ec2Client == nil {
		return fmt.Errorf("ec2Client is not initialized")
	}

	sg, err := h.getSecurityGroup(sgID)
	if err != nil {
		return fmt.Errorf("failed to get security group %s: %v", sgID, err)
	}

	// Check if expected ports are covered
	for _, expectedPort := range expectedPorts {
		expectedProtocol := strings.ToLower(string(expectedPort.Protocol))
		expectedPortNum := int32(expectedPort.Port)

		found := false
		for _, rule := range sg.IpPermissions {
			ruleProtocol := aws.ToString(rule.IpProtocol)
			fromPort := aws.ToInt32(rule.FromPort)
			toPort := aws.ToInt32(rule.ToPort)

			if ruleProtocol == expectedProtocol && fromPort <= expectedPortNum && expectedPortNum <= toPort {
				found = true
				break
			}
		}

		if !found {
			framework.Logf("WARNING: Expected rule for protocol=%s port=%d not found in security group %s", expectedProtocol, expectedPortNum, sgID)
		}
	}

	return nil
}

// waitForSecurityGroupDeletion attempts to delete a security group and waits for it to be deleted
// It handles dependency violations when the SG is still attached to resources like load balancers
func (h *awsHelper) waitForSecurityGroupDeletion(sgID string, timeout time.Duration) error {
	return wait.PollImmediate(1*time.Second, timeout, func() (bool, error) {
		_, err := h.getSecurityGroup(sgID)
		if err != nil {
			return true, nil
		}

		err = h.deleteSecurityGroup(sgID)
		if err != nil {
			// Check for dependency violation errors
			if strings.Contains(err.Error(), "DependencyViolation") ||
				strings.Contains(err.Error(), "InvalidGroup.InUse") ||
				strings.Contains(err.Error(), "resource has a dependent object") {
				return false, nil // Keep waiting
			}

			// Check if it's already deleted
			if strings.Contains(err.Error(), "InvalidGroup.NotFound") ||
				strings.Contains(err.Error(), "InvalidGroupId.NotFound") {
				return true, nil
			}

			// For other errors, return the error
			return false, err
		}

		framework.Logf("Successfully deleted security group %s", sgID)
		return true, nil
	})
}

// deleteSecurityGroup deletes a security group
func (h *awsHelper) deleteSecurityGroup(sgID string) error {
	if _, err := h.ec2Client.DeleteSecurityGroup(h.ctx, &ec2.DeleteSecurityGroupInput{
		GroupId: aws.String(sgID),
	}); err != nil {
		return fmt.Errorf("failed to delete security group %s: %v", sgID, err)
	}

	return nil
}
