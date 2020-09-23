/*
Copyright 2020 The Kubernetes Authors.

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

// Package v2 is an out-of-tree only implementation of the AWS cloud provider.
// It is not compatible with v1 and should only be used on new clusters.
package v2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"

	"k8s.io/api/core/v1"
	"k8s.io/cloud-provider"
)

// newInstances returns an implementation of cloudprovider.InstancesV2
func newInstances(region string, creds *credentials.Credentials) (cloudprovider.InstancesV2, error) {
	awsConfig := &aws.Config{
		Region:      aws.String(region),
		Credentials: creds,
	}
	awsConfig = awsConfig.WithCredentialsChainVerboseErrors(true)

	sess, err := session.NewSession(awsConfig)
	if err != nil {
		return nil, err
	}
	ec2Service := ec2.New(sess)

	return &instances{
		ec2: ec2Service,
	}, nil
}

// EC2 is an interface defining only the methods we call from the AWS EC2 SDK.
type EC2 interface {
	DescribeInstances(request *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error)
}

// instances is an implementation of cloudprovider.InstancesV2
type instances struct {
	ec2 EC2
}

// InstanceExists indicates whether a given node exists according to the cloud provider
func (i *instances) InstanceExists(ctx context.Context, node *v1.Node) (bool, error) {
	var err error
	if node.Spec.ProviderID == "" {
		_, err = i.getInstanceByPrivateDNSName(ctx, node.Name)
		if err == cloudprovider.InstanceNotFound {
			return false, nil
		}

		if err != nil {
			return false, err
		}
	} else {
		_, err = i.getInstanceByProviderID(ctx, node.Spec.ProviderID)
		if err == cloudprovider.InstanceNotFound {
			return false, nil
		}

		if err != nil {
			return false, err
		}
	}

	return true, nil
}

func (i *instances) InstanceShutdown(ctx context.Context, node *v1.Node) (bool, error) {
	return false, nil
}

func (i *instances) InstanceMetadata(ctx context.Context, node *v1.Node) (*cloudprovider.InstanceMetadata, error) {
	var err error
	var ec2Instance *ec2.Instance
	if node.Spec.ProviderID == "" {
		//  TODO: support node name policy other than private DNS names
		ec2Instance, err = i.getInstanceByPrivateDNSName(ctx, node.Name)
		if err != nil {
			return nil, err
		}
	} else {
		ec2Instance, err = i.getInstanceByProviderID(ctx, node.Spec.ProviderID)
		if err != nil {
			return nil, err
		}
	}

	nodeAddresses, err := nodeAddressesForInstance(ec2Instance)
	if err != nil {
		return nil, err
	}

	providerID, err := getInstanceProviderID(ec2Instance)
	if err != nil {
		return nil, err
	}

	metadata := &cloudprovider.InstanceMetadata{
		ProviderID:    providerID,
		InstanceType:  aws.StringValue(ec2Instance.InstanceType),
		NodeAddresses: nodeAddresses,
	}

	return metadata, nil
}

func (i *instances) getInstanceByProviderID(ctx context.Context, providerID string) (*ec2.Instance, error) {
	instanceID := parseInstanceIDFromProviderID(providerID)

	request := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{
			aws.String(instanceID),
		},
	}

	results := []*ec2.Instance{}
	var nextToken *string
	for {
		response, err := i.ec2.DescribeInstances(request)
		if err != nil {
			return nil, fmt.Errorf("error describing ec2 instances: %v", err)
		}

		for _, reservation := range response.Reservations {
			results = append(results, reservation.Instances...)
		}

		nextToken = response.NextToken
		if aws.StringValue(nextToken) == "" {
			break
		}
		request.NextToken = nextToken
	}

	if len(results) == 0 {
		return nil, cloudprovider.InstanceNotFound
	}

	if len(results) > 1 {
		return nil, fmt.Errorf("multiple instances found with private DNS name: %q", instanceID)
	}

	return results[0], nil
}

func (i *instances) getInstanceByPrivateDNSName(ctx context.Context, nodeName string) (*ec2.Instance, error) {
	request := &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			newEc2Filter("private-dns-name", nodeName),
			newEc2Filter("instance-state-name", aliveFilter...),
		},
	}

	results := []*ec2.Instance{}
	var nextToken *string
	for {
		response, err := i.ec2.DescribeInstances(request)
		if err != nil {
			return nil, fmt.Errorf("error describing ec2 instances: %v", err)
		}

		for _, reservation := range response.Reservations {
			results = append(results, reservation.Instances...)
		}

		nextToken = response.NextToken
		if aws.StringValue(nextToken) == "" {
			break
		}
		request.NextToken = nextToken
	}

	if len(results) == 0 {
		return nil, cloudprovider.InstanceNotFound
	}

	if len(results) > 1 {
		return nil, fmt.Errorf("multiple instances found with private DNS name: %q", nodeName)
	}

	return results[0], nil
}

// getInstanceProviderID returns the provider ID of an instance which is ultimately set in the node.Spec.ProviderID field.
// The well-known format for a node's providerID is:
//    * aws://<availability-zone>/<instance-id>
func getInstanceProviderID(instance *ec2.Instance) (string, error) {
	if aws.StringValue(instance.Placement.AvailabilityZone) == "" {
		return "", errors.New("instance availability zone was not set")
	}

	if aws.StringValue(instance.InstanceId) == "" {
		return "", errors.New("instance ID was not set")
	}

	return "aws://" + aws.StringValue(instance.Placement.AvailabilityZone) + "/" + aws.StringValue(instance.InstanceId), nil
}

// parseInstanceIDFromProviderID parses the node's instance ID based on the well-known provider ID format:
//   * aws://<availability-zone>/<instance-id>
// This function always assumes a valid providerID format was provided.
func parseInstanceIDFromProviderID(providerID string) string {
	// trim the provider name prefix 'aws://', renaming providerID should contain metadata in the format:
	// <availability-zone>/<instance-id>
	metadata := strings.Split(strings.TrimPrefix("aws://", providerID), "/")
	return metadata[1]
}

// nodeAddresses for Instance returns a list of v1.NodeAddress for the give instance.
// TODO: should we support ExternalIP by default?
func nodeAddressesForInstance(instance *ec2.Instance) ([]v1.NodeAddress, error) {
	if instance == nil {
		return nil, errors.New("provided instances is nil")
	}

	addresses := []v1.NodeAddress{}
	for _, networkInterface := range instance.NetworkInterfaces {
		if aws.StringValue(networkInterface.Status) != ec2.NetworkInterfaceStatusInUse {
			continue
		}

		for _, privateIP := range networkInterface.PrivateIpAddresses {
			if ipAddress := aws.StringValue(privateIP.PrivateIpAddress); ipAddress != "" {
				ip := net.ParseIP(ipAddress)
				if ip == nil {
					return nil, fmt.Errorf("invalid IP address %q from instance %q", ipAddress, aws.StringValue(instance.InstanceId))
				}

				addresses = append(addresses, v1.NodeAddress{
					Type:    v1.NodeInternalIP,
					Address: ip.String(),
				})
			}
		}
	}

	return addresses, nil
}

var aliveFilter = []string{
	ec2.InstanceStateNamePending,
	ec2.InstanceStateNameRunning,
	ec2.InstanceStateNameShuttingDown,
	ec2.InstanceStateNameStopping,
	ec2.InstanceStateNameStopped,
}

func newEc2Filter(name string, values ...string) *ec2.Filter {
	filter := &ec2.Filter{
		Name: aws.String(name),
	}

	for _, value := range values {
		filter.Values = append(filter.Values, aws.String(value))
	}

	return filter
}
