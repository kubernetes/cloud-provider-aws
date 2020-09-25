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

	"k8s.io/klog/v2"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"

	v1 "k8s.io/api/core/v1"
	cloudprovider "k8s.io/cloud-provider"
)

// newInstances returns an implementation of cloudprovider.InstancesV2
func newInstances(az string, creds *credentials.Credentials) (cloudprovider.InstancesV2, error) {
	region, err := azToRegion(az)
	if err != nil {
		return nil, err
	}

	awsConfig := &aws.Config{
		Region:      aws.String(region),
		Credentials: creds,
	}
	awsConfig = awsConfig.WithCredentialsChainVerboseErrors(true)

	sess, err := session.NewSession(awsConfig)
	if err != nil {
		return nil, fmt.Errorf("error creating new session: %v", err)
	}
	ec2Service := ec2.New(sess)

	return &instances{
		availabilityZone: az,
		ec2:              ec2Service,
		region:           region,
	}, nil
}

// EC2 is an interface defining only the methods we call from the AWS EC2 SDK.
type EC2 interface {
	DescribeInstances(request *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error)
}

// instances is an implementation of cloudprovider.InstancesV2
type instances struct {
	availabilityZone string
	ec2              EC2
	region           string
}

// InstanceExists indicates whether a given node exists according to the cloud provider
func (i *instances) InstanceExists(ctx context.Context, node *v1.Node) (bool, error) {
	_, err := i.getInstance(ctx, node)

	if err == cloudprovider.InstanceNotFound {
		klog.V(6).Infof("instance not found for node: %s", node.Name)
		return false, nil
	}

	if err != nil {
		return false, err
	}

	return true, nil
}

// InstanceShutdown returns true if the instance is shutdown according to the cloud provider.
func (i *instances) InstanceShutdown(ctx context.Context, node *v1.Node) (bool, error) {
	ec2Instance, err := i.getInstance(ctx, node)
	if err != nil {
		return false, err
	}

	if ec2Instance.State != nil {
		state := aws.StringValue(ec2Instance.State.Name)
		// valid state for detaching volumes
		if state == ec2.InstanceStateNameStopped {
			return true, nil
		}
	}

	return false, nil
}

// InstanceMetadata returns the instance's metadata.
func (i *instances) InstanceMetadata(ctx context.Context, node *v1.Node) (*cloudprovider.InstanceMetadata, error) {
	var err error
	var ec2Instance *ec2.Instance

	//  TODO: support node name policy other than private DNS names
	ec2Instance, err = i.getInstance(ctx, node)
	if err != nil {
		return nil, err
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

// getInstance returns the instance if the instance with the given node info still exists.
// If false an error will be returned, the instance will be immediately deleted by the cloud controller manager.
func (i *instances) getInstance(ctx context.Context, node *v1.Node) (*ec2.Instance, error) {
	var request *ec2.DescribeInstancesInput
	if node.Spec.ProviderID == "" {
		// get Instance by private DNS name
		request = &ec2.DescribeInstancesInput{
			Filters: []*ec2.Filter{
				newEc2Filter("private-dns-name", node.Name),
			},
		}
		klog.V(4).Infof("looking for node by private DNS name %v", node.Name)
	} else {
		// get Instance by provider ID
		instanceID, err := parseInstanceIDFromProviderID(node.Spec.ProviderID)
		if err != nil {
			return nil, err
		}

		request = &ec2.DescribeInstancesInput{
			InstanceIds: []*string{aws.String(instanceID)},
		}
		klog.V(4).Infof("looking for node by provider ID %v", node.Spec.ProviderID)
	}

	instances := []*ec2.Instance{}
	var nextToken *string
	for {
		response, err := i.ec2.DescribeInstances(request)
		if err != nil {
			return nil, fmt.Errorf("error describing ec2 instances: %v", err)
		}

		for _, reservation := range response.Reservations {
			instances = append(instances, reservation.Instances...)
		}

		nextToken = response.NextToken
		if aws.StringValue(nextToken) == "" {
			break
		}
		request.NextToken = nextToken
	}

	if len(instances) == 0 {
		return nil, cloudprovider.InstanceNotFound
	}

	if len(instances) > 1 {
		return nil, errors.New("getInstance: multiple instances found")
	}

	state := instances[0].State.Name
	if *state == ec2.InstanceStateNameTerminated {
		return nil, cloudprovider.InstanceNotFound
	}

	return instances[0], nil
}

// nodeAddresses for Instance returns a list of v1.NodeAddress for the give instance.
// TODO: should we support ExternalIP by default?
func nodeAddressesForInstance(instance *ec2.Instance) ([]v1.NodeAddress, error) {
	if instance == nil {
		return nil, errors.New("provided instances is nil")
	}

	addresses := []v1.NodeAddress{}
	for _, networkInterface := range instance.NetworkInterfaces {
		// skip network interfaces that are not currently in use
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

// getInstanceProviderID returns the provider ID of an instance which is ultimately set in the node.Spec.ProviderID field.
// The well-known format for a node's providerID is:
//    * aws:///<availability-zone>/<instance-id>
func getInstanceProviderID(instance *ec2.Instance) (string, error) {
	if aws.StringValue(instance.Placement.AvailabilityZone) == "" {
		return "", errors.New("instance availability zone was not set")
	}

	if aws.StringValue(instance.InstanceId) == "" {
		return "", errors.New("instance ID was not set")
	}

	return "aws:///" + aws.StringValue(instance.Placement.AvailabilityZone) + "/" + aws.StringValue(instance.InstanceId), nil
}

// parseInstanceIDFromProviderID parses the node's instance ID based on the following formats:
//   * aws://<availability-zone>/<instance-id>
//   * aws:///<instance-id>
//   * <instance-id>
// This function always assumes a valid providerID format was provided.
func parseInstanceIDFromProviderID(providerID string) (string, error) {
	// trim the provider name prefix 'aws://', renaming providerID should contain metadata in one of the following formats:
	// * <availability-zone>/<instance-id>
	// * /<availability-zone>/<instance-id>
	// * <instance-id>
	instanceID := ""
	metadata := strings.Split(strings.TrimPrefix(providerID, "aws://"), "/")
	if len(metadata) == 1 {
		// instance-id
		instanceID = metadata[0]
	} else if len(metadata) == 2 {
		// az/instance-id
		instanceID = metadata[1]
	} else if len(metadata) == 3 {
		// /az/instance-id
		instanceID = metadata[2]
	}

	return instanceID, nil
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
