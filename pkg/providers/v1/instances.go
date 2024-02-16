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
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	cloudprovider "k8s.io/cloud-provider"
	"k8s.io/klog/v2"
)

// awsInstanceRegMatch represents Regex Match for AWS instance.
var awsInstanceRegMatch = regexp.MustCompile("^i-[^/]*$")

// InstanceID represents the ID of the instance in the AWS API, e.g. i-12345678
// The "traditional" format is "i-12345678"
// A new longer format is also being introduced: "i-12345678abcdef01"
// We should not assume anything about the length or format, though it seems
// reasonable to assume that instances will continue to start with "i-".
type InstanceID string

func (i InstanceID) awsString() *string {
	return aws.String(string(i))
}

// KubernetesInstanceID represents the id for an instance in the kubernetes API;
// the following form
//   - aws:///<zone>/<awsInstanceId>
//   - aws:////<awsInstanceId>
//   - aws:///<zone>/fargate-<eni-ip-address>
//   - <awsInstanceId>
type KubernetesInstanceID string

// MapToAWSInstanceID extracts the InstanceID from the KubernetesInstanceID
func (name KubernetesInstanceID) MapToAWSInstanceID() (InstanceID, error) {
	s := string(name)

	if !strings.HasPrefix(s, "aws://") {
		// Assume a bare aws volume id (vol-1234...)
		// Build a URL with an empty host (AZ)
		s = "aws://" + "/" + "/" + s
	}
	url, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("Invalid instance name (%s): %v", name, err)
	}
	if url.Scheme != "aws" {
		return "", fmt.Errorf("Invalid scheme for AWS instance (%s)", name)
	}

	awsID := ""
	tokens := strings.Split(strings.Trim(url.Path, "/"), "/")
	// last token in the providerID is the aws resource ID for both EC2 and Fargate nodes
	if len(tokens) > 0 {
		awsID = tokens[len(tokens)-1]
	}

	// We sanity check the resulting volume; the two known formats are
	// i-12345678 and i-12345678abcdef01
	if awsID == "" || !(awsInstanceRegMatch.MatchString(awsID) || IsFargateNode(awsID)) {
		return "", fmt.Errorf("Invalid format for AWS instance (%s)", name)
	}

	return InstanceID(awsID), nil
}

// mapToAWSInstanceID extracts the InstanceIDs from the Nodes, returning an error if a Node cannot be mapped
func mapToAWSInstanceIDs(nodes []*v1.Node) ([]InstanceID, error) {
	var instanceIDs []InstanceID
	for _, node := range nodes {
		if node.Spec.ProviderID == "" {
			return nil, fmt.Errorf("node %q did not have ProviderID set", node.Name)
		}
		instanceID, err := KubernetesInstanceID(node.Spec.ProviderID).MapToAWSInstanceID()
		if err != nil {
			return nil, fmt.Errorf("unable to parse ProviderID %q for node %q", node.Spec.ProviderID, node.Name)
		}
		instanceIDs = append(instanceIDs, instanceID)
	}

	return instanceIDs, nil
}

// mapToAWSInstanceIDsTolerant extracts the InstanceIDs from the Nodes, skipping Nodes that cannot be mapped
func mapToAWSInstanceIDsTolerant(nodes []*v1.Node) []InstanceID {
	var instanceIDs []InstanceID
	for _, node := range nodes {
		if node.Spec.ProviderID == "" {
			klog.Warningf("node %q did not have ProviderID set", node.Name)
			continue
		}
		instanceID, err := KubernetesInstanceID(node.Spec.ProviderID).MapToAWSInstanceID()
		if err != nil {
			klog.Warningf("unable to parse ProviderID %q for node %q", node.Spec.ProviderID, node.Name)
			continue
		}
		instanceIDs = append(instanceIDs, instanceID)
	}

	return instanceIDs
}

// Gets the full information about this instance from the EC2 API
func describeInstance(ec2Client EC2, instanceID InstanceID) (*ec2.Instance, error) {
	request := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{instanceID.awsString()},
	}

	instances, err := ec2Client.DescribeInstances(request)
	if err != nil {
		return nil, err
	}
	if len(instances) == 0 {
		return nil, fmt.Errorf("no instances found for instance: %s", instanceID)
	}
	if len(instances) > 1 {
		return nil, fmt.Errorf("multiple instances found for instance: %s", instanceID)
	}
	return instances[0], nil
}

// instanceCache manages the cache of DescribeInstances
type instanceCache struct {
	// TODO: Get rid of this field, send all calls through the instanceCache
	cloud *Cloud

	mutex    sync.Mutex
	snapshot *allInstancesSnapshot
}

// Gets the full information about these instance from the EC2 API. Caller must have acquired c.mutex before
// calling describeAllInstancesUncached.
func (c *instanceCache) describeAllInstancesUncached() (*allInstancesSnapshot, error) {
	now := time.Now()

	klog.V(4).Infof("EC2 DescribeInstances - fetching all instances")

	var filters []*ec2.Filter
	instances, err := c.cloud.describeInstances(filters)
	if err != nil {
		return nil, err
	}

	m := make(map[InstanceID]*ec2.Instance)
	for _, i := range instances {
		id := InstanceID(aws.StringValue(i.InstanceId))
		m[id] = i
	}

	snapshot := &allInstancesSnapshot{now, m}
	if c.snapshot != nil && snapshot.olderThan(c.snapshot) {
		// If this happens a lot, we could run this function in a mutex and only return one result
		klog.Infof("Not caching concurrent AWS DescribeInstances results")
	} else {
		c.snapshot = snapshot
	}

	return snapshot, nil
}

// cacheCriteria holds criteria that must hold to use a cached snapshot
type cacheCriteria struct {
	// MaxAge indicates the maximum age of a cached snapshot we can accept.
	// If set to 0 (i.e. unset), cached values will not time out because of age.
	MaxAge time.Duration

	// HasInstances is a list of InstanceIDs that must be in a cached snapshot for it to be considered valid.
	// If an instance is not found in the cached snapshot, the snapshot be ignored and we will re-fetch.
	HasInstances []InstanceID
}

// describeAllInstancesCached returns all instances, using cached results if applicable
func (c *instanceCache) describeAllInstancesCached(criteria cacheCriteria) (*allInstancesSnapshot, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.snapshot != nil && c.snapshot.MeetsCriteria(criteria) {
		klog.V(6).Infof("EC2 DescribeInstances - using cached results")
		return c.snapshot, nil
	}

	return c.describeAllInstancesUncached()
}

// olderThan is a simple helper to encapsulate timestamp comparison
func (s *allInstancesSnapshot) olderThan(other *allInstancesSnapshot) bool {
	// After() is technically broken by time changes until we have monotonic time
	return other.timestamp.After(s.timestamp)
}

// MeetsCriteria returns true if the snapshot meets the criteria in cacheCriteria
func (s *allInstancesSnapshot) MeetsCriteria(criteria cacheCriteria) bool {
	if criteria.MaxAge > 0 {
		// Sub() is technically broken by time changes until we have monotonic time
		now := time.Now()
		if now.Sub(s.timestamp) > criteria.MaxAge {
			klog.V(6).Infof("instanceCache snapshot cannot be used as is older than MaxAge=%s", criteria.MaxAge)
			return false
		}
	}

	if len(criteria.HasInstances) != 0 {
		for _, id := range criteria.HasInstances {
			if nil == s.instances[id] {
				klog.V(6).Infof("instanceCache snapshot cannot be used as does not contain instance %s", id)
				return false
			}
		}
	}

	return true
}

// allInstancesSnapshot holds the results from querying for all instances,
// along with the timestamp for cache-invalidation purposes
type allInstancesSnapshot struct {
	timestamp time.Time
	instances map[InstanceID]*ec2.Instance
}

// FindInstances returns the instances corresponding to the specified ids.  If an id is not found, it is ignored.
func (s *allInstancesSnapshot) FindInstances(ids []InstanceID) map[InstanceID]*ec2.Instance {
	m := make(map[InstanceID]*ec2.Instance)
	for _, id := range ids {
		instance := s.instances[id]
		if instance != nil {
			m[id] = instance
		}
	}
	return m
}

/*
The following methods implement the Instances interface, which will be superceded by the
InstancesV2 interface.
*/

// NodeAddresses is an implementation of Instances.NodeAddresses.
func (c *Cloud) NodeAddresses(ctx context.Context, name types.NodeName) ([]v1.NodeAddress, error) {
	instanceID, err := c.nodeNameToInstanceID(name)
	if err != nil {
		return nil, fmt.Errorf("could not look up instance ID for node %q: %v", name, err)
	}
	return c.NodeAddressesByProviderID(ctx, string(instanceID))
}

// NodeAddressesByProviderID returns the node addresses of an instances with the specified unique providerID
// This method will not be called from the node that is requesting this ID. i.e. metadata service
// and other local methods cannot be used here
func (c *Cloud) NodeAddressesByProviderID(ctx context.Context, providerID string) ([]v1.NodeAddress, error) {
	instanceID, err := KubernetesInstanceID(providerID).MapToAWSInstanceID()
	if err != nil {
		return nil, err
	}

	if IsFargateNode(string(instanceID)) {
		eni, err := c.describeNetworkInterfaces(string(instanceID))
		if eni == nil || err != nil {
			return nil, err
		}

		var addresses []v1.NodeAddress

		// Assign NodeInternalIP based on IP family
		for _, family := range c.cfg.Global.NodeIPFamilies {
			switch family {
			case "ipv4":
				nodeAddresses := getNodeAddressesForFargateNode(aws.StringValue(eni.PrivateDnsName), aws.StringValue(eni.PrivateIpAddress))
				addresses = append(addresses, nodeAddresses...)
			case "ipv6":
				if eni.Ipv6Addresses == nil || len(eni.Ipv6Addresses) == 0 {
					klog.Errorf("no Ipv6Addresses associated with the eni")
					continue
				}
				internalIPv6Address := eni.Ipv6Addresses[0].Ipv6Address
				nodeAddresses := getNodeAddressesForFargateNode(aws.StringValue(eni.PrivateDnsName), aws.StringValue(internalIPv6Address))
				addresses = append(addresses, nodeAddresses...)
			}
		}
		return addresses, nil
	}

	instance, err := describeInstance(c.ec2, instanceID)
	if err != nil {
		return nil, err
	}

	var addresses []v1.NodeAddress

	for _, family := range c.cfg.Global.NodeIPFamilies {
		switch family {
		case "ipv4":
			ipv4addr, err := extractIPv4NodeAddresses(instance)
			if err != nil {
				return nil, err
			}
			addresses = append(addresses, ipv4addr...)
		case "ipv6":
			ipv6addr, err := extractIPv6NodeAddresses(instance)
			if err != nil {
				return nil, err
			}
			addresses = append(addresses, ipv6addr...)
		}
	}

	return addresses, nil
}

// InstanceID returns the cloud provider ID of the node with the specified nodeName.
func (c *Cloud) InstanceID(ctx context.Context, nodeName types.NodeName) (string, error) {
	// In the future it is possible to also return an endpoint as:
	// <endpoint>/<zone>/<instanceid>
	if c.selfAWSInstance.nodeName == nodeName {
		return "/" + c.selfAWSInstance.availabilityZone + "/" + c.selfAWSInstance.awsID, nil
	}
	inst, err := c.getInstanceByNodeName(nodeName)
	if err != nil {
		if err == cloudprovider.InstanceNotFound {
			// The Instances interface requires that we return InstanceNotFound (without wrapping)
			return "", err
		}
		return "", fmt.Errorf("getInstanceByNodeName failed for %q with %q", nodeName, err)
	}
	return "/" + aws.StringValue(inst.Placement.AvailabilityZone) + "/" + aws.StringValue(inst.InstanceId), nil
}

// InstanceType returns the type of the node with the specified nodeName.
func (c *Cloud) InstanceType(ctx context.Context, nodeName types.NodeName) (string, error) {
	if c.selfAWSInstance.nodeName == nodeName {
		return c.selfAWSInstance.instanceType, nil
	}
	inst, err := c.getInstanceByNodeName(nodeName)
	if err != nil {
		return "", fmt.Errorf("getInstanceByNodeName failed for %q with %q", nodeName, err)
	}
	return aws.StringValue(inst.InstanceType), nil
}

// InstanceTypeByProviderID returns the cloudprovider instance type of the node with the specified unique providerID
// This method will not be called from the node that is requesting this ID. i.e. metadata service
// and other local methods cannot be used here
func (c *Cloud) InstanceTypeByProviderID(ctx context.Context, providerID string) (string, error) {
	instanceID, err := KubernetesInstanceID(providerID).MapToAWSInstanceID()
	if err != nil {
		return "", err
	}

	if IsFargateNode(string(instanceID)) {
		return "", nil
	}

	instance, err := describeInstance(c.ec2, instanceID)
	if err != nil {
		return "", err
	}

	return aws.StringValue(instance.InstanceType), nil
}

// AddSSHKeyToAllInstances is currently not implemented.
func (c *Cloud) AddSSHKeyToAllInstances(ctx context.Context, user string, keyData []byte) error {
	return cloudprovider.NotImplemented
}

// CurrentNodeName returns the name of the current node
func (c *Cloud) CurrentNodeName(ctx context.Context, hostname string) (types.NodeName, error) {
	return c.selfAWSInstance.nodeName, nil
}

// InstanceExistsByProviderID returns true if the instance with the given provider id still exists.
// If false is returned with no error, the instance will be immediately deleted by the cloud controller manager.
func (c *Cloud) InstanceExistsByProviderID(ctx context.Context, providerID string) (bool, error) {
	instanceID, err := KubernetesInstanceID(providerID).MapToAWSInstanceID()
	if err != nil {
		return false, err
	}

	if IsFargateNode(string(instanceID)) {
		eni, err := c.describeNetworkInterfaces(string(instanceID))
		return eni != nil, err
	}

	request := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{instanceID.awsString()},
	}

	instances, err := c.ec2.DescribeInstances(request)
	if err != nil {
		// if err is InstanceNotFound, return false with no error
		if IsAWSErrorInstanceNotFound(err) {
			return false, nil
		}
		return false, err
	}
	if len(instances) == 0 {
		return false, nil
	}
	if len(instances) > 1 {
		return false, fmt.Errorf("multiple instances found for instance: %s", instanceID)
	}

	state := instances[0].State.Name
	if *state == ec2.InstanceStateNameTerminated {
		klog.Warningf("the instance %s is terminated", instanceID)
		return false, nil
	}

	return true, nil
}

// InstanceShutdownByProviderID returns true if the instance is in safe state to detach volumes
func (c *Cloud) InstanceShutdownByProviderID(ctx context.Context, providerID string) (bool, error) {
	instanceID, err := KubernetesInstanceID(providerID).MapToAWSInstanceID()
	if err != nil {
		return false, err
	}

	if IsFargateNode(string(instanceID)) {
		eni, err := c.describeNetworkInterfaces(string(instanceID))
		return eni != nil, err
	}

	request := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{instanceID.awsString()},
	}

	instances, err := c.ec2.DescribeInstances(request)
	if err != nil {
		return false, err
	}
	if len(instances) == 0 {
		klog.Warningf("the instance %s does not exist anymore", providerID)
		// returns false, because otherwise node is not deleted from cluster
		// false means that it will continue to check InstanceExistsByProviderID
		return false, nil
	}
	if len(instances) > 1 {
		return false, fmt.Errorf("multiple instances found for instance: %s", instanceID)
	}

	instance := instances[0]
	if instance.State != nil {
		state := aws.StringValue(instance.State.Name)
		// valid state for detaching volumes
		if state == ec2.InstanceStateNameStopped {
			return true, nil
		}
	}
	return false, nil
}
