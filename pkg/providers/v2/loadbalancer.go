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
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/elb"
	v1 "k8s.io/api/core/v1"
	cloudprovider "k8s.io/cloud-provider"
	"k8s.io/klog/v2"
	"k8s.io/kube-openapi/pkg/util/sets"
)

// ServiceAnnotationLoadBalancerTargetNodeLabels is the annotation used on the service
// to specify a comma-separated list of key-value pairs which will be used to select
// the target nodes for the load balancer
// For example: "Key1=Val1,Key2=Val2,KeyNoVal1=,KeyNoVal2"
const ServiceAnnotationLoadBalancerTargetNodeLabels = "service.beta.kubernetes.io/aws-load-balancer-target-node-labels"

// ServiceAnnotationLoadBalancerAdditionalTags is the annotation used on the service
// to specify a comma-separated list of key-value pairs which will be recorded as
// additional tags in the ELB.
// For example: "Key1=Val1,Key2=Val2,KeyNoVal1=,KeyNoVal2"
const ServiceAnnotationLoadBalancerAdditionalTags = "service.beta.kubernetes.io/aws-load-balancer-additional-resource-tags"

// ServiceAnnotationLoadBalancerSSLNegotiationPolicy is the annotation used on
// the service to specify a SSL negotiation settings for the HTTPS/SSL listeners
// of your load balancer. Defaults to AWS's default
const ServiceAnnotationLoadBalancerSSLNegotiationPolicy = "service.beta.kubernetes.io/aws-load-balancer-ssl-negotiation-policy"

// ServiceAnnotationLoadBalancerExtraSecurityGroups is the annotation used
// on the service to specify additional security groups to be added to ELB created
const ServiceAnnotationLoadBalancerExtraSecurityGroups = "service.beta.kubernetes.io/aws-load-balancer-extra-security-groups"

// ServiceAnnotationLoadBalancerSecurityGroups is the annotation used
// on the service to specify the security groups to be added to ELB created. Differently from the annotation
// "service.beta.kubernetes.io/aws-load-balancer-extra-security-groups", this replaces all other security groups previously assigned to the ELB.
const ServiceAnnotationLoadBalancerSecurityGroups = "service.beta.kubernetes.io/aws-load-balancer-security-groups"

// SSLNegotiationPolicyNameFormat is a format string used for the SSL
// negotiation policy tag name
const SSLNegotiationPolicyNameFormat = "k8s-SSLNegotiationPolicy-%s"

// loadbalancer is an implementation of cloudprovider.LoadBalancer
type loadbalancer struct {
	ec2 EC2
	elb ELB
}

// ELB is an interface defining only the methods we call from the AWS ELB SDK.
type ELB interface {
	CreateLoadBalancer(*elb.CreateLoadBalancerInput) (*elb.CreateLoadBalancerOutput, error)
	DeleteLoadBalancer(*elb.DeleteLoadBalancerInput) (*elb.DeleteLoadBalancerOutput, error)
	DescribeLoadBalancers(*elb.DescribeLoadBalancersInput) (*elb.DescribeLoadBalancersOutput, error)
	RegisterInstancesWithLoadBalancer(*elb.RegisterInstancesWithLoadBalancerInput) (*elb.RegisterInstancesWithLoadBalancerOutput, error)
	DeregisterInstancesFromLoadBalancer(*elb.DeregisterInstancesFromLoadBalancerInput) (*elb.DeregisterInstancesFromLoadBalancerOutput, error)
	CreateLoadBalancerPolicy(*elb.CreateLoadBalancerPolicyInput) (*elb.CreateLoadBalancerPolicyOutput, error)
	SetLoadBalancerPoliciesOfListener(input *elb.SetLoadBalancerPoliciesOfListenerInput) (*elb.SetLoadBalancerPoliciesOfListenerOutput, error)
	DescribeLoadBalancerPolicies(input *elb.DescribeLoadBalancerPoliciesInput) (*elb.DescribeLoadBalancerPoliciesOutput, error)

	CreateLoadBalancerListeners(*elb.CreateLoadBalancerListenersInput) (*elb.CreateLoadBalancerListenersOutput, error)
	DeleteLoadBalancerListeners(*elb.DeleteLoadBalancerListenersInput) (*elb.DeleteLoadBalancerListenersOutput, error)

	ApplySecurityGroupsToLoadBalancer(*elb.ApplySecurityGroupsToLoadBalancerInput) (*elb.ApplySecurityGroupsToLoadBalancerOutput, error)

	DescribeLoadBalancerAttributes(*elb.DescribeLoadBalancerAttributesInput) (*elb.DescribeLoadBalancerAttributesOutput, error)
	ModifyLoadBalancerAttributes(*elb.ModifyLoadBalancerAttributesInput) (*elb.ModifyLoadBalancerAttributesOutput, error)
}

// newLoadBalancer returns an implementation of cloudprovider.LoadBalancer
func newLoadBalancer(region string, creds *credentials.Credentials) (cloudprovider.LoadBalancer, error) {
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
	elbService := elb.New(sess)

	return &loadbalancer{
		ec2: ec2Service,
		elb: elbService,
	}, nil
}

// GetLoadBalancer returns whether the specified load balancer exists, and
// if so, what its status is.
func (l *loadbalancer) GetLoadBalancer(ctx context.Context, clusterName string, service *v1.Service) (status *v1.LoadBalancerStatus, exists bool, err error) {
	loadBalancerName := l.GetLoadBalancerName(ctx, clusterName, service)

	// Get the current load balancer information
	lbDesc, err := l.getLoadBalancerDescription(loadBalancerName)
	if err != nil {
		return nil, false, err
	}

	if lbDesc == nil {
		return nil, false, nil
	}

	return getLoadBalancerStatus(lbDesc), true, nil
}

// GetLoadBalancerName returns the name of the load balancer.
func (l *loadbalancer) GetLoadBalancerName(ctx context.Context, clusterName string, service *v1.Service) string {
	//  TODO: create a unique and friendly name with fixed length
	name := strings.ToLower(clusterName) + strings.ToLower(service.Name) + string(service.UID)
	name = strings.Replace(name, "-", "", -1)
	// AWS requires that the name of a load balancer can have a maximum of 32 characters
	if len(name) > 32 {
		name = name[:32]
	}
	return name
}

// EnsureLoadBalancer ensures a new load balancer, or updates the existing one. Returns the status of the balancer
func (l *loadbalancer) EnsureLoadBalancer(ctx context.Context, clusterName string, service *v1.Service, nodes []*v1.Node) (*v1.LoadBalancerStatus, error) {
	return nil, nil
}

// UpdateLoadBalancer updates hosts under the specified load balancer.
func (l *loadbalancer) UpdateLoadBalancer(ctx context.Context, clusterName string, service *v1.Service, nodes []*v1.Node) error {
	instances, err := l.getInstancesForELB(nodes, service.Annotations)
	if err != nil {
		return err
	}

	loadBalancerName := l.GetLoadBalancerName(ctx, clusterName, service)
	lb, err := l.getLoadBalancerDescription(loadBalancerName)
	if err != nil {
		return err
	}

	if lb == nil {
		return fmt.Errorf("Load balancer not found")
	}

	if sslPolicyName, ok := service.Annotations[ServiceAnnotationLoadBalancerSSLNegotiationPolicy]; ok {
		err := l.ensureSSLNegotiationPolicy(lb, sslPolicyName)
		if err != nil {
			return err
		}

		for _, port := range l.getLoadBalancerTLSPorts(lb) {
			err := l.setSSLNegotiationPolicy(loadBalancerName, sslPolicyName, port)
			if err != nil {
				return err
			}
		}
	}

	err = l.ensureLoadBalancerInstances(aws.StringValue(lb.LoadBalancerName), lb.Instances, instances)
	if err != nil {
		return nil
	}

	err = l.updateInstanceSecurityGroupsForLoadBalancer(lb, instances, service.Annotations)
	if err != nil {
		return err
	}

	return nil
}

// EnsureLoadBalancerDeleted deletes the specified load balancer if it exists, returning nil if the load balancer specified
// either didn't exist or was successfully deleted.
func (l *loadbalancer) EnsureLoadBalancerDeleted(ctx context.Context, clusterName string, service *v1.Service) error {
	loadBalancerName := l.GetLoadBalancerName(ctx, clusterName, service)

	lb, err := l.getLoadBalancerDescription(loadBalancerName)
	if err != nil {
		return err
	}

	if lb == nil {
		klog.Info("Load balancer already deleted: ", loadBalancerName)
		return nil
	}

	// De-authorize the load balancer security group from the instances security group
	err = l.updateInstanceSecurityGroupsForLoadBalancer(lb, nil, service.Annotations)
	if err != nil {
		klog.Errorf("Error deregistering load balancer from instance security groups: %q", err)
		return err
	}

	// Delete the load balancer itself
	request := &elb.DeleteLoadBalancerInput{
		LoadBalancerName: aws.String(loadBalancerName),
	}

	_, err = l.elb.DeleteLoadBalancer(request)
	if err != nil {
		// TODO: Check if error was because load balancer was concurrently deleted
		klog.Errorf("Error deleting load balancer: %q", err)
		return err
	}

	// Delete the security group(s) for the load balancer
	err = l.deleteSecurityGroupsForLoadBalancer(loadBalancerName, lb, service)
	if err != nil {
		klog.Errorf("Error deleting security groups for the load balancer: %q", err)
		return err
	}

	return nil
}

// getLoadBalancerDescription gets the information about the current load balancer
// elb.DescribeLoadBalancers will not return the type of the load balancer
func (l *loadbalancer) getLoadBalancerDescription(name string) (*elb.LoadBalancerDescription, error) {
	request := &elb.DescribeLoadBalancersInput{
		LoadBalancerNames: []*string{aws.String(name)},
	}

	response, err := l.elb.DescribeLoadBalancers(request)
	if err != nil {
		if awsError, ok := err.(awserr.Error); ok {
			if awsError.Code() == elb.ErrCodeAccessPointNotFoundException {
				return nil, nil
			}
		}
		return nil, fmt.Errorf("error describing load balancer: %q", err)
	}

	var lbDesc *elb.LoadBalancerDescription
	for _, loadBalancerDesc := range response.LoadBalancerDescriptions {
		if lbDesc != nil {
			klog.Errorf("Found multiple load balancers with name: %s", name)
		}
		lbDesc = loadBalancerDesc
	}
	return lbDesc, nil
}

// getLoadBalancerStatus converts the load balancer description to its status
func getLoadBalancerStatus(lb *elb.LoadBalancerDescription) *v1.LoadBalancerStatus {
	status := &v1.LoadBalancerStatus{}

	if aws.StringValue(lb.DNSName) != "" {
		var ingress v1.LoadBalancerIngress
		ingress.Hostname = aws.StringValue(lb.DNSName)
		status.Ingress = []v1.LoadBalancerIngress{ingress}
	}

	return status
}

// getInstancesForELB gets the EC2 instances corresponding to the Nodes, for setting up an ELB
// We ignore Nodes (with a log message) where the instanceID cannot be determined from the provider,
// and we ignore instances which are not found
func (l *loadbalancer) getInstancesForELB(nodes []*v1.Node, annotations map[string]string) (map[string]*ec2.Instance, error) {
	targetNodes := filterTargetNodes(nodes, annotations)

	// Get instance ids ignoring Nodes where we cannot find the id (but logging)
	instanceIDs, err := getInstanceIDsFromNodes(targetNodes)
	if err != nil {
		return nil, err
	}

	instances, err := l.getInstancesByIDs(instanceIDs)
	if err != nil {
		return nil, err
	}

	return instances, nil
}

// getInstancesByIDs returns a list of instances if the instance with the given instance id exists.
func (l *loadbalancer) getInstancesByIDs(instanceIDs []*string) (map[string]*ec2.Instance, error) {
	instancesByID := make(map[string]*ec2.Instance)
	if len(instanceIDs) == 0 {
		return instancesByID, nil
	}

	request := &ec2.DescribeInstancesInput{
		InstanceIds: instanceIDs,
	}

	instances := []*ec2.Instance{}
	var nextToken *string
	for {
		response, err := l.ec2.DescribeInstances(request)
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

	for _, instance := range instances {
		instanceID := aws.StringValue(instance.InstanceId)
		if instanceID == "" {
			continue
		}

		instancesByID[instanceID] = instance
	}

	return instancesByID, nil
}

// filterTargetNodes uses node labels to filter the nodes that should be targeted by the ELB,
// checking if all the labels provided in an annotation are present in the nodes
func filterTargetNodes(nodes []*v1.Node, annotations map[string]string) []*v1.Node {
	targetNodeLabels := getKeyValuePairsFromAnnotation(annotations, ServiceAnnotationLoadBalancerTargetNodeLabels)

	if len(targetNodeLabels) == 0 {
		return nodes
	}

	targetNodes := make([]*v1.Node, 0, len(nodes))

	for _, node := range nodes {
		if node.Labels != nil && len(node.Labels) > 0 {
			allFiltersMatch := true

			for targetLabelKey, targetLabelValue := range targetNodeLabels {
				if nodeLabelValue, ok := node.Labels[targetLabelKey]; !ok || (nodeLabelValue != targetLabelValue && targetLabelValue != "") {
					allFiltersMatch = false
					break
				}
			}

			if allFiltersMatch {
				targetNodes = append(targetNodes, node)
			}
		}
	}

	return targetNodes
}

// getKeyValuePairsFromAnnotation converts the comma separated list of key-value
// pairs from the specified annotation and returns it as a map.
func getKeyValuePairsFromAnnotation(annotations map[string]string, annotation string) map[string]string {
	additionalTags := make(map[string]string)
	if additionalTagsList, ok := annotations[annotation]; ok {
		additionalTagsList = strings.TrimSpace(additionalTagsList)

		// Break up list of "Key1=Val,Key2=Val2"
		tagList := strings.Split(additionalTagsList, ",")

		// Break up "Key=Val"
		for _, tagSet := range tagList {
			tag := strings.Split(strings.TrimSpace(tagSet), "=")

			// Accept "Key=val" or "Key=" or just "Key"
			if len(tag) >= 2 && len(tag[0]) != 0 {
				// There is a key and a value, so save it
				additionalTags[tag[0]] = tag[1]
			} else if len(tag) == 1 && len(tag[0]) != 0 {
				// Just "Key"
				additionalTags[tag[0]] = ""
			}
		}
	}

	return additionalTags
}

// getInstanceIDsFromNodes extracts the InstanceIDs from the Nodes, skipping Nodes that cannot be mapped
func getInstanceIDsFromNodes(nodes []*v1.Node) ([]*string, error) {
	var instanceIDs []*string
	for _, node := range nodes {
		if node.Spec.ProviderID == "" {
			klog.Warningf("node %q did not have ProviderID set", node.Name)
			continue
		}
		instanceID, err := parseInstanceIDFromProviderID(node.Spec.ProviderID)
		klog.Infof("instanid is: %v", instanceID)
		if err != nil {
			klog.Warningf("unable to parse ProviderID %q for node %q", node.Spec.ProviderID, node.Name)
			continue
		}
		instanceIDs = append(instanceIDs, &instanceID)
	}

	return instanceIDs, nil
}

// Makes sure that exactly the specified hosts are registered as instances with the load balancer
func (l *loadbalancer) ensureLoadBalancerInstances(loadBalancerName string, lbInstances []*elb.Instance, instanceIDs map[string]*ec2.Instance) error {
	expected := sets.NewString()
	for id := range instanceIDs {
		expected.Insert(string(id))
	}

	actual := sets.NewString()
	for _, lbInstance := range lbInstances {
		actual.Insert(aws.StringValue(lbInstance.InstanceId))
	}

	additions := expected.Difference(actual)
	removals := actual.Difference(expected)

	addInstances := []*elb.Instance{}
	for _, instanceID := range additions.List() {
		addInstance := &elb.Instance{}
		addInstance.InstanceId = aws.String(instanceID)
		addInstances = append(addInstances, addInstance)
	}

	removeInstances := []*elb.Instance{}
	for _, instanceID := range removals.List() {
		removeInstance := &elb.Instance{}
		removeInstance.InstanceId = aws.String(instanceID)
		removeInstances = append(removeInstances, removeInstance)
	}

	if len(addInstances) > 0 {
		registerRequest := &elb.RegisterInstancesWithLoadBalancerInput{}
		registerRequest.Instances = addInstances
		registerRequest.LoadBalancerName = aws.String(loadBalancerName)
		_, err := l.elb.RegisterInstancesWithLoadBalancer(registerRequest)
		if err != nil {
			return err
		}
		klog.V(1).Infof("Instances added to load-balancer %s", loadBalancerName)
	}

	if len(removeInstances) > 0 {
		deregisterRequest := &elb.DeregisterInstancesFromLoadBalancerInput{}
		deregisterRequest.Instances = removeInstances
		deregisterRequest.LoadBalancerName = aws.String(loadBalancerName)
		_, err := l.elb.DeregisterInstancesFromLoadBalancer(deregisterRequest)
		if err != nil {
			return err
		}
		klog.V(1).Infof("Instances removed from load-balancer %s", loadBalancerName)
	}

	return nil
}

func (l *loadbalancer) getLoadBalancerTLSPorts(loadBalancer *elb.LoadBalancerDescription) []int64 {
	ports := []int64{}
	for _, listenerDescription := range loadBalancer.ListenerDescriptions {
		protocol := aws.StringValue(listenerDescription.Listener.Protocol)
		if protocol == "SSL" || protocol == "HTTPS" {
			ports = append(ports, aws.Int64Value(listenerDescription.Listener.LoadBalancerPort))
		}
	}

	return ports
}

// ensureSSLNegotiationPolicy makes sure that the specific SSL negotiation policy exists on the current load balancer
// It returns error if we can not get or create security policies on the current load balancer
func (l *loadbalancer) ensureSSLNegotiationPolicy(loadBalancer *elb.LoadBalancerDescription, policyName string) error {
	klog.V(2).Info("Describing load balancer policies on load balancer")
	result, err := l.elb.DescribeLoadBalancerPolicies(&elb.DescribeLoadBalancerPoliciesInput{
		LoadBalancerName: loadBalancer.LoadBalancerName,
		PolicyNames: []*string{
			aws.String(fmt.Sprintf(SSLNegotiationPolicyNameFormat, policyName)),
		},
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case elb.ErrCodePolicyNotFoundException:
			default:
				return fmt.Errorf("error describing security policies on load balancer: %q", err)
			}
		}
	}

	if len(result.PolicyDescriptions) > 0 {
		return nil
	}

	klog.V(2).Infof("Creating SSL negotiation policy '%s' on load balancer", fmt.Sprintf(SSLNegotiationPolicyNameFormat, policyName))
	// there is an upper limit of 98 policies on an ELB, we're pretty safe from
	// running into it
	_, err = l.elb.CreateLoadBalancerPolicy(&elb.CreateLoadBalancerPolicyInput{
		LoadBalancerName: loadBalancer.LoadBalancerName,
		PolicyName:       aws.String(fmt.Sprintf(SSLNegotiationPolicyNameFormat, policyName)),
		PolicyTypeName:   aws.String("SSLNegotiationPolicyType"),
		PolicyAttributes: []*elb.PolicyAttribute{
			{
				AttributeName:  aws.String("Reference-Security-Policy"),
				AttributeValue: aws.String(policyName),
			},
		},
	})
	if err != nil {
		return fmt.Errorf("error creating security policy on load balancer: %q", err)
	}
	return nil
}

// setSSLNegotiationPolicy sets a specific SSL negotiation policy on the current load balancer
func (l *loadbalancer) setSSLNegotiationPolicy(loadBalancerName, sslPolicyName string, port int64) error {
	policyName := fmt.Sprintf(SSLNegotiationPolicyNameFormat, sslPolicyName)
	request := &elb.SetLoadBalancerPoliciesOfListenerInput{
		LoadBalancerName: aws.String(loadBalancerName),
		LoadBalancerPort: aws.Int64(port),
		PolicyNames: []*string{
			aws.String(policyName),
		},
	}

	klog.V(2).Infof("Setting SSL negotiation policy '%s' on load balancer", policyName)
	_, err := l.elb.SetLoadBalancerPoliciesOfListener(request)
	if err != nil {
		return fmt.Errorf("error setting SSL negotiation policy '%s' on load balancer: %q", policyName, err)
	}

	return nil
}

// Open security group ingress rules on the instances so that the load balancer can talk to them
// Will also remove any security groups ingress rules for the load balancer that are _not_ needed for allInstances
func (l *loadbalancer) updateInstanceSecurityGroupsForLoadBalancer(lb *elb.LoadBalancerDescription, instances map[string]*ec2.Instance, annotations map[string]string) error {
	// Determine the load balancer security group id
	lbSecurityGroupIDs := aws.StringValueSlice(lb.SecurityGroups)
	if len(lbSecurityGroupIDs) == 0 {
		return fmt.Errorf("could not determine security group for load balancer: %s", aws.StringValue(lb.LoadBalancerName))
	}

	l.sortELBSecurityGroupList(lbSecurityGroupIDs, annotations)
	loadBalancerSecurityGroupID := lbSecurityGroupIDs[0]

	// Get the actual list of groups that allow ingress from the load-balancer
	var actualGroups []*ec2.SecurityGroup
	{
		describeRequest := &ec2.DescribeSecurityGroupsInput{}
		describeRequest.Filters = []*ec2.Filter{
			newEc2Filter("ip-permission.group-id", loadBalancerSecurityGroupID),
		}

		var nextToken *string
		for {
			response, err := l.ec2.DescribeSecurityGroups(describeRequest)
			if err != nil {
				return fmt.Errorf("error querying security groups for ELB: %q", err)
			}

			for _, sg := range response.SecurityGroups {
				// TODO: check cluster tag
				actualGroups = append(actualGroups, sg)
			}

			nextToken = response.NextToken
			if aws.StringValue(nextToken) == "" {
				break
			}
			describeRequest.NextToken = nextToken
		}
	}

	taggedSecurityGroups, err := l.getTaggedSecurityGroups()
	if err != nil {
		return fmt.Errorf("error querying for tagged security groups: %q", err)
	}

	// Open the firewall from the load balancer to the instance
	// We don't actually have a trivial way to know in advance which security group the instance is in
	// (it is probably the node security group, but we don't easily have that).
	// However, we _do_ have the list of security groups on the instance records.

	// Map containing the changes we want to make; true to add, false to remove
	instanceSecurityGroupIds := map[string]bool{}

	// Scan instances for groups we want open
	for _, instance := range instances {
		securityGroup, err := findSecurityGroupForInstance(instance, taggedSecurityGroups)
		if err != nil {
			return err
		}

		if securityGroup == nil {
			klog.Warning("Ignoring instance without security group: ", aws.StringValue(instance.InstanceId))
			continue
		}

		id := aws.StringValue(securityGroup.GroupId)
		if id == "" {
			klog.Warningf("found security group without id: %v", securityGroup)
			continue
		}

		instanceSecurityGroupIds[id] = true
	}

	// Compare to actual groups
	for _, actualGroup := range actualGroups {
		actualGroupID := aws.StringValue(actualGroup.GroupId)
		if actualGroupID == "" {
			klog.Warning("Ignoring group without ID: ", actualGroup)
			continue
		}

		adding, found := instanceSecurityGroupIds[actualGroupID]
		if found && adding {
			// We don't need to make a change; the permission is already in place
			delete(instanceSecurityGroupIds, actualGroupID)
		} else {
			// This group is not needed by allInstances; delete it
			instanceSecurityGroupIds[actualGroupID] = false
		}
	}

	for instanceSecurityGroupID, add := range instanceSecurityGroupIds {
		if add {
			klog.V(2).Infof("Adding rule for traffic from the load balancer (%s) to instances (%s)", loadBalancerSecurityGroupID, instanceSecurityGroupID)
		} else {
			klog.V(2).Infof("Removing rule for traffic from the load balancer (%s) to instance (%s)", loadBalancerSecurityGroupID, instanceSecurityGroupID)
		}
		sourceGroupID := &ec2.UserIdGroupPair{}
		sourceGroupID.GroupId = &loadBalancerSecurityGroupID

		// specify -1 to allow traffic on all ports, regardless of any port range you specify
		allProtocols := "-1"

		permission := &ec2.IpPermission{
			IpProtocol:       &allProtocols,
			UserIdGroupPairs: []*ec2.UserIdGroupPair{sourceGroupID},
		}

		permissions := []*ec2.IpPermission{permission}

		if add {
			changed, err := l.addSecurityGroupIngress(instanceSecurityGroupID, permissions)
			if err != nil {
				return err
			}
			if !changed {
				klog.Warning("Allowing ingress was not needed; concurrent change? groupId=", instanceSecurityGroupID)
			}
		} else {
			changed, err := l.removeSecurityGroupIngress(instanceSecurityGroupID, permissions)
			if err != nil {
				return err
			}
			if !changed {
				klog.Warning("Revoking ingress was not needed; concurrent change? groupId=", instanceSecurityGroupID)
			}
		}
	}

	return nil
}

// Returns the first security group for an instance, or nil
// We only create instances with one security group, so we don't expect multiple security groups.
// However, if there are multiple security groups, we will choose the one tagged with our cluster filter.
// Otherwise we will return an error.
func findSecurityGroupForInstance(instance *ec2.Instance, taggedSecurityGroups map[string]*ec2.SecurityGroup) (*ec2.GroupIdentifier, error) {
	instanceID := aws.StringValue(instance.InstanceId)

	var tagged []*ec2.GroupIdentifier
	var untagged []*ec2.GroupIdentifier
	for _, group := range instance.SecurityGroups {
		groupID := aws.StringValue(group.GroupId)
		if groupID == "" {
			klog.Warningf("Ignoring security group without id for instance %q: %v", instanceID, group)
			continue
		}
		_, isTagged := taggedSecurityGroups[groupID]
		if isTagged {
			tagged = append(tagged, group)
		} else {
			untagged = append(untagged, group)
		}
	}

	if len(tagged) > 0 {
		// We create instances with one SG
		// If users create multiple SGs, they must tag one of them as being k8s owned
		if len(tagged) != 1 {
			taggedGroups := ""
			for _, v := range tagged {
				taggedGroups += fmt.Sprintf("%s(%s) ", *v.GroupId, *v.GroupName)
			}
			return nil, fmt.Errorf("Multiple tagged security groups found for instance %s; ensure only the k8s security group is tagged; the tagged groups were %v", instanceID, taggedGroups)
		}
		return tagged[0], nil
	}

	if len(untagged) > 0 {
		// For back-compat, we will allow a single untagged SG
		if len(untagged) != 1 {
			return nil, fmt.Errorf("Multiple untagged security groups found for instance %s; ensure the k8s security group is tagged", instanceID)
		}
		return untagged[0], nil
	}

	klog.Warningf("No security group found for instance %q", instanceID)
	return nil, nil
}

// This function is useful in extracting the security group list from annotation
func getSGListFromAnnotation(annotatedSG string) []string {
	sgList := []string{}
	for _, extraSG := range strings.Split(annotatedSG, ",") {
		extraSG = strings.TrimSpace(extraSG)
		if len(extraSG) > 0 {
			sgList = append(sgList, extraSG)
		}
	}
	return sgList
}

// Return all the security groups that are tagged as being part of our cluster
func (l *loadbalancer) getTaggedSecurityGroups() (map[string]*ec2.SecurityGroup, error) {
	request := &ec2.DescribeSecurityGroupsInput{}

	groups := make(map[string]*ec2.SecurityGroup)
	var nextToken *string
	for {
		response, err := l.ec2.DescribeSecurityGroups(request)
		if err != nil {
			return nil, fmt.Errorf("error querying security groups: %q", err)
		}

		for _, sg := range response.SecurityGroups {
			// TODO: check cluster tag
			id := aws.StringValue(sg.GroupId)
			if id == "" {
				klog.Warningf("Ignoring group without id: %v", sg)
				continue
			}
			groups[id] = sg
		}

		nextToken = response.NextToken
		if aws.StringValue(nextToken) == "" {
			break
		}
		request.NextToken = nextToken
	}

	return groups, nil
}

// sortELBSecurityGroupList returns a list of sorted securityGroupIDs based on the original order
// from buildELBSecurityGroupList. The logic is:
//  * securityGroups specified by ServiceAnnotationLoadBalancerSecurityGroups appears first in order
//  * securityGroups specified by ServiceAnnotationLoadBalancerExtraSecurityGroups appears last in order
func (l *loadbalancer) sortELBSecurityGroupList(securityGroupIDs []string, annotations map[string]string) {
	annotatedSGList := getSGListFromAnnotation(annotations[ServiceAnnotationLoadBalancerSecurityGroups])
	annotatedExtraSGList := getSGListFromAnnotation(annotations[ServiceAnnotationLoadBalancerExtraSecurityGroups])
	annotatedSGIndex := make(map[string]int, len(annotatedSGList))
	annotatedExtraSGIndex := make(map[string]int, len(annotatedExtraSGList))

	for i, sgID := range annotatedSGList {
		annotatedSGIndex[sgID] = i
	}
	for i, sgID := range annotatedExtraSGList {
		annotatedExtraSGIndex[sgID] = i
	}
	sgOrderMapping := make(map[string]int, len(securityGroupIDs))
	for _, sgID := range securityGroupIDs {
		if i, ok := annotatedSGIndex[sgID]; ok {
			sgOrderMapping[sgID] = i
		} else if j, ok := annotatedExtraSGIndex[sgID]; ok {
			sgOrderMapping[sgID] = len(annotatedSGIndex) + 1 + j
		} else {
			sgOrderMapping[sgID] = len(annotatedSGIndex)
		}
	}
	sort.Slice(securityGroupIDs, func(i, j int) bool {
		return sgOrderMapping[securityGroupIDs[i]] < sgOrderMapping[securityGroupIDs[j]]
	})
}

// Makes sure the security group includes the specified permissions
// Returns true if and only if changes were made
// The security group must already exist
func (l *loadbalancer) addSecurityGroupIngress(securityGroupID string, addPermissions []*ec2.IpPermission) (bool, error) {
	group, err := l.findSecurityGroup(securityGroupID)
	if err != nil {
		klog.Warningf("Error retrieving security group: %q", err)
		return false, err
	}

	if group == nil {
		return false, fmt.Errorf("security group not found: %s", securityGroupID)
	}

	klog.V(2).Infof("Existing security group ingress: %s %v", securityGroupID, group.IpPermissions)

	changes := []*ec2.IpPermission{}
	for _, addPermission := range addPermissions {
		hasUserID := false
		for i := range addPermission.UserIdGroupPairs {
			if addPermission.UserIdGroupPairs[i].UserId != nil {
				hasUserID = true
			}
		}

		found := false
		for _, groupPermission := range group.IpPermissions {
			if ipPermissionExists(addPermission, groupPermission, hasUserID) {
				found = true
				break
			}
		}

		if !found {
			changes = append(changes, addPermission)
		}
	}

	if len(changes) == 0 {
		return false, nil
	}

	klog.V(2).Infof("Adding security group ingress: %s %v", securityGroupID, changes)

	request := &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId:       &securityGroupID,
		IpPermissions: changes,
	}

	_, err = l.ec2.AuthorizeSecurityGroupIngress(request)
	if err != nil {
		klog.Warningf("Error authorizing security group ingress %q", err)
		return false, fmt.Errorf("error authorizing security group ingress: %q", err)
	}

	return true, nil
}

// Makes sure the security group no longer includes the specified permissions
// Returns true if and only if changes were made
// If the security group no longer exists, will return (false, nil)
func (l *loadbalancer) removeSecurityGroupIngress(securityGroupID string, removePermissions []*ec2.IpPermission) (bool, error) {
	group, err := l.findSecurityGroup(securityGroupID)
	if err != nil {
		klog.Warningf("Error retrieving security group: %q", err)
		return false, err
	}

	if group == nil {
		klog.Warning("Security group not found: ", securityGroupID)
		return false, nil
	}

	changes := []*ec2.IpPermission{}
	for _, removePermission := range removePermissions {
		hasUserID := false
		for i := range removePermission.UserIdGroupPairs {
			if removePermission.UserIdGroupPairs[i].UserId != nil {
				hasUserID = true
			}
		}

		var found *ec2.IpPermission
		for _, groupPermission := range group.IpPermissions {
			if ipPermissionExists(removePermission, groupPermission, hasUserID) {
				found = removePermission
				break
			}
		}

		if found != nil {
			changes = append(changes, found)
		}
	}

	if len(changes) == 0 {
		return false, nil
	}

	klog.V(2).Infof("Removing security group ingress: %s %v", securityGroupID, changes)

	request := &ec2.RevokeSecurityGroupIngressInput{
		GroupId:       &securityGroupID,
		IpPermissions: changes,
	}
	_, err = l.ec2.RevokeSecurityGroupIngress(request)
	if err != nil {
		klog.Warningf("Error revoking security group ingress: %q", err)
		return false, err
	}

	return true, nil
}

// Retrieves the specified security group from the AWS API, or returns nil if not found
func (l *loadbalancer) findSecurityGroup(securityGroupID string) (*ec2.SecurityGroup, error) {
	describeSecurityGroupsRequest := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []*string{&securityGroupID},
	}
	// We don't apply our tag filters because we are retrieving by ID

	groups := []*ec2.SecurityGroup{}
	var nextToken *string
	for {
		response, err := l.ec2.DescribeSecurityGroups(describeSecurityGroupsRequest)
		if err != nil {
			klog.Warningf("Error retrieving security group: %q", err)
			return nil, err
		}

		for _, sg := range response.SecurityGroups {
			groups = append(groups, sg)
		}

		nextToken = response.NextToken
		if aws.StringValue(nextToken) == "" {
			break
		}
		describeSecurityGroupsRequest.NextToken = nextToken
	}

	if len(groups) == 0 {
		return nil, nil
	}
	if len(groups) != 1 {
		// This should not be possible - ids should be unique
		return nil, fmt.Errorf("multiple security groups found with same id %q", securityGroupID)
	}

	group := groups[0]
	return group, nil
}

// ipPermissionExists returns true if newPermission is a subset of existing
func ipPermissionExists(newPermission, existing *ec2.IpPermission, compareGroupUserIDs bool) bool {
	if !isEqualIntPointer(newPermission.FromPort, existing.FromPort) || !isEqualIntPointer(newPermission.ToPort, existing.ToPort) ||
		!isEqualStringPointer(newPermission.IpProtocol, existing.IpProtocol) {
		return false
	}

	// Check only if newPermission is a subset of existing. Usually it has zero or one elements.
	// Not doing actual CIDR math yet; not clear it's needed, either.
	klog.V(4).Infof("Comparing %v to %v", newPermission, existing)
	if len(newPermission.IpRanges) > len(existing.IpRanges) {
		return false
	}

	for j := range newPermission.IpRanges {
		found := false
		for k := range existing.IpRanges {
			if isEqualStringPointer(newPermission.IpRanges[j].CidrIp, existing.IpRanges[k].CidrIp) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	for _, leftPair := range newPermission.UserIdGroupPairs {
		found := false
		for _, rightPair := range existing.UserIdGroupPairs {
			if isEqualUserGroupPair(leftPair, rightPair, compareGroupUserIDs) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func isEqualUserGroupPair(l, r *ec2.UserIdGroupPair, compareGroupUserIDs bool) bool {
	klog.V(2).Infof("Comparing %v to %v", *l.GroupId, *r.GroupId)
	if isEqualStringPointer(l.GroupId, r.GroupId) {
		if compareGroupUserIDs {
			if isEqualStringPointer(l.UserId, r.UserId) {
				return true
			}
		} else {
			return true
		}
	}

	return false
}

// Delete the security group(s) for the load balancer
// Note that this is annoying: the load balancer disappears from the API immediately, but it is still
// deleting in the background.  We get a DependencyViolation until the load balancer has deleted itself
func (l *loadbalancer) deleteSecurityGroupsForLoadBalancer(loadBalancerName string, lb *elb.LoadBalancerDescription, service *v1.Service) error {
	var loadBalancerSGs = aws.StringValueSlice(lb.SecurityGroups)

	describeRequest := &ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			newEc2Filter("group-id", loadBalancerSGs...),
		},
	}

	// Collect the security groups to delete
	securityGroupIDs := map[string]struct{}{}
	annotatedSgSet := map[string]bool{}
	annotatedSgsList := getSGListFromAnnotation(service.Annotations[ServiceAnnotationLoadBalancerSecurityGroups])
	annotatedExtraSgsList := getSGListFromAnnotation(service.Annotations[ServiceAnnotationLoadBalancerExtraSecurityGroups])
	annotatedSgsList = append(annotatedSgsList, annotatedExtraSgsList...)

	for _, sg := range annotatedSgsList {
		annotatedSgSet[sg] = true
	}

	var nextToken *string
	for {
		response, err := l.ec2.DescribeSecurityGroups(describeRequest)
		if err != nil {
			return fmt.Errorf("error querying security groups for ELB: %q", err)
		}

		for _, sg := range response.SecurityGroups {
			sgID := aws.StringValue(sg.GroupId)

			// TODO: We don't want to delete a security group that was defined in the Cloud Configuration.

			if sgID == "" {
				klog.Warningf("Ignoring empty security group in %s", service.Name)
				continue
			}
			// TODO: check cluster tag

			// This is an extra protection of deletion of non provisioned Security Group which is annotated with `service.beta.kubernetes.io/aws-load-balancer-security-groups`.
			if _, ok := annotatedSgSet[sgID]; ok {
				klog.Warningf("Ignoring security group with annotation `service.beta.kubernetes.io/aws-load-balancer-security-groups` or service.beta.kubernetes.io/aws-load-balancer-extra-security-groups in %s", service.Name)
				continue
			}

			securityGroupIDs[sgID] = struct{}{}
		}

		nextToken = response.NextToken
		if aws.StringValue(nextToken) == "" {
			break
		}
		describeRequest.NextToken = nextToken
	}

	// Loop through and try to delete them
	timeoutAt := time.Now().Add(time.Second * 600)
	for {
		for securityGroupID := range securityGroupIDs {
			deleteRequest := &ec2.DeleteSecurityGroupInput{
				GroupId: &securityGroupID,
			}

			_, err := l.ec2.DeleteSecurityGroup(deleteRequest)
			if err == nil {
				delete(securityGroupIDs, securityGroupID)
			} else {
				ignore := false
				if awsError, ok := err.(awserr.Error); ok {
					if awsError.Code() == "DependencyViolation" {
						klog.V(2).Infof("Ignoring DependencyViolation while deleting load-balancer security group (%s), assuming because LB is in process of deleting", securityGroupID)
						ignore = true
					}
				}
				if !ignore {
					return fmt.Errorf("error while deleting load balancer security group (%s): %q", securityGroupID, err)
				}
			}
		}

		if len(securityGroupIDs) == 0 {
			klog.V(2).Info("Success! Deleted all security groups for load balancer: ", service.Name)
			break
		}

		if time.Now().After(timeoutAt) {
			ids := []string{}
			for id := range securityGroupIDs {
				ids = append(ids, id)
			}

			return fmt.Errorf("timed out deleting ELB: %s. Could not delete security groups %v", service.Name, strings.Join(ids, ","))
		}

		klog.V(2).Info("Waiting for load-balancer to delete so we can delete security groups: ", service.Name)

		time.Sleep(10 * time.Second)
	}

	return nil
}
