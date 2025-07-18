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
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/smithy-go"
	"gopkg.in/gcfg.v1"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	informercorev1 "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	cloudprovider "k8s.io/cloud-provider"
	servicehelpers "k8s.io/cloud-provider/service/helpers"
	"k8s.io/klog/v2"
	netutils "k8s.io/utils/net"

	"k8s.io/cloud-provider-aws/pkg/providers/v1/config"
	"k8s.io/cloud-provider-aws/pkg/providers/v1/iface"
	"k8s.io/cloud-provider-aws/pkg/providers/v1/variant"
	_ "k8s.io/cloud-provider-aws/pkg/providers/v1/variant/fargate" // ensure the fargate variant gets registered
	"k8s.io/cloud-provider-aws/pkg/services"
)

// NLBHealthCheckRuleDescription is the comment used on a security group rule to
// indicate that it is used for health checks
const NLBHealthCheckRuleDescription = "kubernetes.io/rule/nlb/health"

// NLBClientRuleDescription is the comment used on a security group rule to
// indicate that it is used for client traffic
const NLBClientRuleDescription = "kubernetes.io/rule/nlb/client"

// NLBMtuDiscoveryRuleDescription is the comment used on a security group rule
// to indicate that it is used for mtu discovery
const NLBMtuDiscoveryRuleDescription = "kubernetes.io/rule/nlb/mtu"

// ProviderName is the name of this cloud provider.
const ProviderName = "aws"

// TagNameKubernetesService is the tag name we use to differentiate multiple
// services. Used currently for ELBs only.
const TagNameKubernetesService = "kubernetes.io/service-name"

// TagNameSubnetInternalELB is the tag name used on a subnet to designate that
// it should be used for internal ELBs
const TagNameSubnetInternalELB = "kubernetes.io/role/internal-elb"

// TagNameSubnetPublicELB is the tag name used on a subnet to designate that
// it should be used for internet ELBs
const TagNameSubnetPublicELB = "kubernetes.io/role/elb"

// ServiceAnnotationLoadBalancerType is the annotation used on the service
// to indicate what type of Load Balancer we want. Right now, the only accepted
// value is "nlb"
const ServiceAnnotationLoadBalancerType = "service.beta.kubernetes.io/aws-load-balancer-type"

// ServiceAnnotationLoadBalancerInternal is the annotation used on the service
// to indicate that we want an internal ELB.
const ServiceAnnotationLoadBalancerInternal = "service.beta.kubernetes.io/aws-load-balancer-internal"

// ServiceAnnotationLoadBalancerProxyProtocol is the annotation used on the
// service to enable the proxy protocol on an ELB. Right now we only accept the
// value "*" which means enable the proxy protocol on all ELB backends. In the
// future we could adjust this to allow setting the proxy protocol only on
// certain backends.
const ServiceAnnotationLoadBalancerProxyProtocol = "service.beta.kubernetes.io/aws-load-balancer-proxy-protocol"

// ServiceAnnotationLoadBalancerAccessLogEmitInterval is the annotation used to
// specify access log emit interval.
const ServiceAnnotationLoadBalancerAccessLogEmitInterval = "service.beta.kubernetes.io/aws-load-balancer-access-log-emit-interval"

// ServiceAnnotationLoadBalancerAccessLogEnabled is the annotation used on the
// service to enable or disable access logs.
const ServiceAnnotationLoadBalancerAccessLogEnabled = "service.beta.kubernetes.io/aws-load-balancer-access-log-enabled"

// ServiceAnnotationLoadBalancerAccessLogS3BucketName is the annotation used to
// specify access log s3 bucket name.
const ServiceAnnotationLoadBalancerAccessLogS3BucketName = "service.beta.kubernetes.io/aws-load-balancer-access-log-s3-bucket-name"

// ServiceAnnotationLoadBalancerAccessLogS3BucketPrefix is the annotation used
// to specify access log s3 bucket prefix.
const ServiceAnnotationLoadBalancerAccessLogS3BucketPrefix = "service.beta.kubernetes.io/aws-load-balancer-access-log-s3-bucket-prefix"

// ServiceAnnotationLoadBalancerConnectionDrainingEnabled is the annnotation
// used on the service to enable or disable connection draining.
const ServiceAnnotationLoadBalancerConnectionDrainingEnabled = "service.beta.kubernetes.io/aws-load-balancer-connection-draining-enabled"

// ServiceAnnotationLoadBalancerConnectionDrainingTimeout is the annotation
// used on the service to specify a connection draining timeout.
const ServiceAnnotationLoadBalancerConnectionDrainingTimeout = "service.beta.kubernetes.io/aws-load-balancer-connection-draining-timeout"

// ServiceAnnotationLoadBalancerConnectionIdleTimeout is the annotation used
// on the service to specify the idle connection timeout.
const ServiceAnnotationLoadBalancerConnectionIdleTimeout = "service.beta.kubernetes.io/aws-load-balancer-connection-idle-timeout"

// ServiceAnnotationLoadBalancerCrossZoneLoadBalancingEnabled is the annotation
// used on the service to enable or disable cross-zone load balancing.
const ServiceAnnotationLoadBalancerCrossZoneLoadBalancingEnabled = "service.beta.kubernetes.io/aws-load-balancer-cross-zone-load-balancing-enabled"

// ServiceAnnotationLoadBalancerExtraSecurityGroups is the annotation used
// on the service to specify additional security groups to be added to ELB created
const ServiceAnnotationLoadBalancerExtraSecurityGroups = "service.beta.kubernetes.io/aws-load-balancer-extra-security-groups"

// ServiceAnnotationLoadBalancerSecurityGroups is the annotation used
// on the service to specify the security groups to be added to ELB created. Differently from the annotation
// "service.beta.kubernetes.io/aws-load-balancer-extra-security-groups", this replaces all other security groups previously assigned to the ELB.
const ServiceAnnotationLoadBalancerSecurityGroups = "service.beta.kubernetes.io/aws-load-balancer-security-groups"

// ServiceAnnotationLoadBalancerCertificate is the annotation used on the
// service to request a secure listener. Value is a valid certificate ARN.
// For more, see http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-listener-config.html
// CertARN is an IAM or CM certificate ARN, e.g. arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012
const ServiceAnnotationLoadBalancerCertificate = "service.beta.kubernetes.io/aws-load-balancer-ssl-cert"

// ServiceAnnotationLoadBalancerSSLPorts is the annotation used on the service
// to specify a comma-separated list of ports that will use SSL/HTTPS
// listeners. Defaults to '*' (all).
const ServiceAnnotationLoadBalancerSSLPorts = "service.beta.kubernetes.io/aws-load-balancer-ssl-ports"

// ServiceAnnotationLoadBalancerSSLNegotiationPolicy is the annotation used on
// the service to specify a SSL negotiation settings for the HTTPS/SSL listeners
// of your load balancer. Defaults to AWS's default
const ServiceAnnotationLoadBalancerSSLNegotiationPolicy = "service.beta.kubernetes.io/aws-load-balancer-ssl-negotiation-policy"

// ServiceAnnotationLoadBalancerBEProtocol is the annotation used on the service
// to specify the protocol spoken by the backend (pod) behind a listener.
// If `http` (default) or `https`, an HTTPS listener that terminates the
//
//	connection and parses headers is created.
//
// If set to `ssl` or `tcp`, a "raw" SSL listener is used.
// If set to `http` and `aws-load-balancer-ssl-cert` is not used then
// a HTTP listener is used.
const ServiceAnnotationLoadBalancerBEProtocol = "service.beta.kubernetes.io/aws-load-balancer-backend-protocol"

// ServiceAnnotationLoadBalancerAdditionalTags is the annotation used on the service
// to specify a comma-separated list of key-value pairs which will be recorded as
// additional tags in the ELB.
// For example: "Key1=Val1,Key2=Val2,KeyNoVal1=,KeyNoVal2"
const ServiceAnnotationLoadBalancerAdditionalTags = "service.beta.kubernetes.io/aws-load-balancer-additional-resource-tags"

// ServiceAnnotationLoadBalancerHealthCheckProtocol is the annotation used on the service to
// specify the protocol used for the ELB health check. Supported values are TCP, HTTP, HTTPS
// Default is TCP if externalTrafficPolicy is Cluster, HTTP if externalTrafficPolicy is Local
const ServiceAnnotationLoadBalancerHealthCheckProtocol = "service.beta.kubernetes.io/aws-load-balancer-healthcheck-protocol"

// ServiceAnnotationLoadBalancerHealthCheckPort is the annotation used on the service to
// specify the port used for ELB health check.
// Default is traffic-port if externalTrafficPolicy is Cluster, healthCheckNodePort if externalTrafficPolicy is Local
const ServiceAnnotationLoadBalancerHealthCheckPort = "service.beta.kubernetes.io/aws-load-balancer-healthcheck-port"

// ServiceAnnotationLoadBalancerHealthCheckPath is the annotation used on the service to
// specify the path for the ELB health check when the health check protocol is HTTP/HTTPS
// Defaults to /healthz if externalTrafficPolicy is Local, / otherwise
const ServiceAnnotationLoadBalancerHealthCheckPath = "service.beta.kubernetes.io/aws-load-balancer-healthcheck-path"

// ServiceAnnotationLoadBalancerHCHealthyThreshold is the annotation used on
// the service to specify the number of successive successful health checks
// required for a backend to be considered healthy for traffic. For NLB, healthy-threshold
// and unhealthy-threshold must be equal.
const ServiceAnnotationLoadBalancerHCHealthyThreshold = "service.beta.kubernetes.io/aws-load-balancer-healthcheck-healthy-threshold"

// ServiceAnnotationLoadBalancerHCUnhealthyThreshold is the annotation used
// on the service to specify the number of unsuccessful health checks
// required for a backend to be considered unhealthy for traffic
const ServiceAnnotationLoadBalancerHCUnhealthyThreshold = "service.beta.kubernetes.io/aws-load-balancer-healthcheck-unhealthy-threshold"

// ServiceAnnotationLoadBalancerHCTimeout is the annotation used on the
// service to specify, in seconds, how long to wait before marking a health
// check as failed.
const ServiceAnnotationLoadBalancerHCTimeout = "service.beta.kubernetes.io/aws-load-balancer-healthcheck-timeout"

// ServiceAnnotationLoadBalancerHCInterval is the annotation used on the
// service to specify, in seconds, the interval between health checks.
const ServiceAnnotationLoadBalancerHCInterval = "service.beta.kubernetes.io/aws-load-balancer-healthcheck-interval"

// ServiceAnnotationLoadBalancerEIPAllocations is the annotation used on the
// service to specify a comma separated list of EIP allocations to use as
// static IP addresses for the NLB. Only supported on elbv2 (NLB)
const ServiceAnnotationLoadBalancerEIPAllocations = "service.beta.kubernetes.io/aws-load-balancer-eip-allocations"

// ServiceAnnotationLoadBalancerTargetNodeLabels is the annotation used on the service
// to specify a comma-separated list of key-value pairs which will be used to select
// the target nodes for the load balancer
// For example: "Key1=Val1,Key2=Val2,KeyNoVal1=,KeyNoVal2"
const ServiceAnnotationLoadBalancerTargetNodeLabels = "service.beta.kubernetes.io/aws-load-balancer-target-node-labels"

// ServiceAnnotationLoadBalancerSubnets is the annotation used on the service to specify the
// Availability Zone configuration for the load balancer. The values are comma separated list of
// subnetID or subnetName from different AZs
// By default, the controller will auto-discover the subnets. If there are multiple subnets per AZ, auto-discovery
// will break the tie in the following order -
//  1. prefer the subnet with the correct role tag. kubernetes.io/role/elb for public and kubernetes.io/role/internal-elb for private access
//  2. prefer the subnet with the cluster tag kubernetes.io/cluster/<Cluster Name>
//  3. prefer the subnet that is first in lexicographic order
const ServiceAnnotationLoadBalancerSubnets = "service.beta.kubernetes.io/aws-load-balancer-subnets"

const headerSourceArn = "x-amz-source-arn"
const headerSourceAccount = "x-amz-source-account"

const (
	// createTag* is configuration of exponential backoff for CreateTag call. We
	// retry mainly because if we create an object, we cannot tag it until it is
	// "fully created" (eventual consistency). Starting with 1 second, doubling
	// it every step and taking 9 steps results in 255 second total waiting
	// time.
	createTagInitialDelay = 1 * time.Second
	createTagFactor       = 2.0
	createTagSteps        = 9

	// Number of node names that can be added to a filter. The AWS limit is 200
	// but we are using a lower limit on purpose
	filterNodeLimit = 150

	// privateDNSNamePrefix is the prefix added to ENI Private DNS Name.
	privateDNSNamePrefix = "ip-"

	// rbnNamePrefix is the prefix added to ENI Private DNS Name with RBN.
	rbnNamePrefix = "i-"
)

const (
	localZoneType               = "local-zone"
	wavelengthZoneType          = "wavelength-zone"
	regularAvailabilityZoneType = "availability-zone"
)

// awsTagNameMasterRoles is a set of well-known AWS tag names that indicate the instance is a master
var awsTagNameMasterRoles = sets.NewString("kubernetes.io/role/master", "k8s.io/role/master")

// Maps from backend protocol to ELB protocol
var backendProtocolMapping = map[string]string{
	"https": "https",
	"http":  "https",
	"ssl":   "ssl",
	"tcp":   "ssl",
}

// MaxReadThenCreateRetries sets the maximum number of attempts we will make when
// we read to see if something exists and then try to create it if we didn't find it.
// This can fail once in a consistent system if done in parallel
// In an eventually consistent system, it could fail unboundedly
const MaxReadThenCreateRetries = 30

// Services is an abstraction over AWS, to allow mocking/other implementations
type Services interface {
	Compute(ctx context.Context, region string, assumeRoleProvider *stscreds.AssumeRoleProvider) (iface.EC2, error)
	LoadBalancing(ctx context.Context, regionName string, assumeRoleProvider *stscreds.AssumeRoleProvider) (ELB, error)
	LoadBalancingV2(ctx context.Context, regionName string, assumeRoleProvider *stscreds.AssumeRoleProvider) (ELBV2, error)
	Metadata(ctx context.Context) (config.EC2Metadata, error)
	KeyManagement(ctx context.Context, regionName string, assumeRoleProvider *stscreds.AssumeRoleProvider) (KMS, error)
}

// ELB is a simple pass-through of AWS' ELB client interface, which allows for testing
type ELB interface {
	CreateLoadBalancer(ctx context.Context, input *elb.CreateLoadBalancerInput, optFns ...func(*elb.Options)) (*elb.CreateLoadBalancerOutput, error)
	DeleteLoadBalancer(ctx context.Context, input *elb.DeleteLoadBalancerInput, optFns ...func(*elb.Options)) (*elb.DeleteLoadBalancerOutput, error)
	DescribeLoadBalancers(ctx context.Context, input *elb.DescribeLoadBalancersInput, optFns ...func(*elb.Options)) (*elb.DescribeLoadBalancersOutput, error)
	AddTags(ctx context.Context, input *elb.AddTagsInput, optFns ...func(*elb.Options)) (*elb.AddTagsOutput, error)
	RegisterInstancesWithLoadBalancer(ctx context.Context, input *elb.RegisterInstancesWithLoadBalancerInput, optFns ...func(*elb.Options)) (*elb.RegisterInstancesWithLoadBalancerOutput, error)
	DeregisterInstancesFromLoadBalancer(ctx context.Context, input *elb.DeregisterInstancesFromLoadBalancerInput, optFns ...func(*elb.Options)) (*elb.DeregisterInstancesFromLoadBalancerOutput, error)
	CreateLoadBalancerPolicy(ctx context.Context, input *elb.CreateLoadBalancerPolicyInput, optFns ...func(*elb.Options)) (*elb.CreateLoadBalancerPolicyOutput, error)
	SetLoadBalancerPoliciesForBackendServer(ctx context.Context, input *elb.SetLoadBalancerPoliciesForBackendServerInput, optFns ...func(*elb.Options)) (*elb.SetLoadBalancerPoliciesForBackendServerOutput, error)
	SetLoadBalancerPoliciesOfListener(ctx context.Context, input *elb.SetLoadBalancerPoliciesOfListenerInput, optFns ...func(*elb.Options)) (*elb.SetLoadBalancerPoliciesOfListenerOutput, error)
	DescribeLoadBalancerPolicies(ctx context.Context, input *elb.DescribeLoadBalancerPoliciesInput, optFns ...func(*elb.Options)) (*elb.DescribeLoadBalancerPoliciesOutput, error)

	DetachLoadBalancerFromSubnets(ctx context.Context, input *elb.DetachLoadBalancerFromSubnetsInput, optFns ...func(*elb.Options)) (*elb.DetachLoadBalancerFromSubnetsOutput, error)
	AttachLoadBalancerToSubnets(ctx context.Context, input *elb.AttachLoadBalancerToSubnetsInput, optFns ...func(*elb.Options)) (*elb.AttachLoadBalancerToSubnetsOutput, error)

	CreateLoadBalancerListeners(ctx context.Context, input *elb.CreateLoadBalancerListenersInput, optFns ...func(*elb.Options)) (*elb.CreateLoadBalancerListenersOutput, error)
	DeleteLoadBalancerListeners(ctx context.Context, input *elb.DeleteLoadBalancerListenersInput, optFns ...func(*elb.Options)) (*elb.DeleteLoadBalancerListenersOutput, error)

	ApplySecurityGroupsToLoadBalancer(ctx context.Context, input *elb.ApplySecurityGroupsToLoadBalancerInput, optFns ...func(*elb.Options)) (*elb.ApplySecurityGroupsToLoadBalancerOutput, error)

	ConfigureHealthCheck(ctx context.Context, input *elb.ConfigureHealthCheckInput, optFns ...func(*elb.Options)) (*elb.ConfigureHealthCheckOutput, error)

	DescribeLoadBalancerAttributes(ctx context.Context, input *elb.DescribeLoadBalancerAttributesInput, optFns ...func(*elb.Options)) (*elb.DescribeLoadBalancerAttributesOutput, error)
	ModifyLoadBalancerAttributes(ctx context.Context, input *elb.ModifyLoadBalancerAttributesInput, optFns ...func(*elb.Options)) (*elb.ModifyLoadBalancerAttributesOutput, error)
}

// ELBV2 is a simple pass-through of AWS' ELBV2 client interface, which allows for testing
type ELBV2 interface {
	AddTags(ctx context.Context, input *elbv2.AddTagsInput, optFns ...func(*elbv2.Options)) (*elbv2.AddTagsOutput, error)

	CreateLoadBalancer(ctx context.Context, input *elbv2.CreateLoadBalancerInput, optFns ...func(*elbv2.Options)) (*elbv2.CreateLoadBalancerOutput, error)
	DescribeLoadBalancers(ctx context.Context, input *elbv2.DescribeLoadBalancersInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error)
	DeleteLoadBalancer(ctx context.Context, input *elbv2.DeleteLoadBalancerInput, optFns ...func(*elbv2.Options)) (*elbv2.DeleteLoadBalancerOutput, error)

	ModifyLoadBalancerAttributes(ctx context.Context, input *elbv2.ModifyLoadBalancerAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.ModifyLoadBalancerAttributesOutput, error)
	DescribeLoadBalancerAttributes(ctx context.Context, input *elbv2.DescribeLoadBalancerAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancerAttributesOutput, error)

	CreateTargetGroup(ctx context.Context, input *elbv2.CreateTargetGroupInput, optFns ...func(*elbv2.Options)) (*elbv2.CreateTargetGroupOutput, error)
	DescribeTargetGroups(ctx context.Context, input *elbv2.DescribeTargetGroupsInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupsOutput, error)
	ModifyTargetGroup(ctx context.Context, input *elbv2.ModifyTargetGroupInput, optFns ...func(*elbv2.Options)) (*elbv2.ModifyTargetGroupOutput, error)
	DeleteTargetGroup(ctx context.Context, input *elbv2.DeleteTargetGroupInput, optFns ...func(*elbv2.Options)) (*elbv2.DeleteTargetGroupOutput, error)

	DescribeTargetHealth(ctx context.Context, input *elbv2.DescribeTargetHealthInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetHealthOutput, error)

	DescribeTargetGroupAttributes(ctx context.Context, input *elbv2.DescribeTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupAttributesOutput, error)
	ModifyTargetGroupAttributes(ctx context.Context, input *elbv2.ModifyTargetGroupAttributesInput, optFns ...func(*elbv2.Options)) (*elbv2.ModifyTargetGroupAttributesOutput, error)

	RegisterTargets(ctx context.Context, input *elbv2.RegisterTargetsInput, optFns ...func(*elbv2.Options)) (*elbv2.RegisterTargetsOutput, error)
	DeregisterTargets(ctx context.Context, input *elbv2.DeregisterTargetsInput, optFns ...func(*elbv2.Options)) (*elbv2.DeregisterTargetsOutput, error)

	CreateListener(ctx context.Context, input *elbv2.CreateListenerInput, optFns ...func(*elbv2.Options)) (*elbv2.CreateListenerOutput, error)
	DescribeListeners(ctx context.Context, input *elbv2.DescribeListenersInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeListenersOutput, error)
	DeleteListener(ctx context.Context, input *elbv2.DeleteListenerInput, optFns ...func(*elbv2.Options)) (*elbv2.DeleteListenerOutput, error)
	ModifyListener(ctx context.Context, input *elbv2.ModifyListenerInput, optFns ...func(*elbv2.Options)) (*elbv2.ModifyListenerOutput, error)
}

// KMS is a simple pass-through of the Key Management Service client interface,
// which allows for testing.
type KMS interface {
	DescribeKey(ctx context.Context, input *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

var _ cloudprovider.Interface = (*Cloud)(nil)
var _ cloudprovider.Instances = (*Cloud)(nil)
var _ cloudprovider.LoadBalancer = (*Cloud)(nil)
var _ cloudprovider.Routes = (*Cloud)(nil)
var _ cloudprovider.Zones = (*Cloud)(nil)

// Cloud is an implementation of Interface, LoadBalancer and Instances for Amazon Web Services.
type Cloud struct {
	ec2      iface.EC2
	elb      ELB
	elbv2    ELBV2
	kms      KMS
	metadata config.EC2Metadata
	cfg      *config.CloudConfig
	region   string
	vpcID    string

	tagging awsTagging

	// The AWS instance that we are running on
	// Note that we cache some state in awsInstance (mountpoints), so we must preserve the instance
	selfAWSInstance *awsInstance

	instanceCache           instanceCache
	zoneCache               zoneCache
	instanceTopologyManager InstanceTopologyManager

	clientBuilder cloudprovider.ControllerClientBuilder
	kubeClient    clientset.Interface

	nodeInformer informercorev1.NodeInformer
	// Extract the function out to make it easier to test
	nodeInformerHasSynced cache.InformerSynced

	eventBroadcaster record.EventBroadcaster
	eventRecorder    record.EventRecorder

	// Batching AWS api calls
	createTagsBatcher       *createTagsBatcher
	deleteTagsBatcher       *deleteTagsBatcher
	describeInstanceBatcher *describeInstanceBatcher
}

// Interface to make the CloudConfig immutable for awsSDKProvider
type awsCloudConfigProvider interface {
	GetEC2EndpointOpts(region string) []func(*ec2.Options)
	GetCustomEC2Resolver() ec2.EndpointResolverV2
	GetELBEndpointOpts(region string) []func(*elb.Options)
	GetCustomELBResolver() elb.EndpointResolverV2
	GetELBV2EndpointOpts(region string) []func(*elbv2.Options)
	GetCustomELBV2Resolver() elbv2.EndpointResolverV2
	GetKMSEndpointOpts(region string) []func(*kms.Options)
	GetCustomKMSResolver() kms.EndpointResolverV2
	GetIMDSEndpointOpts() []func(*imds.Options)
}

// InstanceIDIndexFunc indexes based on a Node's instance ID found in its spec.providerID
func InstanceIDIndexFunc(obj interface{}) ([]string, error) {
	node, ok := obj.(*v1.Node)
	if !ok {
		return []string{""}, fmt.Errorf("%+v is not a Node", obj)
	}
	if node.Spec.ProviderID == "" {
		// provider ID hasn't been populated yet
		return []string{""}, nil
	}
	instanceID, err := KubernetesInstanceID(node.Spec.ProviderID).MapToAWSInstanceID()
	if err != nil {
		//logging the error as warning as Informer.AddIndexers would panic if there is an error
		klog.Warningf("error mapping node %q's provider ID %q to instance ID: %v", node.Name, node.Spec.ProviderID, err)
		return []string{""}, nil
	}
	return []string{string(instanceID)}, nil
}

// SetInformers implements InformerUser interface by setting up informer-fed caches for aws lib to
// leverage Kubernetes API for caching
func (c *Cloud) SetInformers(informerFactory informers.SharedInformerFactory) {
	klog.Infof("Setting up informers for Cloud")
	c.nodeInformer = informerFactory.Core().V1().Nodes()
	c.nodeInformerHasSynced = c.nodeInformer.Informer().HasSynced
	c.nodeInformer.Informer().AddIndexers(cache.Indexers{
		"instanceID": InstanceIDIndexFunc,
	})
}

func newEc2Filter(name string, values ...string) ec2types.Filter {
	filter := ec2types.Filter{
		Name: aws.String(name),
	}
	for _, value := range values {
		filter.Values = append(filter.Values, value)
	}
	return filter
}

// AddSSHKeyToAllInstances is currently not implemented.
func (c *Cloud) AddSSHKeyToAllInstances(ctx context.Context, user string, keyData []byte) error {
	return cloudprovider.NotImplemented
}

// CurrentNodeName returns the name of the current node
func (c *Cloud) CurrentNodeName(ctx context.Context, hostname string) (types.NodeName, error) {
	return c.selfAWSInstance.nodeName, nil
}

func init() {
	registerMetrics()
	cloudprovider.RegisterCloudProvider(ProviderName, func(config io.Reader) (cloudprovider.Interface, error) {
		ctx := context.Background()
		cfg, err := readAWSCloudConfig(config)
		if err != nil {
			return nil, fmt.Errorf("unable to read AWS cloud provider config file: %v", err)
		}

		if err = cfg.ValidateOverrides(); err != nil {
			return nil, fmt.Errorf("unable to validate custom endpoint overrides: %v", err)
		}

		metadata, err := newAWSSDKProvider(nil, cfg).Metadata(ctx)
		if err != nil {
			return nil, fmt.Errorf("error creating AWS metadata client: %q", err)
		}

		regionName, err := getRegionFromMetadata(ctx, *cfg, metadata)
		if err != nil {
			return nil, err
		}

		var creds *stscreds.AssumeRoleProvider
		if cfg.Global.RoleARN != "" {
			stsClient, err := services.NewStsClient(ctx, regionName, cfg.Global.RoleARN, cfg.Global.SourceARN)
			if err != nil {
				return nil, fmt.Errorf("unable to create sts v2 client: %v", err)
			}
			creds = stscreds.NewAssumeRoleProvider(stsClient, cfg.Global.RoleARN)
		}

		aws := newAWSSDKProvider(creds, cfg)
		return newAWSCloud2(*cfg, aws, aws, creds)
	})
}

// readAWSCloudConfig reads an instance of AWSCloudConfig from config reader.
func readAWSCloudConfig(cloudConfig io.Reader) (*config.CloudConfig, error) {
	var cfg config.CloudConfig
	var err error

	if cloudConfig != nil {
		err = gcfg.FatalOnly(gcfg.ReadInto(&cfg, cloudConfig))
		if err != nil {
			return nil, err
		}
	}

	return &cfg, nil
}

// Derives the region from a valid az name.
// Returns an error if the az is known invalid (empty)
func azToRegion(az string) (string, error) {
	if len(az) < 1 {
		return "", fmt.Errorf("invalid (empty) AZ")
	}

	r := regexp.MustCompile(`^([a-zA-Z]+-)+\d+`)
	region := r.FindString(az)
	if region == "" {
		return "", fmt.Errorf("invalid AZ: %s", az)
	}

	return region, nil
}

func newAWSCloud(cfg config.CloudConfig, awsServices Services) (*Cloud, error) {
	return newAWSCloud2(cfg, awsServices, nil, nil)
}

// newAWSCloud creates a new instance of AWSCloud.
// AWSProvider and instanceId are primarily for tests
func newAWSCloud2(cfg config.CloudConfig, awsServices Services, provider config.SDKProvider, credentials *stscreds.AssumeRoleProvider) (*Cloud, error) {
	ctx := context.Background()
	// We have some state in the Cloud object
	// Log so that if we are building multiple Cloud objects, it is obvious!
	klog.Infof("Building AWS cloudprovider")

	metadata, err := awsServices.Metadata(ctx)
	if err != nil {
		return nil, fmt.Errorf("error creating AWS metadata client: %q", err)
	}

	regionName, err := getRegionFromMetadata(ctx, cfg, metadata)
	if err != nil {
		return nil, err
	}

	ec2, err := awsServices.Compute(ctx, regionName, credentials)
	if err != nil {
		return nil, fmt.Errorf("error creating AWS EC2 client: %v", err)
	}

	elb, err := awsServices.LoadBalancing(ctx, regionName, credentials)
	if err != nil {
		return nil, fmt.Errorf("error creating AWS ELB client: %v", err)
	}

	elbv2, err := awsServices.LoadBalancingV2(ctx, regionName, credentials)
	if err != nil {
		return nil, fmt.Errorf("error creating AWS ELBV2 client: %v", err)
	}

	kms, err := awsServices.KeyManagement(ctx, regionName, credentials)
	if err != nil {
		return nil, fmt.Errorf("error creating AWS key management client: %v", err)
	}

	awsCloud := &Cloud{
		ec2:                     ec2,
		elb:                     elb,
		elbv2:                   elbv2,
		metadata:                metadata,
		kms:                     kms,
		cfg:                     &cfg,
		region:                  regionName,
		createTagsBatcher:       newCreateTagsBatcher(ctx, ec2),
		deleteTagsBatcher:       newDeleteTagsBatcher(ctx, ec2),
		describeInstanceBatcher: newdescribeInstanceBatcher(ctx, ec2),
	}
	awsCloud.instanceCache.cloud = awsCloud
	awsCloud.zoneCache.cloud = awsCloud
	awsCloud.instanceTopologyManager = NewInstanceTopologyManager(ec2, &cfg)

	tagged := cfg.Global.KubernetesClusterTag != "" || cfg.Global.KubernetesClusterID != ""
	if cfg.Global.VPC != "" && (cfg.Global.SubnetID != "" || cfg.Global.RoleARN != "") && tagged {
		// When the master is running on a different AWS account, cloud provider or on-premise
		// build up a dummy instance and use the VPC from the nodes account
		klog.Info("Master is configured to run on a different AWS account, different cloud provider or on-premises")
		awsCloud.selfAWSInstance = &awsInstance{
			nodeName: "master-dummy",
			vpcID:    cfg.Global.VPC,
			subnetID: cfg.Global.SubnetID,
		}
		awsCloud.vpcID = cfg.Global.VPC
	} else {
		selfAWSInstance, err := awsCloud.buildSelfAWSInstance(ctx)
		if err != nil {
			return nil, err
		}
		awsCloud.selfAWSInstance = selfAWSInstance
		awsCloud.vpcID = selfAWSInstance.vpcID
	}

	if cfg.Global.KubernetesClusterTag != "" || cfg.Global.KubernetesClusterID != "" {
		if err := awsCloud.tagging.init(cfg.Global.KubernetesClusterTag, cfg.Global.KubernetesClusterID); err != nil {
			return nil, err
		}
	} else {
		// TODO: Clean up double-API query
		info, err := awsCloud.selfAWSInstance.describeInstance(ctx)
		if err != nil {
			return nil, err
		}
		if err := awsCloud.tagging.initFromTags(info.Tags); err != nil {
			return nil, err
		}
	}

	if len(cfg.Global.NodeIPFamilies) == 0 {
		cfg.Global.NodeIPFamilies = []string{"ipv4"}
	}
	klog.Infof("The following IP families will be added to nodes: %v", cfg.Global.NodeIPFamilies)

	variants := variant.GetVariants()
	for _, v := range variants {
		if err := v.Initialize(&cfg, credentials, provider, awsCloud.ec2, awsCloud.region); err != nil {
			return nil, err
		}
	}
	return awsCloud, nil
}

// NewAWSCloud calls and return new aws cloud from newAWSCloud with the supplied configuration
func NewAWSCloud(cfg config.CloudConfig, awsServices Services) (*Cloud, error) {
	return newAWSCloud(cfg, awsServices)
}

// Initialize passes a Kubernetes clientBuilder interface to the cloud provider
func (c *Cloud) Initialize(clientBuilder cloudprovider.ControllerClientBuilder, stop <-chan struct{}) {
	c.clientBuilder = clientBuilder
	c.kubeClient = clientBuilder.ClientOrDie("aws-cloud-provider")
	c.eventBroadcaster = record.NewBroadcaster()
	c.eventBroadcaster.StartStructuredLogging(0)
	c.eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: c.kubeClient.CoreV1().Events("")})
	c.eventRecorder = c.eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "aws-cloud-provider"})

	v, err := c.kubeClient.Discovery().ServerVersion()
	if err != nil {
		klog.Errorf("Error looking up cluster version: %q", err)
	} else {
		klog.Infof("cluster version: v%s.%s. git version: %s. git tree state: %s. commit: %s. platform: %s",
			v.Major, v.Minor, v.GitVersion, v.GitTreeState, v.GitCommit, v.Platform)
	}
}

// Clusters returns the list of clusters.
func (c *Cloud) Clusters() (cloudprovider.Clusters, bool) {
	return nil, false
}

// ProviderName returns the cloud provider ID.
func (c *Cloud) ProviderName() string {
	return ProviderName
}

// LoadBalancer returns an implementation of LoadBalancer for Amazon Web Services.
func (c *Cloud) LoadBalancer() (cloudprovider.LoadBalancer, bool) {
	return c, true
}

// Instances returns an implementation of Instances for Amazon Web Services.
func (c *Cloud) Instances() (cloudprovider.Instances, bool) {
	return c, true
}

// InstancesV2 returns an implementation of InstancesV2 for Amazon Web Services.
func (c *Cloud) InstancesV2() (cloudprovider.InstancesV2, bool) {
	return c, true
}

// Zones returns an implementation of Zones for Amazon Web Services.
func (c *Cloud) Zones() (cloudprovider.Zones, bool) {
	return c, true
}

// Routes returns an implementation of Routes for Amazon Web Services.
func (c *Cloud) Routes() (cloudprovider.Routes, bool) {
	return c, true
}

// HasClusterID returns true if the cluster has a clusterID
func (c *Cloud) HasClusterID() bool {
	return len(c.tagging.clusterID()) > 0
}

// NodeAddresses is an implementation of Instances.NodeAddresses.
func (c *Cloud) NodeAddresses(ctx context.Context, name types.NodeName) ([]v1.NodeAddress, error) {
	instanceID, err := c.nodeNameToInstanceID(name)
	if err != nil {
		return nil, fmt.Errorf("could not look up instance ID for node %q: %v", name, err)
	}
	return c.NodeAddressesByProviderID(ctx, string(instanceID))
}

// extractIPv4NodeAddresses maps the instance information from EC2 to an array of NodeAddresses.
// This function will extract private and public IP addresses and their corresponding DNS names.
func extractIPv4NodeAddresses(instance *ec2types.Instance) ([]v1.NodeAddress, error) {
	// Not clear if the order matters here, but we might as well indicate a sensible preference order

	if instance == nil {
		return nil, fmt.Errorf("nil instance passed to extractNodeAddresses")
	}

	addresses := []v1.NodeAddress{}

	// sort by device index so that the first address added to the addresses list is from the first (primary) device
	sort.Slice(instance.NetworkInterfaces, func(i, j int) bool {
		// These nil checks should cause interfaces with non-nil attachments to sort before those with nil attachments
		if instance.NetworkInterfaces[i].Attachment == nil {
			return false
		}
		if instance.NetworkInterfaces[j].Attachment == nil {
			return true
		}

		return aws.ToInt32(instance.NetworkInterfaces[i].Attachment.DeviceIndex) < aws.ToInt32(instance.NetworkInterfaces[j].Attachment.DeviceIndex)
	})

	// handle internal network interfaces
	for _, networkInterface := range instance.NetworkInterfaces {
		// skip network interfaces that are not currently in use
		if networkInterface.Status != ec2types.NetworkInterfaceStatusInUse {
			continue
		}

		for _, internalIP := range networkInterface.PrivateIpAddresses {
			if ipAddress := aws.ToString(internalIP.PrivateIpAddress); ipAddress != "" {
				ip := netutils.ParseIPSloppy(ipAddress)
				if ip == nil {
					return nil, fmt.Errorf("EC2 instance had invalid private address: %s (%q)", aws.ToString(instance.InstanceId), ipAddress)
				}
				addresses = append(addresses, v1.NodeAddress{Type: v1.NodeInternalIP, Address: ip.String()})
			}
		}
	}

	// TODO: Other IP addresses (multiple ips)?
	publicIPAddress := aws.ToString(instance.PublicIpAddress)
	if publicIPAddress != "" {
		ip := netutils.ParseIPSloppy(publicIPAddress)
		if ip == nil {
			return nil, fmt.Errorf("EC2 instance had invalid public address: %s (%s)", aws.ToString(instance.InstanceId), publicIPAddress)
		}
		addresses = append(addresses, v1.NodeAddress{Type: v1.NodeExternalIP, Address: ip.String()})
	}

	privateDNSName := aws.ToString(instance.PrivateDnsName)
	if privateDNSName != "" {
		addresses = append(addresses, v1.NodeAddress{Type: v1.NodeInternalDNS, Address: privateDNSName})
		addresses = append(addresses, v1.NodeAddress{Type: v1.NodeHostName, Address: privateDNSName})
	}

	publicDNSName := aws.ToString(instance.PublicDnsName)
	if publicDNSName != "" {
		addresses = append(addresses, v1.NodeAddress{Type: v1.NodeExternalDNS, Address: publicDNSName})
	}

	return addresses, nil
}

// extractIPv6NodeAddresses maps the instance information from EC2 to an array of NodeAddresses
// All IPv6 addresses are considered internal even if they are publicly routable. There are no instance DNS names associated with IPv6.
func extractIPv6NodeAddresses(instance *ec2types.Instance) ([]v1.NodeAddress, error) {
	// Not clear if the order matters here, but we might as well indicate a sensible preference order

	if instance == nil {
		return nil, fmt.Errorf("nil instance passed to extractNodeAddresses")
	}

	addresses := []v1.NodeAddress{}

	// handle internal network interfaces with IPv6 addresses
	for _, networkInterface := range instance.NetworkInterfaces {
		// skip network interfaces that are not currently in use
		if networkInterface.Status != ec2types.NetworkInterfaceStatusInUse || len(networkInterface.Ipv6Addresses) == 0 {
			continue
		}

		// return only the "first" address for each ENI
		internalIPv6 := aws.ToString(networkInterface.Ipv6Addresses[0].Ipv6Address)
		ip := net.ParseIP(internalIPv6)
		if ip == nil {
			return nil, fmt.Errorf("EC2 instance had invalid IPv6 address: %s (%q)", aws.ToString(instance.InstanceId), internalIPv6)
		}
		addresses = append(addresses, v1.NodeAddress{Type: v1.NodeInternalIP, Address: ip.String()})
	}

	return addresses, nil
}

// NodeAddressesByProviderID returns the node addresses of an instances with the specified unique providerID
// This method will not be called from the node that is requesting this ID. i.e. metadata service
// and other local methods cannot be used here
func (c *Cloud) NodeAddressesByProviderID(ctx context.Context, providerID string) ([]v1.NodeAddress, error) {
	instanceID, err := KubernetesInstanceID(providerID).MapToAWSInstanceID()
	if err != nil {
		return nil, err
	}

	if v := variant.GetVariant(string(instanceID)); v != nil {
		return v.NodeAddresses(ctx, string(instanceID), c.vpcID)
	}

	instance, err := describeInstance(ctx, c.ec2, instanceID)
	if err != nil {
		return nil, err
	}

	return c.getInstanceNodeAddress(instance)
}

func (c *Cloud) getInstanceNodeAddress(instance *ec2types.Instance) ([]v1.NodeAddress, error) {
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

// InstanceExistsByProviderID returns true if the instance with the given provider id still exists.
// If false is returned with no error, the instance will be immediately deleted by the cloud controller manager.
func (c *Cloud) InstanceExistsByProviderID(ctx context.Context, providerID string) (bool, error) {
	instanceID, err := KubernetesInstanceID(providerID).MapToAWSInstanceID()
	if err != nil {
		return false, err
	}

	if v := variant.GetVariant(string(instanceID)); v != nil {
		return v.InstanceExists(ctx, string(instanceID), c.vpcID)
	}

	request := &ec2.DescribeInstancesInput{
		InstanceIds: []string{string(instanceID)},
	}

	instances, err := c.describeInstanceBatcher.DescribeInstances(ctx, request)
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
	if state == ec2types.InstanceStateNameTerminated {
		klog.Warningf("the instance %s is terminated", instanceID)
		return false, nil
	}

	return true, nil
}

// InstanceShutdownByProviderID returns true if the instance is terminated
func (c *Cloud) InstanceShutdownByProviderID(ctx context.Context, providerID string) (bool, error) {
	instanceID, err := KubernetesInstanceID(providerID).MapToAWSInstanceID()
	if err != nil {
		return false, err
	}

	if v := variant.GetVariant(string(instanceID)); v != nil {
		return v.InstanceShutdown(ctx, string(instanceID), c.vpcID)
	}

	request := &ec2.DescribeInstancesInput{
		InstanceIds: []string{string(instanceID)},
	}

	instances, err := c.describeInstanceBatcher.DescribeInstances(ctx, request)
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
		state := instance.State.Name
		if state == ec2types.InstanceStateNameStopped {
			return true, nil
		}
	}
	return false, nil
}

// InstanceID returns the cloud provider ID of the node with the specified nodeName.
func (c *Cloud) InstanceID(ctx context.Context, nodeName types.NodeName) (string, error) {
	// In the future it is possible to also return an endpoint as:
	// <endpoint>/<zone>/<instanceid>
	if c.selfAWSInstance.nodeName == nodeName {
		return "/" + c.selfAWSInstance.availabilityZone + "/" + c.selfAWSInstance.awsID, nil
	}
	inst, err := c.getInstanceByNodeName(ctx, nodeName)
	if err != nil {
		if err == cloudprovider.InstanceNotFound {
			// The Instances interface requires that we return InstanceNotFound (without wrapping)
			return "", err
		}
		return "", fmt.Errorf("getInstanceByNodeName failed for %q with %q", nodeName, err)
	}
	return "/" + aws.ToString(inst.Placement.AvailabilityZone) + "/" + aws.ToString(inst.InstanceId), nil
}

// InstanceTypeByProviderID returns the cloudprovider instance type of the node with the specified unique providerID
// This method will not be called from the node that is requesting this ID. i.e. metadata service
// and other local methods cannot be used here
func (c *Cloud) InstanceTypeByProviderID(ctx context.Context, providerID string) (string, error) {
	instanceID, err := KubernetesInstanceID(providerID).MapToAWSInstanceID()
	if err != nil {
		return "", err
	}

	if v := variant.GetVariant(string(instanceID)); v != nil {
		return v.InstanceTypeByProviderID(string(instanceID))
	}

	instance, err := describeInstance(ctx, c.ec2, instanceID)
	if err != nil {
		return "", err
	}
	return c.getInstanceType(instance), nil
}

func (c *Cloud) getInstanceType(instance *ec2types.Instance) string {
	return string(instance.InstanceType)
}

// InstanceType returns the type of the node with the specified nodeName.
func (c *Cloud) InstanceType(ctx context.Context, nodeName types.NodeName) (string, error) {
	if c.selfAWSInstance.nodeName == nodeName {
		return c.selfAWSInstance.instanceType, nil
	}
	inst, err := c.getInstanceByNodeName(ctx, nodeName)
	if err != nil {
		return "", fmt.Errorf("getInstanceByNodeName failed for %q with %q", nodeName, err)
	}
	return string(inst.InstanceType), nil
}

// GetZone implements Zones.GetZone
func (c *Cloud) GetZone(ctx context.Context) (cloudprovider.Zone, error) {
	return cloudprovider.Zone{
		FailureDomain: c.selfAWSInstance.availabilityZone,
		Region:        c.region,
	}, nil
}

// GetZoneByProviderID implements Zones.GetZoneByProviderID
// This is particularly useful in external cloud providers where the kubelet
// does not initialize node data.
func (c *Cloud) GetZoneByProviderID(ctx context.Context, providerID string) (cloudprovider.Zone, error) {
	instanceID, err := KubernetesInstanceID(providerID).MapToAWSInstanceID()
	if err != nil {
		return cloudprovider.Zone{}, err
	}

	if v := variant.GetVariant(string(instanceID)); v != nil {
		return v.GetZone(ctx, string(instanceID), c.vpcID, c.region)
	}

	instance, err := c.getInstanceByID(ctx, string(instanceID))
	if err != nil {
		return cloudprovider.Zone{}, err
	}
	return c.getInstanceZone(instance), nil
}

func (c *Cloud) getInstanceZone(instance *ec2types.Instance) cloudprovider.Zone {
	return cloudprovider.Zone{
		FailureDomain: *(instance.Placement.AvailabilityZone),
		Region:        c.region,
	}
}

// GetZoneByNodeName implements Zones.GetZoneByNodeName
// This is particularly useful in external cloud providers where the kubelet
// does not initialize node data.
func (c *Cloud) GetZoneByNodeName(ctx context.Context, nodeName types.NodeName) (cloudprovider.Zone, error) {
	instance, err := c.getInstanceByNodeName(ctx, nodeName)
	if err != nil {
		return cloudprovider.Zone{}, err
	}
	zone := cloudprovider.Zone{
		FailureDomain: *(instance.Placement.AvailabilityZone),
		Region:        c.region,
	}

	return zone, nil

}

// IsAWSErrorInstanceNotFound returns true if the specified error is an awserr.Error with the code `InvalidInstanceId.NotFound`.
func IsAWSErrorInstanceNotFound(err error) bool {
	if err == nil {
		return false
	}

	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode() == string(ec2types.UnsuccessfulInstanceCreditSpecificationErrorCodeInstanceNotFound)
	} else if strings.Contains(err.Error(), string(ec2types.UnsuccessfulInstanceCreditSpecificationErrorCodeInstanceNotFound)) {
		// In places like https://github.com/kubernetes/cloud-provider-aws/blob/1c6194aad0122ab44504de64187e3d1a7415b198/pkg/providers/v1/aws.go#L1007,
		// the error has been transformed into something else so check the error string to see if it contains the error code we're looking for.
		return true
	}

	return false
}

// Builds the awsInstance for the EC2 instance on which we are running.
// This is called when the AWSCloud is initialized, and should not be called otherwise (because the awsInstance for the local instance is a singleton with drive mapping state)
func (c *Cloud) buildSelfAWSInstance(ctx context.Context) (*awsInstance, error) {
	if c.selfAWSInstance != nil {
		panic("do not call buildSelfAWSInstance directly")
	}
	instanceIDMetadata, err := c.metadata.GetMetadata(ctx, &imds.GetMetadataInput{Path: "instance-id"})
	if err != nil {
		return nil, fmt.Errorf("error fetching instance-id from ec2 metadata service: %q", err)
	}

	// We want to fetch the hostname via the EC2 metadata service
	// (`GetMetadata("local-hostname")`): But see #11543 - we need to use
	// the EC2 API to get the privateDnsName in case of a private DNS zone
	// e.g. mydomain.io, because the metadata service returns the wrong
	// hostname.  Once we're doing that, we might as well get all our
	// information from the instance returned by the EC2 API - it is a
	// single API call to get all the information, and it means we don't
	// have two code paths.
	instanceIDBytes, err := io.ReadAll(instanceIDMetadata.Content)
	if err != nil {
		return nil, fmt.Errorf("unable to parse instance id: %q", err)
	}
	defer instanceIDMetadata.Content.Close()

	instance, err := c.getInstanceByID(ctx, string(instanceIDBytes))
	if err != nil {
		return nil, fmt.Errorf("error finding instance %s: %q", string(instanceIDBytes), err)
	}
	return newAWSInstance(c.ec2, instance), nil
}

// Gets the current load balancer state
func (c *Cloud) describeLoadBalancer(ctx context.Context, name string) (*elbtypes.LoadBalancerDescription, error) {
	request := &elb.DescribeLoadBalancersInput{}
	request.LoadBalancerNames = []string{name}

	response, err := c.elb.DescribeLoadBalancers(ctx, request)

	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) {
			if ae.ErrorCode() == "LoadBalancerNotFound" {
				return nil, nil
			}
		}

		return nil, err
	}

	var ret *elbtypes.LoadBalancerDescription
	for _, loadBalancer := range response.LoadBalancerDescriptions {
		if ret != nil {
			klog.Errorf("Found multiple load balancers with name: %s", name)
		}
		ret = &loadBalancer
	}
	return ret, nil
}

func (c *Cloud) addLoadBalancerTags(ctx context.Context, loadBalancerName string, requested map[string]string) error {
	var tags []elbtypes.Tag
	for k, v := range requested {
		tag := elbtypes.Tag{
			Key:   aws.String(k),
			Value: aws.String(v),
		}
		tags = append(tags, tag)
	}

	request := &elb.AddTagsInput{}
	request.LoadBalancerNames = []string{loadBalancerName}
	request.Tags = tags

	_, err := c.elb.AddTags(ctx, request)
	if err != nil {
		return fmt.Errorf("error adding tags to load balancer: %v", err)
	}
	return nil
}

// Gets the current load balancer state
func (c *Cloud) describeLoadBalancerv2(ctx context.Context, name string) (*elbv2types.LoadBalancer, error) {
	request := &elbv2.DescribeLoadBalancersInput{
		Names: []string{name},
	}

	response, err := c.elbv2.DescribeLoadBalancers(ctx, request)
	if err != nil {
		var notFoundErr *elbv2types.LoadBalancerNotFoundException
		if errors.As(err, &notFoundErr) {
			return nil, nil
		}
		return nil, fmt.Errorf("error describing load balancer: %q", err)
	}

	// AWS will not return 2 load balancers with the same name _and_ type.
	for i := range response.LoadBalancers {
		if response.LoadBalancers[i].Type == elbv2types.LoadBalancerTypeEnumNetwork {
			return &response.LoadBalancers[i], nil
		}
	}

	return nil, fmt.Errorf("NLB '%s' could not be found", name)
}

// Retrieves instance's vpc id from metadata
func (c *Cloud) findVPCID(ctx context.Context) (string, error) {
	macsMetadata, err := c.metadata.GetMetadata(ctx, &imds.GetMetadataInput{Path: "network/interfaces/macs/"})
	if err != nil {
		return "", fmt.Errorf("could not list interfaces of the instance: %q", err)
	}
	macsBytes, err := io.ReadAll(macsMetadata.Content)
	if err != nil {
		return "", fmt.Errorf("unable to parse macs: %q", err)
	}
	defer macsMetadata.Content.Close()
	macs := string(macsBytes)

	// loop over interfaces, first vpc id returned wins
	for _, macPath := range strings.Split(macs, "\n") {
		if len(macPath) == 0 {
			continue
		}
		url := fmt.Sprintf("network/interfaces/macs/%svpc-id", macPath)
		vpcIDMetadata, err := c.metadata.GetMetadata(ctx, &imds.GetMetadataInput{Path: url})
		if err != nil {
			continue
		}
		vpcIDBytes, err := io.ReadAll(vpcIDMetadata.Content)
		if err != nil {
			continue
		}
		defer vpcIDMetadata.Content.Close()
		return string(vpcIDBytes), nil
	}
	return "", fmt.Errorf("could not find VPC ID in instance metadata")
}

// Retrieves the specified security group from the AWS API, or returns nil if not found
func (c *Cloud) findSecurityGroup(ctx context.Context, securityGroupID string) (*ec2types.SecurityGroup, error) {
	describeSecurityGroupsRequest := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{securityGroupID},
	}
	// We don't apply our tag filters because we are retrieving by ID

	groups, err := c.ec2.DescribeSecurityGroups(ctx, describeSecurityGroupsRequest)
	if err != nil {
		klog.Warningf("Error retrieving security group: %q", err)
		return nil, err
	}

	if len(groups) == 0 {
		return nil, nil
	}
	if len(groups) != 1 {
		// This should not be possible - ids should be unique
		return nil, fmt.Errorf("multiple security groups found with same id %q", securityGroupID)
	}
	group := groups[0]
	return &group, nil
}

func isEqualIntPointer(l, r *int32) bool {
	if l == nil {
		return r == nil
	}
	if r == nil {
		return l == nil
	}
	return *l == *r
}

func isEqualStringPointer(l, r *string) bool {
	if l == nil {
		return r == nil
	}
	if r == nil {
		return l == nil
	}
	return *l == *r
}

func ipPermissionExists(newPermission, existing *ec2types.IpPermission, compareGroupUserIDs bool) bool {
	if !isEqualIntPointer(newPermission.FromPort, existing.FromPort) {
		return false
	}
	if !isEqualIntPointer(newPermission.ToPort, existing.ToPort) {
		return false
	}
	if !isEqualStringPointer(newPermission.IpProtocol, existing.IpProtocol) {
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
			if isEqualUserGroupPair(&leftPair, &rightPair, compareGroupUserIDs) {
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

func isEqualUserGroupPair(l, r *ec2types.UserIdGroupPair, compareGroupUserIDs bool) bool {
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

// Makes sure the security group ingress is exactly the specified permissions
// Returns true if and only if changes were made
// The security group must already exist
func (c *Cloud) setSecurityGroupIngress(ctx context.Context, securityGroupID string, permissions IPPermissionSet) (bool, error) {
	group, err := c.findSecurityGroup(ctx, securityGroupID)
	if err != nil {
		klog.Warningf("Error retrieving security group %q", err)
		return false, err
	}

	if group == nil {
		return false, fmt.Errorf("security group not found: %s", securityGroupID)
	}

	klog.V(2).Infof("Existing security group ingress: %s %v", securityGroupID, group.IpPermissions)

	actual := NewIPPermissionSet(group.IpPermissions...)

	// EC2 groups rules together, for example combining:
	//
	// { Port=80, Range=[A] } and { Port=80, Range=[B] }
	//
	// into { Port=80, Range=[A,B] }
	//
	// We have to ungroup them, because otherwise the logic becomes really
	// complicated, and also because if we have Range=[A,B] and we try to
	// add Range=[A] then EC2 complains about a duplicate rule.
	permissions = permissions.Ungroup()
	actual = actual.Ungroup()

	remove := actual.Difference(permissions)
	add := permissions.Difference(actual)

	if add.Len() == 0 && remove.Len() == 0 {
		return false, nil
	}

	// TODO: There is a limit in VPC of 100 rules per security group, so we
	// probably should try grouping or combining to fit under this limit.
	// But this is only used on the ELB security group currently, so it
	// would require (ports * CIDRS) > 100.  Also, it isn't obvious exactly
	// how removing single permissions from compound rules works, and we
	// don't want to accidentally open more than intended while we're
	// applying changes.
	if add.Len() != 0 {
		klog.V(2).Infof("Adding security group ingress: %s %v", securityGroupID, add.List())

		request := &ec2.AuthorizeSecurityGroupIngressInput{}
		request.GroupId = &securityGroupID
		request.IpPermissions = add.List()
		_, err = c.ec2.AuthorizeSecurityGroupIngress(ctx, request)
		if err != nil {
			return false, fmt.Errorf("error authorizing security group ingress: %q", err)
		}
	}
	if remove.Len() != 0 {
		klog.V(2).Infof("Remove security group ingress: %s %v", securityGroupID, remove.List())

		request := &ec2.RevokeSecurityGroupIngressInput{}
		request.GroupId = &securityGroupID
		request.IpPermissions = remove.List()
		_, err = c.ec2.RevokeSecurityGroupIngress(ctx, request)
		if err != nil {
			return false, fmt.Errorf("error revoking security group ingress: %q", err)
		}
	}

	return true, nil
}

// Makes sure the security group includes the specified permissions
// Returns true if and only if changes were made
// The security group must already exist
func (c *Cloud) addSecurityGroupIngress(ctx context.Context, securityGroupID string, addPermissions []ec2types.IpPermission) (bool, error) {
	// We do not want to make changes to the Global defined SG
	if securityGroupID == c.cfg.Global.ElbSecurityGroup {
		return false, nil
	}

	group, err := c.findSecurityGroup(ctx, securityGroupID)
	if err != nil {
		klog.Warningf("Error retrieving security group: %q", err)
		return false, err
	}

	if group == nil {
		return false, fmt.Errorf("security group not found: %s", securityGroupID)
	}

	klog.V(2).Infof("Existing security group ingress: %s %v", securityGroupID, group.IpPermissions)

	changes := []ec2types.IpPermission{}
	for _, addPermission := range addPermissions {
		hasUserID := false
		for i := range addPermission.UserIdGroupPairs {
			if addPermission.UserIdGroupPairs[i].UserId != nil {
				hasUserID = true
			}
		}

		found := false
		for _, groupPermission := range group.IpPermissions {
			if ipPermissionExists(&addPermission, &groupPermission, hasUserID) {
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

	request := &ec2.AuthorizeSecurityGroupIngressInput{}
	request.GroupId = &securityGroupID
	request.IpPermissions = changes
	_, err = c.ec2.AuthorizeSecurityGroupIngress(ctx, request)
	if err != nil {
		klog.Warningf("Error authorizing security group ingress %q", err)
		return false, fmt.Errorf("error authorizing security group ingress: %q", err)
	}

	return true, nil
}

// Makes sure the security group no longer includes the specified permissions
// Returns true if and only if changes were made
// If the security group no longer exists, will return (false, nil)
func (c *Cloud) removeSecurityGroupIngress(ctx context.Context, securityGroupID string, removePermissions []ec2types.IpPermission) (bool, error) {
	// We do not want to make changes to the Global defined SG
	if securityGroupID == c.cfg.Global.ElbSecurityGroup {
		return false, nil
	}

	group, err := c.findSecurityGroup(ctx, securityGroupID)
	if err != nil {
		klog.Warningf("Error retrieving security group: %q", err)
		return false, err
	}

	if group == nil {
		klog.Warning("Security group not found: ", securityGroupID)
		return false, nil
	}

	changes := []ec2types.IpPermission{}
	for _, removePermission := range removePermissions {
		hasUserID := false
		for i := range removePermission.UserIdGroupPairs {
			if removePermission.UserIdGroupPairs[i].UserId != nil {
				hasUserID = true
			}
		}

		var found *ec2types.IpPermission
		for _, groupPermission := range group.IpPermissions {
			if ipPermissionExists(&removePermission, &groupPermission, hasUserID) {
				found = &removePermission
				break
			}
		}

		if found != nil {
			changes = append(changes, *found)
		}
	}

	if len(changes) == 0 {
		return false, nil
	}

	klog.V(2).Infof("Removing security group ingress: %s %v", securityGroupID, changes)

	request := &ec2.RevokeSecurityGroupIngressInput{}
	request.GroupId = &securityGroupID
	request.IpPermissions = changes
	_, err = c.ec2.RevokeSecurityGroupIngress(ctx, request)
	if err != nil {
		klog.Warningf("Error revoking security group ingress: %q", err)
		return false, err
	}

	return true, nil
}

// Makes sure the security group exists.
// For multi-cluster isolation, name must be globally unique, for example derived from the service UUID.
// Additional tags can be specified
// Returns the security group id or error
func (c *Cloud) ensureSecurityGroup(ctx context.Context, name string, description string, additionalTags map[string]string) (string, error) {
	groupID := ""
	attempt := 0
	for {
		attempt++

		// Note that we do _not_ add our tag filters; group-name + vpc-id is the EC2 primary key.
		// However, we do check that it matches our tags.
		// If it doesn't have any tags, we tag it; this is how we recover if we failed to tag before.
		// If it has a different cluster's tags, that is an error.
		// This shouldn't happen because name is expected to be globally unique (UUID derived)
		request := &ec2.DescribeSecurityGroupsInput{}
		request.Filters = []ec2types.Filter{
			newEc2Filter("group-name", name),
			newEc2Filter("vpc-id", c.vpcID),
		}

		securityGroups, err := c.ec2.DescribeSecurityGroups(ctx, request)
		if err != nil {
			return "", err
		}

		if len(securityGroups) >= 1 {
			if len(securityGroups) > 1 {
				klog.Warningf("Found multiple security groups with name: %q", name)
			}
			err := c.tagging.readRepairClusterTags(ctx,
				c.ec2, aws.ToString(securityGroups[0].GroupId),
				ResourceLifecycleOwned, nil, securityGroups[0].Tags)
			if err != nil {
				return "", err
			}

			return aws.ToString(securityGroups[0].GroupId), nil
		}

		createRequest := &ec2.CreateSecurityGroupInput{}
		createRequest.VpcId = &c.vpcID
		createRequest.GroupName = &name
		createRequest.Description = &description
		tags := c.tagging.buildTags(ResourceLifecycleOwned, additionalTags)
		var awsTags []ec2types.Tag
		for k, v := range tags {
			tag := ec2types.Tag{
				Key:   aws.String(k),
				Value: aws.String(v),
			}
			awsTags = append(awsTags, tag)
		}
		createRequest.TagSpecifications = []ec2types.TagSpecification{
			{
				ResourceType: ec2types.ResourceTypeSecurityGroup,
				Tags:         awsTags,
			},
		}

		createResponse, err := c.ec2.CreateSecurityGroup(ctx, createRequest)
		if err != nil {
			ignore := false
			var ae smithy.APIError
			if errors.As(err, &ae) {
				if ae.ErrorCode() == "InvalidGroup.Duplicate" && attempt < MaxReadThenCreateRetries {
					klog.V(2).Infof("Got InvalidGroup.Duplicate while creating security group (race?); will retry")
					ignore = true
				}
			}
			if !ignore {
				klog.Errorf("Error creating security group: %q", err)
				return "", err
			}
			time.Sleep(1 * time.Second)
		} else {
			groupID = aws.ToString(createResponse.GroupId)
			break
		}
	}
	if groupID == "" {
		return "", fmt.Errorf("created security group, but id was not returned: %s", name)
	}

	return groupID, nil
}

// Finds the value for a given tag.
func findTag(tags []ec2types.Tag, key string) (string, bool) {
	for _, tag := range tags {
		if aws.ToString(tag.Key) == key {
			return aws.ToString(tag.Value), true
		}
	}
	return "", false
}

// Finds the subnets associated with the cluster, by matching cluster tags if present.
// For maximal backwards compatibility, if no subnets are tagged, it will fall-back to the current subnet.
// However, in future this will likely be treated as an error.
func (c *Cloud) findSubnets(ctx context.Context) ([]ec2types.Subnet, error) {
	request := &ec2.DescribeSubnetsInput{}
	request.Filters = []ec2types.Filter{newEc2Filter("vpc-id", c.vpcID)}

	subnets, err := c.ec2.DescribeSubnets(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("error describing subnets: %q", err)
	}

	var matches []ec2types.Subnet
	for _, subnet := range subnets {
		if c.tagging.hasClusterTag(subnet.Tags) {
			matches = append(matches, subnet)
		} else if c.tagging.hasNoClusterPrefixTag(subnet.Tags) {
			matches = append(matches, subnet)
		}
	}

	if len(matches) != 0 {
		return matches, nil
	}

	// Fall back to the current instance subnets, if nothing is tagged
	klog.Warningf("No tagged subnets found; will fall-back to the current subnet only.  This is likely to be an error in a future version of k8s.")

	request = &ec2.DescribeSubnetsInput{}
	request.Filters = []ec2types.Filter{newEc2Filter("subnet-id", c.selfAWSInstance.subnetID)}

	subnets, err = c.ec2.DescribeSubnets(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("error describing subnets: %q", err)
	}

	return subnets, nil
}

// Finds the subnets to use for an ELB we are creating.
// Normal (Internet-facing) ELBs must use public subnets, so we skip private subnets.
// Internal ELBs can use public or private subnets, but if we have a private subnet we should prefer that.
func (c *Cloud) findELBSubnets(ctx context.Context, internalELB bool) ([]string, error) {
	vpcIDFilter := newEc2Filter("vpc-id", c.vpcID)

	subnets, err := c.findSubnets(ctx)
	if err != nil {
		return nil, err
	}

	rRequest := &ec2.DescribeRouteTablesInput{}
	rRequest.Filters = []ec2types.Filter{vpcIDFilter}
	rt, err := c.ec2.DescribeRouteTables(ctx, rRequest)
	if err != nil {
		return nil, fmt.Errorf("error describe route table: %q", err)
	}

	subnetsByAZ := make(map[string]ec2types.Subnet)
	for _, subnet := range subnets {
		az := aws.ToString(subnet.AvailabilityZone)
		id := aws.ToString(subnet.SubnetId)
		if az == "" || id == "" {
			klog.Warningf("Ignoring subnet with empty az/id: %v", subnet)
			continue
		}

		isPublic, err := isSubnetPublic(rt, id)
		if err != nil {
			return nil, err
		}
		if !internalELB && !isPublic {
			klog.V(2).Infof("Ignoring private subnet for public ELB %q", id)
			continue
		}

		existing, exists := subnetsByAZ[az]
		if !exists {
			subnetsByAZ[az] = subnet
			continue
		}

		// Try to break the tie using the role tag
		var tagName string
		if internalELB {
			tagName = TagNameSubnetInternalELB
		} else {
			tagName = TagNameSubnetPublicELB
		}

		_, existingHasTag := findTag(existing.Tags, tagName)
		_, subnetHasTag := findTag(subnet.Tags, tagName)

		if existingHasTag != subnetHasTag {
			if subnetHasTag {
				subnetsByAZ[az] = subnet
			}
			continue
		}

		// Prefer the one with the cluster Tag
		existingHasClusterTag := c.tagging.hasClusterTag(existing.Tags)
		subnetHasClusterTag := c.tagging.hasClusterTag(subnet.Tags)
		if existingHasClusterTag != subnetHasClusterTag {
			if subnetHasClusterTag {
				subnetsByAZ[az] = subnet
			}
			continue
		}

		// If we have two subnets for the same AZ we arbitrarily choose the one that is first lexicographically.
		if strings.Compare(*existing.SubnetId, *subnet.SubnetId) > 0 {
			klog.Warningf("Found multiple subnets in AZ %q; choosing %q between subnets %q and %q", az, *subnet.SubnetId, *existing.SubnetId, *subnet.SubnetId)
			subnetsByAZ[az] = subnet
			continue
		}

		klog.Warningf("Found multiple subnets in AZ %q; choosing %q between subnets %q and %q", az, *existing.SubnetId, *existing.SubnetId, *subnet.SubnetId)
		continue
	}

	var azNames []string
	for key := range subnetsByAZ {
		azNames = append(azNames, key)
	}

	sort.Strings(azNames)

	zoneNameToDetails, err := c.zoneCache.getZoneDetailsByNames(ctx, azNames)
	if err != nil {
		return nil, fmt.Errorf("error get availability zone types: %q", err)
	}

	var subnetIDs []string
	for _, zone := range azNames {
		azType, found := zoneNameToDetails[zone]
		if found && azType.zoneType != regularAvailabilityZoneType {
			// take subnets only from zones with `availability-zone` type
			// because another zone types (like local, wavelength and outpost zones)
			// does not support NLB/CLB for the moment, only ALB.
			continue
		}
		subnetIDs = append(subnetIDs, aws.ToString(subnetsByAZ[zone].SubnetId))
	}

	return subnetIDs, nil
}

func splitCommaSeparatedString(commaSeparatedString string) []string {
	var result []string
	parts := strings.Split(commaSeparatedString, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if len(part) == 0 {
			continue
		}
		result = append(result, part)
	}
	return result
}

// parses comma separated values from annotation into string slice, returns true if annotation exists
func parseStringSliceAnnotation(annotations map[string]string, annotation string, value *[]string) bool {
	rawValue := ""
	if exists := parseStringAnnotation(annotations, annotation, &rawValue); !exists {
		return false
	}
	*value = splitCommaSeparatedString(rawValue)
	return true
}

func (c *Cloud) getLoadBalancerSubnets(ctx context.Context, service *v1.Service, internalELB bool) ([]string, error) {
	var rawSubnetNameOrIDs []string
	if exists := parseStringSliceAnnotation(service.Annotations, ServiceAnnotationLoadBalancerSubnets, &rawSubnetNameOrIDs); exists {
		return c.resolveSubnetNameOrIDs(ctx, rawSubnetNameOrIDs)
	}
	return c.findELBSubnets(ctx, internalELB)
}

func (c *Cloud) resolveSubnetNameOrIDs(ctx context.Context, subnetNameOrIDs []string) ([]string, error) {
	var subnetIDs []string
	var subnetNames []string
	if len(subnetNameOrIDs) == 0 {
		return []string{}, fmt.Errorf("unable to resolve empty subnet slice")
	}
	for _, nameOrID := range subnetNameOrIDs {
		if strings.HasPrefix(nameOrID, "subnet-") {
			subnetIDs = append(subnetIDs, nameOrID)
		} else {
			subnetNames = append(subnetNames, nameOrID)
		}
	}
	var resolvedSubnets []ec2types.Subnet
	if len(subnetIDs) > 0 {
		req := &ec2.DescribeSubnetsInput{
			SubnetIds: subnetIDs,
		}
		subnets, err := c.ec2.DescribeSubnets(ctx, req)
		if err != nil {
			return []string{}, err
		}
		resolvedSubnets = append(resolvedSubnets, subnets...)
	}
	if len(subnetNames) > 0 {
		req := &ec2.DescribeSubnetsInput{
			Filters: []ec2types.Filter{
				{
					Name:   aws.String("tag:Name"),
					Values: subnetNames,
				},
				{
					Name:   aws.String("vpc-id"),
					Values: []string{c.vpcID},
				},
			},
		}
		subnets, err := c.ec2.DescribeSubnets(ctx, req)
		if err != nil {
			return []string{}, err
		}
		resolvedSubnets = append(resolvedSubnets, subnets...)
	}
	if len(resolvedSubnets) != len(subnetNameOrIDs) {
		return []string{}, fmt.Errorf("expected to find %v, but found %v subnets", len(subnetNameOrIDs), len(resolvedSubnets))
	}
	var subnets []string
	for _, subnet := range resolvedSubnets {
		subnets = append(subnets, aws.ToString(subnet.SubnetId))
	}
	return subnets, nil
}

func isSubnetPublic(rt []ec2types.RouteTable, subnetID string) (bool, error) {
	var subnetTable *ec2types.RouteTable
	for _, table := range rt {
		for _, assoc := range table.Associations {
			if aws.ToString(assoc.SubnetId) == subnetID {
				subnetTable = &table
				break
			}
		}
	}

	if subnetTable == nil {
		// If there is no explicit association, the subnet will be implicitly
		// associated with the VPC's main routing table.
		for _, table := range rt {
			for _, assoc := range table.Associations {
				if aws.ToBool(assoc.Main) == true {
					klog.V(4).Infof("Assuming implicit use of main routing table %s for %s",
						aws.ToString(table.RouteTableId), subnetID)
					subnetTable = &table
					break
				}
			}
		}
	}

	if subnetTable == nil {
		return false, fmt.Errorf("could not locate routing table for subnet %s", subnetID)
	}

	for _, route := range subnetTable.Routes {
		// There is no direct way in the AWS API to determine if a subnet is public or private.
		// A public subnet is one which has an internet gateway route
		// we look for the gatewayId and make sure it has the prefix of igw to differentiate
		// from the default in-subnet route which is called "local"
		// or other virtual gateway (starting with vgv)
		// or vpc peering connections (starting with pcx).
		if strings.HasPrefix(aws.ToString(route.GatewayId), "igw") {
			return true, nil
		}
	}

	return false, nil
}

type portSets struct {
	names   sets.Set[string]
	numbers sets.Set[int32]
}

// getPortSets returns a portSets structure representing port names and numbers
// that the comma-separated string describes. If the input is empty or equal to
// "*", a nil pointer is returned.
func getPortSets(annotation string) (ports *portSets) {
	if annotation != "" && annotation != "*" {
		ports = &portSets{
			sets.New[string](),
			sets.New[int32](),
		}
		portStringSlice := strings.Split(annotation, ",")
		for _, item := range portStringSlice {
			port, err := strconv.Atoi(item)
			if err != nil {
				ports.names.Insert(item)
			} else {
				ports.numbers.Insert(int32(port))
			}
		}
	}
	return
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

// buildELBSecurityGroupList returns list of SecurityGroups which should be
// attached to ELB created by a service. List always consist of at least
// 1 member which is an SG created for this service or a SG from the Global config.
// Extra groups can be specified via annotation, as can extra tags for any
// new groups. The annotation "ServiceAnnotationLoadBalancerSecurityGroups" allows for
// setting the security groups specified.
func (c *Cloud) buildELBSecurityGroupList(ctx context.Context, serviceName types.NamespacedName, loadBalancerName string, annotations map[string]string) ([]string, bool, error) {
	var err error
	var securityGroupID string
	// We do not want to make changes to a Global defined SG
	var setupSg = false

	sgList := getSGListFromAnnotation(annotations[ServiceAnnotationLoadBalancerSecurityGroups])

	// If no Security Groups have been specified with the ServiceAnnotationLoadBalancerSecurityGroups annotation, we add the default one.
	if len(sgList) == 0 {
		if c.cfg.Global.ElbSecurityGroup != "" {
			sgList = append(sgList, c.cfg.Global.ElbSecurityGroup)
		} else {
			// Create a security group for the load balancer
			sgName := "k8s-elb-" + loadBalancerName
			sgDescription := fmt.Sprintf("Security group for Kubernetes ELB %s (%v)", loadBalancerName, serviceName)
			securityGroupID, err = c.ensureSecurityGroup(ctx, sgName, sgDescription, getKeyValuePropertiesFromAnnotation(annotations, ServiceAnnotationLoadBalancerAdditionalTags))
			if err != nil {
				klog.Errorf("Error creating load balancer security group: %q", err)
				return nil, setupSg, err
			}
			sgList = append(sgList, securityGroupID)
			setupSg = true
		}
	}

	extraSGList := getSGListFromAnnotation(annotations[ServiceAnnotationLoadBalancerExtraSecurityGroups])
	sgList = append(sgList, extraSGList...)

	return sgList, setupSg, nil
}

// sortELBSecurityGroupList returns a list of sorted securityGroupIDs based on the original order
// from buildELBSecurityGroupList. The logic is:
//   - securityGroups specified by ServiceAnnotationLoadBalancerSecurityGroups appears first in order
//   - securityGroups specified by ServiceAnnotationLoadBalancerExtraSecurityGroups appears last in order
func (c *Cloud) sortELBSecurityGroupList(securityGroupIDs []string, annotations map[string]string, taggedLBSecurityGroups map[string]struct{}) {
	annotatedSGList := getSGListFromAnnotation(annotations[ServiceAnnotationLoadBalancerSecurityGroups])
	annotatedExtraSGList := getSGListFromAnnotation(annotations[ServiceAnnotationLoadBalancerExtraSecurityGroups])
	annotatedSGIndex := make(map[string]int, len(annotatedSGList))
	annotatedExtraSGIndex := make(map[string]int, len(annotatedExtraSGList))

	if taggedLBSecurityGroups == nil {
		taggedLBSecurityGroups = make(map[string]struct{})
	}

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
		// If i is tagged but j is not, then i should be before j.
		_, iTagged := taggedLBSecurityGroups[securityGroupIDs[i]]
		_, jTagged := taggedLBSecurityGroups[securityGroupIDs[j]]

		return sgOrderMapping[securityGroupIDs[i]] < sgOrderMapping[securityGroupIDs[j]] || iTagged && !jTagged
	})
}

// buildListener creates a new listener from the given port, adding an SSL certificate
// if indicated by the appropriate annotations.
func buildListener(port v1.ServicePort, annotations map[string]string, sslPorts *portSets) (elbtypes.Listener, error) {
	loadBalancerPort := port.Port
	portName := strings.ToLower(port.Name)
	instancePort := port.NodePort
	protocol := strings.ToLower(string(port.Protocol))
	instanceProtocol := protocol

	listener := elbtypes.Listener{}
	listener.InstancePort = &instancePort
	listener.LoadBalancerPort = loadBalancerPort
	certID := annotations[ServiceAnnotationLoadBalancerCertificate]
	if certID != "" && (sslPorts == nil || sslPorts.numbers.Has(loadBalancerPort) || sslPorts.names.Has(portName)) {
		instanceProtocol = annotations[ServiceAnnotationLoadBalancerBEProtocol]
		if instanceProtocol == "" {
			protocol = "ssl"
			instanceProtocol = "tcp"
		} else {
			protocol = backendProtocolMapping[instanceProtocol]
			if protocol == "" {
				return elbtypes.Listener{}, fmt.Errorf("Invalid backend protocol %s for %s in %s", instanceProtocol, certID, ServiceAnnotationLoadBalancerBEProtocol)
			}
		}
		listener.SSLCertificateId = &certID
	} else if annotationProtocol := annotations[ServiceAnnotationLoadBalancerBEProtocol]; annotationProtocol == "http" {
		instanceProtocol = annotationProtocol
		protocol = "http"
	}

	listener.Protocol = &protocol
	listener.InstanceProtocol = &instanceProtocol

	return listener, nil
}

func (c *Cloud) getSubnetCidrs(ctx context.Context, subnetIDs []string) ([]string, error) {
	request := &ec2.DescribeSubnetsInput{}
	for _, subnetID := range subnetIDs {
		request.SubnetIds = append(request.SubnetIds, subnetID)
	}

	subnets, err := c.ec2.DescribeSubnets(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("error querying Subnet for ELB: %q", err)
	}
	if len(subnets) != len(subnetIDs) {
		return nil, fmt.Errorf("error querying Subnet for ELB, got %d subnets for %v", len(subnets), subnetIDs)
	}

	cidrs := make([]string, 0, len(subnets))
	for _, subnet := range subnets {
		cidrs = append(cidrs, aws.ToString(subnet.CidrBlock))
	}
	return cidrs, nil
}

func parseStringAnnotation(annotations map[string]string, annotation string, value *string) bool {
	if v, ok := annotations[annotation]; ok {
		*value = v
		return true
	}
	return false
}

func parseInt32Annotation(annotations map[string]string, annotation string, value *int32) (bool, error) {
	if v, ok := annotations[annotation]; ok {
		parsed64, err := strconv.ParseInt(v, 10, 0)
		parsed := int32(parsed64)
		if err != nil {
			return true, fmt.Errorf("failed to parse annotation %v=%v", annotation, v)
		}
		*value = parsed
		return true, nil
	}
	return false, nil
}

func (c *Cloud) buildNLBHealthCheckConfiguration(svc *v1.Service) (healthCheckConfig, error) {
	hc := healthCheckConfig{
		Port:               defaultHealthCheckPort,
		Path:               defaultHealthCheckPath,
		Protocol:           elbv2types.ProtocolEnumTcp,
		Interval:           defaultNlbHealthCheckInterval,
		Timeout:            defaultNlbHealthCheckTimeout,
		HealthyThreshold:   defaultNlbHealthCheckThreshold,
		UnhealthyThreshold: defaultNlbHealthCheckThreshold,
	}
	if svc.Spec.ExternalTrafficPolicy == v1.ServiceExternalTrafficPolicyTypeLocal {
		path, port := servicehelpers.GetServiceHealthCheckPathPort(svc)
		hc = healthCheckConfig{
			Port:               strconv.Itoa(int(port)),
			Path:               path,
			Protocol:           elbv2types.ProtocolEnumHttp,
			Interval:           10,
			Timeout:            10,
			HealthyThreshold:   2,
			UnhealthyThreshold: 2,
		}
	}

	var protocolStr string = string(hc.Protocol)
	if parseStringAnnotation(svc.Annotations, ServiceAnnotationLoadBalancerHealthCheckProtocol, &protocolStr) {
		hc.Protocol = elbv2types.ProtocolEnum(strings.ToUpper(protocolStr))
	}
	switch hc.Protocol {
	case elbv2types.ProtocolEnumHttp, elbv2types.ProtocolEnumHttps:
		parseStringAnnotation(svc.Annotations, ServiceAnnotationLoadBalancerHealthCheckPath, &hc.Path)
	case elbv2types.ProtocolEnumTcp:
		hc.Path = ""
	default:
		return healthCheckConfig{}, fmt.Errorf("Unsupported health check protocol %v", hc.Protocol)
	}

	parseStringAnnotation(svc.Annotations, ServiceAnnotationLoadBalancerHealthCheckPort, &hc.Port)

	switch c.cfg.Global.ClusterServiceLoadBalancerHealthProbeMode {
	case config.ClusterServiceLoadBalancerHealthProbeModeShared:
		// For a non-local service, we override the health check to use the kube-proxy port when no other overrides are provided.
		// The kube-proxy port should be open on all nodes and allows the health check to check the nodes ability to proxy traffic.
		// When the node is shutting down, the health check should fail before the node loses the ability to route traffic to the backend pod.
		// This allows the load balancer to gracefully drain connections from the node.
		if svc.Spec.ExternalTrafficPolicy != v1.ServiceExternalTrafficPolicyTypeLocal {
			hc.Path = defaultKubeProxyHealthCheckPath
			if c.cfg.Global.ClusterServiceSharedLoadBalancerHealthProbePath != "" {
				hc.Path = c.cfg.Global.ClusterServiceSharedLoadBalancerHealthProbePath
			}

			hc.Port = strconv.Itoa(int(defaultKubeProxyHealthCheckPort))
			if c.cfg.Global.ClusterServiceSharedLoadBalancerHealthProbePort != 0 {
				hc.Port = strconv.Itoa(int(c.cfg.Global.ClusterServiceSharedLoadBalancerHealthProbePort))
			}

			hc.Protocol = elbv2types.ProtocolEnumHttp
		}
	case config.ClusterServiceLoadBalancerHealthProbeModeServiceNodePort, "":
		// Configuration is already up to date as this is the default case.
	default:
		return healthCheckConfig{}, fmt.Errorf("Unsupported ClusterServiceLoadBalancerHealthProbeMode %v", c.cfg.Global.ClusterServiceLoadBalancerHealthProbeMode)
	}

	if _, err := parseInt32Annotation(svc.Annotations, ServiceAnnotationLoadBalancerHCInterval, &hc.Interval); err != nil {
		return healthCheckConfig{}, err
	}
	if _, err := parseInt32Annotation(svc.Annotations, ServiceAnnotationLoadBalancerHCTimeout, &hc.Timeout); err != nil {
		return healthCheckConfig{}, err
	}
	if _, err := parseInt32Annotation(svc.Annotations, ServiceAnnotationLoadBalancerHCHealthyThreshold, &hc.HealthyThreshold); err != nil {
		return healthCheckConfig{}, err
	}
	if _, err := parseInt32Annotation(svc.Annotations, ServiceAnnotationLoadBalancerHCUnhealthyThreshold, &hc.UnhealthyThreshold); err != nil {
		return healthCheckConfig{}, err
	}

	if hc.Port != defaultHealthCheckPort {
		if _, err := strconv.ParseInt(hc.Port, 10, 0); err != nil {
			return healthCheckConfig{}, fmt.Errorf("Invalid health check port '%v'", hc.Port)
		}
	}
	return hc, nil
}

// EnsureLoadBalancer implements LoadBalancer.EnsureLoadBalancer
func (c *Cloud) EnsureLoadBalancer(ctx context.Context, clusterName string, apiService *v1.Service, nodes []*v1.Node) (*v1.LoadBalancerStatus, error) {
	annotations := apiService.Annotations
	if isLBExternal(annotations) {
		return nil, cloudprovider.ImplementedElsewhere
	}
	klog.V(2).Infof("EnsureLoadBalancer(%v, %v, %v, %v, %v, %v, %v)",
		clusterName, apiService.Namespace, apiService.Name, c.region, apiService.Spec.LoadBalancerIP, apiService.Spec.Ports, annotations)

	if apiService.Spec.SessionAffinity != v1.ServiceAffinityNone {
		// ELB supports sticky sessions, but only when configured for HTTP/HTTPS
		return nil, fmt.Errorf("unsupported load balancer affinity: %v", apiService.Spec.SessionAffinity)
	}

	if len(apiService.Spec.Ports) == 0 {
		return nil, fmt.Errorf("requested load balancer with no ports")
	}
	if err := checkMixedProtocol(apiService.Spec.Ports); err != nil {
		return nil, err
	}
	// Figure out what mappings we want on the load balancer
	listeners := []elbtypes.Listener{}
	v2Mappings := []nlbPortMapping{}

	sslPorts := getPortSets(annotations[ServiceAnnotationLoadBalancerSSLPorts])
	for _, port := range apiService.Spec.Ports {
		if err := checkProtocol(port, annotations); err != nil {
			return nil, err
		}

		if port.NodePort == 0 {
			klog.Errorf("Ignoring port without NodePort defined: %v", port)
			continue
		}

		if isNLB(annotations) {
			portMapping := nlbPortMapping{
				FrontendPort:     int32(port.Port),
				FrontendProtocol: elbv2types.ProtocolEnum(port.Protocol),
				TrafficPort:      int32(port.NodePort),
				TrafficProtocol:  elbv2types.ProtocolEnum(port.Protocol),
			}
			var err error
			if portMapping.HealthCheckConfig, err = c.buildNLBHealthCheckConfiguration(apiService); err != nil {
				return nil, err
			}

			certificateARN := annotations[ServiceAnnotationLoadBalancerCertificate]
			if port.Protocol != v1.ProtocolUDP && certificateARN != "" && (sslPorts == nil || sslPorts.numbers.Has(port.Port) || sslPorts.names.Has(port.Name)) {
				portMapping.FrontendProtocol = elbv2types.ProtocolEnumTls
				portMapping.SSLCertificateARN = certificateARN
				portMapping.SSLPolicy = annotations[ServiceAnnotationLoadBalancerSSLNegotiationPolicy]

				if backendProtocol := annotations[ServiceAnnotationLoadBalancerBEProtocol]; backendProtocol == "ssl" {
					portMapping.TrafficProtocol = elbv2types.ProtocolEnumTls
				}
			}

			v2Mappings = append(v2Mappings, portMapping)
		} else {
			listener, err := buildListener(port, annotations, sslPorts)
			if err != nil {
				return nil, err
			}
			listeners = append(listeners, listener)
		}
	}

	if apiService.Spec.LoadBalancerIP != "" {
		return nil, fmt.Errorf("LoadBalancerIP cannot be specified for AWS ELB")
	}

	instances, err := c.findInstancesForELB(ctx, nodes, annotations)
	if err != nil {
		return nil, err
	}

	sourceRanges, err := servicehelpers.GetLoadBalancerSourceRanges(apiService)
	if err != nil {
		return nil, err
	}

	// Determine if this is tagged as an Internal ELB
	internalELB := false
	internalAnnotation := apiService.Annotations[ServiceAnnotationLoadBalancerInternal]
	if internalAnnotation == "false" {
		internalELB = false
	} else if internalAnnotation != "" {
		internalELB = true
	}

	if isNLB(annotations) {
		// Find the subnets that the ELB will live in
		discoveredSubnetIDs, err := c.getLoadBalancerSubnets(ctx, apiService, internalELB)
		if err != nil {
			klog.Errorf("Error listing subnets in VPC: %q", err)
			return nil, err
		}
		// Bail out early if there are no subnets
		if len(discoveredSubnetIDs) == 0 {
			return nil, fmt.Errorf("could not find any suitable subnets for creating the ELB")
		}

		loadBalancerName := c.GetLoadBalancerName(ctx, clusterName, apiService)
		serviceName := types.NamespacedName{Namespace: apiService.Namespace, Name: apiService.Name}

		instanceIDs := []string{}
		for id := range instances {
			instanceIDs = append(instanceIDs, string(id))
		}

		v2LoadBalancer, err := c.ensureLoadBalancerv2(ctx,
			serviceName,
			loadBalancerName,
			v2Mappings,
			instanceIDs,
			discoveredSubnetIDs,
			internalELB,
			annotations,
		)
		if err != nil {
			return nil, err
		}

		// try to get the ensured subnets of the LBs from AZs
		var ensuredSubnetIDs []string
		var subnetCidrs []string
		for _, az := range v2LoadBalancer.AvailabilityZones {
			ensuredSubnetIDs = append(ensuredSubnetIDs, *az.SubnetId)
		}
		if len(ensuredSubnetIDs) == 0 {
			return nil, fmt.Errorf("did not find ensured subnets on LB %s", loadBalancerName)
		}
		subnetCidrs, err = c.getSubnetCidrs(ctx, ensuredSubnetIDs)
		if err != nil {
			klog.Errorf("Error getting subnet cidrs: %q", err)
			return nil, err
		}

		sourceRangeCidrs := []string{}
		for cidr := range sourceRanges {
			sourceRangeCidrs = append(sourceRangeCidrs, cidr)
		}
		if len(sourceRangeCidrs) == 0 {
			sourceRangeCidrs = append(sourceRangeCidrs, "0.0.0.0/0")
		}

		err = c.updateInstanceSecurityGroupsForNLB(ctx, loadBalancerName, instances, subnetCidrs, sourceRangeCidrs, v2Mappings)
		if err != nil {
			klog.Warningf("Error opening ingress rules for the load balancer to the instances: %q", err)
			return nil, err
		}

		// We don't have an `ensureLoadBalancerInstances()` function for elbv2
		// because `ensureLoadBalancerv2()` requires instance Ids

		// TODO: Wait for creation?
		return v2toStatus(v2LoadBalancer), nil
	}

	// Determine if we need to set the Proxy protocol policy
	proxyProtocol := false
	proxyProtocolAnnotation := apiService.Annotations[ServiceAnnotationLoadBalancerProxyProtocol]
	if proxyProtocolAnnotation != "" {
		if proxyProtocolAnnotation != "*" {
			return nil, fmt.Errorf("annotation %q=%q detected, but the only value supported currently is '*'", ServiceAnnotationLoadBalancerProxyProtocol, proxyProtocolAnnotation)
		}
		proxyProtocol = true
	}

	// Some load balancer attributes are required, so defaults are set. These can be overridden by annotations.
	loadBalancerAttributes := &elbtypes.LoadBalancerAttributes{
		AccessLog:              &elbtypes.AccessLog{Enabled: false},
		ConnectionDraining:     &elbtypes.ConnectionDraining{Enabled: false},
		ConnectionSettings:     &elbtypes.ConnectionSettings{IdleTimeout: aws.Int32(60)},
		CrossZoneLoadBalancing: &elbtypes.CrossZoneLoadBalancing{Enabled: false},
	}

	// Determine if an access log emit interval has been specified
	accessLogEmitIntervalAnnotation := annotations[ServiceAnnotationLoadBalancerAccessLogEmitInterval]
	if accessLogEmitIntervalAnnotation != "" {
		accessLogEmitInterval, err := strconv.ParseInt(accessLogEmitIntervalAnnotation, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("error parsing service annotation: %s=%s",
				ServiceAnnotationLoadBalancerAccessLogEmitInterval,
				accessLogEmitIntervalAnnotation,
			)
		}
		loadBalancerAttributes.AccessLog.EmitInterval = aws.Int32(int32(accessLogEmitInterval))
	}

	// Determine if access log enabled/disabled has been specified
	accessLogEnabledAnnotation := annotations[ServiceAnnotationLoadBalancerAccessLogEnabled]
	if accessLogEnabledAnnotation != "" {
		accessLogEnabled, err := strconv.ParseBool(accessLogEnabledAnnotation)
		if err != nil {
			return nil, fmt.Errorf("error parsing service annotation: %s=%s",
				ServiceAnnotationLoadBalancerAccessLogEnabled,
				accessLogEnabledAnnotation,
			)
		}
		loadBalancerAttributes.AccessLog.Enabled = accessLogEnabled
	}

	// Determine if access log s3 bucket name has been specified
	accessLogS3BucketNameAnnotation := annotations[ServiceAnnotationLoadBalancerAccessLogS3BucketName]
	if accessLogS3BucketNameAnnotation != "" {
		loadBalancerAttributes.AccessLog.S3BucketName = &accessLogS3BucketNameAnnotation
	}

	// Determine if access log s3 bucket prefix has been specified
	accessLogS3BucketPrefixAnnotation := annotations[ServiceAnnotationLoadBalancerAccessLogS3BucketPrefix]
	if accessLogS3BucketPrefixAnnotation != "" {
		loadBalancerAttributes.AccessLog.S3BucketPrefix = &accessLogS3BucketPrefixAnnotation
	}

	// Determine if connection draining enabled/disabled has been specified
	connectionDrainingEnabledAnnotation := annotations[ServiceAnnotationLoadBalancerConnectionDrainingEnabled]
	if connectionDrainingEnabledAnnotation != "" {
		connectionDrainingEnabled, err := strconv.ParseBool(connectionDrainingEnabledAnnotation)
		if err != nil {
			return nil, fmt.Errorf("error parsing service annotation: %s=%s",
				ServiceAnnotationLoadBalancerConnectionDrainingEnabled,
				connectionDrainingEnabledAnnotation,
			)
		}
		loadBalancerAttributes.ConnectionDraining.Enabled = connectionDrainingEnabled
	}

	// Determine if connection draining timeout has been specified
	connectionDrainingTimeoutAnnotation := annotations[ServiceAnnotationLoadBalancerConnectionDrainingTimeout]
	if connectionDrainingTimeoutAnnotation != "" {
		connectionDrainingTimeout, err := strconv.ParseInt(connectionDrainingTimeoutAnnotation, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("error parsing service annotation: %s=%s",
				ServiceAnnotationLoadBalancerConnectionDrainingTimeout,
				connectionDrainingTimeoutAnnotation,
			)
		}
		loadBalancerAttributes.ConnectionDraining.Timeout = aws.Int32(int32(connectionDrainingTimeout))
	}

	// Determine if connection idle timeout has been specified
	connectionIdleTimeoutAnnotation := annotations[ServiceAnnotationLoadBalancerConnectionIdleTimeout]
	if connectionIdleTimeoutAnnotation != "" {
		connectionIdleTimeout, err := strconv.ParseInt(connectionIdleTimeoutAnnotation, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("error parsing service annotation: %s=%s",
				ServiceAnnotationLoadBalancerConnectionIdleTimeout,
				connectionIdleTimeoutAnnotation,
			)
		}
		loadBalancerAttributes.ConnectionSettings.IdleTimeout = aws.Int32(int32(connectionIdleTimeout))
	}

	// Determine if cross zone load balancing enabled/disabled has been specified
	crossZoneLoadBalancingEnabledAnnotation := annotations[ServiceAnnotationLoadBalancerCrossZoneLoadBalancingEnabled]
	if crossZoneLoadBalancingEnabledAnnotation != "" {
		crossZoneLoadBalancingEnabled, err := strconv.ParseBool(crossZoneLoadBalancingEnabledAnnotation)
		if err != nil {
			return nil, fmt.Errorf("error parsing service annotation: %s=%s",
				ServiceAnnotationLoadBalancerCrossZoneLoadBalancingEnabled,
				crossZoneLoadBalancingEnabledAnnotation,
			)
		}
		loadBalancerAttributes.CrossZoneLoadBalancing.Enabled = crossZoneLoadBalancingEnabled
	}

	// Find the subnets that the ELB will live in
	subnetIDs, err := c.getLoadBalancerSubnets(ctx, apiService, internalELB)
	if err != nil {
		klog.Errorf("Error listing subnets in VPC: %q", err)
		return nil, err
	}

	// Bail out early if there are no subnets
	if len(subnetIDs) == 0 {
		return nil, fmt.Errorf("could not find any suitable subnets for creating the ELB")
	}

	loadBalancerName := c.GetLoadBalancerName(ctx, clusterName, apiService)
	serviceName := types.NamespacedName{Namespace: apiService.Namespace, Name: apiService.Name}
	securityGroupIDs, setupSg, err := c.buildELBSecurityGroupList(ctx, serviceName, loadBalancerName, annotations)
	if err != nil {
		return nil, err
	}
	if len(securityGroupIDs) == 0 {
		return nil, fmt.Errorf("[BUG] ELB can't have empty list of Security Groups to be assigned, this is a Kubernetes bug, please report")
	}

	if setupSg {
		ec2SourceRanges := []ec2types.IpRange{}
		for _, sourceRange := range sourceRanges.StringSlice() {
			ec2SourceRanges = append(ec2SourceRanges, ec2types.IpRange{CidrIp: aws.String(sourceRange)})
		}

		permissions := NewIPPermissionSet()
		for _, port := range apiService.Spec.Ports {
			protocol := strings.ToLower(string(port.Protocol))

			permission := ec2types.IpPermission{}
			permission.FromPort = aws.Int32(port.Port)
			permission.ToPort = aws.Int32(port.Port)
			permission.IpRanges = ec2SourceRanges
			permission.IpProtocol = &protocol

			permissions.Insert(permission)
		}

		// Allow ICMP fragmentation packets, important for MTU discovery
		{
			permission := ec2types.IpPermission{
				IpProtocol: aws.String("icmp"),
				FromPort:   aws.Int32(3),
				ToPort:     aws.Int32(4),
				IpRanges:   ec2SourceRanges,
			}

			permissions.Insert(permission)
		}
		_, err = c.setSecurityGroupIngress(ctx, securityGroupIDs[0], permissions)
		if err != nil {
			return nil, err
		}
	}

	// Build the load balancer itself
	loadBalancer, err := c.ensureLoadBalancer(ctx,
		serviceName,
		loadBalancerName,
		listeners,
		subnetIDs,
		securityGroupIDs,
		internalELB,
		proxyProtocol,
		loadBalancerAttributes,
		annotations,
	)
	if err != nil {
		return nil, err
	}

	if sslPolicyName, ok := annotations[ServiceAnnotationLoadBalancerSSLNegotiationPolicy]; ok {
		err := c.ensureSSLNegotiationPolicy(ctx, loadBalancer, sslPolicyName)
		if err != nil {
			return nil, err
		}

		for _, port := range c.getLoadBalancerTLSPorts(loadBalancer) {
			err := c.setSSLNegotiationPolicy(ctx, loadBalancerName, sslPolicyName, port)
			if err != nil {
				return nil, err
			}
		}
	}

	// We only configure a TCP health-check on the first port
	var tcpHealthCheckPort int32
	for _, listener := range listeners {
		if listener.InstancePort == nil {
			continue
		}
		tcpHealthCheckPort = int32(*listener.InstancePort)
		break
	}
	if path, healthCheckNodePort := servicehelpers.GetServiceHealthCheckPathPort(apiService); path != "" {
		klog.V(4).Infof("service %v (%v) needs health checks on :%d%s)", apiService.Name, loadBalancerName, healthCheckNodePort, path)
		if annotations[ServiceAnnotationLoadBalancerHealthCheckPort] == defaultHealthCheckPort {
			healthCheckNodePort = tcpHealthCheckPort
		}
		err = c.ensureLoadBalancerHealthCheck(ctx, loadBalancer, "HTTP", healthCheckNodePort, path, annotations)
		if err != nil {
			return nil, fmt.Errorf("Failed to ensure health check for localized service %v on node port %v: %q", loadBalancerName, healthCheckNodePort, err)
		}
	} else {
		klog.V(4).Infof("service %v does not need custom health checks", apiService.Name)
		var hcPath string
		hcPort := tcpHealthCheckPort

		annotationProtocol := strings.ToLower(annotations[ServiceAnnotationLoadBalancerBEProtocol])
		var hcProtocol string
		if annotationProtocol == "https" || annotationProtocol == "ssl" {
			hcProtocol = "SSL"
		} else {
			hcProtocol = "TCP"
		}

		if c.cfg.Global.ClusterServiceLoadBalancerHealthProbeMode == config.ClusterServiceLoadBalancerHealthProbeModeShared {
			// Use the kube-proxy port as the health check port for non-local services.
			hcProtocol = "HTTP"
			hcPath = defaultKubeProxyHealthCheckPath
			hcPort = int32(defaultKubeProxyHealthCheckPort)

			if c.cfg.Global.ClusterServiceSharedLoadBalancerHealthProbePath != "" {
				hcPath = c.cfg.Global.ClusterServiceSharedLoadBalancerHealthProbePath
			}

			if c.cfg.Global.ClusterServiceSharedLoadBalancerHealthProbePort != 0 {
				hcPort = c.cfg.Global.ClusterServiceSharedLoadBalancerHealthProbePort
			}
		}

		err = c.ensureLoadBalancerHealthCheck(ctx, loadBalancer, hcProtocol, hcPort, hcPath, annotations)
		if err != nil {
			return nil, err
		}
	}

	err = c.updateInstanceSecurityGroupsForLoadBalancer(ctx, loadBalancer, instances, annotations, false)
	if err != nil {
		klog.Warningf("Error opening ingress rules for the load balancer to the instances: %q", err)
		return nil, err
	}

	err = c.ensureLoadBalancerInstances(ctx, aws.ToString(loadBalancer.LoadBalancerName), loadBalancer.Instances, instances)
	if err != nil {
		klog.Warningf("Error registering instances with the load balancer: %q", err)
		return nil, err
	}

	klog.V(1).Infof("Loadbalancer %s (%v) has DNS name %s", loadBalancerName, serviceName, aws.ToString(loadBalancer.DNSName))

	// TODO: Wait for creation?

	status := toStatus(loadBalancer)
	return status, nil
}

// GetLoadBalancer is an implementation of LoadBalancer.GetLoadBalancer
func (c *Cloud) GetLoadBalancer(ctx context.Context, clusterName string, service *v1.Service) (*v1.LoadBalancerStatus, bool, error) {
	if isLBExternal(service.Annotations) {
		return nil, false, nil
	}
	loadBalancerName := c.GetLoadBalancerName(ctx, clusterName, service)

	if isNLB(service.Annotations) {
		lb, err := c.describeLoadBalancerv2(ctx, loadBalancerName)
		if err != nil {
			return nil, false, err
		}
		if lb == nil {
			return nil, false, nil
		}
		return v2toStatus(lb), true, nil
	}

	lb, err := c.describeLoadBalancer(ctx, loadBalancerName)
	if err != nil {
		return nil, false, err
	}

	if lb == nil {
		return nil, false, nil
	}

	status := toStatus(lb)
	return status, true, nil
}

// GetLoadBalancerName is an implementation of LoadBalancer.GetLoadBalancerName
func (c *Cloud) GetLoadBalancerName(ctx context.Context, clusterName string, service *v1.Service) string {
	// TODO: replace DefaultLoadBalancerName to generate more meaningful loadbalancer names.
	return cloudprovider.DefaultLoadBalancerName(service)
}

func toStatus(lb *elbtypes.LoadBalancerDescription) *v1.LoadBalancerStatus {
	status := &v1.LoadBalancerStatus{}

	if aws.ToString(lb.DNSName) != "" {
		var ingress v1.LoadBalancerIngress
		ingress.Hostname = aws.ToString(lb.DNSName)
		status.Ingress = []v1.LoadBalancerIngress{ingress}
	}

	return status
}

func v2toStatus(lb *elbv2types.LoadBalancer) *v1.LoadBalancerStatus {
	status := &v1.LoadBalancerStatus{}
	if lb == nil {
		klog.Error("[BUG] v2toStatus got nil input, this is a Kubernetes bug, please report")
		return status
	}

	// We check for Active or Provisioning, the only successful statuses
	if aws.ToString(lb.DNSName) != "" && (lb.State.Code == elbv2types.LoadBalancerStateEnumActive ||
		lb.State.Code == elbv2types.LoadBalancerStateEnumProvisioning) {
		var ingress v1.LoadBalancerIngress
		ingress.Hostname = aws.ToString(lb.DNSName)
		status.Ingress = []v1.LoadBalancerIngress{ingress}
	}

	return status
}

// Returns the first security group for an instance, or nil
// We only create instances with one security group, so we don't expect multiple security groups.
// However, if there are multiple security groups, we will choose the one tagged with our cluster filter.
// Otherwise we will return an error.
func findSecurityGroupForInstance(instance *ec2types.Instance, taggedSecurityGroups map[string]*ec2types.SecurityGroup) (*ec2types.GroupIdentifier, error) {
	instanceID := aws.ToString(instance.InstanceId)

	var tagged []ec2types.GroupIdentifier
	var untagged []ec2types.GroupIdentifier
	for _, group := range instance.SecurityGroups {
		groupID := aws.ToString(group.GroupId)
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
		return &tagged[0], nil
	}

	if len(untagged) > 0 {
		// For back-compat, we will allow a single untagged SG
		if len(untagged) != 1 {
			return nil, fmt.Errorf("Multiple untagged security groups found for instance %s; ensure the k8s security group is tagged", instanceID)
		}
		return &untagged[0], nil
	}

	klog.Warningf("No security group found for instance %q", instanceID)
	return nil, nil
}

// Return all the security groups that are tagged as being part of our cluster
func (c *Cloud) getTaggedSecurityGroups(ctx context.Context) (map[string]*ec2types.SecurityGroup, error) {
	request := &ec2.DescribeSecurityGroupsInput{}
	groups, err := c.ec2.DescribeSecurityGroups(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("error querying security groups: %q", err)
	}

	m := make(map[string]*ec2types.SecurityGroup)
	for _, group := range groups {
		if !c.tagging.hasClusterTag(group.Tags) {
			continue
		}

		id := aws.ToString(group.GroupId)
		if id == "" {
			klog.Warningf("Ignoring group without id: %v", group)
			continue
		}
		m[id] = &group
	}
	return m, nil
}

// Open security group ingress rules on the instances so that the load balancer can talk to them
// Will also remove any security groups ingress rules for the load balancer that are _not_ needed for allInstances
func (c *Cloud) updateInstanceSecurityGroupsForLoadBalancer(ctx context.Context, lb *elbtypes.LoadBalancerDescription, instances map[InstanceID]*ec2types.Instance, annotations map[string]string, isDeleting bool) error {
	if c.cfg.Global.DisableSecurityGroupIngress {
		return nil
	}

	// Determine the load balancer security group id
	lbSecurityGroupIDs := lb.SecurityGroups
	if len(lbSecurityGroupIDs) == 0 {
		return fmt.Errorf("could not determine security group for load balancer: %s", aws.ToString(lb.LoadBalancerName))
	}

	taggedSecurityGroups, err := c.getTaggedSecurityGroups(ctx)
	if err != nil {
		return fmt.Errorf("error querying for tagged security groups: %q", err)
	}

	taggedLBSecurityGroups := make(map[string]struct{})
	for _, sg := range lbSecurityGroupIDs {
		if _, ok := taggedSecurityGroups[sg]; ok {
			taggedLBSecurityGroups[sg] = struct{}{}
		}
	}

	c.sortELBSecurityGroupList(lbSecurityGroupIDs, annotations, taggedLBSecurityGroups)
	loadBalancerSecurityGroupID := lbSecurityGroupIDs[0]

	// Get the actual list of groups that allow ingress from the load-balancer
	actualGroups := make(map[*ec2types.SecurityGroup]bool)
	{
		describeRequest := &ec2.DescribeSecurityGroupsInput{}
		describeRequest.Filters = []ec2types.Filter{
			newEc2Filter("ip-permission.group-id", loadBalancerSecurityGroupID),
		}
		response, err := c.ec2.DescribeSecurityGroups(ctx, describeRequest)
		if err != nil {
			return fmt.Errorf("error querying security groups for ELB: %q", err)
		}
		for _, sg := range response {
			actualGroups[&sg] = c.tagging.hasClusterTag(sg.Tags)
		}
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
			klog.Warning("Ignoring instance without security group: ", aws.ToString(instance.InstanceId))
			continue
		}
		id := aws.ToString(securityGroup.GroupId)
		if id == "" {
			klog.Warningf("found security group without id: %v", securityGroup)
			continue
		}

		instanceSecurityGroupIds[id] = true
	}

	// Compare to actual groups
	for actualGroup, hasClusterTag := range actualGroups {
		actualGroupID := aws.ToString(actualGroup.GroupId)
		if actualGroupID == "" {
			klog.Warning("Ignoring group without ID: ", actualGroup)
			continue
		}

		adding, found := instanceSecurityGroupIds[actualGroupID]
		if found && adding {
			// We don't need to make a change; the permission is already in place
			delete(instanceSecurityGroupIds, actualGroupID)
		} else {
			if hasClusterTag || isDeleting {
				// If the group is tagged, and we don't need the rule, we should remove it.
				// If the security group is deleting, we should also remove the rule else
				// we cannot remove the security group, we wiil get a dependency violation.
				instanceSecurityGroupIds[actualGroupID] = false
			}
		}
	}

	for instanceSecurityGroupID, add := range instanceSecurityGroupIds {
		if add {
			klog.V(2).Infof("Adding rule for traffic from the load balancer (%s) to instances (%s)", loadBalancerSecurityGroupID, instanceSecurityGroupID)
		} else {
			klog.V(2).Infof("Removing rule for traffic from the load balancer (%s) to instance (%s)", loadBalancerSecurityGroupID, instanceSecurityGroupID)
		}
		sourceGroupID := ec2types.UserIdGroupPair{}
		sourceGroupID.GroupId = &loadBalancerSecurityGroupID

		allProtocols := "-1"

		permission := ec2types.IpPermission{}
		permission.IpProtocol = &allProtocols
		permission.UserIdGroupPairs = []ec2types.UserIdGroupPair{sourceGroupID}

		permissions := []ec2types.IpPermission{permission}

		if add {
			changed, err := c.addSecurityGroupIngress(ctx, instanceSecurityGroupID, permissions)
			if err != nil {
				return err
			}
			if !changed {
				klog.Warning("Allowing ingress was not needed; concurrent change? groupId=", instanceSecurityGroupID)
			}
		} else {
			changed, err := c.removeSecurityGroupIngress(ctx, instanceSecurityGroupID, permissions)
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

// deleteSecurityGroupsWithBackoff deletes a list of security group IDs with retries and exponential backoff.
// The function attempts to delete each security group in the provided list, handling potential dependency violations
// caused by resources still being associated with the security groups (e.g., load balancers in the process of deletion).
//
// Parameters:
// - `ctx`: The context for the operation.
// - `svcName`: The name of the service associated with the security groups.
// - `securityGroupIDs`: A map of security group IDs to be deleted.
//
// Behavior:
// - If the list of security group IDs is empty, the function returns immediately.
// - The function retries deletion for up to 10 minutes, with an initial backoff of 5 seconds that doubles with each retry.
// - Dependency violations are logged and ignored, allowing retries until the timeout is reached.
// - If all security groups are successfully deleted, the function exits.
// - If the timeout is reached and some security groups remain, an error is returned.
//
// Returns:
// - `error`: An error if any security groups could not be deleted within the timeout period.
func (c *Cloud) deleteSecurityGroupsWithBackoff(ctx context.Context, svcName string, securityGroupIDs map[string]struct{}) error {
	if len(securityGroupIDs) == 0 {
		return nil
	}
	err := wait.PollUntilContextTimeout(ctx, 5*time.Second, 10*time.Minute, true, func(ctx context.Context) (bool, error) {
		for securityGroupID := range securityGroupIDs {
			_, err := c.ec2.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{
				GroupId: &securityGroupID,
			})
			if err == nil {
				delete(securityGroupIDs, securityGroupID)
				continue
			}
			ignore := false
			var ae smithy.APIError
			if errors.As(err, &ae) {
				if ae.ErrorCode() == "DependencyViolation" {
					klog.V(2).Infof("Ignoring DependencyViolation while deleting load-balancer security group (%s), assuming because LB is in process of deleting", securityGroupID)
					ignore = true
				}
			}
			if !ignore {
				return true, fmt.Errorf("error while deleting load balancer security group (%s): %q", securityGroupID, err)
			}
		}

		if len(securityGroupIDs) == 0 {
			klog.V(2).Info("Deleted all security groups for load balancer: ", svcName)
			return true, nil
		}

		klog.V(2).Infof("Waiting for load-balancer %q to delete so we can delete security groups: %v", svcName, securityGroupIDs)
		return false, nil
	})
	if err != nil {
		ids := []string{}
		for id := range securityGroupIDs {
			ids = append(ids, id)
		}
		return fmt.Errorf("could not delete security groups %v for Load Balancer %q: %w", strings.Join(ids, ","), svcName, err)
	}
	return nil
}

// buildSecurityGroupsToDelete evaluates all deletion criteria and creates a list of valid security group IDs to be deleted.
// It returns two maps:
// - `securityGroupIDs`: A map of security group IDs that are eligible for deletion.
// - `taggedLBSecurityGroups`: A map of security group IDs that are tagged and associated with the load balancer.
// The function filters security groups based on the following criteria:
//   - Excludes security groups defined in the Cloud Configuration.
//   - Excludes security groups with no cluster tags.
//   - Excludes security groups annotated with `service.beta.kubernetes.io/aws-load-balancer-security-groups` or
//     `service.beta.kubernetes.io/aws-load-balancer-extra-security-groups`.
//
// Parameters:
// - `ctx`: The context for the operation.
// - `service`: The Kubernetes service object.
// - `lbSecurityGroups`: A list of security group IDs associated with the load balancer.
// Returns:
// - `securityGroupIDs`: A map of security group IDs to be deleted.
// - `taggedLBSecurityGroups`: A map of tagged security group IDs.
// - `error`: An error if the operation fails.
func (c *Cloud) buildSecurityGroupsToDelete(ctx context.Context, service *v1.Service, lbSecurityGroups []string) (map[string]struct{}, map[string]struct{}, error) {
	securityGroupIDs := map[string]struct{}{}
	taggedLBSecurityGroups := map[string]struct{}{}

	describeRequest := &ec2.DescribeSecurityGroupsInput{}
	describeRequest.Filters = []ec2types.Filter{
		newEc2Filter("group-id", lbSecurityGroups...),
	}
	response, err := c.ec2.DescribeSecurityGroups(ctx, describeRequest)
	if err != nil {
		return nil, nil, fmt.Errorf("error querying security groups for ELB: %q", err)
	}

	annotatedSgSet := map[string]bool{}
	annotatedSgsList := getSGListFromAnnotation(service.Annotations[ServiceAnnotationLoadBalancerSecurityGroups])
	annotatedExtraSgsList := getSGListFromAnnotation(service.Annotations[ServiceAnnotationLoadBalancerExtraSecurityGroups])
	annotatedSgsList = append(annotatedSgsList, annotatedExtraSgsList...)

	for _, sg := range annotatedSgsList {
		annotatedSgSet[sg] = true
	}

	for _, sg := range response {
		sgID := aws.ToString(sg.GroupId)

		if sgID == c.cfg.Global.ElbSecurityGroup {
			//We don't want to delete a security group that was defined in the Cloud Configuration.
			continue
		}
		if sgID == "" {
			klog.Warningf("Ignoring empty security group in %s", service.Name)
			continue
		}

		if !c.tagging.hasClusterTag(sg.Tags) {
			klog.Warningf("Ignoring security group with no cluster tag in %s", service.Name)
			continue
		} else {
			taggedLBSecurityGroups[sgID] = struct{}{}
		}

		// This is an extra protection of deletion of non provisioned Security Group which is annotated with `service.beta.kubernetes.io/aws-load-balancer-security-groups`.
		if _, ok := annotatedSgSet[sgID]; ok {
			klog.Warningf("Ignoring security group with annotation `service.beta.kubernetes.io/aws-load-balancer-security-groups` or service.beta.kubernetes.io/aws-load-balancer-extra-security-groups in %s", service.Name)
			continue
		}

		securityGroupIDs[sgID] = struct{}{}
	}

	return securityGroupIDs, taggedLBSecurityGroups, nil
}

// EnsureLoadBalancerDeleted implements LoadBalancer.EnsureLoadBalancerDeleted.
func (c *Cloud) EnsureLoadBalancerDeleted(ctx context.Context, clusterName string, service *v1.Service) error {
	if isLBExternal(service.Annotations) {
		return nil
	}
	loadBalancerName := c.GetLoadBalancerName(ctx, clusterName, service)

	if isNLB(service.Annotations) {
		lb, err := c.describeLoadBalancerv2(ctx, loadBalancerName)
		if err != nil {
			return err
		}
		if lb == nil {
			klog.Info("Load balancer already deleted: ", loadBalancerName)
			return nil
		}

		// Delete the LoadBalancer and target groups
		//
		// Deleting a target group while associated with a load balancer will
		// fail. We delete the loadbalancer first. This does leave the
		// possibility of zombie target groups if DeleteLoadBalancer() fails
		//
		// * Get target groups for NLB
		// * Delete Load Balancer
		// * Delete target groups
		// * Clean up SecurityGroupRules
		{

			targetGroups, err := c.elbv2.DescribeTargetGroups(ctx,
				&elbv2.DescribeTargetGroupsInput{LoadBalancerArn: lb.LoadBalancerArn},
			)
			if err != nil {
				return fmt.Errorf("error listing target groups before deleting load balancer: %q", err)
			}

			_, err = c.elbv2.DeleteLoadBalancer(ctx,
				&elbv2.DeleteLoadBalancerInput{LoadBalancerArn: lb.LoadBalancerArn},
			)
			if err != nil {
				return fmt.Errorf("error deleting load balancer %q: %v", loadBalancerName, err)
			}

			for _, group := range targetGroups.TargetGroups {
				_, err := c.elbv2.DeleteTargetGroup(ctx,
					&elbv2.DeleteTargetGroupInput{TargetGroupArn: group.TargetGroupArn},
				)
				if err != nil {
					return fmt.Errorf("error deleting target groups after deleting load balancer: %q", err)
				}
			}
		}

		return c.updateInstanceSecurityGroupsForNLB(ctx, loadBalancerName, nil, nil, nil, nil)
	}

	lb, err := c.describeLoadBalancer(ctx, loadBalancerName)
	if err != nil {
		return err
	}

	if lb == nil {
		klog.Info("Load balancer already deleted: ", loadBalancerName)
		return nil
	}

	// Collect the security groups to delete.
	// We need to know this ahead of time so that we can check
	// if the load balancer security group is being deleted.
	securityGroupIDs := map[string]struct{}{}
	taggedLBSecurityGroups := map[string]struct{}{}

	// Delete the security group(s) for the load balancer
	// Note that this is annoying: the load balancer disappears from the API immediately, but it is still
	// deleting in the background.  We get a DependencyViolation until the load balancer has deleted itself
	securityGroupIDs, taggedLBSecurityGroups, err = c.buildSecurityGroupsToDelete(ctx, service, lb.SecurityGroups)
	if err != nil {
		return fmt.Errorf("unable to build security groups to delete: %w", err)
	}

	{
		// Determine the load balancer security group id
		lbSecurityGroupIDs := lb.SecurityGroups
		if len(lbSecurityGroupIDs) == 0 {
			return fmt.Errorf("could not determine security group for load balancer: %s", aws.ToString(lb.LoadBalancerName))
		}
		c.sortELBSecurityGroupList(lbSecurityGroupIDs, service.Annotations, taggedLBSecurityGroups)
		loadBalancerSecurityGroupID := lbSecurityGroupIDs[0]

		_, isDeleteingLBSecurityGroup := securityGroupIDs[loadBalancerSecurityGroupID]

		// De-authorize the load balancer security group from the instances security group
		err = c.updateInstanceSecurityGroupsForLoadBalancer(ctx, lb, nil, service.Annotations, isDeleteingLBSecurityGroup)
		if err != nil {
			klog.Errorf("Error deregistering load balancer from instance security groups: %q", err)
			return err
		}
	}

	{
		// Delete the load balancer itself
		request := &elb.DeleteLoadBalancerInput{}
		request.LoadBalancerName = lb.LoadBalancerName

		_, err = c.elb.DeleteLoadBalancer(ctx, request)
		if err != nil {
			// TODO: Check if error was because load balancer was concurrently deleted
			klog.Errorf("Error deleting load balancer: %q", err)
			return err
		}
	}

	return c.deleteSecurityGroupsWithBackoff(ctx, service.Name, securityGroupIDs)
}

// UpdateLoadBalancer implements LoadBalancer.UpdateLoadBalancer
func (c *Cloud) UpdateLoadBalancer(ctx context.Context, clusterName string, service *v1.Service, nodes []*v1.Node) error {
	if isLBExternal(service.Annotations) {
		return cloudprovider.ImplementedElsewhere
	}
	instances, err := c.findInstancesForELB(ctx, nodes, service.Annotations)
	if err != nil {
		return err
	}
	loadBalancerName := c.GetLoadBalancerName(ctx, clusterName, service)
	if isNLB(service.Annotations) {
		lb, err := c.describeLoadBalancerv2(ctx, loadBalancerName)
		if err != nil {
			return err
		}
		if lb == nil {
			return fmt.Errorf("Load balancer not found")
		}
		_, err = c.EnsureLoadBalancer(ctx, clusterName, service, nodes)
		return err
	}
	lb, err := c.describeLoadBalancer(ctx, loadBalancerName)
	if err != nil {
		return err
	}

	if lb == nil {
		return fmt.Errorf("Load balancer not found")
	}

	if sslPolicyName, ok := service.Annotations[ServiceAnnotationLoadBalancerSSLNegotiationPolicy]; ok {
		err := c.ensureSSLNegotiationPolicy(ctx, lb, sslPolicyName)
		if err != nil {
			return err
		}
		for _, port := range c.getLoadBalancerTLSPorts(lb) {
			err := c.setSSLNegotiationPolicy(ctx, loadBalancerName, sslPolicyName, port)
			if err != nil {
				return err
			}
		}
	}

	err = c.ensureLoadBalancerInstances(ctx, aws.ToString(lb.LoadBalancerName), lb.Instances, instances)
	if err != nil {
		klog.Warningf("Error registering/deregistering instances with the load balancer: %q", err)
		return err
	}

	err = c.updateInstanceSecurityGroupsForLoadBalancer(ctx, lb, instances, service.Annotations, false)
	if err != nil {
		return err
	}

	return nil
}

// Returns the instance with the specified ID
func (c *Cloud) getInstanceByID(ctx context.Context, instanceID string) (*ec2types.Instance, error) {
	instances, err := c.getInstancesByIDs(ctx, []string{instanceID})
	if err != nil {
		return nil, err
	}

	if len(instances) == 0 {
		return nil, cloudprovider.InstanceNotFound
	}
	if len(instances) > 1 {
		return nil, fmt.Errorf("multiple instances found for instance: %s", instanceID)
	}

	return instances[instanceID], nil
}

func (c *Cloud) getInstancesByIDs(ctx context.Context, instanceIDs []string) (map[string]*ec2types.Instance, error) {
	instancesByID := make(map[string]*ec2types.Instance)
	if len(instanceIDs) == 0 {
		return instancesByID, nil
	}

	request := &ec2.DescribeInstancesInput{
		InstanceIds: instanceIDs,
	}

	instances, err := c.describeInstanceBatcher.DescribeInstances(ctx, request)
	if err != nil {
		return nil, err
	}

	for _, instance := range instances {
		instanceID := aws.ToString(instance.InstanceId)
		if instanceID == "" {
			continue
		}

		instancesByID[instanceID] = instance
	}

	return instancesByID, nil
}

func (c *Cloud) getInstancesByNodeNames(ctx context.Context, nodeNames []string, states ...string) ([]*ec2types.Instance, error) {
	ec2Instances := []*ec2types.Instance{}

	for i := 0; i < len(nodeNames); i += filterNodeLimit {
		end := i + filterNodeLimit
		if end > len(nodeNames) {
			end = len(nodeNames)
		}

		nameSlice := nodeNames[i:end]

		nodeNameFilter := ec2types.Filter{
			Name:   aws.String("private-dns-name"),
			Values: nameSlice,
		}

		filters := []ec2types.Filter{nodeNameFilter}
		if len(states) > 0 {
			filters = append(filters, newEc2Filter("instance-state-name", states...))
		}

		instances, err := c.describeInstances(ctx, filters)
		if err != nil {
			klog.V(2).Infof("Failed to describe instances %v", nodeNames)
			return nil, err
		}
		ec2Instances = append(ec2Instances, instances...)
	}

	if len(ec2Instances) == 0 {
		klog.V(3).Infof("Failed to find any instances %v", nodeNames)
		return nil, nil
	}
	return ec2Instances, nil
}

// TODO: Move to instanceCache
func (c *Cloud) describeInstances(ctx context.Context, filters []ec2types.Filter) ([]*ec2types.Instance, error) {
	request := &ec2.DescribeInstancesInput{
		Filters: filters,
	}

	response, err := c.ec2.DescribeInstances(ctx, request)
	if err != nil {
		return nil, err
	}

	var matches []*ec2types.Instance
	for _, instance := range response {
		if c.tagging.hasClusterTag(instance.Tags) {
			matches = append(matches, &instance)
		}
	}
	return matches, nil
}

// mapNodeNameToPrivateDNSName maps a k8s NodeName to an AWS Instance PrivateDNSName
// This is a simple string cast
//
// Deprecated: use nodeNameToInstanceID instead. mapNodeNameToPrivateDNSName
// assumes node name is equal to private DNS name for all nodes.
//
// But it is only safe to assume so for --cloud-provider=aws kubelets. Because
// then the in-tree AWS cloud provider dictates node name with its
// CurrentNodeName implementation and that always returns private DNS name.
//
// It is not safe to assume so for --cloud-provider=external kubelets. Because
// then kubelet dictates its own node name with its OS hostname (or
// --hostname-override) and that hostname won't always be private DNS name.
// This AWS cloud provider can initialize a node so long as the node's name
// satisfies its InstanceID implementation, i.e. as long as the instance id can
// be derived from the node name.
//
// For example, kops 1.23 with external cloud provider sets node names to
// instance ID like "i-0123456789abcde". nodeNameToInstanceID handles these
// cases that this function cannot.
//
// Removing this function is part of the effort to support non private DNS node
// names [2].
//
// [1] https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-naming.html
// [2] https://github.com/kubernetes/cloud-provider-aws/issues/63
func mapNodeNameToPrivateDNSName(nodeName types.NodeName) string {
	return string(nodeName)
}

// mapInstanceToNodeName maps a EC2 instance to a k8s NodeName, by extracting the PrivateDNSName
//
// Deprecated: use instanceIDToNodeName instead. See
// mapNodeNameToPrivateDNSName for details.
func mapInstanceToNodeName(i *ec2types.Instance) types.NodeName {
	return types.NodeName(aws.ToString(i.PrivateDnsName))
}

var aliveFilter = []string{
	string(ec2types.InstanceStateNamePending),
	string(ec2types.InstanceStateNameRunning),
	string(ec2types.InstanceStateNameShuttingDown),
	string(ec2types.InstanceStateNameStopping),
	string(ec2types.InstanceStateNameStopped),
}

// Returns the instance with the specified node name
// Returns nil if it does not exist
func (c *Cloud) findInstanceByNodeName(ctx context.Context, nodeName types.NodeName) (*ec2types.Instance, error) {
	privateDNSName := mapNodeNameToPrivateDNSName(nodeName)
	filters := []ec2types.Filter{
		newEc2Filter("private-dns-name", privateDNSName),
		// exclude instances in "terminated" state
		newEc2Filter("instance-state-name", aliveFilter...),
	}

	instances, err := c.describeInstances(ctx, filters)
	if err != nil {
		return nil, err
	}

	if len(instances) == 0 {
		return nil, nil
	}
	if len(instances) > 1 {
		return nil, fmt.Errorf("multiple instances found for name: %s", nodeName)
	}
	return instances[0], nil
}

// Returns the instance with the specified node name
// Like findInstanceByNodeName, but returns error if node not found
func (c *Cloud) getInstanceByNodeName(ctx context.Context, nodeName types.NodeName) (*ec2types.Instance, error) {
	var instance *ec2types.Instance

	// we leverage node cache to try to retrieve node's instance id first, as
	// get instance by instance id is way more efficient than by filters in
	// aws context
	awsID, err := c.nodeNameToInstanceID(nodeName)
	if err != nil {
		klog.V(3).Infof("Unable to convert node name %q to aws instanceID, fall back to findInstanceByNodeName: %v", nodeName, err)
		instance, err = c.findInstanceByNodeName(ctx, nodeName)
	} else {
		instance, err = c.getInstanceByID(ctx, string(awsID))
	}
	if err == nil && instance == nil {
		return nil, cloudprovider.InstanceNotFound
	}
	return instance, err
}

func (c *Cloud) getFullInstance(ctx context.Context, nodeName types.NodeName) (*awsInstance, *ec2types.Instance, error) {
	if nodeName == "" {
		instance, err := c.getInstanceByID(ctx, c.selfAWSInstance.awsID)
		return c.selfAWSInstance, instance, err
	}
	instance, err := c.getInstanceByNodeName(ctx, nodeName)
	if err != nil {
		return nil, nil, err
	}
	awsInstance := newAWSInstance(c.ec2, instance)
	return awsInstance, instance, err
}

// extract private ip address from node name
func nodeNameToIPAddress(nodeName string) string {
	nodeName = strings.TrimPrefix(nodeName, privateDNSNamePrefix)
	nodeName = strings.Split(nodeName, ".")[0]
	return strings.ReplaceAll(nodeName, "-", ".")
}

func (c *Cloud) nodeNameToInstanceID(nodeName types.NodeName) (InstanceID, error) {
	if strings.HasPrefix(string(nodeName), rbnNamePrefix) {
		// depending on if you use a RHEL (e.g. AL2) or Debian (e.g. standard Ubuntu) based distribution, the
		// hostname on the machine may be either i-00000000000000001 or i-00000000000000001.region.compute.internal.
		// This handles both scenarios by returning anything before the first '.' in the node name if it has an RBN prefix.
		if idx := strings.IndexByte(string(nodeName), '.'); idx != -1 {
			return InstanceID(nodeName[0:idx]), nil
		}
		return InstanceID(nodeName), nil
	}
	if len(nodeName) == 0 {
		return "", fmt.Errorf("no nodeName provided")
	}

	if c.nodeInformerHasSynced == nil || !c.nodeInformerHasSynced() {
		return "", fmt.Errorf("node informer has not synced yet")
	}

	node, err := c.nodeInformer.Lister().Get(string(nodeName))
	if err != nil {
		return "", err
	}
	if len(node.Spec.ProviderID) == 0 {
		return "", fmt.Errorf("node has no providerID")
	}

	return KubernetesInstanceID(node.Spec.ProviderID).MapToAWSInstanceID()
}

func (c *Cloud) instanceIDToNodeName(instanceID InstanceID) (types.NodeName, error) {
	if len(instanceID) == 0 {
		return "", fmt.Errorf("no instanceID provided")
	}

	if c.nodeInformerHasSynced == nil || !c.nodeInformerHasSynced() {
		return "", fmt.Errorf("node informer has not synced yet")
	}

	nodes, err := c.nodeInformer.Informer().GetIndexer().IndexKeys("instanceID", string(instanceID))
	if err != nil {
		return "", fmt.Errorf("error getting node with instanceID %q: %v", string(instanceID), err)
	} else if len(nodes) == 0 {
		return "", fmt.Errorf("node with instanceID %q not found", string(instanceID))
	} else if len(nodes) > 1 {
		return "", fmt.Errorf("multiple nodes with instanceID %q found: %v", string(instanceID), nodes)
	}

	return types.NodeName(nodes[0]), nil
}

func checkMixedProtocol(ports []v1.ServicePort) error {
	if len(ports) == 0 {
		return nil
	}
	firstProtocol := ports[0].Protocol
	for _, port := range ports[1:] {
		if port.Protocol != firstProtocol {
			return fmt.Errorf("mixed protocol is not supported for LoadBalancer")
		}
	}
	return nil
}

func checkProtocol(port v1.ServicePort, annotations map[string]string) error {
	// nlb supports tcp, udp
	if isNLB(annotations) && (port.Protocol == v1.ProtocolTCP || port.Protocol == v1.ProtocolUDP) {
		return nil
	}
	// elb only supports tcp
	if !isNLB(annotations) && port.Protocol == v1.ProtocolTCP {
		return nil
	}
	return fmt.Errorf("Protocol %s not supported by LoadBalancer", port.Protocol)
}

func getRegionFromMetadata(ctx context.Context, cfg config.CloudConfig, metadata config.EC2Metadata) (string, error) {
	// For backwards compatibility reasons, keeping this check to avoid breaking possible
	// cases where Zone was set to override the region configuration. Otherwise, fall back
	// to getting region the standard way.
	if cfg.Global.Zone != "" {
		zone := cfg.Global.Zone
		klog.Infof("Zone %s configured in cloud config. Using that to get region.", zone)

		return azToRegion(zone)
	}

	return cfg.GetRegion(ctx, metadata)
}
