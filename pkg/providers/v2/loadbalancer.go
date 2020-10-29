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
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/elb"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	cloudprovider "k8s.io/cloud-provider"
	servicehelpers "k8s.io/cloud-provider/service/helpers"
	"k8s.io/klog/v2"
)

// ServiceAnnotationLoadBalancerTargetNodeLabels is the annotation used on the service
// to specify a comma-separated list of key-value pairs which will be used to select
// the target nodes for the load balancer
// For example: "Key1=Val1,Key2=Val2,KeyNoVal1=,KeyNoVal2"
const ServiceAnnotationLoadBalancerTargetNodeLabels = "service.beta.kubernetes.io/aws-load-balancer-target-node-labels"

// ServiceAnnotationLoadBalancerInternal is the annotation used on the service
// to indicate that we want an internal ELB.
const ServiceAnnotationLoadBalancerInternal = "service.beta.kubernetes.io/aws-load-balancer-internal"

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

// ServiceAnnotationLoadBalancerType is the annotation used on the service
// to indicate what type of Load Balancer we want. Right now, the only accepted
// value is "nlb"
const ServiceAnnotationLoadBalancerType = "service.beta.kubernetes.io/aws-load-balancer-type"

// ServiceAnnotationLoadBalancerAdditionalTags is the annotation used on the service
// to specify a comma-separated list of key-value pairs which will be recorded as
// additional tags in the ELB.
// For example: "Key1=Val1,Key2=Val2,KeyNoVal1=,KeyNoVal2"
const ServiceAnnotationLoadBalancerAdditionalTags = "service.beta.kubernetes.io/aws-load-balancer-additional-resource-tags"

// ServiceAnnotationLoadBalancerHealthCheckPort is the annotation used on the service to
// specify the port used for ELB health check.
// Default is traffic-port if externalTrafficPolicy is Cluster, healthCheckNodePort if externalTrafficPolicy is Local
const ServiceAnnotationLoadBalancerHealthCheckPort = "service.beta.kubernetes.io/aws-load-balancer-healthcheck-port"

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

// ServiceAnnotationLoadBalancerSSLPorts is the annotation used on the service
// to specify a comma-separated list of ports that will use SSL/HTTPS
// listeners. Defaults to '*' (all).
const ServiceAnnotationLoadBalancerSSLPorts = "service.beta.kubernetes.io/aws-load-balancer-ssl-ports"

// ServiceAnnotationLoadBalancerCertificate is the annotation used on the
// service to request a secure listener. Value is a valid certificate ARN.
// For more, see http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-listener-config.html
// CertARN is an IAM or CM certificate ARN, e.g. arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012
const ServiceAnnotationLoadBalancerCertificate = "service.beta.kubernetes.io/aws-load-balancer-ssl-cert"

// ServiceAnnotationLoadBalancerBEProtocol is the annotation used on the service
// to specify the protocol spoken by the backend (pod) behind a listener.
// If `http` (default) or `https`, an HTTPS listener that terminates the
//  connection and parses headers is created.
// If set to `ssl` or `tcp`, a "raw" SSL listener is used.
// If set to `http` and `aws-load-balancer-ssl-cert` is not used then
// a HTTP listener is used.
const ServiceAnnotationLoadBalancerBEProtocol = "service.beta.kubernetes.io/aws-load-balancer-backend-protocol"

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

// SSLNegotiationPolicyNameFormat is a format string used for the SSL
// negotiation policy tag name
const SSLNegotiationPolicyNameFormat = "k8s-SSLNegotiationPolicy-%s"

// MaxReadThenCreateRetries sets the maximum number of attempts we will make when
// we read to see if something exists and then try to create it if we didn't find it.
// This can fail once in a consistent system if done in parallel
// In an eventually consistent system, it could fail unboundedly
const MaxReadThenCreateRetries = 30

// ProxyProtocolPolicyName is the tag named used for the proxy protocol
// policy
const ProxyProtocolPolicyName = "k8s-proxyprotocol-enabled"

// Maps from backend protocol to ELB protocol
var backendProtocolMapping = map[string]string{
	"https": "https",
	"http":  "https",
	"ssl":   "ssl",
	"tcp":   "ssl",
}

// Defaults for ELB Healthcheck
var (
	defaultElbHCHealthyThreshold   = int64(2)
	defaultElbHCUnhealthyThreshold = int64(6)
	defaultElbHCTimeout            = int64(5)
	defaultElbHCInterval           = int64(10)
	defaultNlbHealthCheckInterval  = int64(30)
	defaultNlbHealthCheckTimeout   = int64(10)
	defaultNlbHealthCheckThreshold = int64(3)
	defaultHealthCheckPort         = "traffic-port"
	defaultHealthCheckPath         = "/"
)

// loadbalancer is an implementation of cloudprovider.LoadBalancer
type loadbalancer struct {
	ec2      EC2
	elb      ELB
	vpcID    string
	subnetID string
}

type portSets struct {
	names   sets.String
	numbers sets.Int64
}

// ELB is an interface defining only the methods we call from the AWS ELB SDK.
type ELB interface {
	CreateLoadBalancer(*elb.CreateLoadBalancerInput) (*elb.CreateLoadBalancerOutput, error)
	DeleteLoadBalancer(*elb.DeleteLoadBalancerInput) (*elb.DeleteLoadBalancerOutput, error)
	DescribeLoadBalancers(*elb.DescribeLoadBalancersInput) (*elb.DescribeLoadBalancersOutput, error)
	AddTags(*elb.AddTagsInput) (*elb.AddTagsOutput, error)
	RegisterInstancesWithLoadBalancer(*elb.RegisterInstancesWithLoadBalancerInput) (*elb.RegisterInstancesWithLoadBalancerOutput, error)
	DeregisterInstancesFromLoadBalancer(*elb.DeregisterInstancesFromLoadBalancerInput) (*elb.DeregisterInstancesFromLoadBalancerOutput, error)
	CreateLoadBalancerPolicy(*elb.CreateLoadBalancerPolicyInput) (*elb.CreateLoadBalancerPolicyOutput, error)
	SetLoadBalancerPoliciesOfListener(input *elb.SetLoadBalancerPoliciesOfListenerInput) (*elb.SetLoadBalancerPoliciesOfListenerOutput, error)
	DescribeLoadBalancerPolicies(input *elb.DescribeLoadBalancerPoliciesInput) (*elb.DescribeLoadBalancerPoliciesOutput, error)

	DetachLoadBalancerFromSubnets(*elb.DetachLoadBalancerFromSubnetsInput) (*elb.DetachLoadBalancerFromSubnetsOutput, error)
	AttachLoadBalancerToSubnets(*elb.AttachLoadBalancerToSubnetsInput) (*elb.AttachLoadBalancerToSubnetsOutput, error)

	CreateLoadBalancerListeners(*elb.CreateLoadBalancerListenersInput) (*elb.CreateLoadBalancerListenersOutput, error)
	DeleteLoadBalancerListeners(*elb.DeleteLoadBalancerListenersInput) (*elb.DeleteLoadBalancerListenersOutput, error)

	ApplySecurityGroupsToLoadBalancer(*elb.ApplySecurityGroupsToLoadBalancerInput) (*elb.ApplySecurityGroupsToLoadBalancerOutput, error)

	DescribeLoadBalancerAttributes(*elb.DescribeLoadBalancerAttributesInput) (*elb.DescribeLoadBalancerAttributesOutput, error)
	ModifyLoadBalancerAttributes(*elb.ModifyLoadBalancerAttributesInput) (*elb.ModifyLoadBalancerAttributesOutput, error)

	SetLoadBalancerPoliciesForBackendServer(*elb.SetLoadBalancerPoliciesForBackendServerInput) (*elb.SetLoadBalancerPoliciesForBackendServerOutput, error)

	ConfigureHealthCheck(*elb.ConfigureHealthCheckInput) (*elb.ConfigureHealthCheckOutput, error)
}

// newLoadBalancer returns an implementation of cloudprovider.LoadBalancer
func newLoadBalancer(region string, creds *credentials.Credentials, vpcID string, subnetID string) (cloudprovider.LoadBalancer, error) {
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
		ec2:      ec2Service,
		elb:      elbService,
		vpcID:    vpcID,
		subnetID: subnetID,
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
	annotations := service.Annotations
	klog.V(2).Infof("EnsureLoadBalancer(cluster name: %v, namespace: %v, service name: %v, load balancer IP: %v, ports: %v, annotations: %v)",
		clusterName, service.Namespace, service.Name, service.Spec.LoadBalancerIP, service.Spec.Ports, annotations)

	if len(service.Spec.Ports) == 0 {
		return nil, fmt.Errorf("requested load balancer with no ports")
	}

	listeners := []*elb.Listener{}
	sslPorts := getPortSets(annotations[ServiceAnnotationLoadBalancerSSLPorts])
	for _, port := range service.Spec.Ports {
		if err := checkProtocol(port, annotations); err != nil {
			return nil, err
		}

		if port.NodePort == 0 {
			klog.Errorf("Ignoring port without NodePort defined: %v", port)
			continue
		}

		// Create listeners for the load balancer
		listener, err := buildListener(port, annotations, sslPorts)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, listener)
	}

	// TODO: verify this
	if service.Spec.LoadBalancerIP != "" {
		return nil, fmt.Errorf("LoadBalancerIP cannot be specified for AWS ELB")
	}

	instances, err := l.getInstancesForELB(nodes, annotations)
	if err != nil {
		return nil, err
	}

	// Determine if we need to set the Proxy protocol policy
	proxyProtocol := false
	proxyProtocolAnnotation := service.Annotations[ServiceAnnotationLoadBalancerProxyProtocol]
	if proxyProtocolAnnotation != "" {
		if proxyProtocolAnnotation != "*" {
			return nil, fmt.Errorf("annotation %q=%q detected, but the only value supported currently is '*'", ServiceAnnotationLoadBalancerProxyProtocol, proxyProtocolAnnotation)
		}
		proxyProtocol = true
	}

	// Some load balancer attributes are required, so defaults are set. These can be overridden by annotations.
	loadBalancerAttributes := &elb.LoadBalancerAttributes{
		AccessLog:              &elb.AccessLog{Enabled: aws.Bool(false)},
		ConnectionDraining:     &elb.ConnectionDraining{Enabled: aws.Bool(false)},
		ConnectionSettings:     &elb.ConnectionSettings{IdleTimeout: aws.Int64(60)},
		CrossZoneLoadBalancing: &elb.CrossZoneLoadBalancing{Enabled: aws.Bool(false)},
	}

	// Override attributes by annotations
	// Determine if an access log emit interval has been specified
	accessLogEmitIntervalAnnotation := annotations[ServiceAnnotationLoadBalancerAccessLogEmitInterval]
	if accessLogEmitIntervalAnnotation != "" {
		accessLogEmitInterval, err := strconv.ParseInt(accessLogEmitIntervalAnnotation, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("error parsing service annotation: %s=%s",
				ServiceAnnotationLoadBalancerAccessLogEmitInterval,
				accessLogEmitIntervalAnnotation,
			)
		}
		loadBalancerAttributes.AccessLog.EmitInterval = &accessLogEmitInterval
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
		loadBalancerAttributes.AccessLog.Enabled = &accessLogEnabled
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
		loadBalancerAttributes.ConnectionDraining.Enabled = &connectionDrainingEnabled
	}

	// Determine if connection draining timeout has been specified
	connectionDrainingTimeoutAnnotation := annotations[ServiceAnnotationLoadBalancerConnectionDrainingTimeout]
	if connectionDrainingTimeoutAnnotation != "" {
		connectionDrainingTimeout, err := strconv.ParseInt(connectionDrainingTimeoutAnnotation, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("error parsing service annotation: %s=%s",
				ServiceAnnotationLoadBalancerConnectionDrainingTimeout,
				connectionDrainingTimeoutAnnotation,
			)
		}
		loadBalancerAttributes.ConnectionDraining.Timeout = &connectionDrainingTimeout
	}

	// Determine if connection idle timeout has been specified
	connectionIdleTimeoutAnnotation := annotations[ServiceAnnotationLoadBalancerConnectionIdleTimeout]
	if connectionIdleTimeoutAnnotation != "" {
		connectionIdleTimeout, err := strconv.ParseInt(connectionIdleTimeoutAnnotation, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("error parsing service annotation: %s=%s",
				ServiceAnnotationLoadBalancerConnectionIdleTimeout,
				connectionIdleTimeoutAnnotation,
			)
		}
		loadBalancerAttributes.ConnectionSettings.IdleTimeout = &connectionIdleTimeout
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
		loadBalancerAttributes.CrossZoneLoadBalancing.Enabled = &crossZoneLoadBalancingEnabled
	}

	// Determine if this is tagged as an Internal ELB
	internalELB := false
	internalAnnotation := service.Annotations[ServiceAnnotationLoadBalancerInternal]
	if internalAnnotation == "false" {
		internalELB = false
	} else if internalAnnotation != "" {
		internalELB = true
	}

	// Find the subnets that the ELB will live in
	subnetIDs, err := l.findELBSubnets(internalELB)
	if err != nil {
		klog.Errorf("Error listing subnets in VPC: %q", err)
		return nil, err
	}

	// Bail out early if there are no subnets
	if len(subnetIDs) == 0 {
		return nil, fmt.Errorf("could not find any suitable subnets for creating the ELB")
	}

	loadBalancerName := l.GetLoadBalancerName(ctx, clusterName, service)
	serviceName := types.NamespacedName{Namespace: service.Namespace, Name: service.Name}
	securityGroupIDs, err := l.buildELBSecurityGroupList(serviceName, loadBalancerName, annotations)
	if err != nil {
		return nil, err
	}
	if len(securityGroupIDs) == 0 {
		return nil, fmt.Errorf("[BUG] ELB can't have empty list of Security Groups to be assigned, this is a Kubernetes bug, please report")
	}

	// Build the load balancer itself
	loadBalancer, err := l.ensureLoadBalancer(
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

	// set up SSL negotiation policy
	if sslPolicyName, ok := annotations[ServiceAnnotationLoadBalancerSSLNegotiationPolicy]; ok {
		err := l.ensureSSLNegotiationPolicy(loadBalancer, sslPolicyName)
		if err != nil {
			return nil, err
		}

		for _, port := range l.getLoadBalancerTLSPorts(loadBalancer) {
			err := l.setSSLNegotiationPolicy(loadBalancerName, sslPolicyName, port)
			if err != nil {
				return nil, err
			}
		}
	}

	// TODO: health check
	// We only configure a TCP health-check on the first port
	var tcpHealthCheckPort int32
	for _, listener := range listeners {
		if listener.InstancePort == nil {
			continue
		}
		tcpHealthCheckPort = int32(*listener.InstancePort)
		break
	}

	if path, healthCheckNodePort := servicehelpers.GetServiceHealthCheckPathPort(service); path != "" {
		klog.V(4).Infof("service %v (%v) needs health checks on :%d%s)", service.Name, loadBalancerName, healthCheckNodePort, path)
		if annotations[ServiceAnnotationLoadBalancerHealthCheckPort] == defaultHealthCheckPort {
			healthCheckNodePort = tcpHealthCheckPort
		}

		err = l.ensureLoadBalancerHealthCheck(loadBalancer, "HTTP", healthCheckNodePort, path, annotations)
		if err != nil {
			return nil, fmt.Errorf("Failed to ensure health check for localized service %v on node port %v: %q", loadBalancerName, healthCheckNodePort, err)
		}
	} else {
		klog.V(4).Infof("service %v does not need custom health checks", service.Name)
		annotationProtocol := strings.ToLower(annotations[ServiceAnnotationLoadBalancerBEProtocol])
		var hcProtocol string
		if annotationProtocol == "https" || annotationProtocol == "ssl" {
			hcProtocol = "SSL"
		} else {
			hcProtocol = "TCP"
		}
		// there must be no path on TCP health check
		err = l.ensureLoadBalancerHealthCheck(loadBalancer, hcProtocol, tcpHealthCheckPort, "", annotations)
		if err != nil {
			return nil, err
		}
	}

	err = l.updateInstanceSecurityGroupsForLoadBalancer(loadBalancer, instances, annotations)
	if err != nil {
		klog.Warningf("Error opening ingress rules for the load balancer to the instances: %q", err)
		return nil, err
	}

	err = l.ensureLoadBalancerInstances(aws.StringValue(loadBalancer.LoadBalancerName), loadBalancer.Instances, instances)
	if err != nil {
		klog.Warningf("Error registering instances with the load balancer: %q", err)
		return nil, err
	}

	klog.V(1).Infof("Loadbalancer %s (%v) has DNS name %s", loadBalancerName, serviceName, aws.StringValue(loadBalancer.DNSName))

	// TODO: Wait for creation?

	status := getLoadBalancerStatus(loadBalancer)
	return status, nil
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

// Makes sure that the health check for an ELB matches the configured health check node port
func (l *loadbalancer) ensureLoadBalancerHealthCheck(lb *elb.LoadBalancerDescription, protocol string, port int32, path string, annotations map[string]string) error {
	name := aws.StringValue(lb.LoadBalancerName)

	actual := lb.HealthCheck
	// Override healthcheck protocol, port and path based on annotations
	if s, ok := annotations[ServiceAnnotationLoadBalancerHealthCheckProtocol]; ok {
		protocol = s
	}
	if s, ok := annotations[ServiceAnnotationLoadBalancerHealthCheckPort]; ok && s != defaultHealthCheckPort {
		p, err := strconv.ParseInt(s, 10, 0)
		if err != nil {
			return err
		}
		port = int32(p)
	}
	switch strings.ToUpper(protocol) {
	case "HTTP", "HTTPS":
		if path == "" {
			path = defaultHealthCheckPath
		}
		if s := annotations[ServiceAnnotationLoadBalancerHealthCheckPath]; s != "" {
			path = s
		}
	default:
		path = ""
	}

	expectedTarget := protocol + ":" + strconv.FormatInt(int64(port), 10) + path
	expected, err := l.getExpectedHealthCheck(expectedTarget, annotations)
	if err != nil {
		return fmt.Errorf("cannot update health check for load balancer %q: %q", name, err)
	}

	// comparing attributes 1 by 1 to avoid breakage in case a new field is
	// added to the HC which breaks the equality
	if aws.StringValue(expected.Target) == aws.StringValue(actual.Target) &&
		aws.Int64Value(expected.HealthyThreshold) == aws.Int64Value(actual.HealthyThreshold) &&
		aws.Int64Value(expected.UnhealthyThreshold) == aws.Int64Value(actual.UnhealthyThreshold) &&
		aws.Int64Value(expected.Interval) == aws.Int64Value(actual.Interval) &&
		aws.Int64Value(expected.Timeout) == aws.Int64Value(actual.Timeout) {
		return nil
	}

	request := &elb.ConfigureHealthCheckInput{
		HealthCheck: expected,
		LoadBalancerName: lb.LoadBalancerName,
	}

	_, err = l.elb.ConfigureHealthCheck(request)
	if err != nil {
		return fmt.Errorf("error configuring load balancer health check for %q: %q", name, err)
	}

	return nil
}

// getExpectedHealthCheck returns an elb.Healthcheck for the provided target
// and using either sensible defaults or overrides via Service annotations
func (l *loadbalancer) getExpectedHealthCheck(target string, annotations map[string]string) (*elb.HealthCheck, error) {
	healthcheck := &elb.HealthCheck{Target: &target}
	getOrDefault := func(annotation string, defaultValue int64) (*int64, error) {
		i64 := defaultValue
		var err error
		if s, ok := annotations[annotation]; ok {
			i64, err = strconv.ParseInt(s, 10, 0)
			if err != nil {
				return nil, fmt.Errorf("failed parsing health check annotation value: %v", err)
			}
		}
		return &i64, nil
	}

	var err error
	healthcheck.HealthyThreshold, err = getOrDefault(ServiceAnnotationLoadBalancerHCHealthyThreshold, defaultElbHCHealthyThreshold)
	if err != nil {
		return nil, err
	}
	healthcheck.UnhealthyThreshold, err = getOrDefault(ServiceAnnotationLoadBalancerHCUnhealthyThreshold, defaultElbHCUnhealthyThreshold)
	if err != nil {
		return nil, err
	}
	healthcheck.Timeout, err = getOrDefault(ServiceAnnotationLoadBalancerHCTimeout, defaultElbHCTimeout)
	if err != nil {
		return nil, err
	}
	healthcheck.Interval, err = getOrDefault(ServiceAnnotationLoadBalancerHCInterval, defaultElbHCInterval)
	if err != nil {
		return nil, err
	}
	
	if err = healthcheck.Validate(); err != nil {
		return nil, fmt.Errorf("some of the load balancer health check parameters are invalid: %v", err)
	}
	
	return healthcheck, nil
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

func isNLB(annotations map[string]string) bool {
	if annotations[ServiceAnnotationLoadBalancerType] == "nlb" {
		return true
	}
	return false
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

// getPortSets returns a portSets structure representing port names and numbers
// that the comma-separated string describes. If the input is empty or equal to
// "*", a nil pointer is returned.
func getPortSets(annotation string) (ports *portSets) {
	if annotation != "" && annotation != "*" {
		ports = &portSets{
			sets.NewString(),
			sets.NewInt64(),
		}
		portStringSlice := strings.Split(annotation, ",")
		for _, item := range portStringSlice {
			port, err := strconv.Atoi(item)
			if err != nil {
				ports.names.Insert(item)
			} else {
				ports.numbers.Insert(int64(port))
			}
		}
	}
	return
}

// buildListener creates a new listener from the given port, adding an SSL certificate
// if indicated by the appropriate annotations.
func buildListener(port v1.ServicePort, annotations map[string]string, sslPorts *portSets) (*elb.Listener, error) {
	loadBalancerPort := int64(port.Port)
	portName := strings.ToLower(port.Name)
	instancePort := int64(port.NodePort)
	protocol := strings.ToLower(string(port.Protocol))
	instanceProtocol := protocol

	listener := &elb.Listener{}
	listener.InstancePort = &instancePort
	listener.LoadBalancerPort = &loadBalancerPort
	certID := annotations[ServiceAnnotationLoadBalancerCertificate]
	if certID != "" && (sslPorts == nil || sslPorts.numbers.Has(loadBalancerPort) || sslPorts.names.Has(portName)) {
		instanceProtocol = annotations[ServiceAnnotationLoadBalancerBEProtocol]
		if instanceProtocol == "" {
			protocol = "ssl"
			instanceProtocol = "tcp"
		} else {
			protocol = backendProtocolMapping[instanceProtocol]
			if protocol == "" {
				return nil, fmt.Errorf("Invalid backend protocol %s for %s in %s", instanceProtocol, certID, ServiceAnnotationLoadBalancerBEProtocol)
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

// Finds the subnets associated with the cluster, by matching tags.
// For maximal backwards compatibility, if no subnets are tagged, it will fall-back to the current subnet.
// However, in future this will likely be treated as an error.
func (l *loadbalancer) findSubnets() ([]*ec2.Subnet, error) {
	request := &ec2.DescribeSubnetsInput{
		Filters: []*ec2.Filter{
			newEc2Filter("vpc-id", l.vpcID),
		},
	}

	subnets, err := l.ec2.DescribeSubnets(request)
	if err != nil {
		return nil, fmt.Errorf("error describing subnets: %q", err)
	}

	var matches []*ec2.Subnet
	for _, subnet := range subnets.Subnets {
		if c.tagging.hasClusterTag(subnet.Tags) {
			matches = append(matches, subnet)
		}
	}

	if len(matches) != 0 {
		return matches, nil
	}

	// Fall back to the current instance subnets, if nothing is tagged
	klog.Warningf("No tagged subnets found; will fall-back to the current subnet only.  This is likely to be an error in a future version of k8s.")

	request = &ec2.DescribeSubnetsInput{}
	request.Filters = []*ec2.Filter{newEc2Filter("subnet-id", l.subnetID)}

	response, err := l.ec2.DescribeSubnets(request)
	if err != nil {
		return nil, fmt.Errorf("error describing subnets: %q", err)
	}

	return response.Subnets, nil
}

// Finds the subnets to use for an ELB we are creating. Returns a list of subnet IDs sorted by availability zone
// Normal (Internet-facing) ELBs must use public subnets, so we skip private subnets.
// Internal ELBs can use public or private subnets, but if we have a private subnet we should prefer that.
func (l *loadbalancer) findELBSubnets(internalELB bool) ([]string, error) {
	subnets, err := l.findSubnets()
	if err != nil {
		return nil, err
	}

	request := &ec2.DescribeRouteTablesInput{
		Filters: []*ec2.Filter{
			newEc2Filter("vpc-id", l.vpcID),
		},
	}

	rt, err := l.ec2.DescribeRouteTables(request)
	if err != nil {
		return nil, fmt.Errorf("error describe route table: %q", err)
	}

	subnetsByAZ := make(map[string]*ec2.Subnet)
	for _, subnet := range subnets {
		az := aws.StringValue(subnet.AvailabilityZone)
		id := aws.StringValue(subnet.SubnetId)
		if az == "" || id == "" {
			klog.Warningf("Ignoring subnet with empty az/id: %v", subnet)
			continue
		}

		isPublic, err := isSubnetPublic(rt.RouteTables, id)
		if err != nil {
			return nil, err
		}
		if !internalELB && !isPublic {
			klog.V(2).Infof("Ignoring private subnet for public ELB %q", id)
			continue
		}

		existing := subnetsByAZ[az]
		if existing == nil {
			subnetsByAZ[az] = subnet
			continue
		}

		// TODO: Try to break the tie using a tag

		// If we have two subnets for the same AZ we arbitrarily choose the one that is first lexicographically.
		// TODO: Should this be an error.
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

	var subnetIDs []string
	for _, key := range azNames {
		subnetIDs = append(subnetIDs, aws.StringValue(subnetsByAZ[key].SubnetId))
	}

	return subnetIDs, nil
}

// buildELBSecurityGroupList returns list of SecurityGroups which should be
// attached to ELB created by a service. List always consist of at least
// 1 member which is an SG created for this service or a SG from the Global config.
// Extra groups can be specified via annotation, as can extra tags for any
// new groups. The annotation "ServiceAnnotationLoadBalancerSecurityGroups" allows for
// setting the security groups specified.
func (l *loadbalancer) buildELBSecurityGroupList(serviceName types.NamespacedName, loadBalancerName string, annotations map[string]string) ([]string, error) {
	var err error
	var securityGroupID string

	sgList := getSGListFromAnnotation(annotations[ServiceAnnotationLoadBalancerSecurityGroups])

	// If no Security Groups have been specified with the ServiceAnnotationLoadBalancerSecurityGroups annotation, we add the default one.
	if len(sgList) == 0 {
		// Create a security group for the load balancer
		sgName := "k8s-elb-" + loadBalancerName
		sgDescription := fmt.Sprintf("Security group for Kubernetes ELB %s (%v)", loadBalancerName, serviceName)
		securityGroupID, err = l.ensureSecurityGroup(sgName, sgDescription, getKeyValuePairsFromAnnotation(annotations, ServiceAnnotationLoadBalancerAdditionalTags))
		if err != nil {
			klog.Errorf("Error creating load balancer security group: %q", err)
			return nil, err
		}
		sgList = append(sgList, securityGroupID)
	}

	extraSGList := getSGListFromAnnotation(annotations[ServiceAnnotationLoadBalancerExtraSecurityGroups])
	sgList = append(sgList, extraSGList...)

	return sgList, nil
}

// ensureLoadBalancer makes sure a load balancer is created or synced
func (l *loadbalancer) ensureLoadBalancer(namespacedName types.NamespacedName, loadBalancerName string, listeners []*elb.Listener, subnetIDs []string, securityGroupIDs []string, internalELB, proxyProtocol bool, loadBalancerAttributes *elb.LoadBalancerAttributes, annotations map[string]string) (*elb.LoadBalancerDescription, error) {
	loadBalancer, err := l.getLoadBalancerDescription(loadBalancerName)
	if err != nil {
		return nil, err
	}

	if loadBalancer == nil {
		// create a new load balancer
		request := &elb.CreateLoadBalancerInput{
			Listeners:        listeners,
			LoadBalancerName: aws.String(loadBalancerName),
		}

		if subnetIDs == nil {
			request.Subnets = nil
		} else {
			request.Subnets = aws.StringSlice(subnetIDs)
		}

		if securityGroupIDs == nil {
			request.SecurityGroups = nil
		} else {
			request.SecurityGroups = aws.StringSlice(securityGroupIDs)
		}

		// TODO: add tags

		klog.Infof("Creating load balancer for %v with name: %s", namespacedName, loadBalancerName)
		_, err := l.elb.CreateLoadBalancer(request)
		if err != nil {
			return nil, err
		}

		if proxyProtocol {
			err = l.createProxyProtocolPolicy(loadBalancerName)
			if err != nil {
				return nil, err
			}

			for _, listener := range listeners {
				klog.V(2).Infof("Adjusting AWS loadbalancer proxy protocol on node port %d. Setting to true", *listener.InstancePort)
				err := l.setBackendPolicies(loadBalancerName, *listener.InstancePort, []*string{aws.String(ProxyProtocolPolicyName)})
				if err != nil {
					return nil, err
				}
			}
		}
	} else {
		// Sync the current load balancer
		// Sync subnets
		err := l.syncSubnets(loadBalancerName, subnetIDs, loadBalancer)
		if err != nil {
			return nil, fmt.Errorf("error syncing loadbalancer subnets: %q", err)
		}

		// Sync security groups
		err = l.syncSecurityGroups(loadBalancerName, securityGroupIDs, loadBalancer)
		if err != nil {
			return nil, fmt.Errorf("error syncing loadbalancer security groups: %q", err)
		}

		// Sync listeners
		err = l.syncListeners(loadBalancerName, listeners, loadBalancer)
		if err != nil {
			return nil, fmt.Errorf("error syncing loadbalancer listenrs: %q", err)
		}

		// Sync proxy protocol state for new and existing listeners
		err = l.syncProxyProtocol(loadBalancerName, proxyProtocol, listeners, loadBalancer)
		if err != nil {
			return nil, fmt.Errorf("error syncing loadbalancer proxy protocol: %q", err)
		}

		// Add additional tags
		klog.V(2).Infof("Creating additional load balancer tags for %s", loadBalancerName)
		tags := getKeyValuePairsFromAnnotation(annotations, ServiceAnnotationLoadBalancerAdditionalTags)
		if len(tags) > 0 {
			err := l.addLoadBalancerTags(loadBalancerName, tags)
			if err != nil {
				return nil, fmt.Errorf("unable to create additional load balancer tags: %v", err)
			}
		}
	}

	// Whether the ELB was new or existing, sync attributes regardless. This accounts for things
	// that cannot be specified at the time of creation and can only be modified after the fact,
	// e.g. idle connection timeout.
	{
		describeAttributesRequest := &elb.DescribeLoadBalancerAttributesInput{}
		describeAttributesRequest.LoadBalancerName = aws.String(loadBalancerName)
		describeAttributesOutput, err := l.elb.DescribeLoadBalancerAttributes(describeAttributesRequest)
		if err != nil {
			klog.Warning("Unable to retrieve load balancer attributes during attribute sync")
			return nil, err
		}

		foundAttributes := &describeAttributesOutput.LoadBalancerAttributes

		// Update attributes if they're dirty
		if !reflect.DeepEqual(loadBalancerAttributes, foundAttributes) {
			klog.V(2).Infof("Updating load-balancer attributes for %q", loadBalancerName)

			modifyAttributesRequest := &elb.ModifyLoadBalancerAttributesInput{}
			modifyAttributesRequest.LoadBalancerName = aws.String(loadBalancerName)
			modifyAttributesRequest.LoadBalancerAttributes = loadBalancerAttributes
			_, err = l.elb.ModifyLoadBalancerAttributes(modifyAttributesRequest)
			if err != nil {
				return nil, fmt.Errorf("Unable to update load balancer attributes during attribute sync: %q", err)
			}
		}

		// double check if the load balancer exists after creation/update
		loadBalancer, err = l.getLoadBalancerDescription(loadBalancerName)
		if err != nil {
			klog.Warning("Unable to retrieve load balancer after creation/update")
			return nil, err
		}

		return loadBalancer, nil
	}
}

func (l *loadbalancer) addLoadBalancerTags(loadBalancerName string, requested map[string]string) error {
	var tags []*elb.Tag
	for k, v := range requested {
		tag := &elb.Tag{
			Key:   aws.String(k),
			Value: aws.String(v),
		}
		tags = append(tags, tag)
	}

	request := &elb.AddTagsInput{
		LoadBalancerNames: []*string{&loadBalancerName},
		Tags:              tags,
	}

	_, err := l.elb.AddTags(request)
	if err != nil {
		return fmt.Errorf("error adding tags to load balancer: %v", err)
	}

	return nil
}

// Sync subnets
func (l *loadbalancer) syncSubnets(loadBalancerName string, subnetIDs []string, lb *elb.LoadBalancerDescription) error {
	expected := sets.NewString(subnetIDs...)
	actual := stringSetFromPointers(lb.Subnets)

	additions := expected.Difference(actual)
	removals := actual.Difference(expected)

	if removals.Len() != 0 {
		request := &elb.DetachLoadBalancerFromSubnetsInput{
			LoadBalancerName: aws.String(loadBalancerName),
			Subnets:          stringSetToPointers(removals),
		}
		klog.V(2).Info("Detaching load balancer from removed subnets")

		_, err := l.elb.DetachLoadBalancerFromSubnets(request)
		if err != nil {
			return fmt.Errorf("error detaching AWS loadbalancer from subnets: %q", err)
		}
	}

	if additions.Len() != 0 {
		request := &elb.AttachLoadBalancerToSubnetsInput{
			LoadBalancerName: aws.String(loadBalancerName),
			Subnets:          stringSetToPointers(additions),
		}
		klog.V(2).Info("Attaching load balancer to added subnets")

		_, err := l.elb.AttachLoadBalancerToSubnets(request)
		if err != nil {
			return fmt.Errorf("error attaching AWS loadbalancer to subnets: %q", err)
		}
	}

	return nil
}

// Sync security groups
func (l *loadbalancer) syncSecurityGroups(loadBalancerName string, securityGroupIDs []string, lb *elb.LoadBalancerDescription) error {
	expected := sets.NewString(securityGroupIDs...)
	actual := stringSetFromPointers(lb.SecurityGroups)

	if !expected.Equal(actual) {
		// This call just replaces the security groups, unlike e.g. subnets (!)
		request := &elb.ApplySecurityGroupsToLoadBalancerInput{
			LoadBalancerName: aws.String(loadBalancerName),
		}

		if securityGroupIDs == nil {
			request.SecurityGroups = nil
		} else {
			request.SecurityGroups = aws.StringSlice(securityGroupIDs)
		}
		klog.V(2).Info("Applying updated security groups to load balancer")

		_, err := l.elb.ApplySecurityGroupsToLoadBalancer(request)
		if err != nil {
			return fmt.Errorf("error applying AWS loadbalancer security groups: %q", err)
		}
	}

	return nil
}

// Sync listeners
func (l *loadbalancer) syncListeners(loadBalancerName string, listeners []*elb.Listener, lb *elb.LoadBalancerDescription) error {
	additions, removals := syncElbListeners(loadBalancerName, listeners, lb.ListenerDescriptions)

	if len(removals) != 0 {
		request := &elb.DeleteLoadBalancerListenersInput{}
		request.LoadBalancerName = aws.String(loadBalancerName)
		request.LoadBalancerPorts = removals
		klog.V(2).Info("Deleting removed load balancer listeners")
		if _, err := l.elb.DeleteLoadBalancerListeners(request); err != nil {
			return fmt.Errorf("error deleting AWS loadbalancer listeners: %q", err)
		}
	}

	if len(additions) != 0 {
		request := &elb.CreateLoadBalancerListenersInput{}
		request.LoadBalancerName = aws.String(loadBalancerName)
		request.Listeners = additions
		klog.V(2).Info("Creating added load balancer listeners")
		if _, err := l.elb.CreateLoadBalancerListeners(request); err != nil {
			fmt.Errorf("error creating AWS loadbalancer listeners: %q", err)
		}
	}

	return nil
}

// Sync proxy protocol state for new and existing listeners
func (l *loadbalancer) syncProxyProtocol(loadBalancerName string, proxyProtocol bool, listeners []*elb.Listener, lb *elb.LoadBalancerDescription) error {
	proxyPolicies := make([]*string, 0)
	if proxyProtocol {
		// Ensure the backend policy exists
		err := l.createProxyProtocolPolicy(loadBalancerName)
		if err != nil {
			return err
		}

		proxyPolicies = append(proxyPolicies, aws.String(ProxyProtocolPolicyName))
	}

	foundBackends := make(map[int64]bool)
	proxyProtocolBackends := make(map[int64]bool)
	for _, backendListener := range lb.BackendServerDescriptions {
		foundBackends[*backendListener.InstancePort] = false
		proxyProtocolBackends[*backendListener.InstancePort] = proxyProtocolEnabled(backendListener)
	}

	for _, listener := range listeners {
		setPolicy := false
		instancePort := *listener.InstancePort

		if currentState, ok := proxyProtocolBackends[instancePort]; !ok {
			// This is a new ELB backend so we only need to worry about
			// potentially adding a policy and not removing an
			// existing one
			setPolicy = proxyProtocol
		} else {
			foundBackends[instancePort] = true
			// This is an existing ELB backend so we need to determine
			// if the state changed
			setPolicy = (currentState != proxyProtocol)
		}

		if setPolicy {
			klog.V(2).Infof("Adjusting AWS loadbalancer proxy protocol on node port %d. Setting to %t", instancePort, proxyProtocol)
			err := l.setBackendPolicies(loadBalancerName, instancePort, proxyPolicies)
			if err != nil {
				return err
			}
		}
	}

	// We now need to figure out if any backend policies need removed
	// because these old policies will stick around even if there is no
	// corresponding listener anymore
	for instancePort, found := range foundBackends {
		if !found {
			klog.V(2).Infof("Adjusting AWS loadbalancer proxy protocol on node port %d. Setting to false", instancePort)
			err := l.setBackendPolicies(loadBalancerName, instancePort, []*string{})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// syncElbListeners computes a plan to reconcile the desired vs actual state of the listeners on an ELB
// NOTE: there exists an O(nlgn) implementation for this function. However, as the default limit of
//       listeners per elb is 100, this implementation is reduced from O(m*n) => O(n).
func syncElbListeners(loadBalancerName string, listeners []*elb.Listener, listenerDescriptions []*elb.ListenerDescription) ([]*elb.Listener, []*int64) {
	foundSet := make(map[int]bool)
	removals := []*int64{}
	additions := []*elb.Listener{}

	for _, listenerDescription := range listenerDescriptions {
		actual := listenerDescription.Listener
		if actual == nil {
			klog.Warning("Ignoring empty listener in AWS loadbalancer: ", loadBalancerName)
			continue
		}

		found := false
		for i, expected := range listeners {
			if expected == nil {
				klog.Warning("Ignoring empty desired listener for loadbalancer: ", loadBalancerName)
				continue
			}
			if elbListenersAreEqual(actual, expected) {
				// The current listener on the actual
				// elb is in the set of desired listeners.
				foundSet[i] = true
				found = true
				break
			}
		}
		if !found {
			removals = append(removals, actual.LoadBalancerPort)
		}
	}

	for i := range listeners {
		if !foundSet[i] {
			additions = append(additions, listeners[i])
		}
	}

	return additions, removals
}

func (l *loadbalancer) createProxyProtocolPolicy(loadBalancerName string) error {
	request := &elb.CreateLoadBalancerPolicyInput{
		LoadBalancerName: aws.String(loadBalancerName),
		PolicyAttributes: []*elb.PolicyAttribute{
			{
				AttributeName:  aws.String("ProxyProtocol"),
				AttributeValue: aws.String("true"),
			},
		},
		PolicyName:     aws.String(ProxyProtocolPolicyName),
		PolicyTypeName: aws.String("ProxyProtocolPolicyType"),
	}
	klog.V(2).Info("Creating proxy protocol policy on load balancer")

	_, err := l.elb.CreateLoadBalancerPolicy(request)
	if err != nil {
		return fmt.Errorf("error creating proxy protocol policy on load balancer: %q", err)
	}

	return nil
}

func (l *loadbalancer) setBackendPolicies(loadBalancerName string, instancePort int64, policies []*string) error {
	request := &elb.SetLoadBalancerPoliciesForBackendServerInput{
		InstancePort:     aws.Int64(instancePort),
		LoadBalancerName: aws.String(loadBalancerName),
		PolicyNames:      policies,
	}

	if len(policies) > 0 {
		klog.V(2).Infof("Adding AWS loadbalancer backend policies on node port %d", instancePort)
	} else {
		klog.V(2).Infof("Removing AWS loadbalancer backend policies on node port %d", instancePort)
	}

	_, err := l.elb.SetLoadBalancerPoliciesForBackendServer(request)
	if err != nil {
		return fmt.Errorf("error adjusting AWS loadbalancer backend policies: %q", err)
	}

	return nil
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

// Makes sure the security group exists.
// For multi-cluster isolation, name must be globally unique, for example derived from the service UUID.
// Additional tags can be specified
// Returns the security group id or error
func (l *loadbalancer) ensureSecurityGroup(name string, description string, additionalTags map[string]string) (string, error) {
	attempt := 0
	groupID := ""

	for {
		attempt++

		// TODO: specify correct vpcID
		request := &ec2.DescribeSecurityGroupsInput{
			Filters: []*ec2.Filter{
				newEc2Filter("group-name", name),
				newEc2Filter("vpc-id", l.vpcID),
			},
		}

		response, err := l.ec2.DescribeSecurityGroups(request)
		if err != nil {
			return "", fmt.Errorf("error querying security groups for ELB: %q", err)
		}

		securityGroups := response.SecurityGroups
		if len(securityGroups) >= 1 {
			if len(securityGroups) > 1 {
				klog.Warningf("Found multiple security groups with name: %q", name)
			}

			return aws.StringValue(securityGroups[0].GroupId), nil
		}

		// create security group
		createRequest := &ec2.CreateSecurityGroupInput{
			Description: &description,
			GroupName:   &name,
			VpcId:       aws.String("vpc-fake"),
		}

		createResponse, err := l.ec2.CreateSecurityGroup(createRequest)
		if err != nil {
			ignore := false
			switch err := err.(type) {
			case awserr.Error:
				if err.Code() == "InvalidGroup.Duplicate" && attempt < MaxReadThenCreateRetries {
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
			groupID = aws.StringValue(createResponse.GroupId)
			break
		}
	}

	if groupID == "" {
		return "", fmt.Errorf("created security group, but id was not returned: %s", name)
	}

	return groupID, nil
}
