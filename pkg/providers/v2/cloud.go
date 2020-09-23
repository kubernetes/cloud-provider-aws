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
	"fmt"
	"io"
	"regexp"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"gopkg.in/gcfg.v1"

	cloudprovider "k8s.io/cloud-provider"
)

func init() {
	cloudprovider.RegisterCloudProvider(ProviderName, func(config io.Reader) (cloudprovider.Interface, error) {
		cfg, err := readAWSCloudConfig(config)
		if err != nil {
			return nil, fmt.Errorf("unable to read AWS cloud provider config file: %v", err)
		}

		return newCloud(*cfg)
	})
}

const (
	// ProviderName is the name of the v2 AWS cloud provider
	ProviderName = "aws/v2"
)

var _ cloudprovider.Interface = (*cloud)(nil)

// cloud is the AWS v2 implementation of the cloud provider interface
type cloud struct {
	creds        *credentials.Credentials
	instances    cloudprovider.InstancesV2
	region       string
	ec2          EC2
	metadata     EC2Metadata
	loadbalancer cloudprovider.LoadBalancer
	cfg          *CloudConfig
}

// CloudConfig wraps the settings for the AWS cloud provider.
type CloudConfig struct {
	Global struct {
		// The AWS VPC flag enables the possibility to run the master components
		// on a different aws account, on a different cloud provider or on-premises.
		// If the flag is set also the KubernetesClusterTag must be provided
		VPC string
		// SubnetID enables using a specific subnet to use for ELB's
		SubnetID string
	}
}

// EC2 is an interface defining only the methods we call from the AWS EC2 SDK.
type EC2 interface {
	DescribeInstances(request *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error)
	DescribeSecurityGroups(request *ec2.DescribeSecurityGroupsInput) (*ec2.DescribeSecurityGroupsOutput, error)

	DeleteSecurityGroup(request *ec2.DeleteSecurityGroupInput) (*ec2.DeleteSecurityGroupOutput, error)
	CreateSecurityGroup(*ec2.CreateSecurityGroupInput) (*ec2.CreateSecurityGroupOutput, error)

	AuthorizeSecurityGroupIngress(*ec2.AuthorizeSecurityGroupIngressInput) (*ec2.AuthorizeSecurityGroupIngressOutput, error)
	RevokeSecurityGroupIngress(*ec2.RevokeSecurityGroupIngressInput) (*ec2.RevokeSecurityGroupIngressOutput, error)

	DescribeSubnets(*ec2.DescribeSubnetsInput) (*ec2.DescribeSubnetsOutput, error)

	DescribeRouteTables(request *ec2.DescribeRouteTablesInput) (*ec2.DescribeRouteTablesOutput, error)
}

// EC2Metadata is an abstraction over the AWS metadata service.
type EC2Metadata interface {
	// Query the EC2 metadata service (used to discover instance-id etc)
	GetMetadata(path string) (string, error)
}

func getAvailabilityZone(metadata EC2Metadata) (string, error) {
	return metadata.GetMetadata("placement/availability-zone")
}

// Derives the region from a valid az name.
// Returns an error if the az is known invalid (empty)
func azToRegion(az string) (string, error) {
	if len(az) == 0 {
		return "", fmt.Errorf("invalid (empty) AZ")
	}

	r := regexp.MustCompile(`^([a-zA-Z]+-)+\d+`)
	region := r.FindString(az)
	if region == "" {
		return "", fmt.Errorf("invalid AZ: %s", az)
	}

	return region, nil
}

// readAWSCloudConfig reads an instance of AWSCloudConfig from config reader.
func readAWSCloudConfig(config io.Reader) (*CloudConfig, error) {
	var cfg CloudConfig
	var err error

	if config != nil {
		err = gcfg.ReadInto(&cfg, config)
		if err != nil {
			return nil, err
		}
	}

	return &cfg, nil
}

// newCloud creates a new instance of AWSCloud.
func newCloud(cfg CloudConfig) (cloudprovider.Interface, error) {
	sess, err := session.NewSession(&aws.Config{})
	if err != nil {
		return nil, fmt.Errorf("unable to initialize AWS session: %v", err)
	}

	creds := credentials.NewChainCredentials(
		[]credentials.Provider{
			&credentials.EnvProvider{},
			&ec2rolecreds.EC2RoleProvider{
				Client: ec2metadata.New(sess),
			},
			&credentials.SharedCredentialsProvider{},
		})

	metadataClient := ec2metadata.New(sess)
	if err != nil {
		return nil, fmt.Errorf("error creating AWS metadata client: %q", err)
	}

	az, err := getAvailabilityZone(metadataClient)
	if err != nil {
		return nil, err
	}

	region, err := azToRegion(az)
	if err != nil {
		return nil, err
	}

	instances, err := newInstances(az, creds)
	if err != nil {
		return nil, err
	}

	loadbalancer, err := newLoadBalancer(region, creds, cfg.Global.VPC, cfg.Global.SubnetID)
	if err != nil {
		return nil, err
	}

	ec2Sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: creds,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to initialize AWS session: %v", err)
	}

	ec2Service := ec2.New(ec2Sess)
	if err != nil {
		return nil, fmt.Errorf("error creating AWS ec2 client: %q", err)
	}

	return &cloud{
		creds:        creds,
		instances:    instances,
		region:       region,
		metadata:     metadataClient,
		ec2:          ec2Service,
		loadbalancer: loadbalancer,
		cfg:          &cfg,
	}, nil
}

// Initialize passes a Kubernetes clientBuilder interface to the cloud provider
func (c *cloud) Initialize(clientBuilder cloudprovider.ControllerClientBuilder, stop <-chan struct{}) {
}

// Clusters returns the list of clusters.
func (c *cloud) Clusters() (cloudprovider.Clusters, bool) {
	return nil, false
}

// ProviderName returns the cloud provider ID.
func (c *cloud) ProviderName() string {
	return ProviderName
}

// LoadBalancer returns an implementation of LoadBalancer for Amazon Web Services.
func (c *cloud) LoadBalancer() (cloudprovider.LoadBalancer, bool) {
	return c.loadbalancer, true
}

// Instances returns an implementation of Instances for Amazon Web Services.
func (c *cloud) Instances() (cloudprovider.Instances, bool) {
	return nil, false
}

// Zones returns an implementation of Zones for Amazon Web Services.
func (c *cloud) Zones() (cloudprovider.Zones, bool) {
	return nil, false
}

// Routes returns an implementation of Routes for Amazon Web Services.
func (c *cloud) Routes() (cloudprovider.Routes, bool) {
	return nil, false
}

// HasClusterID returns true if the cluster has a clusterID
func (c *cloud) HasClusterID() bool {
	return false
}

// InstancesV2 is an implementation for instances and should only be implemented by external cloud providers.
// Implementing InstancesV2 is behaviorally identical to Instances but is optimized to significantly reduce
// API calls to the cloud provider when registering and syncing nodes.
// Also returns true if the interface is supported, false otherwise.
// WARNING: InstancesV2 is an experimental interface and is subject to change in v1.20.
func (c *cloud) InstancesV2() (cloudprovider.InstancesV2, bool) {
	return c.instances, true
}
