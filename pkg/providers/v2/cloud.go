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
	"io/ioutil"
	"regexp"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"

	cloudprovider "k8s.io/cloud-provider"
	"k8s.io/cloud-provider-aws/pkg/apis/config/v1alpha1"
	"sigs.k8s.io/yaml"
)

func init() {
	cloudprovider.RegisterCloudProvider(ProviderName, func(config io.Reader) (cloudprovider.Interface, error) {
		cfg, err := readAWSCloudConfig(config)
		if err != nil {
			return nil, fmt.Errorf("failed to read AWS cloud provider config file: %v", err)
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
	creds     *credentials.Credentials
	instances cloudprovider.InstancesV2
	region    string
	ec2       EC2
	metadata  EC2Metadata
	tagging   awsTagging
}

// EC2 is an interface defining only the methods we call from the AWS EC2 SDK.
type EC2 interface {
	DescribeInstances(request *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error)

	CreateTags(*ec2.CreateTagsInput) (*ec2.CreateTagsOutput, error)
}

// EC2Metadata is an abstraction over the AWS metadata service.
type EC2Metadata interface {
	// Query the EC2 metadata service (used to discover instance-id etc)
	GetMetadata(path string) (string, error)
}

func readAWSCloudConfig(config io.Reader) (*v1alpha1.AWSCloudConfig, error) {
	if config == nil {
		return nil, fmt.Errorf("no AWS cloud provider config file given")
	}

	// read the config file
	data, err := ioutil.ReadAll(config)
	if err != nil {
		return nil, fmt.Errorf("unable to read cloud configuration from %q [%v]", config, err)
	}

	var cfg v1alpha1.AWSCloudConfig
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		// we got an error where the decode wasn't related to a missing type
		return nil, err
	}
	if cfg.Kind != "AWSCloudConfig" {
		return nil, fmt.Errorf("invalid cloud configuration object %q", cfg.Kind)
	}

	return &cfg, nil
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

// newCloud creates a new instance of AWSCloud.
func newCloud(cfg v1alpha1.AWSCloudConfig) (cloudprovider.Interface, error) {
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

	awsCloud := &cloud{
		creds:     creds,
		instances: instances,
		region:    region,
		metadata:  metadataClient,
		ec2:       ec2Service,
	}

	if cfg.Config.ClusterName != "" {
		if err := awsCloud.tagging.init(cfg.Config.ClusterName); err != nil {
			return nil, err
		}
	}

	return awsCloud, nil
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
	return nil, false
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
	return len(c.tagging.clusterName()) > 0
}

// InstancesV2 is an implementation for instances and should only be implemented by external cloud providers.
// Implementing InstancesV2 is behaviorally identical to Instances but is optimized to significantly reduce
// API calls to the cloud provider when registering and syncing nodes.
// Also returns true if the interface is supported, false otherwise.
// WARNING: InstancesV2 is an experimental interface and is subject to change in v1.20.
func (c *cloud) InstancesV2() (cloudprovider.InstancesV2, bool) {
	return c.instances, true
}
