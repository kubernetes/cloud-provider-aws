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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"k8s.io/apimachinery/pkg/types"
	cloudprovider "k8s.io/cloud-provider"
)

// newZones returns an implementation of cloudprovider.Zones
// TODO:
// We should add zones / region support via InstancesV2 since kubernetes/kubernetes#93569 was merged in v1.20, where zone/region is just added to InstanceMetadata and implemented as part of InstancesV2
func newZones(az string, creds *credentials.Credentials) (cloudprovider.Zones, error) {
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

	return &zones{
		availabilityZone: az,
		ec2:              ec2Service,
		region:           region,
	}, nil
}

// zones is an implementation of cloudprovider.Zones
type zones struct {
	availabilityZone string
	ec2              EC2
	region           string
}

// GetZone returns the Zone containing the current failure zone and locality region that the program is running in
func (z *zones) GetZone(ctx context.Context) (cloudprovider.Zone, error) {
	return cloudprovider.Zone{
		FailureDomain: z.availabilityZone,
		Region:        z.region,
	}, nil
}

// GetZoneByProviderID returns the Zone containing the current zone and locality region of the node specified by providerID
func (z *zones) GetZoneByProviderID(ctx context.Context, providerID string) (cloudprovider.Zone, error) {
	instance, err := getInstanceByProviderID(ctx, providerID, z.ec2)
	if err != nil {
		return cloudprovider.Zone{}, err
	}

	az := instance.Placement.AvailabilityZone
	regionName, err := azToRegion(*az)
	if err != nil {
		return cloudprovider.Zone{}, err
	}

	return cloudprovider.Zone{
		FailureDomain: *az,
		Region:        regionName,
	}, nil
}

// GetZoneByNodeName returns the Zone containing the current zone and locality region of the node specified by node name
func (z *zones) GetZoneByNodeName(ctx context.Context, nodeName types.NodeName) (cloudprovider.Zone, error) {
	instance, err := getInstanceByPrivateDNSName(ctx, nodeName, z.ec2)
	if err != nil {
		return cloudprovider.Zone{}, err
	}

	az := instance.Placement.AvailabilityZone
	regionName, err := azToRegion(*az)
	if err != nil {
		return cloudprovider.Zone{}, err
	}

	return cloudprovider.Zone{
		FailureDomain: *az,
		Region:        regionName,
	}, nil
}
