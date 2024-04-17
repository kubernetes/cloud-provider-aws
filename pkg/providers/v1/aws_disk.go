/*
Copyright 2024 The Kubernetes Authors.

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
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"k8s.io/apimachinery/pkg/util/wait"
)

type awsDisk struct {
	ec2 EC2

	// Name in k8s
	name KubernetesVolumeID
	// id in AWS
	awsID EBSVolumeID
}

func newAWSDisk(aws *Cloud, name KubernetesVolumeID) (*awsDisk, error) {
	awsID, err := name.MapToAWSVolumeID()
	if err != nil {
		return nil, err
	}
	disk := &awsDisk{ec2: aws.ec2, name: name, awsID: awsID}
	return disk, nil
}

// Helper function for describeVolume callers. Tries to retype given error to AWS error
// and returns true in case the AWS error is "InvalidVolume.NotFound", false otherwise
func isAWSErrorVolumeNotFound(err error) bool {
	if err != nil {
		if awsError, ok := err.(awserr.Error); ok {
			// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html
			if awsError.Code() == "InvalidVolume.NotFound" {
				return true
			}
		}
	}
	return false
}

// Gets the full information about this volume from the EC2 API
func (d *awsDisk) describeVolume() (*ec2.Volume, error) {
	volumeID := d.awsID

	request := &ec2.DescribeVolumesInput{
		VolumeIds: []*string{volumeID.awsString()},
	}

	volumes, err := d.ec2.DescribeVolumes(request)
	if err != nil {
		return nil, err
	}
	if len(volumes) == 0 {
		return nil, fmt.Errorf("no volumes found")
	}
	if len(volumes) > 1 {
		return nil, fmt.Errorf("multiple volumes found")
	}
	return volumes[0], nil
}

func (d *awsDisk) describeVolumeModification() (*ec2.VolumeModification, error) {
	volumeID := d.awsID
	request := &ec2.DescribeVolumesModificationsInput{
		VolumeIds: []*string{volumeID.awsString()},
	}
	volumeMods, err := d.ec2.DescribeVolumeModifications(request)

	if err != nil {
		return nil, fmt.Errorf("error describing volume modification %s with %v", volumeID, err)
	}

	if len(volumeMods) == 0 {
		return nil, fmt.Errorf("no volume modifications found for %s", volumeID)
	}
	lastIndex := len(volumeMods) - 1
	return volumeMods[lastIndex], nil
}

func (d *awsDisk) modifyVolume(requestGiB int64) (int64, error) {
	volumeID := d.awsID

	request := &ec2.ModifyVolumeInput{
		VolumeId: volumeID.awsString(),
		Size:     aws.Int64(requestGiB),
	}
	output, err := d.ec2.ModifyVolume(request)
	if err != nil {
		modifyError := fmt.Errorf("AWS modifyVolume failed for %s with %v", volumeID, err)
		return requestGiB, modifyError
	}

	volumeModification := output.VolumeModification

	if aws.StringValue(volumeModification.ModificationState) == ec2.VolumeModificationStateCompleted {
		return aws.Int64Value(volumeModification.TargetSize), nil
	}

	backoff := wait.Backoff{
		Duration: 1 * time.Second,
		Factor:   2,
		Steps:    10,
	}

	checkForResize := func() (bool, error) {
		volumeModification, err := d.describeVolumeModification()

		if err != nil {
			return false, err
		}

		// According to https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring_mods.html
		// Size changes usually take a few seconds to complete and take effect after a volume is in the Optimizing state.
		if aws.StringValue(volumeModification.ModificationState) == ec2.VolumeModificationStateOptimizing {
			return true, nil
		}
		return false, nil
	}
	waitWithErr := wait.ExponentialBackoff(backoff, checkForResize)
	return requestGiB, waitWithErr
}
