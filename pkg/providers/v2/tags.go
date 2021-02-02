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
	"errors"
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
)

const (
	// TagNameKubernetesClusterPrefix is the tag name we use to differentiate multiple
	// logically independent clusters running in the same AZ.
	// tag format: kubernetes.io/cluster/<clusterID> = shared|owned
	// The tag key = TagNameKubernetesClusterPrefix + clusterID
	// The tag value is an ownership value
	TagNameKubernetesClusterPrefix = "kubernetes.io/cluster/"

	// createTag* is configuration of exponential backoff for CreateTag call. We
	// retry mainly because if we create an object, we cannot tag it until it is
	// "fully created" (eventual consistency). Starting with 1 second, doubling
	// it every step and taking 9 steps results in 255 second total waiting
	// time.
	// TODO: revisit these values
	createTagInitialDelay = 1 * time.Second
	createTagFactor       = 2.0
	createTagSteps        = 9

	// ResourceLifecycleOwned is the value we use when tagging resources to indicate
	// that the resource is considered owned and managed by the cluster,
	// and in particular that the lifecycle is tied to the lifecycle of the cluster.
	ResourceLifecycleOwned = "owned"
)

type awsTagging struct {
	// ClusterName is our cluster identifier: we tag AWS resources with this value,
	// and thus we can run two independent clusters in the same VPC or subnets.
	ClusterName string
}

// newAWSTags is a constructor function for awsTagging
func newAWSTags(clusterName string) (awsTagging, error) {
	if clusterName != "" {
		klog.Infof("AWS cloud filtering on ClusterName: %v", clusterName)
	} else {
		return awsTagging{}, errors.New("No ClusterName found in the config")
	}

	return awsTagging{
		ClusterName: clusterName,
	}, nil
}

// Extracts the cluster name from the given tags, if they are present
// If duplicate tags are found, returns an error
func findClusterName(tags []*ec2.Tag) (string, error) {
	clusterName := ""

	for _, tag := range tags {
		tagKey := aws.StringValue(tag.Key)
		if strings.HasPrefix(tagKey, TagNameKubernetesClusterPrefix) {
			name := strings.TrimPrefix(tagKey, TagNameKubernetesClusterPrefix)
			if clusterName != "" {
				return "", fmt.Errorf("Found multiple cluster tags with prefix %s (%q and %q)", TagNameKubernetesClusterPrefix, clusterName, name)
			}
			clusterName = name
		}
	}

	return clusterName, nil
}

func (t *awsTagging) hasClusterTag(tags []*ec2.Tag) error {
	if len(t.ClusterName) == 0 {
		return errors.New("cluster name is not configured (an empty value)")
	}

	for _, tag := range tags {
		tagKey := aws.StringValue(tag.Key)
		if tagKey == (TagNameKubernetesClusterPrefix + t.ClusterName) {
			return nil
		}
	}

	return errors.New("cluster tag does not exist")
}

func (t *awsTagging) buildTags(additionalTags map[string]string, lifecycle string) map[string]string {
	tags := make(map[string]string)
	for tagKey, tagValue := range additionalTags {
		tags[tagKey] = tagValue
	}

	// no clusterName is a sign of misconfigured cluster, but we can't be tagging the resources with empty
	// strings
	// TODO: revise the logic
	if len(t.ClusterName) == 0 {
		return tags
	}

	// tag format: kubernetes.io/cluster/<clusterID> = shared|owned
	tags[TagNameKubernetesClusterPrefix+t.ClusterName] = lifecycle

	return tags
}

// createTags calls EC2 CreateTags, but adds retry-on-failure logic
// We retry mainly because if we create an object, we cannot tag it until it is "fully created" (eventual consistency)
// The error code varies though (depending on what we are tagging), so we simply retry on all errors
func (t *awsTagging) createTags(ec2Client EC2, resourceID string, lifecycle string, additionalTags map[string]string) error {
	tags := t.buildTags(additionalTags, lifecycle)

	if tags == nil || len(tags) == 0 {
		return nil
	}

	var awsTags []*ec2.Tag
	for tagKey, tagValue := range tags {
		tag := &ec2.Tag{
			Key:   aws.String(tagKey),
			Value: aws.String(tagValue),
		}
		awsTags = append(awsTags, tag)
	}

	backoff := wait.Backoff{
		Duration: createTagInitialDelay,
		Factor:   createTagFactor,
		Steps:    createTagSteps,
	}

	request := &ec2.CreateTagsInput{
		Resources: []*string{&resourceID},
		Tags:      awsTags,
	}

	var lastErr error
	err := wait.ExponentialBackoff(backoff, func() (bool, error) {
		_, err := ec2Client.CreateTags(request)
		if err == nil {
			return true, nil
		}

		// We could check that the error is retryable, but the error code changes based on what we are tagging
		// SecurityGroup: InvalidGroup.NotFound
		klog.V(2).Infof("Failed to create tags; will retry.  Error was %q", err)
		lastErr = err
		return false, nil
	})
	if err == wait.ErrWaitTimeout {
		// return real CreateTags error instead of timeout
		err = lastErr
	}

	return err
}

func (t *awsTagging) clusterName() string {
	return t.ClusterName
}
