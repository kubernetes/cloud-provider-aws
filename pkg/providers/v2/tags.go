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
	// tag format: kubernetes.io/cluster/=<clusterName>
	TagNameKubernetesClusterPrefix = "kubernetes.io/cluster/"

	// createTag* is configuration of exponential backoff for CreateTag call. We
	// retry mainly because if we create an object, we cannot tag it until it is
	// "fully created" (eventual consistency). Starting with 1 second, doubling
	// it every step and taking 9 steps results in 255 second total waiting
	// time.
	createTagInitialDelay = 1 * time.Second
	createTagFactor       = 2.0
	createTagSteps        = 9
)

type awsTagging struct {
	// ClusterName is our cluster identifier: we tag AWS resources with this value,
	// and thus we can run two independent clusters in the same VPC or subnets.
	ClusterName string
}

// Extracts the cluster name from the given tags, if they are present
// If duplicate tags are found, returns an error
func findClusterName(tags []*ec2.Tag) (string, error) {
	clusterName := ""

	for _, tag := range tags {
		tagKey := aws.StringValue(tag.Key)
		if strings.HasPrefix(tagKey, TagNameKubernetesClusterPrefix) {
			name := aws.StringValue(tag.Value)
			if clusterName != "" {
				return "", fmt.Errorf("Found multiple cluster tags with prefix %s (%q and %q)", TagNameKubernetesClusterPrefix, clusterName, name)
			}
			clusterName = name
		}
	}

	return clusterName, nil
}

func (t *awsTagging) init(clusterName string) error {
	t.ClusterName = clusterName

	if clusterName != "" {
		klog.Infof("AWS cloud filtering on ClusterName: %v", clusterName)
	} else {
		return fmt.Errorf("AWS cloud failed to find ClusterName")
	}

	return nil
}

// Extracts a cluster name from the given tags, if one is present
// If no clusterName is found, returns "", nil
// If multiple (different) clusterNames are found, returns an error
func (t *awsTagging) initFromTags(tags []*ec2.Tag) error {
	clusterName, err := findClusterName(tags)
	if err != nil {
		return err
	}

	if clusterName == "" {
		klog.Errorf("Tag %q not found; Kubernetes may behave unexpectedly.", TagNameKubernetesClusterPrefix)
	}

	return t.init(clusterName)
}

func (t *awsTagging) hasClusterTag(tags []*ec2.Tag) bool {
	// if the clusterName is not configured -- we consider all instances.
	if len(t.ClusterName) == 0 {
		return true
	}

	for _, tag := range tags {
		tagKey := aws.StringValue(tag.Key)
		if (tagKey == TagNameKubernetesClusterPrefix) && (aws.StringValue(tag.Value) == t.ClusterName) {
			return true
		}
	}

	return false
}

func (t *awsTagging) buildTags(additionalTags map[string]string, lifecycle string) map[string]string {
	tags := make(map[string]string)
	for k, v := range additionalTags {
		tags[k] = v
	}

	// no clusterName is a sign of misconfigured cluster, but we can't be tagging the resources with empty
	// strings
	if len(t.ClusterName) == 0 {
		return tags
	}

	// tag format: kubernetes.io/cluster/=<clusterName>
	tags[TagNameKubernetesClusterPrefix] = t.ClusterName

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
	for k, v := range tags {
		tag := &ec2.Tag{
			Key:   aws.String(k),
			Value: aws.String(v),
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
