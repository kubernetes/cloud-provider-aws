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
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/stretchr/testify/assert"
	"k8s.io/klog/v2"

	"k8s.io/cloud-provider-aws/pkg/providers/v1/config"
)

func TestFilterTags(t *testing.T) {
	awsServices := NewFakeAWSServices(TestClusterID)
	c, err := newAWSCloud(config.CloudConfig{}, awsServices)
	if err != nil {
		t.Errorf("Error building aws cloud: %v", err)
		return
	}

	if c.tagging.ClusterID != TestClusterID {
		t.Errorf("unexpected ClusterID: %v", c.tagging.ClusterID)
	}
}

func TestFindClusterID(t *testing.T) {
	grid := []struct {
		Tags           map[string]string
		ExpectedNew    string
		ExpectedLegacy string
		ExpectError    bool
	}{
		{
			Tags: map[string]string{},
		},
		{
			Tags: map[string]string{
				TagNameKubernetesClusterLegacy: "a",
			},
			ExpectedLegacy: "a",
		},
		{
			Tags: map[string]string{
				TagNameKubernetesClusterPrefix + "a": "owned",
			},
			ExpectedNew: "a",
		},
		{
			Tags: map[string]string{
				TagNameKubernetesClusterPrefix + "a": "shared",
			},
			ExpectedNew: "a",
		},
		{
			Tags: map[string]string{
				TagNameKubernetesClusterPrefix + "a": "",
			},
			ExpectedNew: "a",
		},
		{
			Tags: map[string]string{
				TagNameKubernetesClusterLegacy:       "a",
				TagNameKubernetesClusterPrefix + "a": "",
			},
			ExpectedLegacy: "a",
			ExpectedNew:    "a",
		},
		{
			Tags: map[string]string{
				TagNameKubernetesClusterPrefix + "a": "",
				TagNameKubernetesClusterPrefix + "b": "",
			},
			ExpectError: true,
		},
	}
	for _, g := range grid {
		var ec2Tags []ec2types.Tag
		for k, v := range g.Tags {
			ec2Tags = append(ec2Tags, ec2types.Tag{Key: aws.String(k), Value: aws.String(v)})
		}
		actualLegacy, actualNew, err := findClusterIDs(ec2Tags)
		if g.ExpectError {
			if err == nil {
				t.Errorf("expected error for tags %v", g.Tags)
				continue
			}
		} else {
			if err != nil {
				t.Errorf("unexpected error for tags %v: %v", g.Tags, err)
				continue
			}

			if g.ExpectedNew != actualNew {
				t.Errorf("unexpected new clusterid for tags %v: %s vs %s", g.Tags, g.ExpectedNew, actualNew)
				continue
			}

			if g.ExpectedLegacy != actualLegacy {
				t.Errorf("unexpected new clusterid for tags %v: %s vs %s", g.Tags, g.ExpectedLegacy, actualLegacy)
				continue
			}
		}
	}
}

func TestHasClusterTag(t *testing.T) {
	awsServices := NewFakeAWSServices(TestClusterID)
	c, err := newAWSCloud(config.CloudConfig{}, awsServices)
	if err != nil {
		t.Errorf("Error building aws cloud: %v", err)
		return
	}
	grid := []struct {
		Tags     map[string]string
		Expected bool
	}{
		{
			Tags: map[string]string{},
		},
		{
			Tags: map[string]string{
				TagNameKubernetesClusterLegacy: TestClusterID,
			},
			Expected: true,
		},
		{
			Tags: map[string]string{
				TagNameKubernetesClusterLegacy: "a",
			},
			Expected: false,
		},
		{
			Tags: map[string]string{
				TagNameKubernetesClusterPrefix + TestClusterID: "owned",
			},
			Expected: true,
		},
		{
			Tags: map[string]string{
				TagNameKubernetesClusterPrefix + TestClusterID: "",
			},
			Expected: true,
		},
		{
			Tags: map[string]string{
				TagNameKubernetesClusterLegacy:                 "a",
				TagNameKubernetesClusterPrefix + TestClusterID: "shared",
			},
			Expected: true,
		},
		{
			Tags: map[string]string{
				TagNameKubernetesClusterPrefix + TestClusterID: "shared",
				TagNameKubernetesClusterPrefix + "b":           "shared",
			},
			Expected: true,
		},
	}
	for _, g := range grid {
		var ec2Tags []ec2types.Tag
		for k, v := range g.Tags {
			ec2Tags = append(ec2Tags, ec2types.Tag{Key: aws.String(k), Value: aws.String(v)})
		}
		result := c.tagging.hasClusterTag(ec2Tags)
		if result != g.Expected {
			t.Errorf("Unexpected result for tags %v: %t", g.Tags, result)
		}
	}
}

func TestHasNoClusterPrefixTag(t *testing.T) {
	awsServices := NewFakeAWSServices(TestClusterID)
	c, err := newAWSCloud(config.CloudConfig{}, awsServices)
	if err != nil {
		t.Errorf("Error building aws cloud: %v", err)
		return
	}
	tests := []struct {
		name string
		tags []ec2types.Tag
		want bool
	}{
		{
			name: "no tags",
			want: true,
		},
		{
			name: "no cluster tags",
			tags: []ec2types.Tag{
				{
					Key:   aws.String("not a cluster tag"),
					Value: aws.String("true"),
				},
			},
			want: true,
		},
		{
			name: "contains cluster tags",
			tags: []ec2types.Tag{
				{
					Key:   aws.String("tag1"),
					Value: aws.String("value1"),
				},
				{
					Key:   aws.String("kubernetes.io/cluster/test.cluster"),
					Value: aws.String("owned"),
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, c.tagging.hasNoClusterPrefixTag(tt.tags))
		})
	}
}

func TestTagResource(t *testing.T) {
	testFlags := flag.NewFlagSet("TestTagResource", flag.ExitOnError)
	klog.InitFlags(testFlags)
	testFlags.Parse([]string{"--logtostderr=false"})
	awsServices := NewFakeAWSServices(TestClusterID)
	c, err := newAWSCloud(config.CloudConfig{}, awsServices)
	if err != nil {
		t.Errorf("Error building aws cloud: %v", err)
		return
	}

	tests := []struct {
		name            string
		instanceID      string
		err             error
		expectedMessage string
	}{
		{
			name:            "tagging successful",
			instanceID:      "i-random",
			err:             nil,
			expectedMessage: "Done calling create-tags to EC2",
		},
		{
			name:            "tagging failed due to unknown error",
			instanceID:      "i-error",
			err:             errors.New("Unable to tag"),
			expectedMessage: "Error occurred trying to tag resources",
		},
		{
			name:            "tagging failed due to resource not found error",
			instanceID:      "i-not-found",
			err:             errors.New("InvalidInstanceID.NotFound: Instance not found"),
			expectedMessage: "Error occurred trying to tag resources",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			klog.SetOutput(&logBuf)
			defer func() {
				klog.SetOutput(os.Stderr)
			}()

			err := c.TagResource(context.TODO(), tt.instanceID, nil)
			assert.Equal(t, tt.err, err)
			assert.Contains(t, logBuf.String(), tt.expectedMessage)
		})
	}
}

func TestUntagResource(t *testing.T) {
	testFlags := flag.NewFlagSet("TestUntagResource", flag.ExitOnError)
	klog.InitFlags(testFlags)
	testFlags.Parse([]string{"--logtostderr=false"})
	awsServices := NewFakeAWSServices(TestClusterID)
	c, err := newAWSCloud(config.CloudConfig{}, awsServices)
	if err != nil {
		t.Errorf("Error building aws cloud: %v", err)
		return
	}

	tests := []struct {
		name            string
		instanceID      string
		err             error
		expectedMessage string
	}{
		{
			name:            "untagging successful",
			instanceID:      "i-random",
			err:             nil,
			expectedMessage: "Done calling delete-tags to EC2",
		},
		{
			name:            "untagging failed due to unknown error",
			instanceID:      "i-error",
			err:             errors.New("Unable to remove tag"),
			expectedMessage: "Error occurred trying to untag resources",
		},
		{
			name:            "untagging failed due to resource not found error",
			instanceID:      "i-not-found",
			err:             nil,
			expectedMessage: "Couldn't find resource when trying to untag it hence skipping it",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			klog.SetOutput(&logBuf)
			defer func() {
				klog.SetOutput(os.Stderr)
			}()

			err := c.UntagResource(context.TODO(), tt.instanceID, nil)
			assert.Equal(t, tt.err, err)
			assert.Contains(t, logBuf.String(), tt.expectedMessage)
		})
	}
}

func TestHasClusterTagOwned(t *testing.T) {
	tests := []struct {
		name          string
		clusterID     string
		tags          []ec2types.Tag
		expected      bool
		expectedError string
	}{
		{
			name:      "empty cluster ID returns error",
			clusterID: "",
			tags: []ec2types.Tag{
				{
					Key:   aws.String("kubernetes.io/cluster/test-cluster"),
					Value: aws.String("owned"),
				},
			},
			expected:      false,
			expectedError: "cannot check cluster tag owned: clusterID is empty",
		},
		{
			name:      "legacy tag with matching cluster ID returns true",
			clusterID: "test-cluster",
			tags: []ec2types.Tag{
				{
					Key:   aws.String("KubernetesCluster"),
					Value: aws.String("test-cluster"),
				},
			},
			expected: true,
		},
		{
			name:      "legacy tag with non-matching cluster ID returns false",
			clusterID: "test-cluster",
			tags: []ec2types.Tag{
				{
					Key:   aws.String("KubernetesCluster"),
					Value: aws.String("other-cluster"),
				},
			},
			expected: false,
		},
		{
			name:      "new tag with owned value returns true",
			clusterID: "test-cluster",
			tags: []ec2types.Tag{
				{
					Key:   aws.String("kubernetes.io/cluster/test-cluster"),
					Value: aws.String("owned"),
				},
			},
			expected: true,
		},
		{
			name:      "new tag with shared value returns false",
			clusterID: "test-cluster",
			tags: []ec2types.Tag{
				{
					Key:   aws.String("kubernetes.io/cluster/test-cluster"),
					Value: aws.String("shared"),
				},
			},
			expected: false,
		},
		{
			name:      "new tag with wrong cluster ID returns false",
			clusterID: "test-cluster",
			tags: []ec2types.Tag{
				{
					Key:   aws.String("kubernetes.io/cluster/other-cluster"),
					Value: aws.String("owned"),
				},
			},
			expected: false,
		},
		{
			name:      "no matching tags returns false",
			clusterID: "test-cluster",
			tags: []ec2types.Tag{
				{
					Key:   aws.String("some-other-tag"),
					Value: aws.String("some-value"),
				},
			},
			expected: false,
		},
		{
			name:      "empty tags list returns false",
			clusterID: "test-cluster",
			tags:      []ec2types.Tag{},
			expected:  false,
		},
		{
			name:      "both legacy and new tags present - legacy matches",
			clusterID: "test-cluster",
			tags: []ec2types.Tag{
				{
					Key:   aws.String("KubernetesCluster"),
					Value: aws.String("test-cluster"),
				},
				{
					Key:   aws.String("kubernetes.io/cluster/test-cluster"),
					Value: aws.String("shared"),
				},
			},
			expected: true,
		},
		{
			name:      "both legacy and new tags present - new matches",
			clusterID: "test-cluster",
			tags: []ec2types.Tag{
				{
					Key:   aws.String("KubernetesCluster"),
					Value: aws.String("other-cluster"),
				},
				{
					Key:   aws.String("kubernetes.io/cluster/test-cluster"),
					Value: aws.String("owned"),
				},
			},
			expected: true,
		},
		{
			name:      "both legacy and new tags present - neither matches",
			clusterID: "test-cluster",
			tags: []ec2types.Tag{
				{
					Key:   aws.String("KubernetesCluster"),
					Value: aws.String("other-cluster"),
				},
				{
					Key:   aws.String("kubernetes.io/cluster/test-cluster"),
					Value: aws.String("shared"),
				},
			},
			expected: false,
		},
		{
			name:      "tags with nil key returns false",
			clusterID: "test-cluster",
			tags: []ec2types.Tag{
				{
					Key:   nil,
					Value: aws.String("test-cluster"),
				},
			},
			expected: false,
		},
		{
			name:      "tags with nil value returns false",
			clusterID: "test-cluster",
			tags: []ec2types.Tag{
				{
					Key:   aws.String("KubernetesCluster"),
					Value: nil,
				},
			},
			expected: false,
		},
		{
			name:      "legacy tag with empty value returns false",
			clusterID: "test-cluster",
			tags: []ec2types.Tag{
				{
					Key:   aws.String("KubernetesCluster"),
					Value: aws.String(""),
				},
			},
			expected: false,
		},
		{
			name:      "new tag with empty value returns false",
			clusterID: "test-cluster",
			tags: []ec2types.Tag{
				{
					Key:   aws.String("kubernetes.io/cluster/test-cluster"),
					Value: aws.String(""),
				},
			},
			expected: false,
		},
		{
			name:      "multiple tags with one legacy match",
			clusterID: "test-cluster",
			tags: []ec2types.Tag{
				{
					Key:   aws.String("some-tag"),
					Value: aws.String("some-value"),
				},
				{
					Key:   aws.String("KubernetesCluster"),
					Value: aws.String("test-cluster"),
				},
				{
					Key:   aws.String("other-tag"),
					Value: aws.String("other-value"),
				},
			},
			expected: true,
		},
		{
			name:      "multiple tags with one new match",
			clusterID: "test-cluster",
			tags: []ec2types.Tag{
				{
					Key:   aws.String("some-tag"),
					Value: aws.String("some-value"),
				},
				{
					Key:   aws.String("kubernetes.io/cluster/test-cluster"),
					Value: aws.String("owned"),
				},
				{
					Key:   aws.String("other-tag"),
					Value: aws.String("other-value"),
				},
			},
			expected: true,
		},
		{
			name:      "case sensitivity - legacy tag key case mismatch",
			clusterID: "test-cluster",
			tags: []ec2types.Tag{
				{
					Key:   aws.String("kubernetescluster"),
					Value: aws.String("test-cluster"),
				},
			},
			expected: false,
		},
		{
			name:      "case sensitivity - new tag key case mismatch",
			clusterID: "test-cluster",
			tags: []ec2types.Tag{
				{
					Key:   aws.String("Kubernetes.io/cluster/test-cluster"),
					Value: aws.String("owned"),
				},
			},
			expected: false,
		},
		{
			name:      "case sensitivity - new tag value case mismatch",
			clusterID: "test-cluster",
			tags: []ec2types.Tag{
				{
					Key:   aws.String("kubernetes.io/cluster/test-cluster"),
					Value: aws.String("Owned"),
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tagging := awsTagging{
				ClusterID: tt.clusterID,
			}

			result, err := tagging.hasClusterTagOwned(tt.tags)
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expected, result, "hasClusterTagOwned returned unexpected result")
		})
	}
}
