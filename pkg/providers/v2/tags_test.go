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
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
)

func TestFindClusterName(t *testing.T) {
	grid := []struct {
		Tags                map[string]string
		ExpectedClusterName string
		ExpectError         bool
	}{
		{
			Tags: map[string]string{},
		},
		{
			Tags: map[string]string{
				TagNameKubernetesClusterPrefix: TestClusterID,
			},
			ExpectedClusterName: TestClusterID,
		},
		{
			Tags: map[string]string{
				TagNameKubernetesClusterPrefix: "",
			},
			ExpectedClusterName: "",
		},
	}
	for _, g := range grid {
		var ec2Tags []*ec2.Tag
		for k, v := range g.Tags {
			ec2Tags = append(ec2Tags, &ec2.Tag{Key: aws.String(k), Value: aws.String(v)})
		}
		clusterName, err := findClusterName(ec2Tags)
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

			if g.ExpectedClusterName != clusterName {
				t.Errorf("unexpected new clusterName for tags %v: %s vs %s", g.Tags, g.ExpectedClusterName, clusterName)
				continue
			}
		}
	}
}
