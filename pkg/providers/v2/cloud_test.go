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
	"bytes"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cloud-provider-aws/pkg/apis/config/v1alpha1"
)

func TestAzToRegion(t *testing.T) {
	testCases := []struct {
		az     string
		region string
	}{
		{"us-east-1a", "us-east-1"},
		{"us-west-2-lax-1a", "us-west-2"},
		{"eu-central-1a", "eu-central-1"},
		{"ap-northeast-2a", "ap-northeast-2"},
		{"us-gov-east-1a", "us-gov-east-1"},
		{"us-iso-east-1a", "us-iso-east-1"},
		{"us-isob-east-1a", "us-isob-east-1"},
	}

	for _, testCase := range testCases {
		ret, err := azToRegion(testCase.az)
		assert.NoError(t, err)
		assert.Equal(t, testCase.region, ret)
	}
}

func TestReadAWSCloudConfig(t *testing.T) {
	testcases := []struct {
		name       string
		configData string
		config     *v1alpha1.AWSCloudConfig
		expectErr  bool
	}{
		{
			name: "config with valid cluster name",
			configData: `---
kind: AWSCloudConfig
apiVersion: config.aws.io/v1alpha1
config:
    clusterName: test
    `,
			config: &v1alpha1.AWSCloudConfig{
				TypeMeta: metav1.TypeMeta{
					Kind:       "AWSCloudConfig",
					APIVersion: "config.aws.io/v1alpha1",
				},
				Config: v1alpha1.AWSConfig{
					ClusterName: "test",
				},
			},
		},
		{
			name: "config with empty cluster name",
			configData: `---
kind: AWSCloudConfig
apiVersion: config.aws.io/v1alpha1
config:
    clusterName: ""
    `,
			config: &v1alpha1.AWSCloudConfig{
				TypeMeta: metav1.TypeMeta{
					Kind:       "AWSCloudConfig",
					APIVersion: "config.aws.io/v1alpha1",
				},
				Config: v1alpha1.AWSConfig{
					ClusterName: "",
				},
			},
		},
		{
			name: "config with only kind and apiVersion",
			configData: `---
kind: AWSCloudConfig
apiVersion: config.aws.io/v1alpha1
    `,
			config: &v1alpha1.AWSCloudConfig{
				TypeMeta: metav1.TypeMeta{
					Kind:       "AWSCloudConfig",
					APIVersion: "config.aws.io/v1alpha1",
				},
				Config: v1alpha1.AWSConfig{
					ClusterName: "",
				},
			},
		},
		{
			name: "config with wrong Kind",
			configData: `---
kind: WrongCloudConfig
apiVersion: config.aws.io/v1alpha1
config:
    clusterName: test
	`,
			config:    nil,
			expectErr: true,
		},
		{
			name: "config with wrong apiversion",
			configData: `---
kind: AWSCloudConfig
apiVersion: wrong.aws.io/v1alpha1
config:
    clusterName: test
	`,
			config:    nil,
			expectErr: true,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			buffer := bytes.NewBufferString(testcase.configData)
			cloudConfig, err := readAWSCloudConfig(buffer)
			if err != nil && !testcase.expectErr {
				t.Fatal(err)
			}

			if err == nil && testcase.expectErr {
				t.Error("expected error but got none")
			}

			if !reflect.DeepEqual(cloudConfig, testcase.config) {
				t.Logf("actual cloud config: %#v", cloudConfig)
				t.Logf("expected cloud config: %#v", testcase.config)
				t.Error("AWS cloud config did not match")
			}
		})
	}
}

func TestValidateAWSCloudConfig(t *testing.T) {
	testcases := []struct {
		name      string
		config    *v1alpha1.AWSCloudConfig
		expectErr bool
	}{
		{
			name: "valid config",
			config: &v1alpha1.AWSCloudConfig{
				TypeMeta: metav1.TypeMeta{
					Kind:       "AWSCloudConfig",
					APIVersion: "config.aws.io/v1alpha1",
				},
				Config: v1alpha1.AWSConfig{
					ClusterName: "test",
				},
			},
		},
		{
			name: "empty cluster name",
			config: &v1alpha1.AWSCloudConfig{
				TypeMeta: metav1.TypeMeta{
					Kind:       "AWSCloudConfig",
					APIVersion: "config.aws.io/v1alpha1",
				},
				Config: v1alpha1.AWSConfig{
					ClusterName: "",
				},
			},
			expectErr: true,
		},
		{
			name: "empty config",
			config: &v1alpha1.AWSCloudConfig{
				TypeMeta: metav1.TypeMeta{
					Kind:       "AWSCloudConfig",
					APIVersion: "config.aws.io/v1alpha1",
				},
				Config: v1alpha1.AWSConfig{},
			},
			expectErr: true,
		},
		{
			name: "invalid config",
			config: &v1alpha1.AWSCloudConfig{
				TypeMeta: metav1.TypeMeta{
					Kind:       "AWSCloudConfig",
					APIVersion: "config.aws.io/v1alpha1",
				},
			},
			expectErr: true,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			errs := validateAWSCloudConfig(testcase.config)

			if testcase.expectErr && len(errs) == 0 {
				t.Errorf("expected error but got none")
			} else if !testcase.expectErr && len(errs) > 0 {
				t.Errorf("expected no error but received errors: %v", errs.ToAggregate())
			}
		})
	}
}
