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

	"github.com/stretchr/testify/assert"
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
