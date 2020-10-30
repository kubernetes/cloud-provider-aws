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

func TestIsEqualIntPointer(t *testing.T) {
	testCases := []struct {
		name           string
		i1             int64
		i2             int64
		expectedResult bool
	}{
		{
			name:           "two different int values",
			i1:             2344,
			i2:             4566,
			expectedResult: false,
		},
		{
			name:           "two different int values",
			i1:             1234,
			i2:             1234,
			expectedResult: true,
		},
		{
			name:           "one zero value",
			i1:             2344,
			i2:             0,
			expectedResult: false,
		},
		{
			name:           "two zero values",
			i1:             0,
			i2:             0,
			expectedResult: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			p1 := &testCase.i1
			p2 := &testCase.i2
			ret := isEqualIntPointer(p1, p2)
			assert.Equal(t, testCase.expectedResult, ret)
		})
	}
}

func TestIsEqualStringPointer(t *testing.T) {
	testCases := []struct {
		name           string
		s1             string
		s2             string
		expectedResult bool
	}{
		{
			name:           "two different string values",
			s1:             "test1",
			s2:             "test2",
			expectedResult: false,
		},
		{
			name:           "two identical string values",
			s1:             "test",
			s2:             "test",
			expectedResult: true,
		},
		{
			name:           "one empty value",
			s1:             "test",
			s2:             "",
			expectedResult: false,
		},
		{
			name:           "two empty values",
			s1:             "",
			s2:             "",
			expectedResult: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			p1 := &testCase.s1
			p2 := &testCase.s2
			ret := isEqualStringPointer(p1, p2)
			assert.Equal(t, testCase.expectedResult, ret)
		})
	}
}
