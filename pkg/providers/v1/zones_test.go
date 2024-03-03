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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func TestGetZoneIDByZoneName(t *testing.T) {
	for _, tc := range []struct {
		name           string
		zoneName       string
		expectedResult string
		expectError    bool
	}{
		{
			name:           "Should return requested zone ID",
			zoneName:       "az1",
			expectedResult: "az1-id",
			expectError:    false,
		},
		{
			name:           "Should return error if AZ doesn't exist",
			zoneName:       "az4",
			expectedResult: "",
			expectError:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := getCloudWithMockedDescribeAvailabilityZones()

			result, err := c.zoneCache.getZoneIDByZoneName(tc.zoneName)
			if tc.expectError {
				if err == nil {
					t.Error("Expected to see an error")
				}
			} else if err != nil {
				t.Errorf("Should not error getting zone ID: %s", err)
			}

			assert.Equal(t, tc.expectedResult, result, "Should return the expected zone ID")
		})
	}
}

func TestGetZoneDetailsByNames(t *testing.T) {
	for _, tc := range []struct {
		name             string
		zones            []string
		expectedResult   map[string]zoneDetails
		expectedAPICalls int
	}{
		{
			name:  "Should return all requested zones when available",
			zones: []string{"az1", "az2"},
			expectedResult: map[string]zoneDetails{
				"az1": {
					name:     "az1",
					id:       "az1-id",
					zoneType: "availability-zone",
				},
				"az2": {
					name:     "az2",
					id:       "az2-id",
					zoneType: "availability-zone",
				},
			},
			expectedAPICalls: 1,
		},
		{
			name:  "Should refresh zones and handle zones not found",
			zones: []string{"az1", "az4"},
			expectedResult: map[string]zoneDetails{
				"az1": {
					name:     "az1",
					id:       "az1-id",
					zoneType: "availability-zone",
				},
			},
			expectedAPICalls: 2,
		},
		{
			name:             "Should handle empty AZs",
			zones:            []string{},
			expectedResult:   map[string]zoneDetails{},
			expectedAPICalls: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, mockedEC2API := getCloudWithMockedDescribeAvailabilityZones()

			result, err := c.zoneCache.getZoneDetailsByNames(tc.zones)
			if err != nil {
				t.Errorf("Should not error getting zone details: %s", err)
			}

			assert.Equal(t, tc.expectedResult, result, "Should return the expected zones")

			// Call again to verify expected caching behavior
			result, err = c.zoneCache.getZoneDetailsByNames(tc.zones)
			if err != nil {
				t.Errorf("Should not error getting zone details: %s", err)
			}
			mockedEC2API.AssertNumberOfCalls(t, "DescribeAvailabilityZones", tc.expectedAPICalls)
		})
	}
}

func getCloudWithMockedDescribeAvailabilityZones() (*Cloud, *MockedEC2API) {
	mockedEC2API := newMockedEC2API()
	c := &Cloud{ec2: &awsSdkEC2{ec2: mockedEC2API}}
	c.zoneCache = zoneCache{cloud: c}

	mockedEC2API.On("DescribeAvailabilityZones", mock.Anything).Return(&ec2.DescribeAvailabilityZonesOutput{
		AvailabilityZones: []*ec2.AvailabilityZone{
			{
				ZoneName: aws.String("az1"),
				ZoneId:   aws.String("az1-id"),
				ZoneType: aws.String("availability-zone"),
			},
			{
				ZoneName: aws.String("az2"),
				ZoneId:   aws.String("az2-id"),
				ZoneType: aws.String("availability-zone"),
			},
			{
				ZoneName: aws.String("az3"),
				ZoneId:   aws.String("az3-id"),
				ZoneType: aws.String("availability-zone"),
			},
		},
	}, nil)

	return c, mockedEC2API
}
