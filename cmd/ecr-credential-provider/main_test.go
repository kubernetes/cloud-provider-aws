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

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/golang/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cloud-provider-aws/pkg/providers/v2/mocks"
	"k8s.io/kubelet/pkg/apis/credentialprovider/v1"
)

func generateGetAuthorizationTokenOutput(user string, password string, proxy string, expiration *time.Time) *ecr.GetAuthorizationTokenOutput {
	creds := []byte(fmt.Sprintf("%s:%s", user, password))
	data := &ecr.AuthorizationData{
		AuthorizationToken: aws.String(base64.StdEncoding.EncodeToString(creds)),
		ExpiresAt:          expiration,
		ProxyEndpoint:      aws.String(proxy),
	}
	output := &ecr.GetAuthorizationTokenOutput{
		AuthorizationData: []*ecr.AuthorizationData{data},
	}
	return output
}

func generateResponse(registry string, username string, password string) *v1.CredentialProviderResponse {
	return &v1.CredentialProviderResponse{
		CacheKeyType:  v1.RegistryPluginCacheKeyType,
		CacheDuration: &metav1.Duration{Duration: 0},
		Auth: map[string]v1.AuthConfig{
			registry: {
				Username: username,
				Password: password,
			},
		},
	}
}

func Test_GetCredentials(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockECR := mocks.NewMockECR(ctrl)

	testcases := []struct {
		name                        string
		image                       string
		args                        []string
		getAuthorizationTokenOutput *ecr.GetAuthorizationTokenOutput
		getAuthorizationTokenError  error
		response                    *v1.CredentialProviderResponse
		expectedError               error
	}{
		{
			name:                        "success",
			image:                       "123456789123.dkr.ecr.us-west-2.amazonaws.com",
			getAuthorizationTokenOutput: generateGetAuthorizationTokenOutput("user", "pass", "", nil),
			response:                    generateResponse("123456789123.dkr.ecr.us-west-2.amazonaws.com", "user", "pass"),
		},
		{
			name:                        "empty authorization data",
			image:                       "123456789123.dkr.ecr.us-west-2.amazonaws.com",
			getAuthorizationTokenOutput: &ecr.GetAuthorizationTokenOutput{},
			getAuthorizationTokenError:  nil,
			expectedError:               errors.New("authorization data was empty"),
		},
		{
			name:                        "nil response",
			image:                       "123456789123.dkr.ecr.us-west-2.amazonaws.com",
			getAuthorizationTokenOutput: nil,
			getAuthorizationTokenError:  nil,
			expectedError:               errors.New("response output from ECR was nil"),
		},
		{
			name:                        "empty authorization token",
			image:                       "123456789123.dkr.ecr.us-west-2.amazonaws.com",
			getAuthorizationTokenOutput: &ecr.GetAuthorizationTokenOutput{AuthorizationData: []*ecr.AuthorizationData{{}}},
			getAuthorizationTokenError:  nil,
			expectedError:               errors.New("authorization token in response was nil"),
		},
		{
			name:                        "invalid authorization token",
			image:                       "123456789123.dkr.ecr.us-west-2.amazonaws.com",
			getAuthorizationTokenOutput: nil,
			getAuthorizationTokenError:  errors.New("getAuthorizationToken failed"),
			expectedError:               errors.New("getAuthorizationToken failed"),
		},
		{
			name:  "invalid authorization token",
			image: "123456789123.dkr.ecr.us-west-2.amazonaws.com",
			getAuthorizationTokenOutput: &ecr.GetAuthorizationTokenOutput{
				AuthorizationData: []*ecr.AuthorizationData{
					{AuthorizationToken: aws.String(base64.StdEncoding.EncodeToString([]byte(fmt.Sprint("foo"))))},
				},
			},
			getAuthorizationTokenError: nil,
			expectedError:              errors.New("error parsing username and password from authorization token"),
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			p := &ecrPlugin{ecr: mockECR}
			mockECR.EXPECT().GetAuthorizationToken(gomock.Any()).Return(testcase.getAuthorizationTokenOutput, testcase.getAuthorizationTokenError)

			creds, err := p.GetCredentials(context.TODO(), testcase.image, testcase.args)

			if testcase.expectedError != nil && (testcase.expectedError.Error() != err.Error()) {
				t.Fatalf("expected %s, got %s", testcase.expectedError.Error(), err.Error())
			}

			if testcase.expectedError == nil {
				if creds.CacheKeyType != testcase.response.CacheKeyType {
					t.Fatalf("Unexpected CacheKeyType. Expected: %s, got: %s", testcase.response.CacheKeyType, creds.CacheKeyType)
				}

				if creds.Auth[testcase.image] != testcase.response.Auth[testcase.image] {
					t.Fatalf("Unexpected Auth. Expected: %s, got: %s", testcase.response.Auth[testcase.image], creds.Auth[testcase.image])
				}

				if creds.CacheDuration.Duration != testcase.response.CacheDuration.Duration {
					t.Fatalf("Unexpected CacheDuration. Expected: %s, got: %s", testcase.response.CacheDuration.Duration, creds.CacheDuration.Duration)
				}
			}
		})
	}
}

func Test_ParseURL(t *testing.T) {
	testcases := []struct {
		name       string
		image      string
		registryID string
		region     string
		registry   string
		err        error
	}{
		{
			name:       "success",
			image:      "123456789123.dkr.ecr.us-west-2.amazonaws.com",
			registryID: "123456789123",
			region:     "us-west-2",
			registry:   "123456789123.dkr.ecr.us-west-2.amazonaws.com",
			err:        nil,
		},
		{
			name:       "invalid registry",
			image:      "foobar",
			registryID: "",
			region:     "",
			registry:   "",
			err:        errors.New("foobar is not a valid ECR repository URL"),
		},
		{
			name:       "invalid URL",
			image:      "foobar  ",
			registryID: "",
			region:     "",
			registry:   "",
			err:        errors.New("error parsing image https://foobar  : parse \"https://foobar  \": invalid character \" \" in host name"),
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			registryID, region, registry, err := parseRepoURL(testcase.image)

			if testcase.err != nil && (testcase.err.Error() != err.Error()) {
				t.Fatalf("expected error %s, got %s", testcase.err, err)
			}

			if registryID != testcase.registryID {
				t.Fatalf("registryID mismatch. Expected %s, got %s", testcase.registryID, registryID)
			}

			if region != testcase.region {
				t.Fatalf("region mismatch. Expected %s, got %s", testcase.region, region)
			}

			if registry != testcase.registry {
				t.Fatalf("registry mismatch. Expected %s, got %s", testcase.registry, registry)
			}
		})
	}
}

func TestRegistryPatternMatch(t *testing.T) {
	grid := []struct {
		Registry string
		Expected bool
	}{
		{"123456789012.dkr.ecr.lala-land-1.amazonaws.com", true},
		// fips
		{"123456789012.dkr.ecr-fips.lala-land-1.amazonaws.com", true},
		// .cn
		{"123456789012.dkr.ecr.lala-land-1.amazonaws.com.cn", true},
		// registry ID too long
		{"1234567890123.dkr.ecr.lala-land-1.amazonaws.com", false},
		// registry ID too short
		{"12345678901.dkr.ecr.lala-land-1.amazonaws.com", false},
		// registry ID has invalid chars
		{"12345678901A.dkr.ecr.lala-land-1.amazonaws.com", false},
		// region has invalid chars
		{"123456789012.dkr.ecr.lala-land-1!.amazonaws.com", false},
		// region starts with invalid char
		{"123456789012.dkr.ecr.#lala-land-1.amazonaws.com", false},
		// invalid host suffix
		{"123456789012.dkr.ecr.lala-land-1.amazonaws.hacker.com", false},
		// invalid host suffix
		{"123456789012.dkr.ecr.lala-land-1.hacker.com", false},
		// invalid host suffix
		{"123456789012.dkr.ecr.lala-land-1.amazonaws.lol", false},
		// without dkr
		{"123456789012.dog.ecr.lala-land-1.amazonaws.com", false},
		// without ecr
		{"123456789012.dkr.cat.lala-land-1.amazonaws.com", false},
		// without amazonaws
		{"123456789012.dkr.cat.lala-land-1.awsamazon.com", false},
		// too short
		{"123456789012.lala-land-1.amazonaws.com", false},
		// iso
		{"123456789012.dkr.ecr.us-iso-east-1.c2s.ic.gov", true},
		// iso-b
		{"123456789012.dkr.ecr.us-isob-east-1.sc2s.sgov.gov", true},
		// iso-e
		{"123456789012.dkr.ecr.eu-isoe-west-1.cloud.adc-e.uk", true},
		// iso-f
		{"123456789012.dkr.ecr.us-isof-east-1.csp.hci.ic.gov", true},
		// invalid gov endpoint
		{"123456789012.dkr.ecr.us-iso-east-1.amazonaws.gov", false},
	}
	for _, g := range grid {
		actual := ecrPattern.MatchString(g.Registry)
		if actual != g.Expected {
			t.Errorf("unexpected pattern match value, want %v for %s", g.Expected, g.Registry)
		}
	}
}

func Test_getCacheDuration(t *testing.T) {
	testcases := []struct {
		ExpiresAt *time.Time
		Expected  time.Duration
	}{
		{nil, 0},
		{aws.Time(time.Now().Add(12 * time.Hour)), 6 * time.Hour},
	}

	for _, tc := range testcases {
		actual := getCacheDuration(tc.ExpiresAt)
		if actual == nil {
			t.Errorf("unexpected nil value returned for test value %v", tc.ExpiresAt)
		} else if actual.Round(time.Second) != tc.Expected {
			t.Errorf("unexpected duration value: want %v, got %v", tc.Expected, actual.Duration)
		}
	}
}
