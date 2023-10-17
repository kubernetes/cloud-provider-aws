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
	"github.com/aws/aws-sdk-go/service/ecrpublic"
	"github.com/golang/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cloud-provider-aws/pkg/mocks"
	v1 "k8s.io/kubelet/pkg/apis/credentialprovider/v1"
)

func generatePrivateGetAuthorizationTokenOutput(user string, password string, proxy string, expiration *time.Time) *ecr.GetAuthorizationTokenOutput {
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

func Test_GetCredentials_Private(t *testing.T) {
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
			getAuthorizationTokenOutput: generatePrivateGetAuthorizationTokenOutput("user", "pass", "", nil),
			response:                    generateResponse("123456789123.dkr.ecr.us-west-2.amazonaws.com", "user", "pass"),
		},
		{
			name:                        "image reference containing public ECR host",
			image:                       "123456789123.dkr.ecr.us-west-2.amazonaws.com/public.ecr.aws/foo:latest",
			getAuthorizationTokenOutput: generatePrivateGetAuthorizationTokenOutput("user", "pass", "", nil),
			response:                    generateResponse("123456789123.dkr.ecr.us-west-2.amazonaws.com", "user", "pass"),
		},
		{
			name:                        "non ECR host",
			image:                       "registry.k8s.io/foo:latest",
			getAuthorizationTokenOutput: generatePrivateGetAuthorizationTokenOutput("user", "pass", "", nil),
			response:                    generateResponse("registry.k8s.io", "user", "pass"),
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

func generatePublicGetAuthorizationTokenOutput(user string, password string, proxy string, expiration *time.Time) *ecrpublic.GetAuthorizationTokenOutput {
	creds := []byte(fmt.Sprintf("%s:%s", user, password))
	data := &ecrpublic.AuthorizationData{
		AuthorizationToken: aws.String(base64.StdEncoding.EncodeToString(creds)),
		ExpiresAt:          expiration,
	}
	output := &ecrpublic.GetAuthorizationTokenOutput{
		AuthorizationData: data,
	}
	return output
}

func Test_GetCredentials_Public(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockECRPublic := mocks.NewMockECRPublic(ctrl)

	testcases := []struct {
		name                        string
		image                       string
		args                        []string
		getAuthorizationTokenOutput *ecrpublic.GetAuthorizationTokenOutput
		getAuthorizationTokenError  error
		response                    *v1.CredentialProviderResponse
		expectedError               error
	}{
		{
			name:                        "success",
			image:                       "public.ecr.aws",
			getAuthorizationTokenOutput: generatePublicGetAuthorizationTokenOutput("user", "pass", "", nil),
			response:                    generateResponse("public.ecr.aws", "user", "pass"),
		},
		{
			name:                        "empty authorization data",
			image:                       "public.ecr.aws",
			getAuthorizationTokenOutput: &ecrpublic.GetAuthorizationTokenOutput{},
			getAuthorizationTokenError:  nil,
			expectedError:               errors.New("authorization data was empty"),
		},
		{
			name:                        "nil response",
			image:                       "public.ecr.aws",
			getAuthorizationTokenOutput: nil,
			getAuthorizationTokenError:  nil,
			expectedError:               errors.New("response output from ECR was nil"),
		},
		{
			name:                        "empty authorization token",
			image:                       "public.ecr.aws",
			getAuthorizationTokenOutput: &ecrpublic.GetAuthorizationTokenOutput{AuthorizationData: &ecrpublic.AuthorizationData{}},
			getAuthorizationTokenError:  nil,
			expectedError:               errors.New("authorization token in response was nil"),
		},
		{
			name:                        "invalid authorization token",
			image:                       "public.ecr.aws",
			getAuthorizationTokenOutput: nil,
			getAuthorizationTokenError:  errors.New("getAuthorizationToken failed"),
			expectedError:               errors.New("getAuthorizationToken failed"),
		},
		{
			name:  "invalid authorization token",
			image: "public.ecr.aws",
			getAuthorizationTokenOutput: &ecrpublic.GetAuthorizationTokenOutput{
				AuthorizationData: &ecrpublic.AuthorizationData{
					AuthorizationToken: aws.String(base64.StdEncoding.EncodeToString([]byte(fmt.Sprint("foo")))),
				},
			},
			getAuthorizationTokenError: nil,
			expectedError:              errors.New("error parsing username and password from authorization token"),
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			p := &ecrPlugin{ecrPublic: mockECRPublic}
			mockECRPublic.EXPECT().GetAuthorizationToken(gomock.Any()).Return(testcase.getAuthorizationTokenOutput, testcase.getAuthorizationTokenError)

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

func Test_parseHostFromImageReference(t *testing.T) {
	testcases := []struct {
		name  string
		image string
		host  string
		err   error
	}{
		{
			name:  "success",
			image: "123456789123.dkr.ecr.us-west-2.amazonaws.com/foo/bar:1.0",
			host:  "123456789123.dkr.ecr.us-west-2.amazonaws.com",
			err:   nil,
		},
		{
			name:  "existing scheme",
			image: "http://foobar",
			host:  "foobar",
			err:   nil,
		},
		{
			name:  "invalid URL",
			image: "foobar  ",
			host:  "",
			err:   errors.New("error parsing image reference https://foobar  : parse \"https://foobar  \": invalid character \" \" in host name"),
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			host, err := parseHostFromImageReference(testcase.image)

			if testcase.err != nil && (testcase.err.Error() != err.Error()) {
				t.Fatalf("expected error %s, got %s", testcase.err, err)
			}

			if host != testcase.host {
				t.Fatalf("registry mismatch. Expected %s, got %s", testcase.host, host)
			}
		})
	}
}

func Test_parseRegionFromECRPrivateHost(t *testing.T) {
	testcases := []struct {
		name   string
		host   string
		region string
	}{
		{
			name:   "success",
			host:   "123456789123.dkr.ecr.us-west-2.amazonaws.com",
			region: "us-west-2",
		},
		{
			name:   "invalid registry",
			host:   "foobar",
			region: "",
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			region := parseRegionFromECRPrivateHost(testcase.host)

			if region != testcase.region {
				t.Fatalf("region mismatch. Expected %s, got %s", testcase.region, region)
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
	}
	for _, g := range grid {
		actual := ecrPrivateHostPattern.MatchString(g.Registry)
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
