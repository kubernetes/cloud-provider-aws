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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/ecrpublic"
	publictypes "github.com/aws/aws-sdk-go-v2/service/ecrpublic/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/stretchr/testify/mock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/kubelet/pkg/apis/credentialprovider/v1"
)

type MockedECR struct {
	mock.Mock
}

func (m *MockedECR) GetAuthorizationToken(ctx context.Context, params *ecr.GetAuthorizationTokenInput, optFns ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error) {
	args := m.Called(ctx, params)

	opts := ecr.Options{}
	for _, fn := range optFns {
		fn(&opts)
	}
	if opts.Credentials != nil {
		opts.Credentials.Retrieve(ctx)
	}

	if args.Get(1) != nil {
		return args.Get(0).(*ecr.GetAuthorizationTokenOutput), args.Get(1).(error)
	}
	return args.Get(0).(*ecr.GetAuthorizationTokenOutput), nil
}

// ECRPublic abstracts the calls we make to aws-sdk for testing purposes
type MockedECRPublic struct {
	mock.Mock
}

func (m *MockedECRPublic) GetAuthorizationToken(ctx context.Context, params *ecrpublic.GetAuthorizationTokenInput, optFns ...func(*ecrpublic.Options)) (*ecrpublic.GetAuthorizationTokenOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(1) != nil {
		return args.Get(0).(*ecrpublic.GetAuthorizationTokenOutput), args.Get(1).(error)
	}
	return args.Get(0).(*ecrpublic.GetAuthorizationTokenOutput), nil
}

type MockedSTS struct {
	mock.Mock
}

func (m *MockedSTS) AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(1) != nil {
		return args.Get(0).(*sts.AssumeRoleWithWebIdentityOutput), args.Get(1).(error)
	}
	return args.Get(0).(*sts.AssumeRoleWithWebIdentityOutput), nil
}

func generatePrivateGetAuthorizationTokenOutput(user string, password string, proxy string, expiration *time.Time) *ecr.GetAuthorizationTokenOutput {
	creds := []byte(fmt.Sprintf("%s:%s", user, password))
	data := types.AuthorizationData{
		AuthorizationToken: aws.String(base64.StdEncoding.EncodeToString(creds)),
		ExpiresAt:          expiration,
		ProxyEndpoint:      aws.String(proxy),
	}
	output := &ecr.GetAuthorizationTokenOutput{
		AuthorizationData: []types.AuthorizationData{data},
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
			getAuthorizationTokenOutput: &ecr.GetAuthorizationTokenOutput{AuthorizationData: []types.AuthorizationData{{}}},
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
				AuthorizationData: []types.AuthorizationData{
					{AuthorizationToken: aws.String(base64.StdEncoding.EncodeToString([]byte("foo")))},
				},
			},
			getAuthorizationTokenError: nil,
			expectedError:              errors.New("error parsing username and password from authorization token"),
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			mockECR := MockedECR{}
			p := &ecrPlugin{ecr: &mockECR}
			mockECR.On("GetAuthorizationToken", mock.Anything, mock.Anything).Return(testcase.getAuthorizationTokenOutput, testcase.getAuthorizationTokenError)

			creds, err := p.GetCredentials(context.TODO(), &v1.CredentialProviderRequest{Image: testcase.image}, testcase.args)

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

func Test_GetCredentials_PrivateForServiceAccount(t *testing.T) {
	testcases := []struct {
		name                            string
		request                         *v1.CredentialProviderRequest
		args                            []string
		expectedAssumeArn               string
		getAuthorizationTokenOutput     *ecr.GetAuthorizationTokenOutput
		getAuthorizationTokenError      error
		assumeRoleWithWebIdentityOutput *sts.AssumeRoleWithWebIdentityOutput
		assumeRoleWithWebIdentityError  error
		response                        *v1.CredentialProviderResponse
		expectedError                   error
	}{
		{
			name:                        "success",
			request:                     &v1.CredentialProviderRequest{Image: "123456789123.dkr.ecr.us-west-2.amazonaws.com", ServiceAccountToken: "DEADBEEF=", ServiceAccountAnnotations: map[string]string{"eks.amazonaws.com/ecr-role-arn": "arn:expected"}},
			expectedAssumeArn:           "arn:expected",
			getAuthorizationTokenOutput: generatePrivateGetAuthorizationTokenOutput("user", "pass", "", nil),
			assumeRoleWithWebIdentityOutput: &sts.AssumeRoleWithWebIdentityOutput{
				Credentials: &ststypes.Credentials{
					AccessKeyId:     aws.String("access-key-id"),
					SecretAccessKey: aws.String("secret-access-key"),
					SessionToken:    aws.String("session-token"),
				},
			},
			response: generateResponse("123456789123.dkr.ecr.us-west-2.amazonaws.com", "user", "pass"),
		},
		{
			name:                        "no arn provided",
			request:                     &v1.CredentialProviderRequest{Image: "123456789123.dkr.ecr.us-west-2.amazonaws.com", ServiceAccountToken: "DEADBEEF="},
			expectedAssumeArn:           "arn:expected",
			getAuthorizationTokenOutput: generatePrivateGetAuthorizationTokenOutput("user", "pass", "", nil),
			assumeRoleWithWebIdentityOutput: &sts.AssumeRoleWithWebIdentityOutput{
				Credentials: &ststypes.Credentials{
					AccessKeyId:     aws.String("access-key-id"),
					SecretAccessKey: aws.String("secret-access-key"),
					SessionToken:    aws.String("session-token"),
				},
			},
			response:      generateResponse("123456789123.dkr.ecr.us-west-2.amazonaws.com", "user", "pass"),
			expectedError: errors.New("no arn provided, cannot assume role using ServiceAccountToken"),
		},
		{
			name:                           "assume error",
			request:                        &v1.CredentialProviderRequest{Image: "123456789123.dkr.ecr.us-west-2.amazonaws.com", ServiceAccountToken: "DEADBEEF=", ServiceAccountAnnotations: map[string]string{"eks.amazonaws.com/ecr-role-arn": "arn:expected"}},
			expectedAssumeArn:              "arn:expected",
			getAuthorizationTokenOutput:    generatePrivateGetAuthorizationTokenOutput("user", "pass", "", nil),
			assumeRoleWithWebIdentityError: errors.New("injected error"),
			response:                       generateResponse("123456789123.dkr.ecr.us-west-2.amazonaws.com", "user", "pass"),
			expectedError:                  errors.New("injected error"),
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			mockECR := MockedECR{}
			mockSTS := MockedSTS{}
			p := &ecrPlugin{ecr: &mockECR, sts: &mockSTS}
			mockECR.On("GetAuthorizationToken", mock.Anything, mock.Anything).Return(testcase.getAuthorizationTokenOutput, testcase.getAuthorizationTokenError)

			expectedInput := sts.AssumeRoleWithWebIdentityInput{
				RoleArn:          aws.String(testcase.expectedAssumeArn),
				RoleSessionName:  aws.String("ecr-credential-provider"),
				WebIdentityToken: aws.String(testcase.request.ServiceAccountToken),
			}
			mockSTS.On("AssumeRoleWithWebIdentity", mock.Anything, &expectedInput).Return(testcase.assumeRoleWithWebIdentityOutput, testcase.assumeRoleWithWebIdentityError)
			creds, err := p.GetCredentials(context.TODO(), testcase.request, testcase.args)
			if err != nil {
				if testcase.expectedError == nil {
					t.Fatalf("got unexpected error %s", err.Error())

				}

				if testcase.expectedError.Error() != err.Error() {
					t.Fatalf("expected %s, got %s", testcase.expectedError.Error(), err.Error())
				}
			}

			if testcase.expectedError == nil {
				if creds.CacheKeyType != testcase.response.CacheKeyType {
					t.Fatalf("Unexpected CacheKeyType. Expected: %s, got: %s", testcase.response.CacheKeyType, creds.CacheKeyType)
				}

				if creds.Auth[testcase.request.Image] != testcase.response.Auth[testcase.request.Image] {
					t.Fatalf("Unexpected Auth. Expected: %s, got: %s", testcase.response.Auth[testcase.request.Image], creds.Auth[testcase.request.Image])
				}

				if creds.CacheDuration.Duration != testcase.response.CacheDuration.Duration {
					t.Fatalf("Unexpected CacheDuration. Expected: %s, got: %s", testcase.response.CacheDuration.Duration, creds.CacheDuration.Duration)
				}
			}
		})
	}
}

func generatePublicGetAuthorizationTokenOutput(user string, password string, expiration *time.Time) *ecrpublic.GetAuthorizationTokenOutput {
	creds := []byte(fmt.Sprintf("%s:%s", user, password))
	data := &publictypes.AuthorizationData{
		AuthorizationToken: aws.String(base64.StdEncoding.EncodeToString(creds)),
		ExpiresAt:          expiration,
	}
	output := &ecrpublic.GetAuthorizationTokenOutput{
		AuthorizationData: data,
	}
	return output
}

func Test_GetCredentials_Public(t *testing.T) {
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
			getAuthorizationTokenOutput: generatePublicGetAuthorizationTokenOutput("user", "pass", nil),
			response:                    generateResponse("public.ecr.aws", "user", "pass"),
		},
		{
			name:                        "empty image",
			image:                       "",
			getAuthorizationTokenOutput: &ecrpublic.GetAuthorizationTokenOutput{},
			getAuthorizationTokenError:  nil,
			expectedError:               errors.New("image in plugin request was empty"),
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
			getAuthorizationTokenOutput: &ecrpublic.GetAuthorizationTokenOutput{AuthorizationData: &publictypes.AuthorizationData{}},
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
				AuthorizationData: &publictypes.AuthorizationData{
					AuthorizationToken: aws.String(base64.StdEncoding.EncodeToString([]byte("foo"))),
				},
			},
			getAuthorizationTokenError: nil,
			expectedError:              errors.New("error parsing username and password from authorization token"),
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			mockECRPublic := MockedECRPublic{}
			p := &ecrPlugin{ecrPublic: &mockECRPublic}
			mockECRPublic.On("GetAuthorizationToken", mock.Anything, mock.Anything).Return(testcase.getAuthorizationTokenOutput, testcase.getAuthorizationTokenError)

			creds, err := p.GetCredentials(context.TODO(), &v1.CredentialProviderRequest{Image: testcase.image}, testcase.args)

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
		// us-west-2
		{
			name:   "success",
			host:   "123456789123.dkr.ecr.us-west-2.amazonaws.com",
			region: "us-west-2",
		},
		// CN region
		{
			name:   "success",
			host:   "123456789123.dkr.ecr.cn-north-1.amazonaws.com.cn",
			region: "cn-north-1",
		},
		// GovCloud
		{
			name:   "success",
			host:   "123456789123.dkr.ecr.us-gov-east-1.amazonaws.com",
			region: "us-gov-east-1",
		},
		// ISO
		{
			name:   "success",
			host:   "123456789123.dkr.ecr.us-iso-east-1.c2s.ic.gov",
			region: "us-iso-east-1",
		},
		// Dual-Stack
		{
			name:   "success",
			host:   "123456789123.dkr-ecr.us-west-2.on.aws",
			region: "us-west-2",
		},
		// Dual-Stack FIPS
		{
			name:   "success",
			host:   "123456789123.dkr-ecr-fips.us-west-2.on.aws",
			region: "us-west-2",
		},
		// IPv6 CN
		{
			name:   "success",
			host:   "123456789123.dkr-ecr.cn-north-1.on.amazonwebservices.com.cn",
			region: "cn-north-1",
		},
		// IPv6 GovCloud
		{
			name:   "success",
			host:   "123456789123.dkr-ecr.us-gov-east-1.on.aws",
			region: "us-gov-east-1",
		},
		// IPv6 GovCloud FIPS
		{
			name:   "success",
			host:   "123456789123.dkr-ecr-fips.us-gov-east-1.on.aws",
			region: "us-gov-east-1",
		},
		// Invalid name
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
		//IPv6 dual stack endpoint
		{"123456789012.dkr-ecr.lala-land-1.on.aws", true},
		//IPv6 dual stack endpoint fips
		{"123456789012.dkr-ecr-fips.lala-land-1.on.aws", true},
		//IPv6 dual stack endpoint .cn
		{"123456789012.dkr-ecr.lala-land-1.on.amazonwebservices.com.cn", true},
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
