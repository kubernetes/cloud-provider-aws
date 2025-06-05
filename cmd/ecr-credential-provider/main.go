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
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecrpublic"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
	v1 "k8s.io/kubelet/pkg/apis/credentialprovider/v1"
)

const ecrPublicRegion string = "us-east-1"
const ecrPublicHost string = "public.ecr.aws"

var ecrPrivateHostPattern = regexp.MustCompile(`^(\d{12})\.dkr[\.\-]ecr(\-fips)?\.([a-zA-Z0-9][a-zA-Z0-9-_]*)\.(amazonaws\.com(?:\.cn)?|on\.(?:aws|amazonwebservices\.com\.cn)|sc2s\.sgov\.gov|c2s\.ic\.gov|cloud\.adc-e\.uk|csp\.hci\.ic\.gov)$`)

// ECR abstracts the calls we make to aws-sdk for testing purposes
type ECR interface {
	GetAuthorizationToken(ctx context.Context, params *ecr.GetAuthorizationTokenInput, optFns ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error)
}

// ECRPublic abstracts the calls we make to aws-sdk for testing purposes
type ECRPublic interface {
	GetAuthorizationToken(ctx context.Context, params *ecrpublic.GetAuthorizationTokenInput, optFns ...func(*ecrpublic.Options)) (*ecrpublic.GetAuthorizationTokenOutput, error)
}

// STS abstracts the calls we make to aws-sdk for testing purposes
type STS interface {
	AssumeRoleWithWebIdentity(context.Context, *sts.AssumeRoleWithWebIdentityInput, ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

type ecrPlugin struct {
	ecr       ECR
	ecrPublic ECRPublic
	sts       STS
}

func defaultECRProvider(ctx context.Context, region string) (ECR, error) {
	var cfg aws.Config
	var err error
	if region != "" {
		cfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(region),
		)
	} else {
		klog.Warningf("No region found in the image reference, the default region will be used. Please refer to AWS SDK documentation for configuration purpose.")
		cfg, err = config.LoadDefaultConfig(ctx)
	}

	if err != nil {
		return nil, err
	}

	return ecr.NewFromConfig(cfg), nil
}

func publicECRProvider(ctx context.Context) (ECRPublic, error) {
	// ECR public registries are only in one region and only accessible from regions
	// in the "aws" partition.
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(ecrPublicRegion),
	)
	if err != nil {
		return nil, err
	}

	return ecrpublic.NewFromConfig(cfg), nil
}

func stsProvider(ctx context.Context, region string) (STS, error) {
	var cfg aws.Config
	var err error
	if region != "" {
		cfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(region),
		)
	} else {
		klog.Warningf("No region found in the image reference, the default region will be used. Please refer to AWS SDK documentation for configuration purpose.")
		cfg, err = config.LoadDefaultConfig(ctx)
	}

	if err != nil {
		return nil, err
	}
	return sts.NewFromConfig(cfg), nil
}

type credsData struct {
	authToken *string
	expiresAt *time.Time
}

func (e *ecrPlugin) getPublicCredsData(ctx context.Context, optFns ...func(*ecrpublic.Options)) (*credsData, error) {
	klog.Infof("Getting creds for public registry")
	var err error

	if e.ecrPublic == nil {
		e.ecrPublic, err = publicECRProvider(ctx)
	}
	if err != nil {
		return nil, err
	}

	output, err := e.ecrPublic.GetAuthorizationToken(ctx, &ecrpublic.GetAuthorizationTokenInput{}, optFns...)
	if err != nil {
		return nil, err
	}

	if output == nil {
		return nil, errors.New("response output from ECR was nil")
	}

	if output.AuthorizationData == nil {
		return nil, errors.New("authorization data was empty")
	}

	return &credsData{
		authToken: output.AuthorizationData.AuthorizationToken,
		expiresAt: output.AuthorizationData.ExpiresAt,
	}, nil
}

func (e *ecrPlugin) getPrivateCredsData(ctx context.Context, imageHost string, image string, optFns ...func(*ecr.Options)) (*credsData, error) {
	klog.Infof("Getting creds for private image %s", image)
	var err error

	if e.ecr == nil {
		region := parseRegionFromECRPrivateHost(imageHost)
		e.ecr, err = defaultECRProvider(ctx, region)
		if err != nil {
			return nil, err
		}
	}

	output, err := e.ecr.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{}, optFns...)
	if err != nil {
		return nil, err
	}
	if output == nil {
		return nil, errors.New("response output from ECR was nil")
	}
	if len(output.AuthorizationData) == 0 {
		return nil, errors.New("authorization data was empty")
	}
	return &credsData{
		authToken: output.AuthorizationData[0].AuthorizationToken,
		expiresAt: output.AuthorizationData[0].ExpiresAt,
	}, nil
}

func (e *ecrPlugin) buildCredentialsProvider(ctx context.Context, request *v1.CredentialProviderRequest, imageHost string) (aws.CredentialsProvider, error) {
	var err error

	arn, ok := request.ServiceAccountAnnotations["eks.amazonaws.com/ecr-role-arn"]
	if !ok {
		arn = os.Getenv("AWS_ECR_ROLE_ARN")
	}
	if arn == "" {
		return nil, errors.New("no arn provided, cannot assume role using ServiceAccountToken")
	}

	if e.sts == nil {
		region := ""
		if imageHost != ecrPublicHost {
			region = parseRegionFromECRPrivateHost(imageHost)
		}
		e.sts, err = stsProvider(ctx, region)
	}
	if err != nil {
		return nil, err
	}

	return aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			assumeOutput, err := e.sts.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{
				RoleArn:          aws.String(arn),
				RoleSessionName:  aws.String("ecr-credential-provider"),
				WebIdentityToken: aws.String(request.ServiceAccountToken),
			})
			if err != nil {
				return aws.Credentials{}, fmt.Errorf("failed to assume role: %w", err)
			}
			return aws.Credentials{
				AccessKeyID:     *assumeOutput.Credentials.AccessKeyId,
				SecretAccessKey: *assumeOutput.Credentials.SecretAccessKey,
				SessionToken:    *assumeOutput.Credentials.SessionToken,
			}, nil
		}),
		nil
}

func (e *ecrPlugin) GetCredentials(ctx context.Context, request *v1.CredentialProviderRequest, args []string) (*v1.CredentialProviderResponse, error) {
	var creds *credsData
	var err error

	if request.Image == "" {
		return nil, errors.New("image in plugin request was empty")
	}

	imageHost, err := parseHostFromImageReference(request.Image)
	if err != nil {
		return nil, err
	}

	var credentialsProvider aws.CredentialsProvider = nil
	if request.ServiceAccountToken != "" {
		credentialsProvider, err = e.buildCredentialsProvider(ctx, request, imageHost)
		if err != nil {
			return nil, err
		}
	}

	if imageHost == ecrPublicHost {
		var optFns = []func(*ecrpublic.Options){}
		if credentialsProvider != nil {
			optFns = append(optFns, func(o *ecrpublic.Options) {
				o.Credentials = credentialsProvider
			})
		}
		creds, err = e.getPublicCredsData(ctx, optFns...)
	} else {
		var optFns = []func(*ecr.Options){}
		if credentialsProvider != nil {
			optFns = append(optFns, func(o *ecr.Options) {
				o.Credentials = credentialsProvider
			})
		}
		creds, err = e.getPrivateCredsData(ctx, imageHost, request.Image, optFns...)
	}

	if err != nil {
		return nil, err
	}

	if creds.authToken == nil {
		return nil, errors.New("authorization token in response was nil")
	}

	decodedToken, err := base64.StdEncoding.DecodeString(aws.ToString(creds.authToken))
	if err != nil {
		return nil, err
	}

	parts := strings.SplitN(string(decodedToken), ":", 2)
	if len(parts) != 2 {
		return nil, errors.New("error parsing username and password from authorization token")
	}

	cacheDuration := getCacheDuration(creds.expiresAt)

	return &v1.CredentialProviderResponse{
		CacheKeyType:  v1.RegistryPluginCacheKeyType,
		CacheDuration: cacheDuration,
		Auth: map[string]v1.AuthConfig{
			imageHost: {
				Username: parts[0],
				Password: parts[1],
			},
		},
	}, nil

}

// getCacheDuration calculates the credentials cache duration based on the ExpiresAt time from the authorization data
func getCacheDuration(expiresAt *time.Time) *metav1.Duration {
	var cacheDuration *metav1.Duration
	if expiresAt == nil {
		// explicitly set cache duration to 0 if expiresAt was nil so that
		// kubelet does not cache it in-memory
		cacheDuration = &metav1.Duration{Duration: 0}
	} else {
		// halving duration in order to compensate for the time loss between
		// the token creation and passing it all the way to kubelet.
		duration := time.Second * time.Duration((expiresAt.Unix()-time.Now().Unix())/2)
		if duration > 0 {
			cacheDuration = &metav1.Duration{Duration: duration}
		}
	}
	return cacheDuration
}

// parseHostFromImageReference parses the hostname from an image reference
func parseHostFromImageReference(image string) (string, error) {
	// a URL needs a scheme to be parsed correctly
	if !strings.Contains(image, "://") {
		image = "https://" + image
	}
	parsed, err := url.Parse(image)
	if err != nil {
		return "", fmt.Errorf("error parsing image reference %s: %v", image, err)
	}
	return parsed.Hostname(), nil
}

func parseRegionFromECRPrivateHost(host string) string {
	splitHost := ecrPrivateHostPattern.FindStringSubmatch(host)
	if len(splitHost) != 5 {
		return ""
	}
	return splitHost[3]
}

func main() {
	logs.InitLogs()
	defer logs.FlushLogs()

	if err := newCredentialProviderCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

var gitVersion string

func newCredentialProviderCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ecr-credential-provider",
		Short:   "ECR credential provider for kubelet",
		Version: gitVersion,
		Run: func(cmd *cobra.Command, args []string) {
			p := NewCredentialProvider(&ecrPlugin{})
			if err := p.Run(context.TODO()); err != nil {
				klog.Errorf("Error running credential provider plugin: %v", err)
				os.Exit(1)
			}
		},
	}
	return cmd
}
