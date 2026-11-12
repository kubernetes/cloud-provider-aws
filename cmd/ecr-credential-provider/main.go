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
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecrpublic"
	"github.com/aws/aws-sdk-go-v2/service/signin"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
	v1 "k8s.io/kubelet/pkg/apis/credentialprovider/v1"
)

const (
	ecrPublicRegion        = "us-east-1"
	tokenTypeRegional      = "regional-token"
	tokenTypeGlobal        = "global-token"
	signInGrantType        = "client_credentials"
	ecrGlobalTokenResource = "ecr.amazonaws.com"
	tokenTypeFlagName      = "ecr-private-token-type"
)

var (
	defaultHTTPClient  = awshttp.NewBuildableClient().WithTimeout(30 * time.Second)
	tokenTypeFlagUsage = fmt.Sprintf("ECR private registry token type: %s or %s", tokenTypeRegional, tokenTypeGlobal)
)

var ecrPublicHosts []string = []string{"public.ecr.aws", "ecr-public.aws.com"}

var ecrPrivateHostPattern = regexp.MustCompile(`^(\d{12})\.dkr[\.\-]ecr(\-fips)?\.([a-zA-Z0-9][a-zA-Z0-9-_]*)\.(amazonaws\.(?:com(?:\.cn)?|eu)|on\.(?:aws|amazonwebservices\.com\.cn)|sc2s\.sgov\.gov|c2s\.ic\.gov|cloud\.adc-e\.uk|csp\.hci\.ic\.gov)$`)

// ECR abstracts the calls we make to aws-sdk for testing purposes
type ECR interface {
	GetAuthorizationToken(ctx context.Context, params *ecr.GetAuthorizationTokenInput, optFns ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error)
}

// ECRPublic abstracts the calls we make to aws-sdk for testing purposes
type ECRPublic interface {
	GetAuthorizationToken(ctx context.Context, params *ecrpublic.GetAuthorizationTokenInput, optFns ...func(*ecrpublic.Options)) (*ecrpublic.GetAuthorizationTokenOutput, error)
}

// SignIn is the subset of the AWS SignIn client used by the provider.
type SignIn interface {
	CreateBearerToken(ctx context.Context, params *signin.CreateBearerTokenInput, optFns ...func(*signin.Options)) (*signin.CreateBearerTokenOutput, error)
}

// STS abstracts the calls we make to aws-sdk for testing purposes
type STS interface {
	AssumeRoleWithWebIdentity(context.Context, *sts.AssumeRoleWithWebIdentityInput, ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

type ecrPlugin struct {
	ecr       ECR
	ecrPublic ECRPublic
	signIn    SignIn
	sts       STS
	tokenType string
}

func defaultECRProvider(ctx context.Context, region string) (ECR, error) {
	var cfg aws.Config
	var err error
	if region != "" {
		cfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(region),
			config.WithHTTPClient(defaultHTTPClient),
		)
	} else {
		klog.Warningf("No region found in the image reference, the default region will be used. Please refer to AWS SDK documentation for configuration purpose.")
		cfg, err = config.LoadDefaultConfig(ctx,
			config.WithHTTPClient(defaultHTTPClient),
		)
	}

	if err != nil {
		return nil, err
	}

	return ecr.NewFromConfig(cfg), nil
}

func defaultSignInProvider(ctx context.Context, region string) (SignIn, string, error) {
	cfg, err := loadSignInConfig(ctx, region)
	if err != nil {
		return nil, cfg.Region, err
	}

	return signin.NewFromConfig(cfg), cfg.Region, nil
}

func loadSignInConfig(ctx context.Context, region string) (aws.Config, error) {
	if region != "" {
		return config.LoadDefaultConfig(ctx,
			config.WithRegion(region),
			config.WithHTTPClient(defaultHTTPClient),
		)
	}

	klog.Warningf("No region found in the image reference, the default region will be used. Please refer to AWS SDK documentation for configuration purpose.")
	return config.LoadDefaultConfig(ctx,
		config.WithHTTPClient(defaultHTTPClient),
	)
}

func publicECRProvider(ctx context.Context) (ECRPublic, error) {
	// ECR public registries are only in one region and only accessible from regions
	// in the "aws" partition.
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(ecrPublicRegion),
		config.WithHTTPClient(defaultHTTPClient),
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
			config.WithHTTPClient(defaultHTTPClient),
		)
	} else {
		klog.Warningf("No region found in the image reference, the default region will be used. Please refer to AWS SDK documentation for configuration purpose.")
		cfg, err = config.LoadDefaultConfig(ctx,
			config.WithHTTPClient(defaultHTTPClient),
		)
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

// getGlobalCredsData fetches a globally valid ECR token through the SignIn CreateBearerToken API.
func (e *ecrPlugin) getGlobalCredsData(ctx context.Context, imageHost string, optFns ...func(*signin.Options)) (*credsData, error) {
	klog.Infof("Getting global token for private registry %s", imageHost)

	region := parseRegionFromECRPrivateHost(imageHost)
	signInRegion := region
	var err error
	if e.signIn == nil {
		e.signIn, signInRegion, err = defaultSignInProvider(ctx, region)
		if err != nil {
			return nil, fmt.Errorf("failed to create SignIn client for image host %q (region %q): %w", imageHost, signInRegion, err)
		}
	}

	requestStartedAt := time.Now()
	output, err := e.signIn.CreateBearerToken(ctx, &signin.CreateBearerTokenInput{
		GrantType: aws.String(signInGrantType),
		Resource:  aws.String(ecrGlobalTokenResource),
	}, optFns...)
	if err != nil {
		return nil, fmt.Errorf("SignIn CreateBearerToken failed for image host %q (region %q): %w", imageHost, signInRegion, err)
	}
	if output == nil ||
		aws.ToString(output.AccessToken) == "" ||
		aws.ToInt32(output.ExpiresIn) <= 0 ||
		!strings.EqualFold(aws.ToString(output.TokenType), "Bearer") {
		return nil, fmt.Errorf("SignIn CreateBearerToken returned missing or invalid token data for image host %q (region %q)", imageHost, signInRegion)
	}

	accessToken := aws.ToString(output.AccessToken)
	expiresIn := aws.ToInt32(output.ExpiresIn)
	expiresAt := requestStartedAt.Add(time.Duration(expiresIn) * time.Second)
	authorizationToken := base64.StdEncoding.EncodeToString([]byte("AWS:" + accessToken))
	return &credsData{
		authToken: aws.String(authorizationToken),
		expiresAt: &expiresAt,
	}, nil
}

func (e *ecrPlugin) buildCredentialsProvider(ctx context.Context, request *v1.CredentialProviderRequest, imageHost string) aws.CredentialsProvider {
	if request.ServiceAccountToken == "" {
		return nil
	}

	arn, ok := request.ServiceAccountAnnotations["eks.amazonaws.com/ecr-role-arn"]
	if !ok {
		arn = os.Getenv("AWS_ECR_ROLE_ARN")
	}
	if arn == "" {
		klog.Info("no arn provided, cannot assume role using ServiceAccountToken")
		return nil
	}

	if e.sts == nil {
		region := ""
		if !slices.Contains(ecrPublicHosts, imageHost) {
			region = parseRegionFromECRPrivateHost(imageHost)
		}
		sts, err := stsProvider(ctx, region)
		if err != nil {
			klog.Errorf("failed to create sts client, cannot assume role: %v", err)
			return nil
		}
		e.sts = sts
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
	})
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
	tokenType, err := normalizeTokenType(e.tokenType)
	if err != nil {
		return nil, err
	}

	credentialsProvider := e.buildCredentialsProvider(ctx, request, imageHost)
	if slices.Contains(ecrPublicHosts, imageHost) {
		var optFns = []func(*ecrpublic.Options){}
		if credentialsProvider != nil {
			optFns = append(optFns, func(o *ecrpublic.Options) {
				o.Credentials = credentialsProvider
			})
		}
		creds, err = e.getPublicCredsData(ctx, optFns...)
	} else if tokenType == tokenTypeGlobal {
		var optFns = []func(*signin.Options){}
		if credentialsProvider != nil {
			optFns = append(optFns, func(o *signin.Options) {
				o.Credentials = credentialsProvider
			})
		}
		creds, err = e.getGlobalCredsData(ctx, imageHost, optFns...)
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

func normalizeTokenType(tokenType string) (string, error) {
	switch tokenType {
	case "", tokenTypeRegional:
		return tokenTypeRegional, nil
	case tokenTypeGlobal:
		return tokenTypeGlobal, nil
	default:
		return "", fmt.Errorf("unsupported --%s value %q; expected %q or %q", tokenTypeFlagName, tokenType, tokenTypeRegional, tokenTypeGlobal)
	}
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
	var tokenType string
	cmd := &cobra.Command{
		Use:     "ecr-credential-provider",
		Short:   "ECR credential provider for kubelet",
		Version: gitVersion,
		Run: func(cmd *cobra.Command, args []string) {
			p := NewCredentialProvider(&ecrPlugin{tokenType: tokenType})
			if err := p.Run(context.TODO()); err != nil {
				klog.Errorf("Error running credential provider plugin: %v", err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringVar(&tokenType, tokenTypeFlagName, tokenTypeRegional, tokenTypeFlagUsage)
	return cmd
}
