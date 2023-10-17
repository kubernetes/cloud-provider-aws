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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/ecrpublic"
	"github.com/spf13/cobra"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
	v1 "k8s.io/kubelet/pkg/apis/credentialprovider/v1"
)

const ecrPublicRegion string = "us-east-1"
const ecrPublicHost string = "public.ecr.aws"

var ecrPrivateHostPattern = regexp.MustCompile(`^(\d{12})\.dkr\.ecr(\-fips)?\.([a-zA-Z0-9][a-zA-Z0-9-_]*)\.(amazonaws\.com(\.cn)?|sc2s\.sgov\.gov|c2s\.ic\.gov)$`)

// ECR abstracts the calls we make to aws-sdk for testing purposes
type ECR interface {
	GetAuthorizationToken(input *ecr.GetAuthorizationTokenInput) (*ecr.GetAuthorizationTokenOutput, error)
}

// ECRPublic abstracts the calls we make to aws-sdk for testing purposes
type ECRPublic interface {
	GetAuthorizationToken(input *ecrpublic.GetAuthorizationTokenInput) (*ecrpublic.GetAuthorizationTokenOutput, error)
}

type ecrPlugin struct {
	ecr       ECR
	ecrPublic ECRPublic
}

func defaultECRProvider(region string) (*ecr.ECR, error) {
	cfg := aws.Config{}
	if region != "" {
		klog.Warningf("No region found in the image reference, the default region will be used. Please refer to AWS SDK documentation for configuration purpose.")
		cfg.Region = aws.String(region)
	}
	sess, err := session.NewSessionWithOptions(session.Options{
		Config:            cfg,
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return nil, err
	}

	return ecr.New(sess), nil
}

func publicECRProvider() (*ecrpublic.ECRPublic, error) {
	// ECR public registries are only in one region and only accessible from regions
	// in the "aws" partition.
	sess, err := session.NewSessionWithOptions(session.Options{
		Config:            aws.Config{Region: aws.String(ecrPublicRegion)},
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return nil, err
	}

	return ecrpublic.New(sess), nil
}

type credsData struct {
	authToken *string
	expiresAt *time.Time
}

func (e *ecrPlugin) getPublicCredsData() (*credsData, error) {
	klog.Infof("Getting creds for public registry")
	var err error

	if e.ecrPublic == nil {
		e.ecrPublic, err = publicECRProvider()
	}
	if err != nil {
		return nil, err
	}

	output, err := e.ecrPublic.GetAuthorizationToken(&ecrpublic.GetAuthorizationTokenInput{})
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

func (e *ecrPlugin) getPrivateCredsData(imageHost string, image string) (*credsData, error) {
	klog.Infof("Getting creds for private image %s", image)
	var err error

	if e.ecr == nil {
		region := parseRegionFromECRPrivateHost(imageHost)
		e.ecr, err = defaultECRProvider(region)
		if err != nil {
			return nil, err
		}
	}
	output, err := e.ecr.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})
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

func (e *ecrPlugin) GetCredentials(ctx context.Context, image string, args []string) (*v1.CredentialProviderResponse, error) {
	var creds *credsData
	var err error

	imageHost, err := parseHostFromImageReference(image)
	if err != nil {
		return nil, err
	}

	if imageHost == ecrPublicHost {
		creds, err = e.getPublicCredsData()
	} else {
		creds, err = e.getPrivateCredsData(imageHost, image)
	}

	if err != nil {
		return nil, err
	}

	if creds.authToken == nil {
		return nil, errors.New("authorization token in response was nil")
	}

	decodedToken, err := base64.StdEncoding.DecodeString(aws.StringValue(creds.authToken))
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
	if len(splitHost) != 6 {
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
